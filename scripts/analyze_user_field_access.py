#!/usr/bin/env python3
"""Inventory direct struct userrec field access in production sources.

The analyzer tracks member accesses only when their base identifier is a known
``struct userrec`` object or one of the historic global records ``usr``,
``usrconfig`` and ``exitinfo``. Common member names such as ``Name`` or
``Password`` in unrelated structures are therefore excluded.

B5.5 initially uses this as an analysis tool. A fail-closed baseline is added
only after all classifications and whole-record access paths are reviewed.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import argparse
import csv
import re
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
USERS_HEADER = REPOSITORY_ROOT / "lib" / "users.h"

SOURCE_DIRS = (
    "lib",
    "mbfido",
    "mbnntp",
    "mbsebbs",
    "mbsetup",
    "mbtask",
    "mbutils",
    "unix",
    "fortytwo-auth/include",
    "fortytwo-auth/src",
)

SOURCE_SUFFIXES = {".c", ".h"}

GLOBAL_USER_RECORDS = {
    "usr",
    "usrconfig",
    "exitinfo",
}

MUTATING_MACROS = {
    "E_BOOL",
    "E_INT",
    "E_IRC",
    "E_JAM",
    "E_LOGL",
    "E_PTH",
    "E_SEC",
    "E_SECRET",
    "E_STR",
    "E_UINT",
    "E_UPS",
    "E_USEC",
}

FIRST_ARGUMENT_WRITERS = {
    "GetstrC",
    "Setup",
    "memcpy",
    "memset",
    "snprintf",
    "strcpy",
    "strncpy",
}

IN_PLACE_READ_WRITE_FUNCTIONS = {
    "tl",
    "tlf",
    "tu",
}

STRUCT_PATTERN = re.compile(
    r"struct\s+userrec\s*\{(.*?)\n\};",
    re.DOTALL,
)

DECLARATION_PATTERN = re.compile(
    r"(?:const\s+)?struct\s+userrec\s*\*?\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)


@dataclass(frozen=True)
class FunctionScope:
    start: int
    end: int
    variables: frozenset[str]


@dataclass(frozen=True, order=True)
class Access:
    field: str
    kind: str
    path: str
    line: int
    column: int
    variable: str
    expression: str
    source: str


def blank_preserving_newlines(text: str) -> str:
    return "".join(
        character if character in "\r\n" else " "
        for character in text
    )


def select_first_preprocessor_branches(
    masked_text: str,
) -> str:
    """Create a structurally balanced view of conditional C source.

    Only the first branch of each #if/#ifdef/#ifndef block is retained.
    All other branches and all preprocessor directives are blanked while
    preserving byte offsets and line numbers.

    This view is used only to locate function boundaries. Direct access
    scanning still uses the complete masked source.
    """

    output: list[str] = []
    parent_activity: list[bool] = []
    active = True
    continuation = False

    for line in masked_text.splitlines(keepends=True):
        stripped = line.lstrip()
        directive_line = continuation or stripped.startswith("#")

        if directive_line:
            if not continuation:
                match = re.match(
                    r"#\s*(if|ifdef|ifndef|elif|else|endif)\b",
                    stripped,
                )
                directive = match.group(1) if match else None

                if directive in {"if", "ifdef", "ifndef"}:
                    parent_activity.append(active)

                elif directive in {"elif", "else"}:
                    if not parent_activity:
                        raise ValueError(
                            "orphan preprocessor alternative"
                        )

                    active = False

                elif directive == "endif":
                    if not parent_activity:
                        raise ValueError(
                            "orphan preprocessor endif"
                        )

                    active = parent_activity.pop()

            continuation = (
                line.rstrip("\r\n").rstrip().endswith("\\")
            )
            output.append(blank_preserving_newlines(line))
            continue

        output.append(
            line if active else blank_preserving_newlines(line)
        )

    if parent_activity:
        raise ValueError(
            "unterminated preprocessor conditional"
        )

    if continuation:
        raise ValueError(
            "unterminated preprocessor directive"
        )

    return "".join(output)


def find_function_scopes(
    masked_text: str,
) -> list[FunctionScope]:
    """Find top-level C function bodies and their userrec variables."""

    structural_text = select_first_preprocessor_branches(
        masked_text
    )
    ranges: list[tuple[int, int]] = []
    depth = 0
    top_level_boundary = 0
    active_start: int | None = None

    for offset, char in enumerate(structural_text):
        if char == "{":
            if depth == 0:
                header = structural_text[
                    top_level_boundary:offset
                ]

                if (
                    re.search(r"\)\s*$", header) is not None
                    and "=" not in header
                ):
                    active_start = top_level_boundary
                else:
                    active_start = None

            depth += 1
            continue

        if char == "}":
            if depth == 0:
                raise ValueError("unbalanced closing brace")

            depth -= 1

            if depth == 0:
                if active_start is not None:
                    ranges.append((active_start, offset + 1))

                active_start = None
                top_level_boundary = offset + 1

            continue

        if depth == 0 and char == ";":
            top_level_boundary = offset + 1

    if depth != 0:
        raise ValueError("unbalanced opening brace")

    scopes: list[FunctionScope] = []

    for start, end in ranges:
        variables = frozenset(
            DECLARATION_PATTERN.findall(masked_text[start:end])
        )
        scopes.append(
            FunctionScope(
                start=start,
                end=end,
                variables=variables,
            )
        )

    return scopes


def global_userrec_variables(
    masked_text: str,
    scopes: list[FunctionScope],
) -> set[str]:
    variables = set(GLOBAL_USER_RECORDS)

    for match in DECLARATION_PATTERN.finditer(masked_text):
        if not any(
            scope.start <= match.start() < scope.end
            for scope in scopes
        ):
            variables.add(match.group(1))

    return variables


def userrec_variables_at(
    offset: int,
    global_variables: set[str],
    scopes: list[FunctionScope],
) -> set[str]:
    variables = set(global_variables)

    for scope in scopes:
        if scope.start <= offset < scope.end:
            variables.update(scope.variables)
            break

    return variables


def mask_comments_and_literals(text: str) -> str:
    """Mask comments and literals while retaining positions and newlines."""

    output = list(text)
    index = 0
    state = "code"

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""

        if state == "code":
            if char == "/" and next_char == "*":
                output[index] = " "
                output[index + 1] = " "
                index += 2
                state = "block_comment"
                continue

            if char == "/" and next_char == "/":
                output[index] = " "
                output[index + 1] = " "
                index += 2
                state = "line_comment"
                continue

            if char == '"':
                output[index] = " "
                index += 1
                state = "string"
                continue

            if char == "'":
                output[index] = " "
                index += 1
                state = "character"
                continue

        elif state == "block_comment":
            if char == "*" and next_char == "/":
                output[index] = " "
                output[index + 1] = " "
                index += 2
                state = "code"
                continue

            if char != "\n":
                output[index] = " "

        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "

        elif state in {"string", "character"}:
            if char == "\\":
                output[index] = " "

                if index + 1 < len(text):
                    if text[index + 1] != "\n":
                        output[index + 1] = " "
                    index += 2
                    continue

            delimiter = '"' if state == "string" else "'"

            if char == delimiter:
                output[index] = " "
                state = "code"
            elif char != "\n":
                output[index] = " "

        index += 1

    return "".join(output)


def parse_record_fields(text: str) -> list[str]:
    match = STRUCT_PATTERN.search(text)

    if match is None:
        raise ValueError("struct userrec was not found")

    fields: list[str] = []

    for raw_line in match.group(1).splitlines():
        declaration = raw_line.split("/*", 1)[0].strip()

        if not declaration or not declaration.endswith(";"):
            continue

        declaration = declaration[:-1].strip()

        field_match = re.search(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*\d+\s*$",
            declaration,
        ) or re.search(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*"
            r"(?:\[[^\]]+\])?(?:\[[^\]]+\])?\s*$",
            declaration,
        )

        if field_match is None:
            raise ValueError(
                f"cannot parse userrec declaration: {raw_line.strip()}"
            )

        fields.append(field_match.group(1))

    return fields


def classify_access(
    masked_line: str,
    match: re.Match[str],
) -> str:
    before = masked_line[:match.start()]
    after = masked_line[match.end():]

    mutating_macro_names = "|".join(
        re.escape(name) for name in sorted(MUTATING_MACROS)
    )

    if re.search(
        rf"\b(?:{mutating_macro_names})\s*\([^;]*$",
        before,
    ):
        return "write"

    if re.search(r"\bsizeof\s*\([^)]*$", before):
        return "metadata"

    if re.search(r"(?:\+\+|--)\s*$", before):
        return "read-write"

    operator = re.match(
        r"\s*(\+\+|--|<<=|>>=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|=(?!=))",
        after,
    )

    if operator is not None:
        return "write" if operator.group(1) == "=" else "read-write"

    function = re.search(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*&?\s*$",
        before,
    )

    if (
        function is not None
        and function.group(1) in IN_PLACE_READ_WRITE_FUNCTIONS
    ):
        return "read-write"

    if (
        function is not None
        and function.group(1) in FIRST_ARGUMENT_WRITERS
    ):
        return "write"

    return "read"


def scan_file(path: Path, fields: list[str]) -> list[Access]:
    original = path.read_text(encoding="utf-8")
    masked = mask_comments_and_literals(original)

    scopes = find_function_scopes(masked)
    global_variables = global_userrec_variables(masked, scopes)
    variables = set(global_variables)

    for scope in scopes:
        variables.update(scope.variables)

    field_alternation = "|".join(
        re.escape(field)
        for field in sorted(fields, key=len, reverse=True)
    )

    variable_alternation = "|".join(
        re.escape(variable)
        for variable in sorted(variables, key=len, reverse=True)
    )

    member_pattern = re.compile(
        rf"\b(?P<variable>{variable_alternation})\s*"
        rf"(?:\[[^\]\n]+\]\s*)?(?:\.|->)\s*"
        rf"(?P<field>{field_alternation})\b"
        rf"(?:\s*(?:"
        rf"\[[^\]\n]+\]|"
        rf"(?:\.|->)\s*[A-Za-z_][A-Za-z0-9_]*"
        rf"))*"
    )

    original_lines = original.split("\n")
    masked_lines = masked.split("\n")
    accesses: list[Access] = []

    line_offset = 0

    for line_number, masked_line in enumerate(masked_lines, start=1):
        original_line = original_lines[line_number - 1]

        for match in member_pattern.finditer(masked_line):
            absolute_offset = line_offset + match.start()
            allowed_variables = userrec_variables_at(
                absolute_offset,
                global_variables,
                scopes,
            )

            if match.group("variable") not in allowed_variables:
                continue

            accesses.append(
                Access(
                    field=match.group("field"),
                    kind=classify_access(masked_line, match),
                    path=path.relative_to(
                        REPOSITORY_ROOT
                    ).as_posix(),
                    line=line_number,
                    column=match.start() + 1,
                    variable=match.group("variable"),
                    expression=original_line[
                        match.start():match.end()
                    ],
                    source=original_line.strip(),
                )
            )

        line_offset += len(masked_line) + 1

    return accesses


def parse_args(
    argv: list[str] | None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inventory direct struct userrec field accesses "
            "in production sources."
        )
    )
    parser.add_argument(
        "--format",
        choices=("summary", "details"),
        default="summary",
        help=(
            "summary prints per-field counts; details prints "
            "one TSV row for every occurrence"
        ),
    )
    parser.add_argument(
        "--field",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "limit output to one field; may be supplied more "
            "than once"
        ),
    )
    return parser.parse_args(argv)


def collect_accesses(
    fields: list[str],
) -> list[Access]:
    accesses: list[Access] = []

    for source_dir in SOURCE_DIRS:
        directory = REPOSITORY_ROOT / source_dir

        if not directory.is_dir():
            raise ValueError(
                f"missing source directory: {directory}"
            )

        for path in sorted(directory.rglob("*")):
            if (
                path.suffix in SOURCE_SUFFIXES
                and path.is_file()
            ):
                accesses.extend(scan_file(path, fields))

    return accesses


def print_summary(
    fields: list[str],
    accesses: list[Access],
) -> None:
    by_field: dict[str, list[Access]] = defaultdict(list)

    for access in accesses:
        by_field[access.field].append(access)

    referenced_fields = {
        field for field in fields if by_field[field]
    }
    source_files = {
        access.path for access in accesses
    }

    print("userrec direct field-access analysis")
    print("====================================")
    print(f"Fields reported:             {len(fields)}")
    print(
        "Fields directly referenced: "
        f"{len(referenced_fields)}"
    )
    print(
        "Fields without direct refs: "
        f"{len(fields) - len(referenced_fields)}"
    )
    print(f"Direct member occurrences:  {len(accesses)}")
    print(f"Source files involved:      {len(source_files)}")
    print()
    print(
        "FIELD\tREAD\tWRITE\tREAD_WRITE\tMETADATA\tFILES"
    )

    for field in fields:
        field_accesses = by_field[field]
        counts: dict[str, int] = defaultdict(int)

        for access in field_accesses:
            counts[access.kind] += 1

        file_count = len({
            access.path for access in field_accesses
        })

        print(
            f"{field}\t"
            f"{counts['read']}\t"
            f"{counts['write']}\t"
            f"{counts['read-write']}\t"
            f"{counts['metadata']}\t"
            f"{file_count}"
        )


def print_details(
    accesses: list[Access],
) -> None:
    writer = csv.writer(
        sys.stdout,
        delimiter="\t",
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writerow(
        (
            "FIELD",
            "KIND",
            "PATH",
            "LINE",
            "COLUMN",
            "VARIABLE",
            "EXPRESSION",
            "SOURCE",
        )
    )

    for access in sorted(accesses):
        writer.writerow(
            (
                access.field,
                access.kind,
                access.path,
                access.line,
                access.column,
                access.variable,
                access.expression,
                access.source,
            )
        )


def main(
    argv: list[str] | None = None,
) -> int:
    args = parse_args(argv)

    try:
        fields = parse_record_fields(
            USERS_HEADER.read_text(encoding="utf-8")
        )

        unknown_fields = sorted(
            set(args.field) - set(fields)
        )

        if unknown_fields:
            raise ValueError(
                "unknown userrec fields: "
                + ", ".join(unknown_fields)
            )

        selected_fields = (
            [
                field
                for field in fields
                if field in set(args.field)
            ]
            if args.field
            else fields
        )

        accesses = collect_accesses(fields)

        if args.field:
            selected = set(selected_fields)
            accesses = [
                access
                for access in accesses
                if access.field in selected
            ]

    except (OSError, UnicodeError, ValueError) as exc:
        print(
            f"user-field access analysis failed: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.format == "details":
        print_details(accesses)
    else:
        print_summary(selected_fields, accesses)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
