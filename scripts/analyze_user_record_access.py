#!/usr/bin/env python3
"""Inventory whole-record struct userrec access candidates.

This complements analyze_user_field_access.py. Direct member expressions such
as ``usr.Security`` are excluded here. The output instead covers operations on
complete ``struct userrec`` objects, including fread/fwrite, read/write,
memcpy/memset, structure assignments and pointer escapes to other functions.

Unknown pointer and value transfers remain explicitly classified as candidates
until their callee semantics have been reviewed.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
import re
import sys

from analyze_user_field_access import (
    DECLARATION_PATTERN,
    GLOBAL_USER_RECORDS,
    REPOSITORY_ROOT,
    SOURCE_DIRS,
    SOURCE_SUFFIXES,
    find_function_scopes,
    global_userrec_variables,
    mask_comments_and_literals,
    userrec_variables_at,
)


@dataclass(frozen=True, order=True)
class RecordAccess:
    kind: str
    path: str
    line: int
    column: int
    variable: str
    expression: str
    source: str


def is_member_access(
    masked_line: str,
    end: int,
) -> bool:
    return re.match(
        r"\s*(?:\[[^\]\n]+\]\s*)?(?:\.|->)",
        masked_line[end:],
    ) is not None


def enclosing_function_argument(
    masked_text: str,
    offset: int,
) -> tuple[str, int] | None:
    """Return the enclosing function call and argument number.

    The backward scan handles casts, nested calls and function calls split
    across several source lines.
    """

    depth = 0
    opening = None
    function = None
    lower_bound = max(0, offset - 8192)

    for position in range(offset - 1, lower_bound - 1, -1):
        character = masked_text[position]

        if character == ")":
            depth += 1
            continue

        if character != "(":
            continue

        if depth > 0:
            depth -= 1
            continue

        prefix = masked_text[
            max(lower_bound, position - 256):position
        ]
        match = re.search(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*$",
            prefix,
        )

        if match is None:
            continue

        opening = position
        function = match.group(1)
        break

    if opening is None or function is None:
        return None

    argument = 1
    parentheses = 0
    brackets = 0
    braces = 0

    for character in masked_text[opening + 1:offset]:
        if character == "(":
            parentheses += 1
        elif character == ")":
            parentheses = max(0, parentheses - 1)
        elif character == "[":
            brackets += 1
        elif character == "]":
            brackets = max(0, brackets - 1)
        elif character == "{":
            braces += 1
        elif character == "}":
            braces = max(0, braces - 1)
        elif (
            character == ","
            and parentheses == 0
            and brackets == 0
            and braces == 0
        ):
            argument += 1

    return function, argument


def classify_record_access(
    masked_text: str,
    start: int,
    end: int,
) -> str:
    before = masked_text[max(0, start - 4096):start]
    after = masked_text[end:min(len(masked_text), end + 256)]

    if re.search(
        r"\bstruct\s+userrec\s*\*?\s*$",
        before,
    ):
        return "declaration"

    if re.search(
        r"\bsizeof\s*\(\s*[*&]?\s*$",
        before,
    ):
        return "metadata"

    if re.match(r"\s*=(?!=)", after):
        return "record-write"

    if re.search(
        r"(?<![=!<>])=\s*"
        r"(?:\([^()\n]*\)\s*)*"
        r"&?\s*$",
        before,
    ):
        return "record-read"

    function_position = enclosing_function_argument(
        masked_text,
        start,
    )

    if function_position is not None:
        function, argument = function_position

        reviewed_accesses = {
            ("read_exact_at", 2): "record-write",
            ("record_identifier_matches", 1): "record-read",
            ("write_record_at", 2): "record-read",
            ("build_record", 2): "record-write",
            ("TerminateUserRecordStrings", 1): "record-read-write",
            ("upd_crc32", 1): "record-read",
        }

        reviewed = reviewed_accesses.get(
            (function, argument)
        )

        if reviewed is not None:
            return reviewed

        if function == "fread" and argument == 1:
            return "record-write"

        if function == "fwrite" and argument == 1:
            return "record-read"

        if function in {"read", "recv"} and argument == 2:
            return "record-write"

        if function in {"write", "send"} and argument == 2:
            return "record-read"

        if function == "memset" and argument == 1:
            return "record-write"

        if function in {"memcpy", "memmove"}:
            if argument == 1:
                return "record-write"
            if argument == 2:
                return "record-read"

        if function in {"memcmp", "bcmp"}:
            return "record-read"

        if re.search(r"&\s*$", before):
            return "pointer-escape"

        return "value-transfer"

    if re.search(r"\breturn\s+&?\s*$", before):
        return "record-read"

    if re.search(r"&\s*$", before):
        return "pointer-escape"

    return "value-use"



def scan_file(path: Path) -> list[RecordAccess]:
    original = path.read_text(encoding="utf-8")
    masked = mask_comments_and_literals(original)
    scopes = find_function_scopes(masked)
    global_variables = global_userrec_variables(masked, scopes)
    variables = set(global_variables)

    for scope in scopes:
        variables.update(scope.variables)

    if not variables:
        return []

    variable_pattern = re.compile(
        r"\b(?P<variable>"
        + "|".join(
            re.escape(variable)
            for variable in sorted(
                variables,
                key=len,
                reverse=True,
            )
        )
        + r")\b"
    )

    original_lines = original.splitlines()
    masked_lines = masked.splitlines()
    accesses: list[RecordAccess] = []

    line_offset = 0

    for line_number, masked_line in enumerate(
        masked_lines,
        start=1,
    ):
        original_line = original_lines[line_number - 1]

        for match in variable_pattern.finditer(masked_line):
            absolute_offset = line_offset + match.start()
            allowed_variables = userrec_variables_at(
                absolute_offset,
                global_variables,
                scopes,
            )

            if match.group("variable") not in allowed_variables:
                continue

            if is_member_access(masked_line, match.end()):
                continue

            kind = classify_record_access(
                masked,
                absolute_offset,
                absolute_offset + (
                    match.end() - match.start()
                ),
            )

            if kind == "declaration":
                continue

            accesses.append(
                RecordAccess(
                    kind=kind,
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


def collect_accesses() -> list[RecordAccess]:
    accesses: list[RecordAccess] = []

    for source_dir in SOURCE_DIRS:
        directory = REPOSITORY_ROOT / source_dir

        if not directory.is_dir():
            raise ValueError(
                f"missing source directory: {directory}"
            )

        for path in sorted(directory.rglob("*")):
            if (
                path.is_file()
                and path.suffix in SOURCE_SUFFIXES
            ):
                accesses.extend(scan_file(path))

    return accesses


def print_summary(
    accesses: list[RecordAccess],
) -> None:
    counts: dict[str, int] = {}
    files: dict[str, set[str]] = {}

    for access in accesses:
        counts[access.kind] = (
            counts.get(access.kind, 0) + 1
        )
        files.setdefault(
            access.kind,
            set(),
        ).add(access.path)

    print("userrec whole-record access candidates")
    print("======================================")
    print(f"Candidate occurrences: {len(accesses)}")
    print(
        "Source files involved: "
        f"{len({item.path for item in accesses})}"
    )
    print()
    print("KIND\tOCCURRENCES\tFILES")

    for kind in sorted(counts):
        print(
            f"{kind}\t"
            f"{counts[kind]}\t"
            f"{len(files[kind])}"
        )


def print_details(
    accesses: list[RecordAccess],
) -> None:
    writer = csv.writer(
        sys.stdout,
        delimiter="\t",
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )

    writer.writerow(
        (
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
                access.kind,
                access.path,
                access.line,
                access.column,
                access.variable,
                access.expression,
                access.source,
            )
        )


def parse_args(
    argv: list[str] | None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inventory whole-record struct userrec "
            "access candidates."
        )
    )
    parser.add_argument(
        "--format",
        choices=("summary", "details"),
        default="summary",
    )
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
) -> int:
    args = parse_args(argv)

    try:
        accesses = collect_accesses()
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            f"user-record access analysis failed: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.format == "details":
        print_details(accesses)
    else:
        print_summary(accesses)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
