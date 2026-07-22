#!/usr/bin/env python3
"""Summarize direct and whole-record writers of struct userrec.

The analysis consumes the reviewed B5.5 inventories. It does not modify source
files, users.data, or PostgreSQL.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import io
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPOSITORY_ROOT / "docs"

FIELD_SUMMARY = DOCS / "MBSETUP_USER_FIELD_ACCESS_RAW.tsv"
FIELD_DETAILS = DOCS / "MBSETUP_USER_FIELD_ACCESS_DETAILS.tsv"
RECORD_DETAILS = DOCS / "MBSETUP_USER_RECORD_ACCESS_DETAILS.tsv"

FIELD_TABLE_HEADER = (
    "FIELD\tREAD\tWRITE\tREAD_WRITE\tMETADATA\tFILES\n"
)

EXPECTED_FIELD_DETAIL_COLUMNS = [
    "FIELD",
    "KIND",
    "PATH",
    "LINE",
    "COLUMN",
    "VARIABLE",
    "EXPRESSION",
    "SOURCE",
]

EXPECTED_RECORD_DETAIL_COLUMNS = [
    "KIND",
    "PATH",
    "LINE",
    "COLUMN",
    "VARIABLE",
    "EXPRESSION",
    "SOURCE",
]

DIRECT_KINDS = {
    "read",
    "write",
    "read-write",
    "metadata",
}

DIRECT_WRITE_KINDS = {
    "write",
    "read-write",
}

RECORD_KINDS = {
    "metadata",
    "record-read",
    "record-read-write",
    "record-write",
}

RECORD_WRITE_KINDS = {
    "record-write",
    "record-read-write",
}


def parse_args(
    argv: list[str] | None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize direct field writers and complete user-record writers."
        )
    )
    parser.add_argument(
        "--field",
        action="append",
        default=[],
        help="limit direct writer details to a field; repeatable",
    )
    parser.add_argument(
        "--format",
        choices=("summary", "details"),
        default="summary",
        help="output format; default: summary",
    )
    return parser.parse_args(argv)


def read_field_order() -> list[str]:
    text = FIELD_SUMMARY.read_text(encoding="utf-8")

    if text.count(FIELD_TABLE_HEADER) != 1:
        raise ValueError(
            "field summary table header is missing or duplicated"
        )

    table = text.split(FIELD_TABLE_HEADER, 1)[1]
    rows = csv.DictReader(
        io.StringIO(FIELD_TABLE_HEADER + table),
        delimiter="\t",
    )

    fields = [row["FIELD"] for row in rows]

    if len(fields) != 72:
        raise ValueError(
            f"expected 72 userrec fields, found {len(fields)}"
        )

    if len(set(fields)) != len(fields):
        raise ValueError("duplicate fields in field summary")

    return fields


def read_tsv(
    path: Path,
    expected_columns: list[str],
) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")

        if reader.fieldnames != expected_columns:
            raise ValueError(
                f"unexpected columns in {path.name}: "
                f"{reader.fieldnames!r}"
            )

        rows = list(reader)

    for number, row in enumerate(rows, start=2):
        if None in row:
            raise ValueError(
                f"extra TSV columns in {path.name}:{number}"
            )

        if any(value is None for value in row.values()):
            raise ValueError(
                f"missing TSV value in {path.name}:{number}"
            )

    return rows


def component(path: str) -> str:
    return path.split("/", 1)[0]


def print_summary(
    field_order: list[str],
    field_rows: list[dict[str, str]],
    record_rows: list[dict[str, str]],
) -> None:
    direct_writers = [
        row
        for row in field_rows
        if row["KIND"] in DIRECT_WRITE_KINDS
    ]

    record_writers = [
        row
        for row in record_rows
        if row["KIND"] in RECORD_WRITE_KINDS
    ]

    by_field: dict[str, list[dict[str, str]]] = defaultdict(list)

    for row in direct_writers:
        by_field[row["FIELD"]].append(row)

    direct_writer_files = {
        row["PATH"]
        for row in direct_writers
    }

    record_writer_files = {
        row["PATH"]
        for row in record_writers
    }

    print("userrec writer analysis")
    print("=======================")
    print(
        "Fields with direct writers:       "
        f"{len(by_field)}"
    )
    print(
        "Direct writer occurrences:        "
        f"{len(direct_writers)}"
    )
    print(
        "Direct writer source files:       "
        f"{len(direct_writer_files)}"
    )
    print(
        "Whole-record writer occurrences:  "
        f"{len(record_writers)}"
    )
    print(
        "Whole-record writer source files: "
        f"{len(record_writer_files)}"
    )
    print()

    print(
        "FIELD\tWRITE\tREAD_WRITE\tOCCURRENCES\tFILES\tCOMPONENTS"
    )

    for field in field_order:
        rows = by_field.get(field)

        if not rows:
            continue

        counts = Counter(row["KIND"] for row in rows)
        files = sorted({row["PATH"] for row in rows})
        components = sorted({component(path) for path in files})

        print(
            "\t".join(
                (
                    field,
                    str(counts["write"]),
                    str(counts["read-write"]),
                    str(len(rows)),
                    str(len(files)),
                    ",".join(components),
                )
            )
        )

    print()
    print("WHOLE_RECORD_PATH\tRECORD_WRITE\tRECORD_READ_WRITE")

    by_path: dict[str, Counter[str]] = defaultdict(Counter)

    for row in record_writers:
        by_path[row["PATH"]][row["KIND"]] += 1

    for path in sorted(by_path):
        counts = by_path[path]

        print(
            "\t".join(
                (
                    path,
                    str(counts["record-write"]),
                    str(counts["record-read-write"]),
                )
            )
        )


def print_details(
    field_order: list[str],
    selected_fields: set[str],
    field_rows: list[dict[str, str]],
    record_rows: list[dict[str, str]],
) -> None:
    writer = csv.writer(
        sys.stdout,
        delimiter="\t",
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )

    writer.writerow(
        (
            "SCOPE",
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

    order = {
        field: index
        for index, field in enumerate(field_order)
    }

    direct_writers = [
        row
        for row in field_rows
        if (
            row["KIND"] in DIRECT_WRITE_KINDS
            and (
                not selected_fields
                or row["FIELD"] in selected_fields
            )
        )
    ]

    direct_writers.sort(
        key=lambda row: (
            order[row["FIELD"]],
            row["PATH"],
            int(row["LINE"]),
            int(row["COLUMN"]),
        )
    )

    for row in direct_writers:
        writer.writerow(
            (
                "field",
                row["FIELD"],
                row["KIND"],
                row["PATH"],
                row["LINE"],
                row["COLUMN"],
                row["VARIABLE"],
                row["EXPRESSION"],
                row["SOURCE"],
            )
        )

    for row in sorted(
        (
            row
            for row in record_rows
            if row["KIND"] in RECORD_WRITE_KINDS
        ),
        key=lambda row: (
            row["PATH"],
            int(row["LINE"]),
            int(row["COLUMN"]),
        ),
    ):
        writer.writerow(
            (
                "record",
                "",
                row["KIND"],
                row["PATH"],
                row["LINE"],
                row["COLUMN"],
                row["VARIABLE"],
                row["EXPRESSION"],
                row["SOURCE"],
            )
        )


def main(
    argv: list[str] | None = None,
) -> int:
    args = parse_args(argv)

    try:
        field_order = read_field_order()
        field_rows = read_tsv(
            FIELD_DETAILS,
            EXPECTED_FIELD_DETAIL_COLUMNS,
        )
        record_rows = read_tsv(
            RECORD_DETAILS,
            EXPECTED_RECORD_DETAIL_COLUMNS,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            f"Writer analysis: FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    field_set = set(field_order)
    selected_fields = set(args.field)

    unknown_selected = selected_fields - field_set

    if unknown_selected:
        print(
            "Writer analysis: FAILED: unknown field(s): "
            + ", ".join(sorted(unknown_selected)),
            file=sys.stderr,
        )
        return 1

    unknown_direct_kinds = {
        row["KIND"]
        for row in field_rows
    } - DIRECT_KINDS

    if unknown_direct_kinds:
        print(
            "Writer analysis: FAILED: unknown direct access kind(s): "
            + ", ".join(sorted(unknown_direct_kinds)),
            file=sys.stderr,
        )
        return 1

    unknown_record_kinds = {
        row["KIND"]
        for row in record_rows
    } - RECORD_KINDS

    if unknown_record_kinds:
        print(
            "Writer analysis: FAILED: unknown record access kind(s): "
            + ", ".join(sorted(unknown_record_kinds)),
            file=sys.stderr,
        )
        return 1

    detail_fields = {
        row["FIELD"]
        for row in field_rows
    }

    if not detail_fields <= field_set:
        print(
            "Writer analysis: FAILED: detail inventory contains "
            "unknown userrec fields",
            file=sys.stderr,
        )
        return 1

    if args.format == "details":
        print_details(
            field_order,
            selected_fields,
            field_rows,
            record_rows,
        )
    else:
        print_summary(
            field_order,
            field_rows,
            record_rows,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
