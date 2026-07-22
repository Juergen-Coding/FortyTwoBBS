#!/usr/bin/env python3
"""Analyze B5.8 profile and terminal-preference fields.

The script consumes the reviewed B5.5 direct-access inventory and the B5.6
ownership baseline. It changes neither users.data nor PostgreSQL.
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPOSITORY_ROOT / "docs"

FIELD_ACCESS_DETAILS = DOCS / "MBSETUP_USER_FIELD_ACCESS_DETAILS.tsv"
OWNERSHIP_DETAILS = DOCS / "MBSETUP_USER_FIELD_OWNERSHIP_DETAILS.tsv"

PROFILE_FIELDS = (
    "sUserName",
    "sHandle",
    "iLanguage",
    "sVoicePhone",
    "sDataPhone",
    "sLocation",
    "address",
    "sDateOfBirth",
    "sSex",
)

TERMINAL_FIELDS = (
    "HotKeys",
    "GraphMode",
    "DoNotDisturb",
    "Cls",
    "More",
    "MailScan",
    "OL_ExtInfo",
    "MsgEditor",
    "Archiver",
    "sProtocol",
    "ieASCII8",
    "ieNEWS",
    "ieFILE",
    "FSemacs",
    "Charset",
)

B5_8_FIELDS = PROFILE_FIELDS + TERMINAL_FIELDS

EXPECTED_DECIDED_FIELDS = {
    "sUserName",
    "sHandle",
    "iLanguage",
}

EXPECTED_ACCESS_COLUMNS = [
    "FIELD",
    "KIND",
    "PATH",
    "LINE",
    "COLUMN",
    "VARIABLE",
    "EXPRESSION",
    "SOURCE",
]

EXPECTED_OWNERSHIP_COLUMNS = [
    "FIELD",
    "MEANING",
    "AUTHORITY",
    "POSTGRESQL_TABLE",
    "POSTGRESQL_TARGET",
    "DECISION_STATUS",
    "DIRECT_WRITE",
    "DIRECT_READ_WRITE",
    "DIRECT_WRITER_FILE_COUNT",
    "DIRECT_WRITER_FILES",
    "DIRECT_WRITER_COMPONENTS",
    "MBSETUP_DIRECT_WRITES",
    "WHOLE_RECORD_EXPOSURE",
]

ACCESS_KINDS = {
    "read",
    "write",
    "read-write",
    "metadata",
}


def parse_args(
    argv: list[str] | None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze B5.8 profile and terminal-preference accesses."
        )
    )
    parser.add_argument(
        "--format",
        choices=("summary", "details"),
        default="summary",
        help="output format; default: summary",
    )
    return parser.parse_args(argv)


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

        if any(
            "\n" in value or "\r" in value
            for value in row.values()
        ):
            raise ValueError(
                f"embedded newline in {path.name}:{number}"
            )

    return rows


def component(path: str) -> str:
    return path.split("/", 1)[0]


def category(field: str) -> str:
    if field in PROFILE_FIELDS:
        return "profile"

    if field in TERMINAL_FIELDS:
        return "terminal-preference"

    raise ValueError(f"field outside B5.8: {field}")


def load_data() -> tuple[
    list[dict[str, str]],
    dict[str, dict[str, str]],
]:
    access_rows = read_tsv(
        FIELD_ACCESS_DETAILS,
        EXPECTED_ACCESS_COLUMNS,
    )
    ownership_rows = read_tsv(
        OWNERSHIP_DETAILS,
        EXPECTED_OWNERSHIP_COLUMNS,
    )

    unknown_kinds = {
        row["KIND"]
        for row in access_rows
    } - ACCESS_KINDS

    if unknown_kinds:
        raise ValueError(
            "unknown access kinds: "
            + ", ".join(sorted(unknown_kinds))
        )

    ownership_by_field = {
        row["FIELD"]: row
        for row in ownership_rows
    }

    if len(ownership_by_field) != 72:
        raise ValueError(
            "expected 72 unique ownership rows, "
            f"found {len(ownership_by_field)}"
        )

    missing_fields = [
        field
        for field in B5_8_FIELDS
        if field not in ownership_by_field
    ]

    if missing_fields:
        raise ValueError(
            "B5.8 fields missing from ownership baseline: "
            + ", ".join(missing_fields)
        )

    decided_fields = {
        field
        for field in B5_8_FIELDS
        if ownership_by_field[field]["DECISION_STATUS"] == "decided"
    }

    if decided_fields != EXPECTED_DECIDED_FIELDS:
        raise ValueError(
            "decided B5.8 fields differ from the reviewed baseline: "
            f"{sorted(decided_fields)!r}"
        )

    selected_accesses = [
        row
        for row in access_rows
        if row["FIELD"] in B5_8_FIELDS
    ]

    access_fields = {
        row["FIELD"]
        for row in selected_accesses
    }

    missing_access_fields = set(B5_8_FIELDS) - access_fields

    if missing_access_fields:
        raise ValueError(
            "B5.8 fields missing from direct-access inventory: "
            + ", ".join(sorted(missing_access_fields))
        )

    return selected_accesses, ownership_by_field


def print_summary(
    access_rows: list[dict[str, str]],
    ownership_by_field: dict[str, dict[str, str]],
) -> None:
    decided_count = sum(
        ownership_by_field[field]["DECISION_STATUS"] == "decided"
        for field in B5_8_FIELDS
    )
    open_count = sum(
        ownership_by_field[field]["DECISION_STATUS"] == "open"
        for field in B5_8_FIELDS
    )

    print("B5.8 profile and terminal-preference access analysis")
    print("====================================================")
    print(f"Profile fields:                  {len(PROFILE_FIELDS)}")
    print(f"Terminal-preference fields:      {len(TERMINAL_FIELDS)}")
    print(f"Fields analyzed:                 {len(B5_8_FIELDS)}")
    print(f"Direct access occurrences:       {len(access_rows)}")
    print(f"Fields already PostgreSQL-led:   {decided_count}")
    print(f"Fields still open:               {open_count}")
    print()

    print(
        "FIELD\tCATEGORY\tREAD\tWRITE\tREAD_WRITE\tMETADATA\t"
        "FILES\tCOMPONENTS\tAUTHORITY\tSTATUS\tMBSETUP_WRITES"
    )

    for field in B5_8_FIELDS:
        rows = [
            row
            for row in access_rows
            if row["FIELD"] == field
        ]
        counts = Counter(row["KIND"] for row in rows)
        files = sorted({row["PATH"] for row in rows})
        components = sorted({component(path) for path in files})
        ownership = ownership_by_field[field]

        print(
            "\t".join(
                (
                    field,
                    category(field),
                    str(counts["read"]),
                    str(counts["write"]),
                    str(counts["read-write"]),
                    str(counts["metadata"]),
                    str(len(files)),
                    ",".join(components),
                    ownership["AUTHORITY"],
                    ownership["DECISION_STATUS"],
                    ownership["MBSETUP_DIRECT_WRITES"],
                )
            )
        )


def print_details(
    access_rows: list[dict[str, str]],
    ownership_by_field: dict[str, dict[str, str]],
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
            "CATEGORY",
            "AUTHORITY",
            "DECISION_STATUS",
            "POSTGRESQL_TABLE",
            "POSTGRESQL_TARGET",
            "KIND",
            "PATH",
            "LINE",
            "COLUMN",
            "VARIABLE",
            "EXPRESSION",
            "SOURCE",
        )
    )

    field_order = {
        field: index
        for index, field in enumerate(B5_8_FIELDS)
    }

    for row in sorted(
        access_rows,
        key=lambda item: (
            field_order[item["FIELD"]],
            item["PATH"],
            int(item["LINE"]),
            int(item["COLUMN"]),
        ),
    ):
        ownership = ownership_by_field[row["FIELD"]]

        writer.writerow(
            (
                row["FIELD"],
                category(row["FIELD"]),
                ownership["AUTHORITY"],
                ownership["DECISION_STATUS"],
                ownership["POSTGRESQL_TABLE"],
                ownership["POSTGRESQL_TARGET"],
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
        access_rows, ownership_by_field = load_data()
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            f"Profile/terminal analysis: FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.format == "details":
        print_details(access_rows, ownership_by_field)
    else:
        print_summary(access_rows, ownership_by_field)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
