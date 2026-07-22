#!/usr/bin/env python3
"""Analyze the remaining B5.10 navigation and session fields.

The script derives the uncovered field set from the B5.6 ownership baseline
and the completed B5.7, B5.8 and B5.9 decision sources. It changes neither
users.data nor PostgreSQL.
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

LIFECYCLE_DECISIONS = DOCS / "ACCOUNT_LIFECYCLE_OWNERSHIP_DECISIONS.tsv"
PROFILE_TERMINAL_DECISIONS = (
    DOCS / "PROFILE_TERMINAL_OWNERSHIP_DECISIONS.tsv"
)
ACTIVITY_USAGE_DECISIONS = (
    DOCS / "ACTIVITY_USAGE_OWNERSHIP_DECISIONS.tsv"
)

COMMENT_MAILBOX_FIELDS = (
    "sComment",
    "Email",
)

NAVIGATION_FIELDS = (
    "iLastFileArea",
    "iLastFileGroup",
    "iLastMsgArea",
    "iLastMsgGroup",
)

OFFLINE_READER_STATE_FIELDS = (
    "LastPktNum",
    "OLRext",
    "OLRlast",
)

SESSION_RUNTIME_FIELDS = (
    "xChat",
    "xFsMsged",
    "xScreenLen",
    "xHangUps",
    "Paged",
    "iTransferTime",
    "iStatus",
)

IEMSI_COMPATIBILITY_FIELDS = (
    "CrtDef",
    "Protocol",
    "IEMSI",
    "ieMNU",
    "ieTAB",
)

B5_10_FIELDS = (
    COMMENT_MAILBOX_FIELDS
    + NAVIGATION_FIELDS
    + OFFLINE_READER_STATE_FIELDS
    + SESSION_RUNTIME_FIELDS
    + IEMSI_COMPATIBILITY_FIELDS
)

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
            "Analyze the remaining B5.10 navigation, session "
            "and compatibility fields."
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
    expected_columns: list[str] | None = None,
) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")

        if reader.fieldnames is None:
            raise ValueError(
                f"missing TSV header in {path.name}"
            )

        if (
            expected_columns is not None
            and reader.fieldnames != expected_columns
        ):
            raise ValueError(
                f"unexpected columns in {path.name}: "
                f"{reader.fieldnames!r}"
            )

        if "FIELD" not in reader.fieldnames:
            raise ValueError(
                f"FIELD column missing from {path.name}"
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


def category(field: str) -> str:
    if field in COMMENT_MAILBOX_FIELDS:
        return "comment-mailbox"

    if field in NAVIGATION_FIELDS:
        return "navigation-state"

    if field in OFFLINE_READER_STATE_FIELDS:
        return "offline-reader-state"

    if field in SESSION_RUNTIME_FIELDS:
        return "session-runtime"

    if field in IEMSI_COMPATIBILITY_FIELDS:
        return "iemsi-compatibility"

    raise ValueError(f"field outside B5.10: {field}")


def component(path: str) -> str:
    return path.split("/", 1)[0]


def fields_from_decisions(
    path: Path,
) -> set[str]:
    rows = read_tsv(path)
    fields = {
        row["FIELD"]
        for row in rows
    }

    if len(fields) != len(rows):
        raise ValueError(
            f"duplicate fields in {path.name}"
        )

    return fields


def load_data() -> tuple[
    list[dict[str, str]],
    dict[str, dict[str, str]],
    set[str],
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

    if len(ownership_rows) != 72:
        raise ValueError(
            "expected 72 ownership rows, "
            f"found {len(ownership_rows)}"
        )

    if len(ownership_by_field) != 72:
        raise ValueError(
            "ownership baseline does not contain "
            "72 unique fields"
        )

    baseline_decided = {
        row["FIELD"]
        for row in ownership_rows
        if row["DECISION_STATUS"] == "decided"
    }

    if len(baseline_decided) != 10:
        raise ValueError(
            "expected 10 decisions in the B5.6 baseline, "
            f"found {len(baseline_decided)}"
        )

    covered_fields = set(baseline_decided)

    for path in (
        LIFECYCLE_DECISIONS,
        PROFILE_TERMINAL_DECISIONS,
        ACTIVITY_USAGE_DECISIONS,
    ):
        covered_fields.update(
            fields_from_decisions(path)
        )

    remaining_fields = (
        set(ownership_by_field)
        - covered_fields
    )

    if remaining_fields != set(B5_10_FIELDS):
        missing = sorted(
            set(B5_10_FIELDS) - remaining_fields
        )
        unexpected = sorted(
            remaining_fields - set(B5_10_FIELDS)
        )

        raise ValueError(
            "derived B5.10 remainder differs from the "
            f"reviewed field set; missing={missing!r}, "
            f"unexpected={unexpected!r}"
        )

    selected_accesses = [
        row
        for row in access_rows
        if row["FIELD"] in remaining_fields
    ]

    directly_accessed_fields = {
        row["FIELD"]
        for row in selected_accesses
    }

    return (
        selected_accesses,
        ownership_by_field,
        directly_accessed_fields,
    )


def print_summary(
    access_rows: list[dict[str, str]],
    ownership_by_field: dict[str, dict[str, str]],
    directly_accessed_fields: set[str],
) -> None:
    print("B5.10 navigation and session access analysis")
    print("============================================")
    print(
        f"Comment/mailbox fields:          "
        f"{len(COMMENT_MAILBOX_FIELDS)}"
    )
    print(
        f"Navigation fields:               "
        f"{len(NAVIGATION_FIELDS)}"
    )
    print(
        f"Offline-reader state fields:     "
        f"{len(OFFLINE_READER_STATE_FIELDS)}"
    )
    print(
        f"Session-runtime fields:          "
        f"{len(SESSION_RUNTIME_FIELDS)}"
    )
    print(
        f"IEMSI compatibility fields:      "
        f"{len(IEMSI_COMPATIBILITY_FIELDS)}"
    )
    print(f"Fields analyzed:                 {len(B5_10_FIELDS)}")
    print(
        "Fields with direct access:       "
        f"{len(directly_accessed_fields)}"
    )
    print(
        "Fields without direct access:    "
        f"{len(B5_10_FIELDS) - len(directly_accessed_fields)}"
    )
    print(f"Direct access occurrences:       {len(access_rows)}")
    print("Fields already decided:          0")
    print(f"Fields still open:               {len(B5_10_FIELDS)}")
    print()
    print(
        "FIELD\tCATEGORY\tREAD\tWRITE\tREAD_WRITE\tMETADATA\t"
        "FILES\tCOMPONENTS\tAUTHORITY\tSTATUS\tMBSETUP_WRITES"
    )

    for field in B5_10_FIELDS:
        rows = [
            row
            for row in access_rows
            if row["FIELD"] == field
        ]
        counts = Counter(
            row["KIND"]
            for row in rows
        )
        files = sorted({
            row["PATH"]
            for row in rows
        })
        components = sorted({
            component(path)
            for path in files
        })
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
        for index, field in enumerate(B5_10_FIELDS)
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
        writer.writerow(
            (
                row["FIELD"],
                category(row["FIELD"]),
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
        (
            access_rows,
            ownership_by_field,
            directly_accessed_fields,
        ) = load_data()
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            f"Navigation/session analysis: FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.format == "details":
        print_details(access_rows)
    else:
        print_summary(
            access_rows,
            ownership_by_field,
            directly_accessed_fields,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
