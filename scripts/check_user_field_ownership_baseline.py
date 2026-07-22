#!/usr/bin/env python3
"""Verify the B5.6 user-field ownership baseline.

The check regenerates the writer inventories and ownership documents, compares
them byte-for-byte with the committed files, and protects the reviewed B5.6
starting state against accidental ownership decisions.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
import subprocess
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPOSITORY_ROOT / "scripts"
DOCS = REPOSITORY_ROOT / "docs"

WRITER_ANALYZER = SCRIPTS / "analyze_user_field_writers.py"
OWNERSHIP_BUILDER = SCRIPTS / "build_user_field_ownership_baseline.py"

WRITER_SUMMARY = DOCS / "MBSETUP_USER_FIELD_WRITERS_RAW.tsv"
WRITER_DETAILS = DOCS / "MBSETUP_USER_FIELD_WRITERS_DETAILS.tsv"
OWNERSHIP_SUMMARY = DOCS / "MBSETUP_USER_FIELD_OWNERSHIP_RAW.tsv"
OWNERSHIP_DETAILS = DOCS / "MBSETUP_USER_FIELD_OWNERSHIP_DETAILS.tsv"
OWNERSHIP_DOCUMENT = DOCS / "USER_FIELD_OWNERSHIP_BASELINE.md"

EXPECTED_WRITER_COUNTS = {
    "Fields with direct writers": 58,
    "Direct writer occurrences": 217,
    "Direct writer source files": 18,
    "Whole-record writer occurrences": 60,
    "Whole-record writer source files": 23,
}

EXPECTED_OWNERSHIP_COUNTS = {
    "Fields documented": 72,
    "Ownership decisions retained": 10,
    "Open ownership decisions": 62,
    "Fields with direct writers": 58,
    "Fields without direct writers": 14,
    "Fields directly written by mbsetup": 40,
    "Fields exposed to record rewrites": 72,
}

EXPECTED_DECIDED_FIELDS = {
    "Deleted",
    "LockedOut",
    "Name",
    "Password",
    "Security",
    "iLanguage",
    "sHandle",
    "sUserName",
    "tLastPwdChange",
    "xPassword",
}

EXPECTED_CREDENTIAL_FIELDS = {
    "Password",
    "xPassword",
}

OPEN_AUTHORITY = "Legacy bis zur Einzelentscheidung"

EXPECTED_WRITER_DETAIL_COLUMNS = [
    "SCOPE",
    "FIELD",
    "KIND",
    "PATH",
    "LINE",
    "COLUMN",
    "VARIABLE",
    "EXPRESSION",
    "SOURCE",
]

EXPECTED_OWNERSHIP_DETAIL_COLUMNS = [
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


def run_script(
    script: Path,
    *arguments: str,
) -> str:
    completed = subprocess.run(
        [sys.executable, str(script), *arguments],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    if completed.returncode != 0:
        raise RuntimeError(
            f"{script.name} failed with exit status "
            f"{completed.returncode}:\n{completed.stderr}"
        )

    if completed.stderr:
        raise RuntimeError(
            f"{script.name} produced unexpected stderr:\n"
            f"{completed.stderr}"
        )

    return completed.stdout


def compare_generated(
    failures: list[str],
    path: Path,
    generated: str,
) -> None:
    try:
        documented = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        failures.append(f"cannot read {path}: {exc}")
        return

    if documented != generated:
        failures.append(
            "generated output differs from "
            f"{path.relative_to(REPOSITORY_ROOT)}"
        )


def parse_named_counts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}

    for line in text.splitlines():
        if ":" not in line:
            continue

        name, raw_value = line.split(":", 1)
        value = raw_value.strip()

        if value.isdigit():
            counts[name.strip()] = int(value)

    return counts


def parse_tsv(
    text: str,
    expected_columns: list[str],
) -> list[dict[str, str]]:
    reader = csv.DictReader(
        io.StringIO(text),
        delimiter="\t",
    )

    if reader.fieldnames != expected_columns:
        raise ValueError(
            f"unexpected TSV columns: {reader.fieldnames!r}"
        )

    rows = list(reader)

    for number, row in enumerate(rows, start=2):
        if None in row:
            raise ValueError(
                f"extra TSV columns on generated line {number}"
            )

        if any(value is None for value in row.values()):
            raise ValueError(
                f"missing TSV value on generated line {number}"
            )

    return rows


def main() -> int:
    failures: list[str] = []

    required_paths = (
        WRITER_ANALYZER,
        OWNERSHIP_BUILDER,
        WRITER_SUMMARY,
        WRITER_DETAILS,
        OWNERSHIP_SUMMARY,
        OWNERSHIP_DETAILS,
        OWNERSHIP_DOCUMENT,
    )

    for path in required_paths:
        if not path.is_file():
            failures.append(
                "required file is missing: "
                f"{path.relative_to(REPOSITORY_ROOT)}"
            )

    if failures:
        print("B5.6 ownership baseline: FAILED", file=sys.stderr)

        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)

        return 1

    try:
        generated_writer_summary = run_script(
            WRITER_ANALYZER,
        )
        generated_writer_details = run_script(
            WRITER_ANALYZER,
            "--format",
            "details",
        )
        generated_ownership_summary = run_script(
            OWNERSHIP_BUILDER,
        )
        generated_ownership_details = run_script(
            OWNERSHIP_BUILDER,
            "--format",
            "details",
        )
        generated_ownership_document = run_script(
            OWNERSHIP_BUILDER,
            "--format",
            "markdown",
        )
    except RuntimeError as exc:
        print(
            f"B5.6 ownership baseline: FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    compare_generated(
        failures,
        WRITER_SUMMARY,
        generated_writer_summary,
    )
    compare_generated(
        failures,
        WRITER_DETAILS,
        generated_writer_details,
    )
    compare_generated(
        failures,
        OWNERSHIP_SUMMARY,
        generated_ownership_summary,
    )
    compare_generated(
        failures,
        OWNERSHIP_DETAILS,
        generated_ownership_details,
    )
    compare_generated(
        failures,
        OWNERSHIP_DOCUMENT,
        generated_ownership_document,
    )

    try:
        writer_counts = parse_named_counts(
            generated_writer_summary
        )
        ownership_counts = parse_named_counts(
            generated_ownership_summary
        )
        writer_rows = parse_tsv(
            generated_writer_details,
            EXPECTED_WRITER_DETAIL_COLUMNS,
        )
        ownership_rows = parse_tsv(
            generated_ownership_details,
            EXPECTED_OWNERSHIP_DETAIL_COLUMNS,
        )
    except (ValueError, KeyError) as exc:
        failures.append(f"cannot parse generated output: {exc}")
        writer_counts = {}
        ownership_counts = {}
        writer_rows = []
        ownership_rows = []

    for name, expected in EXPECTED_WRITER_COUNTS.items():
        actual = writer_counts.get(name)

        if actual != expected:
            failures.append(
                f"writer count {name!r}: "
                f"expected {expected}, found {actual}"
            )

    for name, expected in EXPECTED_OWNERSHIP_COUNTS.items():
        actual = ownership_counts.get(name)

        if actual != expected:
            failures.append(
                f"ownership count {name!r}: "
                f"expected {expected}, found {actual}"
            )

    if len(ownership_rows) != 72:
        failures.append(
            "expected 72 ownership rows, "
            f"found {len(ownership_rows)}"
        )

    fields = [row.get("FIELD", "") for row in ownership_rows]

    if len(set(fields)) != 72:
        failures.append(
            "ownership rows contain missing or duplicate fields"
        )

    decided_rows = [
        row
        for row in ownership_rows
        if row.get("DECISION_STATUS") == "decided"
    ]

    open_rows = [
        row
        for row in ownership_rows
        if row.get("DECISION_STATUS") == "open"
    ]

    decided_fields = {
        row["FIELD"]
        for row in decided_rows
    }

    if decided_fields != EXPECTED_DECIDED_FIELDS:
        failures.append(
            "decided fields differ from the reviewed B5.4 baseline: "
            f"{sorted(decided_fields)!r}"
        )

    if len(open_rows) != 62:
        failures.append(
            f"expected 62 open ownership rows, found {len(open_rows)}"
        )

    for row in open_rows:
        if row["AUTHORITY"] != OPEN_AUTHORITY:
            failures.append(
                f"open field {row['FIELD']} has unexpected authority: "
                f"{row['AUTHORITY']!r}"
            )

        if row["POSTGRESQL_TABLE"] != "noch nicht festgelegt":
            failures.append(
                f"open field {row['FIELD']} already has a PostgreSQL table"
            )

        if row["POSTGRESQL_TARGET"] != "noch nicht festgelegt":
            failures.append(
                f"open field {row['FIELD']} already has a PostgreSQL target"
            )

    for row in decided_rows:
        if row["FIELD"] in EXPECTED_CREDENTIAL_FIELDS:
            if row["AUTHORITY"] != "PostgreSQL-Credential":
                failures.append(
                    f"credential field {row['FIELD']} lost credential authority"
                )

            if row["POSTGRESQL_TABLE"] != "—":
                failures.append(
                    f"credential field {row['FIELD']} must not be migrated"
                )
        elif row["AUTHORITY"] != "PostgreSQL":
            failures.append(
                f"decided field {row['FIELD']} lost PostgreSQL authority"
            )

    direct_writer_rows = [
        row
        for row in writer_rows
        if row.get("SCOPE") == "field"
    ]

    record_writer_rows = [
        row
        for row in writer_rows
        if row.get("SCOPE") == "record"
    ]

    if len(direct_writer_rows) != 217:
        failures.append(
            "expected 217 direct writer detail rows, "
            f"found {len(direct_writer_rows)}"
        )

    if len(record_writer_rows) != 60:
        failures.append(
            "expected 60 whole-record writer detail rows, "
            f"found {len(record_writer_rows)}"
        )

    mbsetup_direct_fields = {
        row["FIELD"]
        for row in direct_writer_rows
        if row["PATH"] == "mbsetup/m_users.c"
    }

    if len(mbsetup_direct_fields) != 40:
        failures.append(
            "expected mbsetup to directly write 40 fields, "
            f"found {len(mbsetup_direct_fields)}"
        )

    mbsetup_record_rows = [
        row
        for row in record_writer_rows
        if row["PATH"] == "mbsetup/m_users.c"
    ]

    if len(mbsetup_record_rows) != 7:
        failures.append(
            "expected 7 mbsetup whole-record operations, "
            f"found {len(mbsetup_record_rows)}"
        )

    exposed_values = {
        row.get("WHOLE_RECORD_EXPOSURE")
        for row in ownership_rows
    }

    if exposed_values != {"yes"}:
        failures.append(
            "not every field is marked as exposed to whole-record rewrites"
        )

    document_fragments = {
        "open decisions":
            "offene Feldhoheiten:                 62",
        "mbsetup direct writers":
            "von mbsetup direkt geschriebene:     40",
        "whole-record exposure":
            "von Ganzsatz-Rewrites betroffene:    72",
        "no automatic synchronization":
            "Es findet kein automatischer PostgreSQL→Legacy- "
            "oder Legacy→PostgreSQL-Schreibabgleich statt.",
        "decision ordering":
            "Identität, Berechtigungen, Sperren und Kontolebenszyklus.",
    }

    normalized_document = " ".join(
        generated_ownership_document.split()
    )

    for label, fragment in document_fragments.items():
        normalized_fragment = " ".join(fragment.split())

        if normalized_fragment not in normalized_document:
            failures.append(
                f"required documentation statement is missing: {label}"
            )

    print("B5.6 user-field ownership baseline")
    print("==================================")
    print(f"Fields documented:                  {len(ownership_rows)}")
    print(f"Ownership decisions retained:       {len(decided_rows)}")
    print(f"Open ownership decisions:           {len(open_rows)}")
    print(f"Direct writer occurrences:          {len(direct_writer_rows)}")
    print(f"Whole-record writer occurrences:    {len(record_writer_rows)}")
    print(f"Fields directly written by mbsetup: {len(mbsetup_direct_fields)}")
    print(f"mbsetup whole-record operations:    {len(mbsetup_record_rows)}")
    print("Generated file comparison:          exact")

    if failures:
        print("\nOwnership result: FAILED", file=sys.stderr)

        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)

        return 1

    print("\nOwnership result: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
