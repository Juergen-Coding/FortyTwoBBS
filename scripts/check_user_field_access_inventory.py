#!/usr/bin/env python3
"""Verify the B5.5 user-field and whole-record access inventory.

The check regenerates all four machine-readable inventories and compares them
byte-for-byte with the committed documentation. It also verifies the central
counts and required migration conclusions.
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

FIELD_ANALYZER = SCRIPTS / "analyze_user_field_access.py"
RECORD_ANALYZER = SCRIPTS / "analyze_user_record_access.py"

FIELD_SUMMARY = DOCS / "MBSETUP_USER_FIELD_ACCESS_RAW.tsv"
FIELD_DETAILS = DOCS / "MBSETUP_USER_FIELD_ACCESS_DETAILS.tsv"
RECORD_SUMMARY = DOCS / "MBSETUP_USER_RECORD_ACCESS_RAW.tsv"
RECORD_DETAILS = DOCS / "MBSETUP_USER_RECORD_ACCESS_DETAILS.tsv"
INVENTORY_DOCUMENT = DOCS / "USER_FIELD_ACCESS_INVENTORY.md"

EXPECTED_FIELD_COUNTS = {
    "Fields reported": 72,
    "Fields directly referenced": 58,
    "Fields without direct refs": 14,
    "Direct member occurrences": 991,
    "Source files involved": 44,
}

EXPECTED_RECORD_COUNTS = {
    "Candidate occurrences": 140,
    "Source files involved": 24,
}

EXPECTED_RECORD_KINDS = {
    "metadata": (57, 14),
    "record-read": (23, 9),
    "record-read-write": (3, 1),
    "record-write": (57, 23),
}

EXPECTED_FIELDS_WITHOUT_DIRECT_ACCESS = {
    "CrtDef",
    "IEMSI",
    "LastPktNum",
    "Paged",
    "Protocol",
    "iLastFileGroup",
    "iLastMsgGroup",
    "iTransferTime",
    "ieMNU",
    "ieTAB",
    "xChat",
    "xFsMsged",
    "xHangUps",
    "xScreenLen",
}


def run_analyzer(
    analyzer: Path,
    *arguments: str,
) -> str:
    completed = subprocess.run(
        [sys.executable, str(analyzer), *arguments],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    if completed.returncode != 0:
        raise RuntimeError(
            f"{analyzer.name} failed with exit status "
            f"{completed.returncode}:\n{completed.stderr}"
        )

    if completed.stderr:
        raise RuntimeError(
            f"{analyzer.name} produced unexpected stderr:\n"
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
            f"generated inventory differs from {path.relative_to(REPOSITORY_ROOT)}"
        )


def parse_named_counts(
    text: str,
) -> dict[str, int]:
    counts: dict[str, int] = {}

    for line in text.splitlines():
        if ":" not in line:
            continue

        name, raw_value = line.split(":", 1)
        value = raw_value.strip()

        if value.isdigit():
            counts[name.strip()] = int(value)

    return counts


def parse_field_table(
    text: str,
) -> list[dict[str, str]]:
    marker = "FIELD\tREAD\tWRITE\tREAD_WRITE\tMETADATA\tFILES\n"

    if text.count(marker) != 1:
        raise ValueError("field summary table header is missing or duplicated")

    table = text.split(marker, 1)[1]

    return list(
        csv.DictReader(
            io.StringIO(marker + table),
            delimiter="\t",
        )
    )


def parse_record_table(
    text: str,
) -> dict[str, tuple[int, int]]:
    marker = "KIND\tOCCURRENCES\tFILES\n"

    if text.count(marker) != 1:
        raise ValueError("record summary table header is missing or duplicated")

    rows = csv.DictReader(
        io.StringIO(marker + text.split(marker, 1)[1]),
        delimiter="\t",
    )

    result: dict[str, tuple[int, int]] = {}

    for row in rows:
        result[row["KIND"]] = (
            int(row["OCCURRENCES"]),
            int(row["FILES"]),
        )

    return result


def parse_detail_rows(
    text: str,
) -> list[dict[str, str]]:
    return list(
        csv.DictReader(
            io.StringIO(text),
            delimiter="\t",
        )
    )


def main() -> int:
    failures: list[str] = []

    required_paths = (
        FIELD_ANALYZER,
        RECORD_ANALYZER,
        FIELD_SUMMARY,
        FIELD_DETAILS,
        RECORD_SUMMARY,
        RECORD_DETAILS,
        INVENTORY_DOCUMENT,
    )

    for path in required_paths:
        if not path.is_file():
            failures.append(
                f"required file is missing: "
                f"{path.relative_to(REPOSITORY_ROOT)}"
            )

    if failures:
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    try:
        generated_field_summary = run_analyzer(FIELD_ANALYZER)
        generated_field_details = run_analyzer(
            FIELD_ANALYZER,
            "--format",
            "details",
        )
        generated_record_summary = run_analyzer(RECORD_ANALYZER)
        generated_record_details = run_analyzer(
            RECORD_ANALYZER,
            "--format",
            "details",
        )
    except RuntimeError as exc:
        print(f"Inventory check: FAILED: {exc}", file=sys.stderr)
        return 1

    compare_generated(
        failures,
        FIELD_SUMMARY,
        generated_field_summary,
    )
    compare_generated(
        failures,
        FIELD_DETAILS,
        generated_field_details,
    )
    compare_generated(
        failures,
        RECORD_SUMMARY,
        generated_record_summary,
    )
    compare_generated(
        failures,
        RECORD_DETAILS,
        generated_record_details,
    )

    try:
        field_counts = parse_named_counts(generated_field_summary)
        record_counts = parse_named_counts(generated_record_summary)
        field_rows = parse_field_table(generated_field_summary)
        record_kinds = parse_record_table(generated_record_summary)
        field_detail_rows = parse_detail_rows(generated_field_details)
        record_detail_rows = parse_detail_rows(generated_record_details)
        document = INVENTORY_DOCUMENT.read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError, KeyError) as exc:
        failures.append(f"cannot parse generated inventory: {exc}")
        field_counts = {}
        record_counts = {}
        field_rows = []
        record_kinds = {}
        field_detail_rows = []
        record_detail_rows = []
        document = ""

    for name, expected in EXPECTED_FIELD_COUNTS.items():
        actual = field_counts.get(name)

        if actual != expected:
            failures.append(
                f"field count {name!r}: expected {expected}, found {actual}"
            )

    for name, expected in EXPECTED_RECORD_COUNTS.items():
        actual = record_counts.get(name)

        if actual != expected:
            failures.append(
                f"record count {name!r}: expected {expected}, found {actual}"
            )

    if record_kinds != EXPECTED_RECORD_KINDS:
        failures.append(
            "whole-record access classes differ from the reviewed baseline: "
            f"{record_kinds!r}"
        )

    if len(field_rows) != 72:
        failures.append(
            f"expected 72 field-summary rows, found {len(field_rows)}"
        )

    fields = [row.get("FIELD", "") for row in field_rows]

    if len(set(fields)) != 72:
        failures.append(
            "field-summary rows are missing, empty or duplicated"
        )

    fields_without_direct_access = {
        row["FIELD"]
        for row in field_rows
        if all(
            int(row[column]) == 0
            for column in (
                "READ",
                "WRITE",
                "READ_WRITE",
                "METADATA",
            )
        )
    }

    if fields_without_direct_access != EXPECTED_FIELDS_WITHOUT_DIRECT_ACCESS:
        failures.append(
            "fields without direct access differ from the reviewed baseline: "
            f"{sorted(fields_without_direct_access)!r}"
        )

    if len(field_detail_rows) != 991:
        failures.append(
            "expected 991 direct field detail rows, "
            f"found {len(field_detail_rows)}"
        )

    if len(record_detail_rows) != 140:
        failures.append(
            "expected 140 whole-record detail rows, "
            f"found {len(record_detail_rows)}"
        )

    field_positions = {
        (
            row.get("PATH"),
            row.get("LINE"),
            row.get("COLUMN"),
        )
        for row in field_detail_rows
    }

    if len(field_positions) != len(field_detail_rows):
        failures.append(
            "direct field inventory contains duplicate source positions"
        )

    record_positions = {
        (
            row.get("PATH"),
            row.get("LINE"),
            row.get("COLUMN"),
        )
        for row in record_detail_rows
    }

    if len(record_positions) != len(record_detail_rows):
        failures.append(
            "whole-record inventory contains duplicate source positions"
        )

    uncertain_kinds = {
        "pointer-escape",
        "value-transfer",
        "value-use",
    }

    found_uncertain = sorted(
        {
            row.get("KIND", "")
            for row in record_detail_rows
            if row.get("KIND", "") in uncertain_kinds
        }
    )

    if found_uncertain:
        failures.append(
            "unclassified whole-record candidates remain: "
            + ", ".join(found_uncertain)
        )

    required_document_fragments = {
        "read-only phase":
            "Die Phase verändert weder `users.data` noch PostgreSQL",
        "72 fields":
            "Felder in struct userrec:             72",
        "991 direct occurrences":
            "Direkte Member-Fundstellen:           991",
        "140 whole-record occurrences":
            "Ganzsatz-Fundstellen:                 140",
        "14 indirect-only fields":
            "Felder ohne direkte Zugriffe:         14",
        "no unknown record candidates":
            "Unklare Ganzsatzkandidaten:              0",
        "whole-record warning":
            "Ein Feld darf nicht allein deshalb entfernt oder ignoriert werden",
        "runtime-analysis boundary":
            "kein Ersatz für Laufzeitbeobachtung",
    }

    normalized_document = " ".join(document.split())

    for label, fragment in required_document_fragments.items():
        normalized_fragment = " ".join(fragment.split())

        if normalized_fragment not in normalized_document:
            failures.append(
                f"required documentation statement is missing: {label}"
            )

    print("B5.5 user access inventory")
    print("==========================")
    print(f"Fields documented:                  {len(field_rows)}")
    print(f"Fields with direct access:          {72 - len(fields_without_direct_access)}")
    print(f"Fields without direct access:       {len(fields_without_direct_access)}")
    print(f"Direct field occurrences:           {len(field_detail_rows)}")
    print(f"Whole-record occurrences:           {len(record_detail_rows)}")
    print(f"Unclassified record candidates:     {len(found_uncertain)}")
    print("Generated TSV comparison:           exact")

    if failures:
        print("\nInventory result: FAILED", file=sys.stderr)

        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)

        return 1

    print("\nInventory result: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
