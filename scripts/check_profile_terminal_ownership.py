#!/usr/bin/env python3
"""Verify the B5.8 profile and terminal-preference ownership decisions."""

from __future__ import annotations

import csv
import io
from pathlib import Path
import subprocess
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPOSITORY_ROOT / "scripts"
DOCS = REPOSITORY_ROOT / "docs"

ACCESS_ANALYZER = SCRIPTS / "analyze_profile_terminal_access.py"
OWNERSHIP_BUILDER = SCRIPTS / "build_profile_terminal_ownership.py"

ACCESS_SUMMARY = DOCS / "PROFILE_TERMINAL_ACCESS_RAW.tsv"
ACCESS_DETAILS = DOCS / "PROFILE_TERMINAL_ACCESS_DETAILS.tsv"
DECISIONS = DOCS / "PROFILE_TERMINAL_OWNERSHIP_DECISIONS.tsv"
OWNERSHIP_SUMMARY = DOCS / "PROFILE_TERMINAL_OWNERSHIP_RAW.tsv"
OWNERSHIP_DETAILS = DOCS / "PROFILE_TERMINAL_OWNERSHIP_DETAILS.tsv"
OWNERSHIP_DOCUMENT = DOCS / "PROFILE_TERMINAL_OWNERSHIP.md"

EXPECTED_FIELDS = (
    "sUserName",
    "sHandle",
    "iLanguage",
    "sVoicePhone",
    "sDataPhone",
    "sLocation",
    "address",
    "sDateOfBirth",
    "sSex",
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

EXPECTED_RETAINED_FIELDS = {
    "sUserName",
    "sHandle",
    "iLanguage",
}

EXPECTED_DECIDED_FIELDS = {
    "sVoicePhone",
    "sDataPhone",
    "sLocation",
    "address",
    "sDateOfBirth",
    "sSex",
    "HotKeys",
    "GraphMode",
    "DoNotDisturb",
    "MailScan",
    "OL_ExtInfo",
    "MsgEditor",
    "Archiver",
    "sProtocol",
    "ieNEWS",
    "ieFILE",
    "FSemacs",
    "Charset",
}

EXPECTED_RETIRED_FIELDS = {
    "Cls",
    "More",
    "ieASCII8",
}

PRIVATE_FIELDS = {
    "sVoicePhone",
    "sDataPhone",
    "address",
    "sDateOfBirth",
    "sSex",
}

EXPECTED_ACCESS_COUNTS = {
    "Profile fields": 9,
    "Terminal-preference fields": 15,
    "Fields analyzed": 24,
    "Direct access occurrences": 464,
    "Fields already PostgreSQL-led": 3,
    "Fields still open": 21,
}

EXPECTED_OWNERSHIP_COUNTS = {
    "Profile fields": 9,
    "Terminal-preference fields": 15,
    "Fields decided": 24,
    "Retained PostgreSQL decisions": 3,
    "New PostgreSQL decisions": 18,
    "Retired legacy fields": 3,
    "Open B5.8 decisions": 0,
    "Direct read occurrences": 332,
    "Direct write occurrences": 119,
    "Direct read-write occurrences": 6,
    "Direct metadata occurrences": 7,
    "Direct access occurrences": 464,
}

EXPECTED_FIELD_COUNTS = {
    "sUserName": (95, 4, 4, 3, 27),
    "sHandle": (46, 7, 0, 4, 15),
    "iLanguage": (4, 4, 0, 0, 6),
    "sVoicePhone": (10, 4, 0, 0, 5),
    "sDataPhone": (9, 5, 0, 0, 5),
    "sLocation": (15, 4, 1, 0, 10),
    "address": (25, 3, 0, 0, 4),
    "sDateOfBirth": (9, 5, 0, 0, 6),
    "sSex": (5, 7, 0, 0, 3),
    "HotKeys": (7, 7, 0, 0, 7),
    "GraphMode": (20, 7, 0, 0, 9),
    "DoNotDisturb": (7, 4, 0, 0, 5),
    "Cls": (2, 3, 0, 0, 3),
    "More": (2, 3, 0, 0, 3),
    "MailScan": (6, 8, 0, 0, 6),
    "OL_ExtInfo": (8, 3, 0, 0, 4),
    "MsgEditor": (7, 9, 0, 0, 7),
    "Archiver": (10, 6, 0, 0, 5),
    "sProtocol": (6, 5, 1, 0, 7),
    "ieASCII8": (0, 2, 0, 0, 2),
    "ieNEWS": (6, 5, 0, 0, 6),
    "ieFILE": (6, 8, 0, 0, 6),
    "FSemacs": (6, 3, 0, 0, 4),
    "Charset": (21, 3, 0, 0, 9),
}

EXPECTED_ACCESS_DETAIL_COLUMNS = [
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
]

EXPECTED_DECISION_COLUMNS = [
    "FIELD",
    "CATEGORY",
    "LEGACY_SEMANTICS",
    "AUTHORITY",
    "POSTGRESQL_TARGET",
    "MIGRATION_RULE",
    "WRITE_POLICY",
    "PRIVACY_POLICY",
    "COMPATIBILITY_RULE",
    "STATUS",
]

EXPECTED_OWNERSHIP_DETAIL_COLUMNS = [
    "FIELD",
    "CATEGORY",
    "STATUS",
    "AUTHORITY",
    "POSTGRESQL_TARGET",
    "READ",
    "WRITE",
    "READ_WRITE",
    "METADATA",
    "FILE_COUNT",
    "FILES",
    "COMPONENTS",
    "MBSETUP_WRITES",
    "LEGACY_SEMANTICS",
    "MIGRATION_RULE",
    "WRITE_POLICY",
    "PRIVACY_POLICY",
    "COMPATIBILITY_RULE",
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


def parse_tsv_text(
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

        if any(
            "\n" in value or "\r" in value
            for value in row.values()
        ):
            raise ValueError(
                f"embedded newline on generated line {number}"
            )

    return rows


def read_tsv_file(
    path: Path,
    expected_columns: list[str],
) -> list[dict[str, str]]:
    return parse_tsv_text(
        path.read_text(encoding="utf-8"),
        expected_columns,
    )


def main() -> int:
    failures: list[str] = []

    required_paths = (
        ACCESS_ANALYZER,
        OWNERSHIP_BUILDER,
        ACCESS_SUMMARY,
        ACCESS_DETAILS,
        DECISIONS,
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
        print(
            "B5.8 profile/terminal ownership: FAILED",
            file=sys.stderr,
        )

        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)

        return 1

    try:
        generated_access_summary = run_script(
            ACCESS_ANALYZER,
        )
        generated_access_details = run_script(
            ACCESS_ANALYZER,
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
            f"B5.8 profile/terminal ownership: FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    compare_generated(
        failures,
        ACCESS_SUMMARY,
        generated_access_summary,
    )
    compare_generated(
        failures,
        ACCESS_DETAILS,
        generated_access_details,
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
        access_counts = parse_named_counts(
            generated_access_summary
        )
        ownership_counts = parse_named_counts(
            generated_ownership_summary
        )
        access_rows = parse_tsv_text(
            generated_access_details,
            EXPECTED_ACCESS_DETAIL_COLUMNS,
        )
        decision_rows = read_tsv_file(
            DECISIONS,
            EXPECTED_DECISION_COLUMNS,
        )
        ownership_rows = parse_tsv_text(
            generated_ownership_details,
            EXPECTED_OWNERSHIP_DETAIL_COLUMNS,
        )
    except (OSError, UnicodeError, ValueError, KeyError) as exc:
        failures.append(f"cannot parse B5.8 output: {exc}")
        access_counts = {}
        ownership_counts = {}
        access_rows = []
        decision_rows = []
        ownership_rows = []

    for name, expected in EXPECTED_ACCESS_COUNTS.items():
        actual = access_counts.get(name)

        if actual != expected:
            failures.append(
                f"access count {name!r}: "
                f"expected {expected}, found {actual}"
            )

    for name, expected in EXPECTED_OWNERSHIP_COUNTS.items():
        actual = ownership_counts.get(name)

        if actual != expected:
            failures.append(
                f"ownership count {name!r}: "
                f"expected {expected}, found {actual}"
            )

    if len(access_rows) != 464:
        failures.append(
            "expected 464 B5.8 access rows, "
            f"found {len(access_rows)}"
        )

    if len(decision_rows) != 24:
        failures.append(
            "expected 24 B5.8 decision rows, "
            f"found {len(decision_rows)}"
        )

    if len(ownership_rows) != 24:
        failures.append(
            "expected 24 B5.8 ownership rows, "
            f"found {len(ownership_rows)}"
        )

    decision_fields = tuple(
        row.get("FIELD", "")
        for row in decision_rows
    )

    ownership_fields = tuple(
        row.get("FIELD", "")
        for row in ownership_rows
    )

    if decision_fields != EXPECTED_FIELDS:
        failures.append(
            "decision field order differs from B5.8 baseline: "
            f"{decision_fields!r}"
        )

    if ownership_fields != EXPECTED_FIELDS:
        failures.append(
            "ownership field order differs from B5.8 baseline: "
            f"{ownership_fields!r}"
        )

    retained_fields = {
        row["FIELD"]
        for row in decision_rows
        if row["STATUS"] == "retained"
    }

    decided_fields = {
        row["FIELD"]
        for row in decision_rows
        if row["STATUS"] == "decided"
    }

    retired_fields = {
        row["FIELD"]
        for row in decision_rows
        if row["STATUS"] == "retired"
    }

    if retained_fields != EXPECTED_RETAINED_FIELDS:
        failures.append(
            "retained fields differ from baseline: "
            f"{sorted(retained_fields)!r}"
        )

    if decided_fields != EXPECTED_DECIDED_FIELDS:
        failures.append(
            "new PostgreSQL decisions differ from baseline: "
            f"{sorted(decided_fields)!r}"
        )

    if retired_fields != EXPECTED_RETIRED_FIELDS:
        failures.append(
            "retired fields differ from baseline: "
            f"{sorted(retired_fields)!r}"
        )

    unknown_statuses = {
        row["STATUS"]
        for row in decision_rows
    } - {"retained", "decided", "retired"}

    if unknown_statuses:
        failures.append(
            "unknown decision statuses: "
            + ", ".join(sorted(unknown_statuses))
        )

    for row in decision_rows:
        field = row["FIELD"]

        for column in (
            "LEGACY_SEMANTICS",
            "MIGRATION_RULE",
            "WRITE_POLICY",
            "PRIVACY_POLICY",
            "COMPATIBILITY_RULE",
        ):
            if not row[column].strip():
                failures.append(
                    f"{field} has empty {column}"
                )

        if field in EXPECTED_RETIRED_FIELDS:
            if row["AUTHORITY"] != "Retired":
                failures.append(
                    f"{field} is retired but not Retired-led"
                )

            if row["POSTGRESQL_TARGET"] != "—":
                failures.append(
                    f"{field} is retired but has a PostgreSQL target"
                )

            if "festen Wert true" not in row["COMPATIBILITY_RULE"]:
                failures.append(
                    f"{field} lacks the reviewed fixed compatibility value"
                )
        else:
            if row["AUTHORITY"] != "PostgreSQL":
                failures.append(
                    f"{field} is not PostgreSQL-led"
                )

            if not row["POSTGRESQL_TARGET"].strip():
                failures.append(
                    f"{field} has no PostgreSQL target"
                )

        if field in PRIVATE_FIELDS:
            normalized_privacy = row["PRIVACY_POLICY"].lower()

            if "privat" not in normalized_privacy:
                failures.append(
                    f"{field} is not marked private"
                )

            if "protokoll" not in normalized_privacy:
                failures.append(
                    f"{field} lacks a logging restriction"
                )

    ownership_by_field = {
        row["FIELD"]: row
        for row in ownership_rows
    }

    for field, expected in EXPECTED_FIELD_COUNTS.items():
        row = ownership_by_field.get(field)

        if row is None:
            failures.append(
                f"ownership row missing for {field}"
            )
            continue

        actual = (
            int(row["READ"]),
            int(row["WRITE"]),
            int(row["READ_WRITE"]),
            int(row["METADATA"]),
            int(row["FILE_COUNT"]),
        )

        if actual != expected:
            failures.append(
                f"{field} access counts differ: "
                f"expected {expected!r}, found {actual!r}"
            )

    access_fields = {
        row["FIELD"]
        for row in access_rows
    }

    if access_fields != set(EXPECTED_FIELDS):
        failures.append(
            "access inventory field set differs from B5.8: "
            f"{sorted(access_fields)!r}"
        )

    document_fragments = {
        "all fields decided":
            "offene B5.8-Entscheidungen:             0",
        "retired fields":
            "`Cls`, `More` und `ieASCII8` werden nicht migriert",
        "private-data boundary":
            "Telefonnummern, Anschrift, Geburtsdatum und "
            "Geschlechtsangabe sind private Profildaten.",
        "no cleartext logging":
            "weder im Klartext protokolliert noch standardmäßig "
            "an Doors",
        "public location distinction":
            "Der öffentliche Standorttext bleibt davon getrennt.",
        "transport preference boundary":
            "Transporterkennung darf dauerhafte Präferenzen nur "
            "vorschlagen, nicht ungefragt überschreiben.",
        "mbsetup protection":
            "`mbsetup` darf PostgreSQL-geführte Werte nicht durch "
            "Ganzsatz-Rewrites aus `users.data` zurücksetzen.",
        "fixed compatibility values":
            "Stillgelegte Felder erhalten höchstens feste "
            "Kompatibilitätswerte",
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

    print("B5.8 profile and terminal ownership")
    print("===================================")
    print(f"Fields documented:                  {len(ownership_rows)}")
    print(f"Retained PostgreSQL decisions:      {len(retained_fields)}")
    print(f"New PostgreSQL decisions:           {len(decided_fields)}")
    print(f"Retired legacy fields:              {len(retired_fields)}")
    print(
        "Open B5.8 decisions:               "
        f"{24 - len(retained_fields) - len(decided_fields) - len(retired_fields)}"
    )
    print(f"Direct access occurrences:          {len(access_rows)}")
    print(f"Private profile fields protected:   {len(PRIVATE_FIELDS)}")
    print("Generated file comparison:          exact")

    if failures:
        print(
            "\nProfile/terminal result: FAILED",
            file=sys.stderr,
        )

        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)

        return 1

    print("\nProfile/terminal result: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
