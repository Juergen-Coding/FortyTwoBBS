#!/usr/bin/env python3
"""Verify the B5.7 account-lifecycle ownership decisions.

The check regenerates the reviewed access and ownership outputs, compares them
byte-for-byte with the committed files, and protects the eight lifecycle-field
decisions against accidental semantic drift.
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

ACCESS_ANALYZER = SCRIPTS / "analyze_account_lifecycle_access.py"
OWNERSHIP_BUILDER = SCRIPTS / "build_account_lifecycle_ownership.py"

ACCESS_SUMMARY = DOCS / "ACCOUNT_LIFECYCLE_ACCESS_RAW.tsv"
ACCESS_DETAILS = DOCS / "ACCOUNT_LIFECYCLE_ACCESS_DETAILS.tsv"
DECISIONS = DOCS / "ACCOUNT_LIFECYCLE_OWNERSHIP_DECISIONS.tsv"
OWNERSHIP_SUMMARY = DOCS / "ACCOUNT_LIFECYCLE_OWNERSHIP_RAW.tsv"
OWNERSHIP_DETAILS = DOCS / "ACCOUNT_LIFECYCLE_OWNERSHIP_DETAILS.tsv"
OWNERSHIP_DOCUMENT = DOCS / "ACCOUNT_LIFECYCLE_OWNERSHIP.md"

EXPECTED_FIELDS = (
    "Security",
    "Deleted",
    "LockedOut",
    "NeverDelete",
    "Guest",
    "Hidden",
    "sExpiryDate",
    "ExpirySec",
)

EXPECTED_RETAINED_FIELDS = {
    "Security",
    "Deleted",
    "LockedOut",
}

EXPECTED_NEW_FIELDS = {
    "NeverDelete",
    "Guest",
    "Hidden",
    "sExpiryDate",
    "ExpirySec",
}

EXPECTED_ACCESS_COUNTS = {
    "Lifecycle fields": 8,
    "Direct access occurrences": 153,
    "Fields already PostgreSQL-led": 3,
    "Fields still open": 5,
}

EXPECTED_OWNERSHIP_COUNTS = {
    "Lifecycle fields": 8,
    "Retained decisions": 3,
    "New B5.7 decisions": 5,
    "Open B5.7 decisions": 0,
    "Direct read occurrences": 134,
    "Direct write occurrences": 19,
    "Direct read-write occurrences": 0,
    "Direct access occurrences": 153,
}

EXPECTED_FIELD_COUNTS = {
    "Security": (91, 6, 0, 18),
    "Deleted": (14, 2, 0, 9),
    "LockedOut": (8, 1, 0, 5),
    "NeverDelete": (3, 1, 0, 2),
    "Guest": (5, 1, 0, 4),
    "Hidden": (6, 1, 0, 4),
    "sExpiryDate": (4, 4, 0, 5),
    "ExpirySec": (3, 3, 0, 4),
}

EXPECTED_TARGETS = {
    "Security":
        "bbs_user_roles / bbs_role_capabilities",
    "Deleted":
        "bbs_users.account_state / deleted_at",
    "LockedOut":
        "bbs_users.account_state / locked_reason",
    "NeverDelete":
        "bbs_users.auto_delete_exempt (planned)",
    "Guest":
        "bbs_users.account_kind (planned)",
    "Hidden":
        "bbs_user_profiles.is_hidden (planned)",
    "sExpiryDate":
        "bbs_user_authorization_expiry.effective_at (planned)",
    "ExpirySec":
        "bbs_user_authorization_expiry.post_expiry_policy (planned)",
}

EXPECTED_ACCESS_DETAIL_COLUMNS = [
    "FIELD",
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
    "AUDIT_REQUIREMENT",
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
    "AUDIT_REQUIREMENT",
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
        print("B5.7 lifecycle ownership: FAILED", file=sys.stderr)

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
            f"B5.7 lifecycle ownership: FAILED: {exc}",
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
        failures.append(f"cannot parse B5.7 output: {exc}")
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

    if len(access_rows) != 153:
        failures.append(
            "expected 153 lifecycle access rows, "
            f"found {len(access_rows)}"
        )

    if len(decision_rows) != 8:
        failures.append(
            "expected 8 lifecycle decision rows, "
            f"found {len(decision_rows)}"
        )

    if len(ownership_rows) != 8:
        failures.append(
            "expected 8 lifecycle ownership rows, "
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
            "decision field order differs from reviewed B5.7 set: "
            f"{decision_fields!r}"
        )

    if ownership_fields != EXPECTED_FIELDS:
        failures.append(
            "ownership field order differs from reviewed B5.7 set: "
            f"{ownership_fields!r}"
        )

    retained_fields = {
        row["FIELD"]
        for row in decision_rows
        if row["STATUS"] == "retained"
    }

    new_fields = {
        row["FIELD"]
        for row in decision_rows
        if row["STATUS"] == "decided"
    }

    if retained_fields != EXPECTED_RETAINED_FIELDS:
        failures.append(
            "retained lifecycle fields differ from baseline: "
            f"{sorted(retained_fields)!r}"
        )

    if new_fields != EXPECTED_NEW_FIELDS:
        failures.append(
            "new lifecycle decisions differ from baseline: "
            f"{sorted(new_fields)!r}"
        )

    unknown_statuses = {
        row["STATUS"]
        for row in decision_rows
    } - {"retained", "decided"}

    if unknown_statuses:
        failures.append(
            "unknown lifecycle decision statuses: "
            + ", ".join(sorted(unknown_statuses))
        )

    for row in decision_rows:
        field = row["FIELD"]

        if row["AUTHORITY"] != "PostgreSQL":
            failures.append(
                f"{field} is not PostgreSQL-led"
            )

        expected_target = EXPECTED_TARGETS.get(field)

        if row["POSTGRESQL_TARGET"] != expected_target:
            failures.append(
                f"{field} target differs: "
                f"expected {expected_target!r}, "
                f"found {row['POSTGRESQL_TARGET']!r}"
            )

        for column in (
            "LEGACY_SEMANTICS",
            "MIGRATION_RULE",
            "WRITE_POLICY",
            "AUDIT_REQUIREMENT",
        ):
            if not row[column].strip():
                failures.append(
                    f"{field} has empty {column}"
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
            int(row["FILE_COUNT"]),
        )

        if actual != expected:
            failures.append(
                f"{field} access counts differ: "
                f"expected {expected!r}, found {actual!r}"
            )

        if row["AUTHORITY"] != "PostgreSQL":
            failures.append(
                f"{field} ownership output lost PostgreSQL authority"
            )

        if row["POSTGRESQL_TARGET"] != EXPECTED_TARGETS[field]:
            failures.append(
                f"{field} ownership target differs from decision source"
            )

    access_fields = {
        row["FIELD"]
        for row in access_rows
    }

    if access_fields != set(EXPECTED_FIELDS):
        failures.append(
            "access inventory field set differs from B5.7 decisions: "
            f"{sorted(access_fields)!r}"
        )

    document_fragments = {
        "all fields decided":
            "offene B5.7-Entscheidungen:     0",
        "PostgreSQL authority":
            "PostgreSQL ist für alle acht Felder das führende System.",
        "deleted distinction":
            "`Deleted` beschreibt eine logische Kontolöschung.",
        "locked distinction":
            "`LockedOut` beschreibt eine administrative Kontosperre.",
        "retention distinction":
            "`NeverDelete` schützt ausschließlich vor automatischer "
            "Inaktivitätsbereinigung.",
        "guest distinction":
            "`Guest` ist eine Kontoklasse",
        "visibility distinction":
            "`Hidden` betrifft nur die Sichtbarkeit",
        "expiry distinction":
            "`sExpiryDate` und `ExpirySec` bilden gemeinsam eine "
            "zeitgesteuerte Autorisierungsänderung.",
        "no numeric security migration":
            "Numerische Legacy-Sicherheitswerte werden nicht direkt "
            "nach PostgreSQL kopiert.",
        "mbsetup protection":
            "`mbsetup` darf diese PostgreSQL-geführten Zustände "
            "nicht durch vollständige Legacy-Datensatz-Rewrites "
            "zurücksetzen.",
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

    print("B5.7 account-lifecycle ownership")
    print("================================")
    print(f"Lifecycle fields:              {len(ownership_rows)}")
    print(f"Retained decisions:            {len(retained_fields)}")
    print(f"New B5.7 decisions:            {len(new_fields)}")
    print(
        "Open B5.7 decisions:           "
        f"{8 - len(retained_fields) - len(new_fields)}"
    )
    print(f"Direct access occurrences:     {len(access_rows)}")
    print("PostgreSQL-led fields:          8")
    print("Generated file comparison:     exact")

    if failures:
        print("\nLifecycle result: FAILED", file=sys.stderr)

        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)

        return 1

    print("\nLifecycle result: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
