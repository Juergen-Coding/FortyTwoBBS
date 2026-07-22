#!/usr/bin/env python3
"""Verify the B5.9 activity and usage ownership decisions."""

from __future__ import annotations

import csv
import io
from pathlib import Path
import subprocess
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPOSITORY_ROOT / "scripts"
DOCS = REPOSITORY_ROOT / "docs"

ACCESS_ANALYZER = SCRIPTS / "analyze_activity_usage_access.py"
OWNERSHIP_BUILDER = SCRIPTS / "build_activity_usage_ownership.py"

ACCESS_SUMMARY = DOCS / "ACTIVITY_USAGE_ACCESS_RAW.tsv"
ACCESS_DETAILS = DOCS / "ACTIVITY_USAGE_ACCESS_DETAILS.tsv"
DECISIONS = DOCS / "ACTIVITY_USAGE_OWNERSHIP_DECISIONS.tsv"
OWNERSHIP_SUMMARY = DOCS / "ACTIVITY_USAGE_OWNERSHIP_RAW.tsv"
OWNERSHIP_DETAILS = DOCS / "ACTIVITY_USAGE_OWNERSHIP_DETAILS.tsv"
OWNERSHIP_DOCUMENT = DOCS / "ACTIVITY_USAGE_OWNERSHIP.md"

EXPECTED_FIELDS = (
    "tFirstLoginDate",
    "tLastLoginDate",
    "iTimeLeft",
    "iTimeUsed",
    "iConnectTime",
    "Credit",
    "Downloads",
    "Uploads",
    "DownloadK",
    "UploadK",
    "DownloadsToday",
    "DownloadKToday",
    "UploadKToday",
    "iTotalCalls",
    "iPosted",
)

EXPECTED_DECIDED_FIELDS = {
    "tFirstLoginDate",
    "tLastLoginDate",
    "iTimeUsed",
    "Credit",
    "Downloads",
    "Uploads",
    "DownloadK",
    "UploadK",
    "DownloadKToday",
    "UploadKToday",
    "iTotalCalls",
    "iPosted",
}

EXPECTED_DERIVED_FIELDS = {
    "iTimeLeft",
    "DownloadsToday",
}

EXPECTED_SESSION_FIELDS = {
    "iConnectTime",
}

CUMULATIVE_COUNTER_FIELDS = {
    "Downloads",
    "Uploads",
    "DownloadK",
    "UploadK",
    "iTotalCalls",
    "iPosted",
}

EXPECTED_ACCESS_COUNTS = {
    "Account-timeline fields": 2,
    "Time-account fields": 3,
    "Value-account fields": 1,
    "Transfer-usage fields": 7,
    "Community-usage fields": 2,
    "Fields analyzed": 15,
    "Direct access occurrences": 126,
    "Fields already decided": 0,
    "Fields still open": 15,
}

EXPECTED_OWNERSHIP_COUNTS = {
    "Account-timeline fields": 2,
    "Time-account fields": 3,
    "Value-account fields": 1,
    "Transfer-usage fields": 7,
    "Community-usage fields": 2,
    "Fields decided": 15,
    "Persistent PostgreSQL decisions": 12,
    "Derived values": 2,
    "Session-only values": 1,
    "Open B5.9 decisions": 0,
    "Direct read occurrences": 86,
    "Direct write occurrences": 21,
    "Direct read-write occurrences": 19,
    "Direct metadata occurrences": 0,
    "Direct access occurrences": 126,
}

EXPECTED_FIELD_COUNTS = {
    "tFirstLoginDate": (5, 2, 0, 0, 5),
    "tLastLoginDate": (11, 4, 0, 0, 8),
    "iTimeLeft": (18, 7, 1, 0, 9),
    "iTimeUsed": (4, 3, 1, 0, 5),
    "iConnectTime": (3, 2, 1, 0, 5),
    "Credit": (3, 1, 0, 0, 2),
    "Downloads": (7, 0, 2, 0, 4),
    "Uploads": (5, 0, 2, 0, 5),
    "DownloadK": (5, 0, 1, 0, 4),
    "UploadK": (6, 0, 1, 0, 4),
    "DownloadsToday": (1, 1, 0, 0, 2),
    "DownloadKToday": (4, 1, 2, 0, 3),
    "UploadKToday": (1, 0, 1, 0, 1),
    "iTotalCalls": (9, 0, 2, 0, 8),
    "iPosted": (4, 0, 5, 0, 7),
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
    "UNIT_RULE",
    "MIGRATION_RULE",
    "WRITE_POLICY",
    "CONSISTENCY_RULE",
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
    "UNIT_RULE",
    "MIGRATION_RULE",
    "WRITE_POLICY",
    "CONSISTENCY_RULE",
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
            "B5.9 activity/usage ownership: FAILED",
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
            f"B5.9 activity/usage ownership: FAILED: {exc}",
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
        failures.append(f"cannot parse B5.9 output: {exc}")
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

    if len(access_rows) != 126:
        failures.append(
            "expected 126 B5.9 access rows, "
            f"found {len(access_rows)}"
        )

    if len(decision_rows) != 15:
        failures.append(
            "expected 15 B5.9 decision rows, "
            f"found {len(decision_rows)}"
        )

    if len(ownership_rows) != 15:
        failures.append(
            "expected 15 B5.9 ownership rows, "
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
            "decision field order differs from B5.9 baseline: "
            f"{decision_fields!r}"
        )

    if ownership_fields != EXPECTED_FIELDS:
        failures.append(
            "ownership field order differs from B5.9 baseline: "
            f"{ownership_fields!r}"
        )

    decided_fields = {
        row["FIELD"]
        for row in decision_rows
        if row["STATUS"] == "decided"
    }

    derived_fields = {
        row["FIELD"]
        for row in decision_rows
        if row["STATUS"] == "derived"
    }

    session_fields = {
        row["FIELD"]
        for row in decision_rows
        if row["STATUS"] == "session-only"
    }

    if decided_fields != EXPECTED_DECIDED_FIELDS:
        failures.append(
            "persistent PostgreSQL fields differ from baseline: "
            f"{sorted(decided_fields)!r}"
        )

    if derived_fields != EXPECTED_DERIVED_FIELDS:
        failures.append(
            "derived fields differ from baseline: "
            f"{sorted(derived_fields)!r}"
        )

    if session_fields != EXPECTED_SESSION_FIELDS:
        failures.append(
            "session-only fields differ from baseline: "
            f"{sorted(session_fields)!r}"
        )

    unknown_statuses = {
        row["STATUS"]
        for row in decision_rows
    } - {"decided", "derived", "session-only"}

    if unknown_statuses:
        failures.append(
            "unknown decision statuses: "
            + ", ".join(sorted(unknown_statuses))
        )

    decision_by_field = {
        row["FIELD"]: row
        for row in decision_rows
    }

    for row in decision_rows:
        field = row["FIELD"]

        for column in (
            "LEGACY_SEMANTICS",
            "AUTHORITY",
            "POSTGRESQL_TARGET",
            "UNIT_RULE",
            "MIGRATION_RULE",
            "WRITE_POLICY",
            "CONSISTENCY_RULE",
            "COMPATIBILITY_RULE",
        ):
            if not row[column].strip():
                failures.append(
                    f"{field} has empty {column}"
                )

        if row["STATUS"] == "decided":
            if row["AUTHORITY"] != "PostgreSQL":
                failures.append(
                    f"{field} is decided but not PostgreSQL-led"
                )

        elif row["STATUS"] == "derived":
            if row["AUTHORITY"] != "Derived":
                failures.append(
                    f"{field} is derived but has authority "
                    f"{row['AUTHORITY']!r}"
                )

            if not row["POSTGRESQL_TARGET"].startswith("derived:"):
                failures.append(
                    f"{field} lacks a derived target"
                )

        elif row["STATUS"] == "session-only":
            if row["AUTHORITY"] != "PostgreSQL session state":
                failures.append(
                    f"{field} lacks PostgreSQL session authority"
                )

    first_login = decision_by_field.get("tFirstLoginDate", {})

    if first_login.get("POSTGRESQL_TARGET") != "bbs_users.registered_at":
        failures.append(
            "tFirstLoginDate is not mapped to bbs_users.registered_at"
        )

    if "Registrierungszeitpunkt" not in first_login.get(
        "LEGACY_SEMANTICS",
        "",
    ):
        failures.append(
            "tFirstLoginDate is not identified as registration time"
        )

    last_login = decision_by_field.get("tLastLoginDate", {})

    if "erfolgreicher" not in last_login.get("WRITE_POLICY", ""):
        failures.append(
            "tLastLoginDate lacks the successful-access write boundary"
        )

    if "fehlgeschlagene Anmeldungen zählen nicht" not in last_login.get(
        "CONSISTENCY_RULE",
        "",
    ):
        failures.append(
            "tLastLoginDate does not exclude failed logins"
        )

    time_left = decision_by_field.get("iTimeLeft", {})

    if time_left.get("STATUS") != "derived":
        failures.append(
            "iTimeLeft is not classified as derived"
        )

    if "60" not in time_left.get("UNIT_RULE", ""):
        failures.append(
            "iTimeLeft lacks the minute-to-second conversion"
        )

    if "86400 Minuten" not in time_left.get("CONSISTENCY_RULE", ""):
        failures.append(
            "iTimeLeft does not reject the legacy 86400-minute value"
        )

    if "1440 Minuten" not in time_left.get("COMPATIBILITY_RULE", ""):
        failures.append(
            "iTimeLeft lacks the reviewed 1440-minute compatibility cap"
        )

    connect_time = decision_by_field.get("iConnectTime", {})

    if connect_time.get("STATUS") != "session-only":
        failures.append(
            "iConnectTime is not session-only"
        )

    if "nicht migrieren" not in connect_time.get(
        "MIGRATION_RULE",
        "",
    ):
        failures.append(
            "iConnectTime lacks the no-migration rule"
        )

    credit = decision_by_field.get("Credit", {})

    if "Blue-Wave-NetMail-Credits" not in credit.get(
        "LEGACY_SEMANTICS",
        "",
    ):
        failures.append(
            "Credit is not restricted to Blue-Wave NetMail credits"
        )

    if "0 bis 65535" not in credit.get("UNIT_RULE", ""):
        failures.append(
            "Credit lacks the reviewed tWORD range"
        )

    credit_consistency = credit.get(
        "CONSISTENCY_RULE",
        "",
    ).lower()

    if "keine verwendung für login" not in credit_consistency:
        failures.append(
            "Credit is not isolated from account authorization"
        )

    downloads_today = decision_by_field.get("DownloadsToday", {})

    if downloads_today.get("STATUS") != "derived":
        failures.append(
            "DownloadsToday is not classified as derived"
        )

    if "weder geprüft noch vermindert" not in downloads_today.get(
        "LEGACY_SEMANTICS",
        "",
    ):
        failures.append(
            "DownloadsToday does not document the incomplete legacy quota"
        )

    if "keine neue Dateiquote" not in downloads_today.get(
        "COMPATIBILITY_RULE",
        "",
    ):
        failures.append(
            "DownloadsToday lacks the disabled-quota compatibility rule"
        )

    download_balance = decision_by_field.get("DownloadKToday", {})

    download_balance_semantics = " ".join(
        (
            download_balance.get("LEGACY_SEMANTICS", ""),
            download_balance.get("WRITE_POLICY", ""),
            download_balance.get("CONSISTENCY_RULE", ""),
        )
    ).lower()

    if not all(
        fragment in download_balance_semantics
        for fragment in (
            "saldo",
            "download",
            "upload",
        )
    ):
        failures.append(
            "DownloadKToday lacks the explicit daily-balance model"
        )

    if "Downloads vermindern" not in download_balance.get(
        "WRITE_POLICY",
        "",
    ):
        failures.append(
            "DownloadKToday lacks atomic download debits"
        )

    upload_today = decision_by_field.get("UploadKToday", {})

    upload_today_storage = " ".join(
        (
            upload_today.get("MIGRATION_RULE", ""),
            upload_today.get("CONSISTENCY_RULE", ""),
        )
    ).lower()

    if "installationstag" not in upload_today_storage:
        failures.append(
            "UploadKToday lacks date-bound daily storage"
        )

    total_calls = decision_by_field.get("iTotalCalls", {})

    if "BBS- und NNTP-Anmeldungen" not in total_calls.get(
        "LEGACY_SEMANTICS",
        "",
    ):
        failures.append(
            "iTotalCalls does not document its transport-spanning semantics"
        )

    posted = decision_by_field.get("iPosted", {})

    if "Nachricht und Zählerfortschreibung müssen gemeinsam committen" not in (
        posted.get("CONSISTENCY_RULE", "")
    ):
        failures.append(
            "iPosted lacks transactional message-counter consistency"
        )

    for field in CUMULATIVE_COUNTER_FIELDS:
        row = decision_by_field.get(field)

        if row is None:
            failures.append(
                f"cumulative counter decision missing for {field}"
            )
            continue

        combined = " ".join(
            (
                row["WRITE_POLICY"],
                row["CONSISTENCY_RULE"],
            )
        ).lower()

        if "atomar" not in combined:
            failures.append(
                f"{field} lacks an atomic-update rule"
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

        try:
            actual = (
                int(row["READ"]),
                int(row["WRITE"]),
                int(row["READ_WRITE"]),
                int(row["METADATA"]),
                int(row["FILE_COUNT"]),
            )
        except ValueError as exc:
            failures.append(
                f"{field} contains a non-integer access count: {exc}"
            )
            continue

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
            "access inventory field set differs from B5.9: "
            f"{sorted(access_fields)!r}"
        )

    normalized_document = " ".join(
        generated_ownership_document.split()
    )

    document_fragments = {
        "all fields decided":
            "offene B5.9-Entscheidungen: 0",
        "time-left derived":
            "`iTimeLeft` und `DownloadsToday` sind keine "
            "eigenständigen Benutzerkontostände",
        "session boundary":
            "`iConnectTime` gehört ausschließlich zur aktiven Sitzung.",
        "registration semantics":
            "`tFirstLoginDate` enthält tatsächlich den "
            "Registrierungszeitpunkt.",
        "transport-spanning access":
            "`tLastLoginDate` und `iTotalCalls` werden sowohl bei "
            "BBS- als auch bei NNTP-Zugriffen verändert.",
        "86400 bug":
            "Der Legacy-Wert `86400` für 24 Stunden ist deshalb "
            "fehlerhaft; korrekt wären 1440 Minuten.",
        "incomplete file quota":
            "`DownloadsToday` ist als verbleibende Dateiquote "
            "gedacht, wird aber weder geprüft noch vermindert.",
        "daily download balance":
            "`DownloadKToday` ist ein veränderlicher Tageskontosaldo",
        "credit semantics":
            "`Credit` bezeichnet ausschließlich Blue-Wave-"
            "NetMail-Credits und keine allgemeine BBS-Währung.",
        "atomic counters":
            "Kumulative Zähler werden atomar erhöht",
        "date-bound daily state":
            "Tageswerte werden nach Benutzer und Installationstag "
            "gespeichert",
        "mbsetup protection":
            "`mbsetup` darf Statistik-, Tages- und Sitzungswerte nicht "
            "durch Bearbeitung eines vollständigen Legacy-Datensatzes ändern.",
        "quota not security boundary":
            "Die unvollständige Legacy-Dateiquote wird nicht als "
            "bestehende Sicherheitsgrenze übernommen.",
    }

    for label, fragment in document_fragments.items():
        normalized_fragment = " ".join(fragment.split())

        if normalized_fragment not in normalized_document:
            failures.append(
                f"required documentation statement is missing: {label}"
            )

    print("B5.9 activity and usage ownership")
    print("=================================")
    print(f"Fields documented:                  {len(ownership_rows)}")
    print(f"Persistent PostgreSQL decisions:    {len(decided_fields)}")
    print(f"Derived values:                     {len(derived_fields)}")
    print(f"Session-only values:                {len(session_fields)}")
    print(
        "Open B5.9 decisions:               "
        f"{15 - len(decided_fields) - len(derived_fields) - len(session_fields)}"
    )
    print(f"Direct access occurrences:          {len(access_rows)}")
    print(f"Atomic cumulative counters:         {len(CUMULATIVE_COUNTER_FIELDS)}")
    print("Generated file comparison:          exact")

    if failures:
        print(
            "\nActivity/usage result: FAILED",
            file=sys.stderr,
        )

        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)

        return 1

    print("\nActivity/usage result: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
