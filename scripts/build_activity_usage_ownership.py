#!/usr/bin/env python3
"""Build the B5.9 activity and usage ownership documents.

The builder combines the reviewed B5.9 direct-access inventory with the
explicit ownership decisions. It changes neither users.data nor PostgreSQL.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPOSITORY_ROOT / "docs"

ACCESS_DETAILS = DOCS / "ACTIVITY_USAGE_ACCESS_DETAILS.tsv"
DECISIONS = DOCS / "ACTIVITY_USAGE_OWNERSHIP_DECISIONS.tsv"

ACCOUNT_TIMELINE_FIELDS = (
    "tFirstLoginDate",
    "tLastLoginDate",
)

TIME_ACCOUNT_FIELDS = (
    "iTimeLeft",
    "iTimeUsed",
    "iConnectTime",
)

VALUE_ACCOUNT_FIELDS = (
    "Credit",
)

TRANSFER_USAGE_FIELDS = (
    "Downloads",
    "Uploads",
    "DownloadK",
    "UploadK",
    "DownloadsToday",
    "DownloadKToday",
    "UploadKToday",
)

COMMUNITY_USAGE_FIELDS = (
    "iTotalCalls",
    "iPosted",
)

B5_9_FIELDS = (
    ACCOUNT_TIMELINE_FIELDS
    + TIME_ACCOUNT_FIELDS
    + VALUE_ACCOUNT_FIELDS
    + TRANSFER_USAGE_FIELDS
    + COMMUNITY_USAGE_FIELDS
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

EXPECTED_ACCESS_COLUMNS = [
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

ACCESS_KINDS = {
    "read",
    "write",
    "read-write",
    "metadata",
}


@dataclass(frozen=True)
class Decision:
    field: str
    category: str
    legacy_semantics: str
    authority: str
    postgresql_target: str
    unit_rule: str
    migration_rule: str
    write_policy: str
    consistency_rule: str
    compatibility_rule: str
    status: str


@dataclass(frozen=True)
class Result:
    decision: Decision
    read: int
    write: int
    read_write: int
    metadata: int
    files: tuple[str, ...]
    components: tuple[str, ...]
    mbsetup_writes: int


def parse_args(
    argv: list[str] | None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build the B5.9 activity and usage ownership decisions."
        )
    )
    parser.add_argument(
        "--format",
        choices=("summary", "details", "markdown"),
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


def load_decisions() -> list[Decision]:
    rows = read_tsv(
        DECISIONS,
        EXPECTED_DECISION_COLUMNS,
    )

    decisions = [
        Decision(
            field=row["FIELD"],
            category=row["CATEGORY"],
            legacy_semantics=row["LEGACY_SEMANTICS"],
            authority=row["AUTHORITY"],
            postgresql_target=row["POSTGRESQL_TARGET"],
            unit_rule=row["UNIT_RULE"],
            migration_rule=row["MIGRATION_RULE"],
            write_policy=row["WRITE_POLICY"],
            consistency_rule=row["CONSISTENCY_RULE"],
            compatibility_rule=row["COMPATIBILITY_RULE"],
            status=row["STATUS"],
        )
        for row in rows
    ]

    fields = tuple(
        decision.field
        for decision in decisions
    )

    if fields != B5_9_FIELDS:
        raise ValueError(
            "decision fields or ordering differ from the "
            "reviewed B5.9 field set"
        )

    if len(set(fields)) != len(fields):
        raise ValueError(
            "duplicate fields in B5.9 decision source"
        )

    decided = {
        decision.field
        for decision in decisions
        if decision.status == "decided"
    }

    derived = {
        decision.field
        for decision in decisions
        if decision.status == "derived"
    }

    session_only = {
        decision.field
        for decision in decisions
        if decision.status == "session-only"
    }

    if decided != EXPECTED_DECIDED_FIELDS:
        raise ValueError(
            "PostgreSQL decisions differ from the reviewed set: "
            f"{sorted(decided)!r}"
        )

    if derived != EXPECTED_DERIVED_FIELDS:
        raise ValueError(
            "derived fields differ from the reviewed set: "
            f"{sorted(derived)!r}"
        )

    if session_only != EXPECTED_SESSION_FIELDS:
        raise ValueError(
            "session-only fields differ from the reviewed set: "
            f"{sorted(session_only)!r}"
        )

    unknown_statuses = {
        decision.status
        for decision in decisions
    } - {"decided", "derived", "session-only"}

    if unknown_statuses:
        raise ValueError(
            "unknown decision statuses: "
            + ", ".join(sorted(unknown_statuses))
        )

    for decision in decisions:
        for label, value in (
            ("legacy semantics", decision.legacy_semantics),
            ("authority", decision.authority),
            ("PostgreSQL target", decision.postgresql_target),
            ("unit rule", decision.unit_rule),
            ("migration rule", decision.migration_rule),
            ("write policy", decision.write_policy),
            ("consistency rule", decision.consistency_rule),
            ("compatibility rule", decision.compatibility_rule),
        ):
            if not value.strip():
                raise ValueError(
                    f"{decision.field} has empty {label}"
                )

        if decision.status == "decided":
            if decision.authority != "PostgreSQL":
                raise ValueError(
                    f"{decision.field} is decided but not PostgreSQL-led"
                )

            if "(planned)" not in decision.postgresql_target and (
                decision.postgresql_target
                not in {"bbs_users.registered_at"}
            ):
                raise ValueError(
                    f"{decision.field} has an unexpected PostgreSQL target"
                )

        elif decision.status == "derived":
            if decision.authority != "Derived":
                raise ValueError(
                    f"{decision.field} is derived but has authority "
                    f"{decision.authority!r}"
                )

            if not decision.postgresql_target.startswith("derived:"):
                raise ValueError(
                    f"{decision.field} lacks a derived target"
                )

        elif decision.status == "session-only":
            if decision.authority != "PostgreSQL session state":
                raise ValueError(
                    f"{decision.field} has unexpected session authority"
                )

    return decisions


def build_results(
    decisions: list[Decision],
) -> list[Result]:
    access_rows = read_tsv(
        ACCESS_DETAILS,
        EXPECTED_ACCESS_COLUMNS,
    )

    if len(access_rows) != 126:
        raise ValueError(
            "expected 126 B5.9 access occurrences, "
            f"found {len(access_rows)}"
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

    access_fields = {
        row["FIELD"]
        for row in access_rows
    }

    if access_fields != set(B5_9_FIELDS):
        raise ValueError(
            "access inventory field set differs from B5.9: "
            f"{sorted(access_fields)!r}"
        )

    rows_by_field: dict[
        str,
        list[dict[str, str]],
    ] = defaultdict(list)

    for row in access_rows:
        rows_by_field[row["FIELD"]].append(row)

    results: list[Result] = []

    for decision in decisions:
        rows = rows_by_field[decision.field]
        counts = Counter(
            row["KIND"]
            for row in rows
        )
        files = tuple(
            sorted({row["PATH"] for row in rows})
        )
        components = tuple(
            sorted({component(path) for path in files})
        )
        mbsetup_writes = sum(
            1
            for row in rows
            if (
                row["PATH"] == "mbsetup/m_users.c"
                and row["KIND"] in {"write", "read-write"}
            )
        )

        results.append(
            Result(
                decision=decision,
                read=counts["read"],
                write=counts["write"],
                read_write=counts["read-write"],
                metadata=counts["metadata"],
                files=files,
                components=components,
                mbsetup_writes=mbsetup_writes,
            )
        )

    totals = (
        sum(result.read for result in results),
        sum(result.write for result in results),
        sum(result.read_write for result in results),
        sum(result.metadata for result in results),
    )

    if totals != (86, 21, 19, 0):
        raise ValueError(
            "B5.9 access totals differ from reviewed baseline: "
            f"{totals!r}"
        )

    return results


def print_summary(
    results: list[Result],
) -> None:
    decided = sum(
        result.decision.status == "decided"
        for result in results
    )
    derived = sum(
        result.decision.status == "derived"
        for result in results
    )
    session_only = sum(
        result.decision.status == "session-only"
        for result in results
    )

    reads = sum(
        result.read
        for result in results
    )
    writes = sum(
        result.write
        for result in results
    )
    read_writes = sum(
        result.read_write
        for result in results
    )
    metadata = sum(
        result.metadata
        for result in results
    )

    print("B5.9 activity and usage ownership decisions")
    print("===========================================")
    print(
        f"Account-timeline fields:           "
        f"{len(ACCOUNT_TIMELINE_FIELDS)}"
    )
    print(
        f"Time-account fields:               "
        f"{len(TIME_ACCOUNT_FIELDS)}"
    )
    print(
        f"Value-account fields:              "
        f"{len(VALUE_ACCOUNT_FIELDS)}"
    )
    print(
        f"Transfer-usage fields:             "
        f"{len(TRANSFER_USAGE_FIELDS)}"
    )
    print(
        f"Community-usage fields:            "
        f"{len(COMMUNITY_USAGE_FIELDS)}"
    )
    print(f"Fields decided:                    {len(results)}")
    print(f"Persistent PostgreSQL decisions:   {decided}")
    print(f"Derived values:                    {derived}")
    print(f"Session-only values:               {session_only}")
    print(
        "Open B5.9 decisions:              "
        f"{len(results) - decided - derived - session_only}"
    )
    print(f"Direct read occurrences:           {reads}")
    print(f"Direct write occurrences:          {writes}")
    print(f"Direct read-write occurrences:     {read_writes}")
    print(f"Direct metadata occurrences:       {metadata}")
    print(
        "Direct access occurrences:         "
        f"{reads + writes + read_writes + metadata}"
    )
    print()
    print(
        "FIELD\tCATEGORY\tSTATUS\tAUTHORITY\tREAD\tWRITE\t"
        "READ_WRITE\tFILES\tTARGET"
    )

    for result in results:
        decision = result.decision

        print(
            "\t".join(
                (
                    decision.field,
                    decision.category,
                    decision.status,
                    decision.authority,
                    str(result.read),
                    str(result.write),
                    str(result.read_write),
                    str(len(result.files)),
                    decision.postgresql_target,
                )
            )
        )


def print_details(
    results: list[Result],
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
        )
    )

    for result in results:
        decision = result.decision

        writer.writerow(
            (
                decision.field,
                decision.category,
                decision.status,
                decision.authority,
                decision.postgresql_target,
                result.read,
                result.write,
                result.read_write,
                result.metadata,
                len(result.files),
                ",".join(result.files),
                ",".join(result.components),
                result.mbsetup_writes,
                decision.legacy_semantics,
                decision.unit_rule,
                decision.migration_rule,
                decision.write_policy,
                decision.consistency_rule,
                decision.compatibility_rule,
            )
        )


def markdown_escape(value: str) -> str:
    return (
        value
        .replace("|", r"\|")
        .replace("\n", " ")
    )


def print_markdown(
    results: list[Result],
) -> None:
    decided = sum(
        result.decision.status == "decided"
        for result in results
    )
    derived = sum(
        result.decision.status == "derived"
        for result in results
    )
    session_only = sum(
        result.decision.status == "session-only"
        for result in results
    )
    total_accesses = sum(
        result.read
        + result.write
        + result.read_write
        + result.metadata
        for result in results
    )

    print(
        "# FortyTwo BBS – B5.9 Aktivität, "
        "Zeitkonten und Nutzungsstatistik"
    )
    print()
    print("**Stand:** 22. Juli 2026")
    print()
    print(
        "**Phase:** B5.9 – Aktivität, "
        "Zeitkonten und Nutzungsstatistik"
    )
    print()
    print("## 1. Ergebnis")
    print()
    print(
        "Für alle 15 untersuchten Aktivitäts-, Zeitkonto- "
        "und Nutzungsfelder ist die künftige Behandlung entschieden."
    )
    print()
    print("```text")
    print(f"Kontohistorie:                       {len(ACCOUNT_TIMELINE_FIELDS)}")
    print(f"Zeitkonten:                          {len(TIME_ACCOUNT_FIELDS)}")
    print(f"Legacy-Kompatibilitätswert:          {len(VALUE_ACCOUNT_FIELDS)}")
    print(f"Transfer- und Quotawerte:            {len(TRANSFER_USAGE_FIELDS)}")
    print(f"Zugriffs- und Beitragszähler:        {len(COMMUNITY_USAGE_FIELDS)}")
    print(f"dauerhafte PostgreSQL-Entscheidungen: {decided}")
    print(f"abgeleitete Werte:                    {derived}")
    print(f"reine Sitzungswerte:                  {session_only}")
    print(
        "offene B5.9-Entscheidungen:            "
        f"{len(results) - decided - derived - session_only}"
    )
    print(f"geprüfte Direktzugriffe:              {total_accesses}")
    print("```")
    print()
    print(
        "`iTimeLeft` und `DownloadsToday` sind keine "
        "eigenständigen Benutzerkontostände, sondern aus "
        "Richtlinie und Verbrauch abzuleitende Werte."
    )
    print()
    print(
        "`iConnectTime` gehört ausschließlich zur aktiven Sitzung."
    )
    print()
    print("## 2. Zentrale Altcodebefunde")
    print()
    print(
        "- `tFirstLoginDate` enthält tatsächlich den "
        "Registrierungszeitpunkt."
    )
    print(
        "- `tLastLoginDate` und `iTotalCalls` werden sowohl bei "
        "BBS- als auch bei NNTP-Zugriffen verändert."
    )
    print(
        "- Die Zeitfelder verwenden Minuten. Der Legacy-Wert "
        "`86400` für 24 Stunden ist deshalb fehlerhaft; korrekt "
        "wären 1440 Minuten."
    )
    print(
        "- `DownloadsToday` ist als verbleibende Dateiquote "
        "gedacht, wird aber weder geprüft noch vermindert."
    )
    print(
        "- `DownloadKToday` ist ein veränderlicher Tageskontosaldo: "
        "Downloads belasten ihn, Uploads können ihn erhöhen."
    )
    print(
        "- `Credit` bezeichnet ausschließlich Blue-Wave-"
        "NetMail-Credits und keine allgemeine BBS-Währung."
    )
    print()
    print("## 3. Entscheidungsübersicht")
    print()
    print(
        "| Feld | Kategorie | Status | Führung | Ziel | "
        "Lesen | Schreiben | Dateien |"
    )
    print(
        "|---|---|---|---|---|---:|---:|---:|"
    )

    for result in results:
        decision = result.decision

        print(
            "| "
            + " | ".join(
                (
                    f"`{decision.field}`",
                    markdown_escape(decision.category),
                    decision.status,
                    markdown_escape(decision.authority),
                    f"`{markdown_escape(decision.postgresql_target)}`",
                    str(result.read),
                    str(result.write + result.read_write),
                    str(len(result.files)),
                )
            )
            + " |"
        )

    print()
    print("## 4. Einzelentscheidungen")
    print()

    for result in results:
        decision = result.decision

        print(f"### `{decision.field}`")
        print()
        print(
            f"**Legacy-Semantik:** "
            f"{decision.legacy_semantics}"
        )
        print()
        print(
            f"**Führung:** {decision.authority}"
        )
        print()
        print(
            f"**PostgreSQL-Ziel:** "
            f"`{decision.postgresql_target}`"
        )
        print()
        print(
            f"**Einheitenregel:** "
            f"{decision.unit_rule}"
        )
        print()
        print(
            f"**Migrationsregel:** "
            f"{decision.migration_rule}"
        )
        print()
        print(
            f"**Schreibregel:** "
            f"{decision.write_policy}"
        )
        print()
        print(
            f"**Konsistenzregel:** "
            f"{decision.consistency_rule}"
        )
        print()
        print(
            f"**Legacy-Kompatibilität:** "
            f"{decision.compatibility_rule}"
        )
        print()

    print("## 5. Konsequenzen für die Umsetzung")
    print()
    print(
        "1. Kumulative Zähler werden atomar erhöht und niemals "
        "über Ganzsatz-Rewrites aus `users.data` zurückgeschrieben."
    )
    print(
        "2. Tageswerte werden nach Benutzer und Installationstag "
        "gespeichert; ein Tageswechsel erzeugt einen neuen Zustand."
    )
    print(
        "3. Zeit- und Transferkontingente werden getrennt von "
        "Verbrauch, Gutschriften und kumulativer Statistik modelliert."
    )
    print(
        "4. Erfolgreiche Zugriffe und Nachrichtenannahmen erzeugen "
        "Ereignis und Zählerfortschreibung in derselben Transaktion."
    )
    print(
        "5. `mbsetup` darf Statistik-, Tages- und Sitzungswerte nicht "
        "durch Bearbeitung eines vollständigen Legacy-Datensatzes ändern."
    )
    print(
        "6. Die unvollständige Legacy-Dateiquote wird nicht als "
        "bestehende Sicherheitsgrenze übernommen."
    )


def main(
    argv: list[str] | None = None,
) -> int:
    args = parse_args(argv)

    try:
        decisions = load_decisions()
        results = build_results(decisions)
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            f"Activity/usage ownership builder: FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.format == "details":
        print_details(results)
    elif args.format == "markdown":
        print_markdown(results)
    else:
        print_summary(results)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
