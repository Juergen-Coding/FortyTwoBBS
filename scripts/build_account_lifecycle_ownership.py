#!/usr/bin/env python3
"""Build the B5.7 account-lifecycle ownership decision document.

The builder combines the reviewed B5.7 access inventory with the explicit
ownership decisions. It changes neither users.data nor PostgreSQL.
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

ACCESS_DETAILS = DOCS / "ACCOUNT_LIFECYCLE_ACCESS_DETAILS.tsv"
DECISIONS = DOCS / "ACCOUNT_LIFECYCLE_OWNERSHIP_DECISIONS.tsv"

LIFECYCLE_FIELDS = (
    "Security",
    "Deleted",
    "LockedOut",
    "NeverDelete",
    "Guest",
    "Hidden",
    "sExpiryDate",
    "ExpirySec",
)

EXPECTED_ACCESS_COLUMNS = [
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
    migration_rule: str
    write_policy: str
    audit_requirement: str
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
            "Build the B5.7 account-lifecycle ownership decisions."
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

        if any("\n" in value or "\r" in value for value in row.values()):
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
            migration_rule=row["MIGRATION_RULE"],
            write_policy=row["WRITE_POLICY"],
            audit_requirement=row["AUDIT_REQUIREMENT"],
            status=row["STATUS"],
        )
        for row in rows
    ]

    fields = [decision.field for decision in decisions]

    if tuple(fields) != LIFECYCLE_FIELDS:
        raise ValueError(
            "decision fields or ordering differ from the "
            "reviewed B5.7 field set"
        )

    if len(set(fields)) != len(fields):
        raise ValueError("duplicate lifecycle decision fields")

    retained = {
        decision.field
        for decision in decisions
        if decision.status == "retained"
    }

    decided = {
        decision.field
        for decision in decisions
        if decision.status == "decided"
    }

    if retained != EXPECTED_RETAINED_FIELDS:
        raise ValueError(
            "retained fields differ from the reviewed baseline: "
            f"{sorted(retained)!r}"
        )

    if decided != EXPECTED_NEW_FIELDS:
        raise ValueError(
            "newly decided fields differ from the reviewed B5.7 set: "
            f"{sorted(decided)!r}"
        )

    unknown_statuses = {
        decision.status
        for decision in decisions
    } - {"retained", "decided"}

    if unknown_statuses:
        raise ValueError(
            "unknown decision statuses: "
            + ", ".join(sorted(unknown_statuses))
        )

    for decision in decisions:
        if decision.authority != "PostgreSQL":
            raise ValueError(
                f"{decision.field} is not PostgreSQL-led"
            )

        if not decision.postgresql_target:
            raise ValueError(
                f"{decision.field} has no PostgreSQL target"
            )

        if not decision.migration_rule:
            raise ValueError(
                f"{decision.field} has no migration rule"
            )

        if not decision.write_policy:
            raise ValueError(
                f"{decision.field} has no write policy"
            )

        if not decision.audit_requirement:
            raise ValueError(
                f"{decision.field} has no audit requirement"
            )

    return decisions


def build_results(
    decisions: list[Decision],
) -> list[Result]:
    access_rows = read_tsv(
        ACCESS_DETAILS,
        EXPECTED_ACCESS_COLUMNS,
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

    selected_fields = set(LIFECYCLE_FIELDS)

    if {
        row["FIELD"]
        for row in access_rows
    } - selected_fields:
        raise ValueError(
            "access inventory contains fields outside B5.7"
        )

    if len(access_rows) != 153:
        raise ValueError(
            "expected 153 lifecycle access occurrences, "
            f"found {len(access_rows)}"
        )

    rows_by_field: dict[
        str,
        list[dict[str, str]],
    ] = defaultdict(list)

    for row in access_rows:
        rows_by_field[row["FIELD"]].append(row)

    results: list[Result] = []

    for decision in decisions:
        rows = rows_by_field.get(decision.field, [])
        counts = Counter(row["KIND"] for row in rows)
        files = tuple(sorted({row["PATH"] for row in rows}))
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

    return results


def print_summary(results: list[Result]) -> None:
    retained = sum(
        result.decision.status == "retained"
        for result in results
    )
    newly_decided = sum(
        result.decision.status == "decided"
        for result in results
    )
    reads = sum(result.read for result in results)
    writes = sum(result.write for result in results)
    read_writes = sum(
        result.read_write
        for result in results
    )

    print("B5.7 account-lifecycle ownership decisions")
    print("==========================================")
    print(f"Lifecycle fields:              {len(results)}")
    print(f"Retained decisions:            {retained}")
    print(f"New B5.7 decisions:            {newly_decided}")
    print(f"Open B5.7 decisions:           {len(results) - retained - newly_decided}")
    print(f"Direct read occurrences:       {reads}")
    print(f"Direct write occurrences:      {writes}")
    print(f"Direct read-write occurrences: {read_writes}")
    print(
        "Direct access occurrences:     "
        f"{reads + writes + read_writes + sum(result.metadata for result in results)}"
    )
    print()
    print("FIELD\tCATEGORY\tSTATUS\tREAD\tWRITE\tFILES\tTARGET")

    for result in results:
        decision = result.decision

        print(
            "\t".join(
                (
                    decision.field,
                    decision.category,
                    decision.status,
                    str(result.read),
                    str(result.write),
                    str(len(result.files)),
                    decision.postgresql_target,
                )
            )
        )


def print_details(results: list[Result]) -> None:
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
            "MIGRATION_RULE",
            "WRITE_POLICY",
            "AUDIT_REQUIREMENT",
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
                decision.migration_rule,
                decision.write_policy,
                decision.audit_requirement,
            )
        )


def markdown_escape(value: str) -> str:
    return value.replace("|", r"\|").replace("\n", " ")


def print_markdown(results: list[Result]) -> None:
    retained = sum(
        result.decision.status == "retained"
        for result in results
    )
    newly_decided = sum(
        result.decision.status == "decided"
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
        "# FortyTwo BBS – B5.7 Kontolebenszyklus, "
        "Sperren und Sichtbarkeit"
    )
    print()
    print("**Stand:** 22. Juli 2026")
    print()
    print(
        "**Phase:** B5.7 – Kontolebenszyklus, "
        "Sperren und Berechtigungen"
    )
    print()
    print("## 1. Ergebnis")
    print()
    print(
        "Für die acht untersuchten Legacy-Felder ist die "
        "fachliche Führung vollständig entschieden."
    )
    print()
    print("```text")
    print(f"untersuchte Felder:             {len(results)}")
    print(f"beibehaltene Entscheidungen:    {retained}")
    print(f"neue B5.7-Entscheidungen:       {newly_decided}")
    print(
        "offene B5.7-Entscheidungen:     "
        f"{len(results) - retained - newly_decided}"
    )
    print(f"geprüfte Direktzugriffe:        {total_accesses}")
    print("```")
    print()
    print(
        "PostgreSQL ist für alle acht Felder das führende System. "
        "`users.data` darf diese Zustände später nur noch als "
        "abgeleitete Legacy-Kompatibilitätsdarstellung enthalten."
    )
    print()
    print("## 2. Zentrale fachliche Trennung")
    print()
    print(
        "- `Deleted` beschreibt eine logische Kontolöschung."
    )
    print(
        "- `LockedOut` beschreibt eine administrative Kontosperre."
    )
    print(
        "- `NeverDelete` schützt ausschließlich vor automatischer "
        "Inaktivitätsbereinigung."
    )
    print(
        "- `Guest` ist eine Kontoklasse mit abweichendem "
        "Persistenz- und Passwortverhalten."
    )
    print(
        "- `Hidden` betrifft nur die Sichtbarkeit in Benutzer- "
        "und Last-Caller-Listen."
    )
    print(
        "- `sExpiryDate` und `ExpirySec` bilden gemeinsam eine "
        "zeitgesteuerte Autorisierungsänderung."
    )
    print()
    print(
        "Insbesondere darf die Legacy-Ablaufregel nicht als "
        "Kontolöschung oder allgemeine Kontosperre umgesetzt werden."
    )
    print()
    print("## 3. Entscheidungsübersicht")
    print()
    print(
        "| Feld | Kategorie | Status | PostgreSQL-Ziel | "
        "Lesen | Schreiben | Dateien |"
    )
    print("|---|---|---|---|---:|---:|---:|")

    for result in results:
        decision = result.decision

        print(
            "| "
            + " | ".join(
                (
                    f"`{decision.field}`",
                    markdown_escape(decision.category),
                    decision.status,
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
            f"**Audit:** "
            f"{decision.audit_requirement}"
        )
        print()

    print("## 5. Konsequenzen für die Umsetzung")
    print()
    print(
        "1. Numerische Legacy-Sicherheitswerte werden nicht direkt "
        "nach PostgreSQL kopiert."
    )
    print(
        "2. Rollen und Capabilities bleiben die einzige moderne "
        "Autorisierungsquelle."
    )
    print(
        "3. Kontolöschung, administrative Sperre und temporäres "
        "Login-Throttling bleiben getrennte Zustände."
    )
    print(
        "4. Die Ablaufregel wird als geplante Änderung einer "
        "Autorisierungs-Policy modelliert."
    )
    print(
        "5. `mbsetup` darf diese PostgreSQL-geführten Zustände "
        "nicht durch vollständige Legacy-Datensatz-Rewrites "
        "zurücksetzen."
    )
    print()
    print(
        "Die konkreten PostgreSQL-Migrationen und administrativen "
        "Schreibschnittstellen folgen in einer späteren "
        "Umsetzungsphase."
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
            f"Lifecycle ownership builder: FAILED: {exc}",
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
