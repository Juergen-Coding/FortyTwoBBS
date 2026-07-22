#!/usr/bin/env python3
"""Build the B5.8 profile and terminal-preference ownership documents.

The builder combines the reviewed B5.8 direct-access inventory with the
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

ACCESS_DETAILS = DOCS / "PROFILE_TERMINAL_ACCESS_DETAILS.tsv"
DECISIONS = DOCS / "PROFILE_TERMINAL_OWNERSHIP_DECISIONS.tsv"

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
    "MIGRATION_RULE",
    "WRITE_POLICY",
    "PRIVACY_POLICY",
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
    migration_rule: str
    write_policy: str
    privacy_policy: str
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
            "Build the B5.8 profile and terminal-preference "
            "ownership decisions."
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
            migration_rule=row["MIGRATION_RULE"],
            write_policy=row["WRITE_POLICY"],
            privacy_policy=row["PRIVACY_POLICY"],
            compatibility_rule=row["COMPATIBILITY_RULE"],
            status=row["STATUS"],
        )
        for row in rows
    ]

    fields = tuple(
        decision.field
        for decision in decisions
    )

    if fields != B5_8_FIELDS:
        raise ValueError(
            "decision fields or ordering differ from the "
            "reviewed B5.8 field set"
        )

    if len(set(fields)) != len(fields):
        raise ValueError(
            "duplicate fields in B5.8 decision source"
        )

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

    retired = {
        decision.field
        for decision in decisions
        if decision.status == "retired"
    }

    if retained != EXPECTED_RETAINED_FIELDS:
        raise ValueError(
            "retained fields differ from the reviewed baseline: "
            f"{sorted(retained)!r}"
        )

    if decided != EXPECTED_DECIDED_FIELDS:
        raise ValueError(
            "new PostgreSQL decisions differ from the reviewed set: "
            f"{sorted(decided)!r}"
        )

    if retired != EXPECTED_RETIRED_FIELDS:
        raise ValueError(
            "retired fields differ from the reviewed set: "
            f"{sorted(retired)!r}"
        )

    unknown_statuses = {
        decision.status
        for decision in decisions
    } - {"retained", "decided", "retired"}

    if unknown_statuses:
        raise ValueError(
            "unknown decision statuses: "
            + ", ".join(sorted(unknown_statuses))
        )

    for decision in decisions:
        if decision.status == "retired":
            if decision.authority != "Retired":
                raise ValueError(
                    f"{decision.field} is retired but has authority "
                    f"{decision.authority!r}"
                )

            if decision.postgresql_target != "—":
                raise ValueError(
                    f"{decision.field} is retired but has a "
                    "PostgreSQL target"
                )
        else:
            if decision.authority != "PostgreSQL":
                raise ValueError(
                    f"{decision.field} is not PostgreSQL-led"
                )

            if not decision.postgresql_target:
                raise ValueError(
                    f"{decision.field} has no PostgreSQL target"
                )

        for label, value in (
            ("legacy semantics", decision.legacy_semantics),
            ("migration rule", decision.migration_rule),
            ("write policy", decision.write_policy),
            ("privacy policy", decision.privacy_policy),
            ("compatibility rule", decision.compatibility_rule),
        ):
            if not value.strip():
                raise ValueError(
                    f"{decision.field} has empty {label}"
                )

    return decisions


def build_results(
    decisions: list[Decision],
) -> list[Result]:
    access_rows = read_tsv(
        ACCESS_DETAILS,
        EXPECTED_ACCESS_COLUMNS,
    )

    if len(access_rows) != 464:
        raise ValueError(
            "expected 464 B5.8 access occurrences, "
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

    if access_fields != set(B5_8_FIELDS):
        raise ValueError(
            "access inventory field set differs from B5.8: "
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

    if totals != (332, 119, 6, 7):
        raise ValueError(
            "B5.8 access totals differ from reviewed baseline: "
            f"{totals!r}"
        )

    return results


def print_summary(
    results: list[Result],
) -> None:
    retained = sum(
        result.decision.status == "retained"
        for result in results
    )
    decided = sum(
        result.decision.status == "decided"
        for result in results
    )
    retired = sum(
        result.decision.status == "retired"
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

    print("B5.8 profile and terminal ownership decisions")
    print("=============================================")
    print(f"Profile fields:                     {len(PROFILE_FIELDS)}")
    print(f"Terminal-preference fields:         {len(TERMINAL_FIELDS)}")
    print(f"Fields decided:                     {len(results)}")
    print(f"Retained PostgreSQL decisions:      {retained}")
    print(f"New PostgreSQL decisions:           {decided}")
    print(f"Retired legacy fields:              {retired}")
    print(
        "Open B5.8 decisions:              "
        f"{len(results) - retained - decided - retired}"
    )
    print(f"Direct read occurrences:            {reads}")
    print(f"Direct write occurrences:           {writes}")
    print(f"Direct read-write occurrences:      {read_writes}")
    print(f"Direct metadata occurrences:        {metadata}")
    print(
        "Direct access occurrences:          "
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
            "MIGRATION_RULE",
            "WRITE_POLICY",
            "PRIVACY_POLICY",
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
                decision.migration_rule,
                decision.write_policy,
                decision.privacy_policy,
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
    retained = sum(
        result.decision.status == "retained"
        for result in results
    )
    decided = sum(
        result.decision.status == "decided"
        for result in results
    )
    retired = sum(
        result.decision.status == "retired"
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
        "# FortyTwo BBS – B5.8 Profil- und "
        "Terminalpräferenzen"
    )
    print()
    print("**Stand:** 22. Juli 2026")
    print()
    print(
        "**Phase:** B5.8 – Profil- und "
        "Terminalpräferenzen"
    )
    print()
    print("## 1. Ergebnis")
    print()
    print(
        "Für alle 24 untersuchten Profil- und "
        "Terminalfelder ist die künftige Behandlung entschieden."
    )
    print()
    print("```text")
    print(f"Profilfelder:                         {len(PROFILE_FIELDS)}")
    print(
        "Terminal- und Bedienpräferenzen:      "
        f"{len(TERMINAL_FIELDS)}"
    )
    print(f"beibehaltene PostgreSQL-Entscheidungen: {retained}")
    print(f"neue PostgreSQL-Entscheidungen:          {decided}")
    print(f"stillgelegte Legacy-Felder:              {retired}")
    print(
        "offene B5.8-Entscheidungen:             "
        f"{len(results) - retained - decided - retired}"
    )
    print(f"geprüfte Direktzugriffe:                 {total_accesses}")
    print("```")
    print()
    print(
        "Die aktiven Felder werden PostgreSQL-geführt. "
        "`Cls`, `More` und `ieASCII8` werden nicht migriert, "
        "weil der untersuchte Laufzeitcode ihre Werte nicht auswertet."
    )
    print()
    print("## 2. Datenschutzgrenze")
    print()
    print(
        "Telefonnummern, Anschrift, Geburtsdatum und "
        "Geschlechtsangabe sind private Profildaten."
    )
    print()
    print(
        "Diese Werte dürfen weder im Klartext protokolliert "
        "noch standardmäßig an Doors, Benutzerlisten oder "
        "andere Legacy-Schnittstellen weitergegeben werden."
    )
    print()
    print(
        "Der öffentliche Standorttext bleibt davon getrennt. "
        "Seine Ausgabe richtet sich nach einer ausdrücklich "
        "festgelegten Sichtbarkeitspolitik."
    )
    print()
    print("## 3. Entscheidungsübersicht")
    print()
    print(
        "| Feld | Kategorie | Status | Führung | "
        "PostgreSQL-Ziel | Lesen | Schreiben | Dateien |"
    )
    print(
        "|---|---|---|---|---|---:|---:|---:|"
    )

    for result in results:
        decision = result.decision
        target = (
            f"`{markdown_escape(decision.postgresql_target)}`"
            if decision.postgresql_target != "—"
            else "keine Speicherung"
        )

        print(
            "| "
            + " | ".join(
                (
                    f"`{decision.field}`",
                    markdown_escape(decision.category),
                    decision.status,
                    decision.authority,
                    target,
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
            if decision.postgresql_target != "—"
            else "**PostgreSQL-Ziel:** keine Speicherung"
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
            f"**Datenschutz:** "
            f"{decision.privacy_policy}"
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
        "1. Aktive Profil- und Präferenzwerte werden aus "
        "PostgreSQL gelesen und über kontrollierte Funktionen geändert."
    )
    print(
        "2. Transporterkennung darf dauerhafte Präferenzen nur "
        "vorschlagen, nicht ungefragt überschreiben."
    )
    print(
        "3. Private Profildaten werden von öffentlichem Profil, "
        "Berechtigungen und Sitzungszustand getrennt."
    )
    print(
        "4. Legacy-Door-Exporte erhalten private Daten nur nach "
        "ausdrücklicher Freigabe und minimalem Datenprinzip."
    )
    print(
        "5. `mbsetup` darf PostgreSQL-geführte Werte nicht durch "
        "Ganzsatz-Rewrites aus `users.data` zurücksetzen."
    )
    print(
        "6. Stillgelegte Felder erhalten höchstens feste "
        "Kompatibilitätswerte, solange das Legacy-Binärformat besteht."
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
            f"Profile/terminal ownership builder: FAILED: {exc}",
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
