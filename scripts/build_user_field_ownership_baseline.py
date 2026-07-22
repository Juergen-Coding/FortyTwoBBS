#!/usr/bin/env python3
"""Build the B5.6 user-field ownership baseline.

The baseline combines:
- the 72-field B5.4 PostgreSQL mapping,
- the reviewed B5.6 direct-writer inventory,
- the complete-record rewrite boundary.

It does not modify users.data, PostgreSQL, or production source code.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from dataclasses import dataclass
from pathlib import Path
import re
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPOSITORY_ROOT / "docs"

FIELD_MATRIX = DOCS / "MBSETUP_USER_FIELD_MATRIX.md"
WRITER_DETAILS = DOCS / "MBSETUP_USER_FIELD_WRITERS_DETAILS.tsv"

EXPECTED_WRITER_COLUMNS = [
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

DIRECT_WRITE_KINDS = {
    "write",
    "read-write",
}

RECORD_WRITE_KINDS = {
    "record-write",
    "record-read-write",
}

OPEN_AUTHORITY = "Legacy bis zur Einzelentscheidung"


@dataclass(frozen=True)
class MatrixRow:
    field: str
    meaning: str
    mbsetup_access: str
    postgresql_table: str
    postgresql_target: str
    authority: str
    note: str


@dataclass(frozen=True)
class OwnershipRow:
    field: str
    meaning: str
    authority: str
    postgresql_table: str
    postgresql_target: str
    decision_status: str
    direct_write: int
    direct_read_write: int
    direct_writer_files: tuple[str, ...]
    direct_writer_components: tuple[str, ...]
    mbsetup_direct_writes: int
    whole_record_exposure: str


def parse_args(
    argv: list[str] | None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the B5.6 user-field ownership baseline."
    )
    parser.add_argument(
        "--format",
        choices=("summary", "details", "markdown"),
        default="summary",
        help="output format; default: summary",
    )
    return parser.parse_args(argv)


def split_markdown_row(line: str) -> list[str]:
    parts = [
        part.strip().replace(r"\|", "|")
        for part in re.split(r"(?<!\\)\|", line)
    ]

    if parts and parts[0] == "":
        parts = parts[1:]

    if parts and parts[-1] == "":
        parts = parts[:-1]

    return parts


def read_field_matrix() -> list[MatrixRow]:
    text = FIELD_MATRIX.read_text(encoding="utf-8")
    rows: list[MatrixRow] = []

    for line in text.splitlines():
        if not line.startswith("| "):
            continue

        if line.startswith("| Legacy-Feld ") or line.startswith("|---"):
            continue

        parts = split_markdown_row(line)

        if len(parts) != 7:
            raise ValueError(
                "field matrix row has "
                f"{len(parts)} columns instead of 7: {line}"
            )

        rows.append(
            MatrixRow(
                field=parts[0],
                meaning=parts[1],
                mbsetup_access=parts[2],
                postgresql_table=parts[3],
                postgresql_target=parts[4],
                authority=parts[5],
                note=parts[6],
            )
        )

    fields = [row.field for row in rows]

    if len(rows) != 72:
        raise ValueError(
            f"expected 72 field-matrix rows, found {len(rows)}"
        )

    if len(set(fields)) != len(fields):
        raise ValueError("duplicate fields in field matrix")

    return rows


def read_writer_details() -> list[dict[str, str]]:
    with WRITER_DETAILS.open(
        encoding="utf-8",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle, delimiter="\t")

        if reader.fieldnames != EXPECTED_WRITER_COLUMNS:
            raise ValueError(
                "unexpected writer-detail columns: "
                f"{reader.fieldnames!r}"
            )

        rows = list(reader)

    for number, row in enumerate(rows, start=2):
        if None in row:
            raise ValueError(
                f"extra TSV columns in {WRITER_DETAILS.name}:{number}"
            )

        if any(value is None for value in row.values()):
            raise ValueError(
                f"missing TSV value in {WRITER_DETAILS.name}:{number}"
            )

    return rows


def component(path: str) -> str:
    return path.split("/", 1)[0]


def build_ownership_rows(
    matrix_rows: list[MatrixRow],
    writer_rows: list[dict[str, str]],
) -> list[OwnershipRow]:
    known_fields = {row.field for row in matrix_rows}
    writers_by_field: dict[
        str,
        list[dict[str, str]],
    ] = defaultdict(list)

    whole_record_writers = [
        row
        for row in writer_rows
        if (
            row["SCOPE"] == "record"
            and row["KIND"] in RECORD_WRITE_KINDS
        )
    ]

    if len(whole_record_writers) != 60:
        raise ValueError(
            "expected 60 whole-record writer occurrences, "
            f"found {len(whole_record_writers)}"
        )

    mbsetup_record_writers = [
        row
        for row in whole_record_writers
        if row["PATH"] == "mbsetup/m_users.c"
    ]

    if len(mbsetup_record_writers) != 7:
        raise ValueError(
            "expected 7 mbsetup whole-record writer operations, "
            f"found {len(mbsetup_record_writers)}"
        )

    for row in writer_rows:
        if row["SCOPE"] != "field":
            continue

        field = row["FIELD"]

        if field not in known_fields:
            raise ValueError(
                f"writer inventory contains unknown field: {field}"
            )

        if row["KIND"] not in DIRECT_WRITE_KINDS:
            raise ValueError(
                "unexpected direct writer kind "
                f"{row['KIND']!r} for {field}"
            )

        writers_by_field[field].append(row)

    result: list[OwnershipRow] = []

    for matrix in matrix_rows:
        writers = writers_by_field.get(matrix.field, [])
        counts = Counter(row["KIND"] for row in writers)
        files = tuple(sorted({row["PATH"] for row in writers}))
        components = tuple(
            sorted({component(path) for path in files})
        )
        mbsetup_direct_writes = sum(
            1
            for row in writers
            if row["PATH"] == "mbsetup/m_users.c"
        )

        decided = not (
            matrix.postgresql_table == "noch nicht festgelegt"
            and matrix.postgresql_target == "noch nicht festgelegt"
            and matrix.authority == OPEN_AUTHORITY
        )

        result.append(
            OwnershipRow(
                field=matrix.field,
                meaning=matrix.meaning,
                authority=matrix.authority,
                postgresql_table=matrix.postgresql_table,
                postgresql_target=matrix.postgresql_target,
                decision_status="decided" if decided else "open",
                direct_write=counts["write"],
                direct_read_write=counts["read-write"],
                direct_writer_files=files,
                direct_writer_components=components,
                mbsetup_direct_writes=mbsetup_direct_writes,
                whole_record_exposure="yes",
            )
        )

    return result


def print_summary(rows: list[OwnershipRow]) -> None:
    decided = [
        row
        for row in rows
        if row.decision_status == "decided"
    ]
    open_rows = [
        row
        for row in rows
        if row.decision_status == "open"
    ]
    direct_writer_fields = [
        row
        for row in rows
        if row.direct_write + row.direct_read_write > 0
    ]
    mbsetup_writer_fields = [
        row
        for row in rows
        if row.mbsetup_direct_writes > 0
    ]

    print("B5.6 user-field ownership baseline")
    print("==================================")
    print(f"Fields documented:                  {len(rows)}")
    print(f"Ownership decisions retained:       {len(decided)}")
    print(f"Open ownership decisions:           {len(open_rows)}")
    print(f"Fields with direct writers:         {len(direct_writer_fields)}")
    print(
        "Fields without direct writers:      "
        f"{len(rows) - len(direct_writer_fields)}"
    )
    print(f"Fields directly written by mbsetup: {len(mbsetup_writer_fields)}")
    print(f"Fields exposed to record rewrites:  {len(rows)}")
    print()
    print("Decided fields:")

    for row in decided:
        target = (
            f"{row.postgresql_table}.{row.postgresql_target}"
            if row.postgresql_table != "—"
            else "not migrated"
        )
        print(
            f"  {row.field}: {row.authority} -> {target}"
        )


def print_details(rows: list[OwnershipRow]) -> None:
    writer = csv.writer(
        sys.stdout,
        delimiter="\t",
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )

    writer.writerow(
        (
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
        )
    )

    for row in rows:
        writer.writerow(
            (
                row.field,
                row.meaning,
                row.authority,
                row.postgresql_table,
                row.postgresql_target,
                row.decision_status,
                row.direct_write,
                row.direct_read_write,
                len(row.direct_writer_files),
                ",".join(row.direct_writer_files),
                ",".join(row.direct_writer_components),
                row.mbsetup_direct_writes,
                row.whole_record_exposure,
            )
        )


def markdown_escape(value: str) -> str:
    return value.replace("|", r"\|").replace("\n", " ")


def print_markdown(rows: list[OwnershipRow]) -> None:
    decided_count = sum(
        row.decision_status == "decided"
        for row in rows
    )
    open_count = len(rows) - decided_count
    direct_writer_count = sum(
        row.direct_write + row.direct_read_write > 0
        for row in rows
    )
    mbsetup_writer_count = sum(
        row.mbsetup_direct_writes > 0
        for row in rows
    )

    print("# FortyTwo BBS – B5.6 Hoheitsbaseline der Benutzerfelder")
    print()
    print("**Stand:** 22. Juli 2026")
    print("**Phase:** B5.6 – Feldhoheit und Migrationsreihenfolge")
    print()
    print("## 1. Zweck")
    print()
    print(
        "Diese Baseline verbindet die B5.4-PostgreSQL-Zuordnung mit "
        "der in B5.5/B5.6 geprüften Schreiberinventur."
    )
    print()
    print(
        "Sie übernimmt ausschließlich bereits dokumentierte "
        "Hoheitsentscheidungen. Offene Felder bleiben bis zu ihrer "
        "fachlichen Einzelprüfung Legacy-geführt."
    )
    print()
    print("## 2. Verbindlicher Ausgangsstand")
    print()
    print("```text")
    print(f"Felder insgesamt:                    {len(rows)}")
    print(f"bereits entschiedene Feldhoheiten:   {decided_count}")
    print(f"offene Feldhoheiten:                 {open_count}")
    print(f"Felder mit direkten Schreibern:      {direct_writer_count}")
    print(
        "Felder ohne direkte Schreiber:       "
        f"{len(rows) - direct_writer_count}"
    )
    print(f"von mbsetup direkt geschriebene:     {mbsetup_writer_count}")
    print(f"von Ganzsatz-Rewrites betroffene:    {len(rows)}")
    print("```")
    print()
    print("## 3. Sicherheits- und Migrationsregel")
    print()
    print(
        "Ein Feld ohne direkten Schreiber ist nicht automatisch "
        "schreibgeschützt oder entbehrlich. `mbsetup/m_users.c` liest "
        "und ersetzt vollständige `struct userrec`-Datensätze."
    )
    print()
    print(
        "Dadurch können alle 72 Felder mit einem älteren Legacy-Stand "
        "zurückgeschrieben werden, auch wenn `mbsetup` das konkrete Feld "
        "weder anzeigt noch direkt bearbeitet."
    )
    print()
    print(
        "Bis zur dokumentierten Einzelentscheidung bleibt für offene "
        "Felder `users.data` führend. Es findet kein automatischer "
        "PostgreSQL→Legacy- oder Legacy→PostgreSQL-Schreibabgleich statt."
    )
    print()
    print("## 4. Hoheitsmatrix")
    print()
    print(
        "| Legacy-Feld | Bedeutung | Führung | PostgreSQL-Ziel | "
        "Status | direkte Writes | RMW | Writer-Komponenten | "
        "mbsetup-Writes | Ganzsatzrisiko |"
    )
    print(
        "|---|---|---|---|---|---:|---:|---|---:|---|"
    )

    for row in rows:
        if row.postgresql_table == "—":
            target = "keine Legacy-Übernahme"
        elif row.postgresql_table == "noch nicht festgelegt":
            target = "noch nicht festgelegt"
        else:
            target = (
                f"`{row.postgresql_table}` / "
                f"`{row.postgresql_target}`"
            )

        components = (
            ", ".join(
                f"`{component_name}`"
                for component_name in row.direct_writer_components
            )
            if row.direct_writer_components
            else "keine direkten Schreiber"
        )

        print(
            "| "
            + " | ".join(
                (
                    f"`{row.field}`",
                    markdown_escape(row.meaning),
                    markdown_escape(row.authority),
                    target,
                    row.decision_status,
                    str(row.direct_write),
                    str(row.direct_read_write),
                    components,
                    str(row.mbsetup_direct_writes),
                    row.whole_record_exposure,
                )
            )
            + " |"
        )

    print()
    print("## 5. Nächste Entscheidungsblöcke")
    print()
    print(
        "Die offenen Felder werden nicht alphabetisch, sondern nach "
        "fachlicher und technischer Kopplung entschieden:"
    )
    print()
    print(
        "1. Identität, Berechtigungen, Sperren und Kontolebenszyklus."
    )
    print("2. Dauerhafte Profil- und Terminalpräferenzen.")
    print("3. Login-, Sitzungs- und Tageszustände.")
    print("4. Upload-, Download- und Nachrichtenstatistiken.")
    print("5. IEMSI-, reservierte und offenbar obsolete Felder.")
    print()
    print(
        "Für jeden Block werden PostgreSQL-Ziel, Datentyp, "
        "Schreibberechtigung, Audit-Ereignis und Legacy-"
        "Kompatibilitätsrichtung separat festgelegt."
    )


def main(
    argv: list[str] | None = None,
) -> int:
    args = parse_args(argv)

    try:
        matrix_rows = read_field_matrix()
        writer_rows = read_writer_details()
        ownership_rows = build_ownership_rows(
            matrix_rows,
            writer_rows,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            f"Ownership baseline: FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.format == "details":
        print_details(ownership_rows)
    elif args.format == "markdown":
        print_markdown(ownership_rows)
    else:
        print_summary(ownership_rows)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
