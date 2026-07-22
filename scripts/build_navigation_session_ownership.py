#!/usr/bin/env python3
"""Build the B5.10 navigation and session ownership documentation."""

from __future__ import annotations

from collections import Counter
import csv
import io
from pathlib import Path
import subprocess
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPOSITORY_ROOT / "docs"
SCRIPTS = REPOSITORY_ROOT / "scripts"

ANALYZER = SCRIPTS / "analyze_navigation_session_access.py"

ACCESS_RAW = DOCS / "NAVIGATION_SESSION_ACCESS_RAW.tsv"
ACCESS_DETAILS = DOCS / "NAVIGATION_SESSION_ACCESS_DETAILS.tsv"
DECISIONS = DOCS / "NAVIGATION_SESSION_OWNERSHIP_DECISIONS.tsv"
BASELINE = DOCS / "MBSETUP_USER_FIELD_OWNERSHIP_DETAILS.tsv"

OUTPUT_RAW = DOCS / "NAVIGATION_SESSION_OWNERSHIP_RAW.tsv"
OUTPUT_DETAILS = DOCS / "NAVIGATION_SESSION_OWNERSHIP_DETAILS.tsv"
OUTPUT_MARKDOWN = DOCS / "NAVIGATION_SESSION_OWNERSHIP.md"

FIELD_ORDER = [
    "sComment",
    "Email",
    "iLastFileArea",
    "iLastFileGroup",
    "iLastMsgArea",
    "iLastMsgGroup",
    "LastPktNum",
    "OLRext",
    "OLRlast",
    "xChat",
    "xFsMsged",
    "xScreenLen",
    "xHangUps",
    "Paged",
    "iTransferTime",
    "iStatus",
    "CrtDef",
    "Protocol",
    "IEMSI",
    "ieMNU",
    "ieTAB",
]

EXPECTED_ACCESS_COLUMNS = [
    "FIELD",
    "CATEGORY",
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
    "DECISION_STATUS",
    "AUTHORITY",
    "POSTGRESQL_TABLE",
    "POSTGRESQL_TARGET",
    "MIGRATION_RULE",
    "WRITE_POLICY",
    "CONSISTENCY_RULE",
    "SECURITY_RULE",
]

EXPECTED_BASELINE_COLUMNS = [
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

OUTPUT_COLUMNS = [
    "FIELD",
    "CATEGORY",
    "DIRECT_READ",
    "DIRECT_WRITE",
    "DIRECT_READ_WRITE",
    "DIRECT_METADATA",
    "DIRECT_ACCESS_COUNT",
    "DIRECT_FILE_COUNT",
    "DIRECT_FILES",
    "DIRECT_COMPONENTS",
    "MBSETUP_DIRECT_WRITES",
    "WHOLE_RECORD_EXPOSURE",
    "LEGACY_SEMANTICS",
    "DECISION_STATUS",
    "AUTHORITY",
    "POSTGRESQL_TABLE",
    "POSTGRESQL_TARGET",
    "MIGRATION_RULE",
    "WRITE_POLICY",
    "CONSISTENCY_RULE",
    "SECURITY_RULE",
]

EXPECTED_STATUS_COUNTS = {
    "persistent": 6,
    "session-only": 1,
    "retired": 14,
}

EXPECTED_CATEGORY_COUNTS = {
    "comment-mailbox": 2,
    "navigation-state": 4,
    "offline-reader-state": 3,
    "session-runtime": 7,
    "iemsi-compatibility": 5,
}

EXPECTED_DIRECT_ACCESS_COUNT = 51
EXPECTED_DIRECT_FIELD_COUNT = 7


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

    for line_number, row in enumerate(rows, start=2):
        if None in row:
            raise ValueError(
                f"extra columns in {path.name}:{line_number}"
            )

        if any(value is None for value in row.values()):
            raise ValueError(
                f"missing value in {path.name}:{line_number}"
            )

        if any(
            "\n" in value or "\r" in value
            for value in row.values()
        ):
            raise ValueError(
                f"embedded newline in {path.name}:{line_number}"
            )

    return rows


def run_analyzer(
    details: bool,
) -> str:
    command = [
        sys.executable,
        str(ANALYZER),
    ]

    if details:
        command.extend(("--format", "details"))

    completed = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    if completed.returncode != 0:
        raise ValueError(
            "navigation/session analyzer failed: "
            + completed.stderr.strip()
        )

    if completed.stderr:
        raise ValueError(
            "navigation/session analyzer emitted stderr: "
            + completed.stderr.strip()
        )

    return completed.stdout


def verify_frozen_access_outputs() -> None:
    expected_raw = run_analyzer(details=False)
    expected_details = run_analyzer(details=True)

    actual_raw = ACCESS_RAW.read_text(encoding="utf-8")
    actual_details = ACCESS_DETAILS.read_text(encoding="utf-8")

    if actual_raw != expected_raw:
        raise ValueError(
            f"{ACCESS_RAW.name} differs from current analyzer output"
        )

    if actual_details != expected_details:
        raise ValueError(
            f"{ACCESS_DETAILS.name} differs from current analyzer output"
        )


def index_unique(
    rows: list[dict[str, str]],
    source: Path,
) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}

    for row in rows:
        field = row["FIELD"]

        if field in indexed:
            raise ValueError(
                f"duplicate field {field!r} in {source.name}"
            )

        indexed[field] = row

    return indexed


def component_from_path(
    path: str,
) -> str:
    return path.split("/", 1)[0]


def build_rows() -> list[dict[str, str]]:
    verify_frozen_access_outputs()

    access_rows = read_tsv(
        ACCESS_DETAILS,
        EXPECTED_ACCESS_COLUMNS,
    )
    decision_rows = read_tsv(
        DECISIONS,
        EXPECTED_DECISION_COLUMNS,
    )
    baseline_rows = read_tsv(
        BASELINE,
        EXPECTED_BASELINE_COLUMNS,
    )

    decisions = index_unique(
        decision_rows,
        DECISIONS,
    )
    baseline = index_unique(
        baseline_rows,
        BASELINE,
    )

    if list(decisions) != FIELD_ORDER:
        raise ValueError(
            "decision field order differs from reviewed B5.10 order"
        )

    if set(decisions) != set(FIELD_ORDER):
        raise ValueError(
            "decision field set differs from reviewed B5.10 set"
        )

    if not set(FIELD_ORDER).issubset(baseline):
        missing = sorted(
            set(FIELD_ORDER) - set(baseline)
        )
        raise ValueError(
            f"fields missing from B5.6 baseline: {missing!r}"
        )

    status_counts = Counter(
        row["DECISION_STATUS"]
        for row in decision_rows
    )

    if dict(status_counts) != EXPECTED_STATUS_COUNTS:
        raise ValueError(
            "unexpected decision distribution: "
            f"{dict(status_counts)!r}"
        )

    category_counts = Counter(
        row["CATEGORY"]
        for row in decision_rows
    )

    if dict(category_counts) != EXPECTED_CATEGORY_COUNTS:
        raise ValueError(
            "unexpected category distribution: "
            f"{dict(category_counts)!r}"
        )

    if len(access_rows) != EXPECTED_DIRECT_ACCESS_COUNT:
        raise ValueError(
            "expected 51 direct accesses, found "
            f"{len(access_rows)}"
        )

    directly_accessed_fields = {
        row["FIELD"]
        for row in access_rows
    }

    if len(directly_accessed_fields) != EXPECTED_DIRECT_FIELD_COUNT:
        raise ValueError(
            "expected 7 directly accessed fields, found "
            f"{len(directly_accessed_fields)}"
        )

    unknown_access_fields = (
        directly_accessed_fields - set(FIELD_ORDER)
    )

    if unknown_access_fields:
        raise ValueError(
            "access evidence contains fields outside B5.10: "
            f"{sorted(unknown_access_fields)!r}"
        )

    result: list[dict[str, str]] = []

    for field in FIELD_ORDER:
        decision = decisions[field]
        baseline_row = baseline[field]
        field_accesses = [
            row
            for row in access_rows
            if row["FIELD"] == field
        ]
        access_counts = Counter(
            row["KIND"]
            for row in field_accesses
        )
        files = sorted({
            row["PATH"]
            for row in field_accesses
        })
        components = sorted({
            component_from_path(path)
            for path in files
        })

        direct_access_count = sum(
            access_counts[kind]
            for kind in (
                "read",
                "write",
                "read-write",
                "metadata",
            )
        )

        if direct_access_count != len(field_accesses):
            raise ValueError(
                f"unknown access kind for {field}"
            )

        status = decision["DECISION_STATUS"]

        if status == "persistent":
            if decision["AUTHORITY"] != "PostgreSQL":
                raise ValueError(
                    f"{field} is persistent but not PostgreSQL-led"
                )

            if (
                decision["POSTGRESQL_TABLE"] == "—"
                or decision["POSTGRESQL_TARGET"] == "—"
            ):
                raise ValueError(
                    f"{field} has no PostgreSQL target"
                )

        elif status == "session-only":
            if decision["AUTHORITY"] != "runtime session":
                raise ValueError(
                    f"{field} is session-only without runtime authority"
                )

            if decision["POSTGRESQL_TABLE"] != "bbs_sessions":
                raise ValueError(
                    f"{field} has unexpected session table"
                )

        elif status == "retired":
            if decision["AUTHORITY"] != "none":
                raise ValueError(
                    f"{field} is retired but still has authority"
                )

            if (
                decision["POSTGRESQL_TABLE"] != "—"
                or decision["POSTGRESQL_TARGET"] != "—"
            ):
                raise ValueError(
                    f"{field} is retired but still has a target"
                )

        else:
            raise ValueError(
                f"unknown decision status for {field}: {status}"
            )

        result.append(
            {
                "FIELD": field,
                "CATEGORY": decision["CATEGORY"],
                "DIRECT_READ": str(access_counts["read"]),
                "DIRECT_WRITE": str(access_counts["write"]),
                "DIRECT_READ_WRITE": str(
                    access_counts["read-write"]
                ),
                "DIRECT_METADATA": str(
                    access_counts["metadata"]
                ),
                "DIRECT_ACCESS_COUNT": str(
                    direct_access_count
                ),
                "DIRECT_FILE_COUNT": str(len(files)),
                "DIRECT_FILES": ",".join(files),
                "DIRECT_COMPONENTS": ",".join(components),
                "MBSETUP_DIRECT_WRITES": baseline_row[
                    "MBSETUP_DIRECT_WRITES"
                ],
                "WHOLE_RECORD_EXPOSURE": baseline_row[
                    "WHOLE_RECORD_EXPOSURE"
                ],
                "LEGACY_SEMANTICS": decision[
                    "LEGACY_SEMANTICS"
                ],
                "DECISION_STATUS": status,
                "AUTHORITY": decision["AUTHORITY"],
                "POSTGRESQL_TABLE": decision[
                    "POSTGRESQL_TABLE"
                ],
                "POSTGRESQL_TARGET": decision[
                    "POSTGRESQL_TARGET"
                ],
                "MIGRATION_RULE": decision[
                    "MIGRATION_RULE"
                ],
                "WRITE_POLICY": decision["WRITE_POLICY"],
                "CONSISTENCY_RULE": decision[
                    "CONSISTENCY_RULE"
                ],
                "SECURITY_RULE": decision["SECURITY_RULE"],
            }
        )

    return result


def render_details(
    rows: list[dict[str, str]],
) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=OUTPUT_COLUMNS,
        delimiter="\t",
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def render_raw(
    rows: list[dict[str, str]],
) -> str:
    statuses = Counter(
        row["DECISION_STATUS"]
        for row in rows
    )
    direct_fields = sum(
        int(row["DIRECT_ACCESS_COUNT"]) > 0
        for row in rows
    )
    direct_accesses = sum(
        int(row["DIRECT_ACCESS_COUNT"])
        for row in rows
    )

    lines = [
        "B5.10 navigation and session ownership",
        "=======================================",
        f"Fields documented:                  {len(rows)}",
        (
            "Persistent PostgreSQL decisions:    "
            f"{statuses['persistent']}"
        ),
        (
            "Session-only values:                "
            f"{statuses['session-only']}"
        ),
        (
            "Retired legacy fields:              "
            f"{statuses['retired']}"
        ),
        "Open B5.10 decisions:               0",
        (
            "Fields with direct access:          "
            f"{direct_fields}"
        ),
        (
            "Fields without direct access:       "
            f"{len(rows) - direct_fields}"
        ),
        (
            "Direct access occurrences:          "
            f"{direct_accesses}"
        ),
        "",
        (
            "FIELD\tCATEGORY\tREAD\tWRITE\tREAD_WRITE\t"
            "METADATA\tACCESS_COUNT\tFILES\tCOMPONENTS\t"
            "STATUS\tAUTHORITY\tTARGET"
        ),
    ]

    for row in rows:
        target = row["POSTGRESQL_TARGET"]

        if target != "—":
            target = (
                f"{row['POSTGRESQL_TABLE']}."
                f"{target}"
            )

        lines.append(
            "\t".join(
                (
                    row["FIELD"],
                    row["CATEGORY"],
                    row["DIRECT_READ"],
                    row["DIRECT_WRITE"],
                    row["DIRECT_READ_WRITE"],
                    row["DIRECT_METADATA"],
                    row["DIRECT_ACCESS_COUNT"],
                    row["DIRECT_FILE_COUNT"],
                    row["DIRECT_COMPONENTS"],
                    row["DECISION_STATUS"],
                    row["AUTHORITY"],
                    target,
                )
            )
        )

    return "\n".join(lines) + "\n"


def markdown_escape(
    value: str,
) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def render_markdown(
    rows: list[dict[str, str]],
) -> str:
    statuses = Counter(
        row["DECISION_STATUS"]
        for row in rows
    )
    categories = Counter(
        row["CATEGORY"]
        for row in rows
    )
    direct_fields = [
        row["FIELD"]
        for row in rows
        if int(row["DIRECT_ACCESS_COUNT"]) > 0
    ]
    no_direct_fields = [
        row["FIELD"]
        for row in rows
        if int(row["DIRECT_ACCESS_COUNT"]) == 0
    ]
    direct_accesses = sum(
        int(row["DIRECT_ACCESS_COUNT"])
        for row in rows
    )

    lines = [
        "# B5.10 – Navigation, Sitzungs- und "
        "Kompatibilitätszustände",
        "",
        "## Status",
        "",
        "**Abgeschlossen.** Sämtliche nach B5.7, B5.8 und "
        "B5.9 noch offenen Felder aus `struct userrec` besitzen "
        "eine ausdrückliche Ownership- und Migrationsentscheidung.",
        "",
        "Offene B5.10-Entscheidungen: **0**.",
        "",
        "## Umfang und Ergebnis",
        "",
        "| Merkmal | Anzahl |",
        "|---|---:|",
        f"| Untersuchte Restfelder | {len(rows)} |",
        (
            "| Persistente PostgreSQL-Entscheidungen | "
            f"{statuses['persistent']} |"
        ),
        (
            "| Reine Sitzungswerte | "
            f"{statuses['session-only']} |"
        ),
        (
            "| Stillgelegte Legacy-Felder | "
            f"{statuses['retired']} |"
        ),
        (
            "| Felder mit direkten Zugriffen | "
            f"{len(direct_fields)} |"
        ),
        (
            "| Felder ohne direkten Zugriff | "
            f"{len(no_direct_fields)} |"
        ),
        (
            "| Direkte Zugriffsfundstellen | "
            f"{direct_accesses} |"
        ),
        "",
        "Die Feldgruppen verteilen sich wie folgt:",
        "",
        "| Kategorie | Felder |",
        "|---|---:|",
    ]

    for category in (
        "comment-mailbox",
        "navigation-state",
        "offline-reader-state",
        "session-runtime",
        "iemsi-compatibility",
    ):
        lines.append(
            f"| `{category}` | {categories[category]} |"
        )

    lines.extend(
        [
            "",
            "## Verbindliche Architekturentscheidungen",
            "",
            "### Administrative Kommentare",
            "",
            "`sComment` wird als privater administrativer Vermerk "
            "nach PostgreSQL übernommen. Bekannte technische "
            "Registrierungsmarker werden nicht als menschliche "
            "Kommentare importiert. Der neue Vermerk darf weder an "
            "Doors noch an Dropfiles, Benutzerlisten oder "
            "unprivilegierte Schnittstellen ausgegeben werden.",
            "",
            "### Interne Mailbox",
            "",
            "`Email` ist im Legacy-Datensatz **keine "
            "E-Mail-Adresse**, sondern ein Boolescher Schalter für "
            "die private interne MBSE-Mailbox. Daraus dürfen weder "
            "Kontaktinformationen noch Login-, Rollen- oder "
            "SSH-Entscheidungen abgeleitet werden.",
            "",
            "### Navigation",
            "",
            "`iLastFileArea` und `iLastMsgArea` werden als "
            "Wiedereinstiegspunkte gespeichert. Gespeicherte "
            "Bereichsnummern gewähren niemals Zugriff: Der Bereich "
            "muss bei jeder Verwendung erneut existieren und für "
            "den Benutzer freigegeben sein.",
            "",
            "`iLastFileGroup` und `iLastMsgGroup` werden nicht "
            "migriert. Gruppen werden bei Bedarf aus dem gültigen "
            "Bereich abgeleitet.",
            "",
            "### Offline-Reader",
            "",
            "`OLRext` und `OLRlast` bleiben als PostgreSQL-geführter "
            "Offline-Reader-Zustand erhalten. Zähler und Datum werden "
            "nach erfolgreicher Paketerzeugung in derselben "
            "Transaktion aktualisiert.",
            "",
            "`LastPktNum` wird stillgelegt. Zukünftige "
            "Paketkennungen müssen unabhängig und kollisionssicher "
            "erzeugt werden.",
            "",
            "### Sitzungsstatus",
            "",
            "`iStatus` ist ausschließlich Zustand der aktuellen "
            "Online-Sitzung. Er gehört zu einer `session_id`, wird "
            "nicht aus `users.data` migriert und darf keine Rolle "
            "oder Capability darstellen.",
            "",
            "### Stillgelegte Kompatibilitätsfelder",
            "",
            "Vierzehn Felder werden nicht nach PostgreSQL migriert. "
            "Sie bleiben im Legacy-Kompatibilitätsdatensatz null und "
            "dürfen ohne eine neue Quellanalyse und "
            "Architekturentscheidung nicht wieder aktiviert werden.",
            "",
            "Stillgelegt sind:",
            "",
            (
                ", ".join(
                    f"`{row['FIELD']}`"
                    for row in rows
                    if row["DECISION_STATUS"] == "retired"
                )
                + "."
            ),
            "",
            "## Zugriffsbefund",
            "",
            "Direkt verwendet werden nur:",
            "",
            ", ".join(
                f"`{field}`"
                for field in direct_fields
            )
            + ".",
            "",
            "Ohne direkten Zugriff im aktuellen Quellbaum sind:",
            "",
            ", ".join(
                f"`{field}`"
                for field in no_direct_fields
            )
            + ".",
            "",
            "Ein fehlender Direktzugriff bedeutet nicht automatisch, "
            "dass das Feld aus dem Binärformat entfernt werden darf. "
            "Solange `users.data` als Legacy-Kompatibilität existiert, "
            "bleiben Strukturgröße und Whole-Record-Verhalten separat "
            "zu berücksichtigen.",
            "",
            "## Entscheidungsübersicht",
            "",
            "| Feld | Kategorie | Zugriffe | Entscheidung | "
            "Autorität | Ziel |",
            "|---|---|---:|---|---|---|",
        ]
    )

    for row in rows:
        target = "—"

        if row["POSTGRESQL_TARGET"] != "—":
            target = (
                f"`{row['POSTGRESQL_TABLE']}."
                f"{row['POSTGRESQL_TARGET']}`"
            )

        lines.append(
            "| "
            + " | ".join(
                (
                    f"`{row['FIELD']}`",
                    f"`{row['CATEGORY']}`",
                    row["DIRECT_ACCESS_COUNT"],
                    f"`{row['DECISION_STATUS']}`",
                    markdown_escape(row["AUTHORITY"]),
                    target,
                )
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Einzelentscheidungen",
            "",
        ]
    )

    for row in rows:
        lines.extend(
            [
                f"### `{row['FIELD']}`",
                "",
                f"- **Kategorie:** `{row['CATEGORY']}`",
                (
                    "- **Direkte Zugriffe:** "
                    f"{row['DIRECT_ACCESS_COUNT']} "
                    f"(Lesen {row['DIRECT_READ']}, "
                    f"Schreiben {row['DIRECT_WRITE']}, "
                    f"Read-Write {row['DIRECT_READ_WRITE']}, "
                    f"Metadaten {row['DIRECT_METADATA']})"
                ),
                (
                    "- **Betroffene Komponenten:** "
                    + (
                        f"`{row['DIRECT_COMPONENTS']}`"
                        if row["DIRECT_COMPONENTS"]
                        else "keine direkten Zugriffe"
                    )
                ),
                (
                    "- **Legacy-Semantik:** "
                    f"{row['LEGACY_SEMANTICS']}"
                ),
                (
                    "- **Entscheidung:** "
                    f"`{row['DECISION_STATUS']}`"
                ),
                (
                    "- **Autorität:** "
                    f"{row['AUTHORITY']}"
                ),
            ]
        )

        if row["POSTGRESQL_TARGET"] != "—":
            lines.append(
                "- **PostgreSQL-Ziel:** "
                f"`{row['POSTGRESQL_TABLE']}."
                f"{row['POSTGRESQL_TARGET']}`"
            )
        else:
            lines.append(
                "- **PostgreSQL-Ziel:** keines"
            )

        lines.extend(
            [
                (
                    "- **Migration:** "
                    f"{row['MIGRATION_RULE']}"
                ),
                (
                    "- **Schreibregel:** "
                    f"{row['WRITE_POLICY']}"
                ),
                (
                    "- **Konsistenzregel:** "
                    f"{row['CONSISTENCY_RULE']}"
                ),
                (
                    "- **Sicherheitsregel:** "
                    f"{row['SECURITY_RULE']}"
                ),
                "",
            ]
        )

    lines.extend(
        [
            "## Reproduzierbarkeit",
            "",
            "Die Dokumentation wird ausschließlich aus folgenden "
            "versionierten Quellen erzeugt:",
            "",
            "- `docs/NAVIGATION_SESSION_ACCESS_RAW.tsv`",
            "- `docs/NAVIGATION_SESSION_ACCESS_DETAILS.tsv`",
            "- `docs/NAVIGATION_SESSION_OWNERSHIP_DECISIONS.tsv`",
            "- `docs/MBSETUP_USER_FIELD_OWNERSHIP_DETAILS.tsv`",
            "- `scripts/analyze_navigation_session_access.py`",
            "- `scripts/build_navigation_session_ownership.py`",
            "",
            "Der Builder akzeptiert nur den geprüften Restbestand von "
            "21 Feldern, exakt 51 direkte Fundstellen sowie die "
            "Entscheidungsverteilung 6 persistent, 1 session-only "
            "und 14 retired.",
            "",
        ]
    )

    return "\n".join(lines)


def write_exact(
    path: Path,
    content: str,
) -> None:
    if not content.endswith("\n"):
        content += "\n"

    path.write_text(
        content,
        encoding="utf-8",
        newline="\n",
    )


def main() -> int:
    try:
        rows = build_rows()
        raw = render_raw(rows)
        details = render_details(rows)
        markdown = render_markdown(rows)

        write_exact(OUTPUT_RAW, raw)
        write_exact(OUTPUT_DETAILS, details)
        write_exact(OUTPUT_MARKDOWN, markdown)
    except (
        OSError,
        UnicodeError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        print(
            f"B5.10 ownership build: FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    statuses = Counter(
        row["DECISION_STATUS"]
        for row in rows
    )
    direct_accesses = sum(
        int(row["DIRECT_ACCESS_COUNT"])
        for row in rows
    )

    print("B5.10 navigation and session ownership")
    print("=======================================")
    print(f"Fields documented:                  {len(rows)}")
    print(
        "Persistent PostgreSQL decisions:    "
        f"{statuses['persistent']}"
    )
    print(
        "Session-only values:                "
        f"{statuses['session-only']}"
    )
    print(
        "Retired legacy fields:              "
        f"{statuses['retired']}"
    )
    print("Open B5.10 decisions:               0")
    print(
        "Direct access occurrences:          "
        f"{direct_accesses}"
    )
    print()
    print(f"Generated: {OUTPUT_RAW.relative_to(REPOSITORY_ROOT)}")
    print(
        "Generated: "
        f"{OUTPUT_DETAILS.relative_to(REPOSITORY_ROOT)}"
    )
    print(
        "Generated: "
        f"{OUTPUT_MARKDOWN.relative_to(REPOSITORY_ROOT)}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
