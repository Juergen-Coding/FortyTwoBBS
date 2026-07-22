#!/usr/bin/env python3
"""Fail-closed validation for B5.10 navigation/session ownership."""

from __future__ import annotations

from collections import Counter
import csv
import importlib.util
from pathlib import Path
import subprocess
import sys
from types import ModuleType

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPOSITORY_ROOT / "docs"
SCRIPTS = REPOSITORY_ROOT / "scripts"

ANALYZER = SCRIPTS / "analyze_navigation_session_access.py"
BUILDER = SCRIPTS / "build_navigation_session_ownership.py"

ACCESS_RAW = DOCS / "NAVIGATION_SESSION_ACCESS_RAW.tsv"
ACCESS_DETAILS = DOCS / "NAVIGATION_SESSION_ACCESS_DETAILS.tsv"
DECISIONS = DOCS / "NAVIGATION_SESSION_OWNERSHIP_DECISIONS.tsv"

OWNERSHIP_RAW = DOCS / "NAVIGATION_SESSION_OWNERSHIP_RAW.tsv"
OWNERSHIP_DETAILS = DOCS / "NAVIGATION_SESSION_OWNERSHIP_DETAILS.tsv"
OWNERSHIP_MARKDOWN = DOCS / "NAVIGATION_SESSION_OWNERSHIP.md"

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

PERSISTENT_FIELDS = {
    "sComment",
    "Email",
    "iLastFileArea",
    "iLastMsgArea",
    "OLRext",
    "OLRlast",
}

SESSION_ONLY_FIELDS = {
    "iStatus",
}

RETIRED_FIELDS = {
    "iLastFileGroup",
    "iLastMsgGroup",
    "LastPktNum",
    "xChat",
    "xFsMsged",
    "xScreenLen",
    "xHangUps",
    "Paged",
    "iTransferTime",
    "CrtDef",
    "Protocol",
    "IEMSI",
    "ieMNU",
    "ieTAB",
}

DIRECT_ACCESS_FIELDS = {
    "sComment",
    "Email",
    "iLastFileArea",
    "iLastMsgArea",
    "OLRext",
    "OLRlast",
    "iStatus",
}

EXPECTED_ACCESS_COUNTS = {
    "sComment": {
        "read": 9,
        "write": 3,
        "read-write": 0,
        "metadata": 3,
    },
    "Email": {
        "read": 11,
        "write": 3,
        "read-write": 0,
        "metadata": 0,
    },
    "iLastFileArea": {
        "read": 2,
        "write": 3,
        "read-write": 0,
        "metadata": 0,
    },
    "iLastMsgArea": {
        "read": 3,
        "write": 3,
        "read-write": 0,
        "metadata": 0,
    },
    "OLRext": {
        "read": 3,
        "write": 3,
        "read-write": 1,
        "metadata": 0,
    },
    "OLRlast": {
        "read": 1,
        "write": 2,
        "read-write": 0,
        "metadata": 0,
    },
    "iStatus": {
        "read": 0,
        "write": 1,
        "read-write": 0,
        "metadata": 0,
    },
}

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

EXPECTED_OWNERSHIP_COLUMNS = [
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
            "analyzer failed: "
            + completed.stderr.strip()
        )

    if completed.stderr:
        raise ValueError(
            "analyzer emitted stderr: "
            + completed.stderr.strip()
        )

    return completed.stdout


def load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "b5_10_navigation_session_builder",
        BUILDER,
    )

    if spec is None or spec.loader is None:
        raise ValueError("cannot load B5.10 builder")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def normalized(
    value: str,
) -> str:
    return " ".join(value.lower().split())


def contains_all(
    value: str,
    fragments: tuple[str, ...],
) -> bool:
    text = normalized(value)
    return all(
        normalized(fragment) in text
        for fragment in fragments
    )


def exact_text(
    path: Path,
    expected: str,
    failures: list[str],
) -> None:
    if not expected.endswith("\n"):
        expected += "\n"

    actual = path.read_text(encoding="utf-8")

    if actual != expected:
        failures.append(
            f"{path.name} differs from generated output"
        )


def indexed_rows(
    rows: list[dict[str, str]],
    source: Path,
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}

    for row in rows:
        field = row["FIELD"]

        if field in result:
            raise ValueError(
                f"duplicate field {field!r} in {source.name}"
            )

        result[field] = row

    return result


def main() -> int:
    failures: list[str] = []

    try:
        decision_rows = read_tsv(
            DECISIONS,
            EXPECTED_DECISION_COLUMNS,
        )
        access_rows = read_tsv(
            ACCESS_DETAILS,
            EXPECTED_ACCESS_COLUMNS,
        )
        ownership_rows = read_tsv(
            OWNERSHIP_DETAILS,
            EXPECTED_OWNERSHIP_COLUMNS,
        )

        decisions = indexed_rows(
            decision_rows,
            DECISIONS,
        )
        ownership = indexed_rows(
            ownership_rows,
            OWNERSHIP_DETAILS,
        )

        expected_access_raw = run_analyzer(details=False)
        expected_access_details = run_analyzer(details=True)

        exact_text(
            ACCESS_RAW,
            expected_access_raw,
            failures,
        )
        exact_text(
            ACCESS_DETAILS,
            expected_access_details,
            failures,
        )

        builder = load_builder()
        generated_rows = builder.build_rows()

        exact_text(
            OWNERSHIP_RAW,
            builder.render_raw(generated_rows),
            failures,
        )
        exact_text(
            OWNERSHIP_DETAILS,
            builder.render_details(generated_rows),
            failures,
        )
        exact_text(
            OWNERSHIP_MARKDOWN,
            builder.render_markdown(generated_rows),
            failures,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        subprocess.SubprocessError,
    ) as exc:
        print(
            f"B5.10 ownership check: FAILED: {exc}",
            file=sys.stderr,
        )
        return 1

    if [row["FIELD"] for row in decision_rows] != FIELD_ORDER:
        failures.append(
            "decision field order differs from reviewed B5.10 order"
        )

    if set(decisions) != set(FIELD_ORDER):
        failures.append(
            "decision field set differs from reviewed B5.10 set"
        )

    if len(decisions) != 21:
        failures.append(
            f"expected 21 decisions, found {len(decisions)}"
        )

    statuses = Counter(
        row["DECISION_STATUS"]
        for row in decision_rows
    )

    expected_statuses = {
        "persistent": 6,
        "session-only": 1,
        "retired": 14,
    }

    if dict(statuses) != expected_statuses:
        failures.append(
            "unexpected decision distribution: "
            f"{dict(statuses)!r}"
        )

    actual_persistent = {
        row["FIELD"]
        for row in decision_rows
        if row["DECISION_STATUS"] == "persistent"
    }
    actual_session_only = {
        row["FIELD"]
        for row in decision_rows
        if row["DECISION_STATUS"] == "session-only"
    }
    actual_retired = {
        row["FIELD"]
        for row in decision_rows
        if row["DECISION_STATUS"] == "retired"
    }

    if actual_persistent != PERSISTENT_FIELDS:
        failures.append(
            "persistent field set differs from reviewed decision"
        )

    if actual_session_only != SESSION_ONLY_FIELDS:
        failures.append(
            "session-only field set differs from reviewed decision"
        )

    if actual_retired != RETIRED_FIELDS:
        failures.append(
            "retired field set differs from reviewed decision"
        )

    if len(access_rows) != 51:
        failures.append(
            f"expected 51 direct accesses, found {len(access_rows)}"
        )

    direct_fields = {
        row["FIELD"]
        for row in access_rows
    }

    if direct_fields != DIRECT_ACCESS_FIELDS:
        failures.append(
            "directly accessed field set differs from reviewed evidence"
        )

    access_by_field: dict[str, Counter[str]] = {
        field: Counter()
        for field in FIELD_ORDER
    }

    for row in access_rows:
        field = row["FIELD"]

        if field not in access_by_field:
            failures.append(
                f"access evidence contains unknown field {field}"
            )
            continue

        access_by_field[field][row["KIND"]] += 1

    for field, expected_counts in EXPECTED_ACCESS_COUNTS.items():
        actual_counts = access_by_field[field]

        for kind, expected in expected_counts.items():
            if actual_counts[kind] != expected:
                failures.append(
                    f"{field} {kind} count changed: "
                    f"expected {expected}, found "
                    f"{actual_counts[kind]}"
                )

    for field in RETIRED_FIELDS:
        if sum(access_by_field[field].values()) != 0:
            failures.append(
                f"retired field {field} has direct accesses"
            )

    for field in PERSISTENT_FIELDS:
        row = decisions[field]

        if row["AUTHORITY"] != "PostgreSQL":
            failures.append(
                f"{field} is persistent but not PostgreSQL-led"
            )

        if (
            row["POSTGRESQL_TABLE"] == "—"
            or row["POSTGRESQL_TARGET"] == "—"
        ):
            failures.append(
                f"{field} lacks a PostgreSQL target"
            )

    for field in RETIRED_FIELDS:
        row = decisions[field]

        if row["AUTHORITY"] != "none":
            failures.append(
                f"retired field {field} still has authority"
            )

        if (
            row["POSTGRESQL_TABLE"] != "—"
            or row["POSTGRESQL_TARGET"] != "—"
        ):
            failures.append(
                f"retired field {field} still has a storage target"
            )

        if "nicht importieren" not in normalized(
            row["MIGRATION_RULE"]
        ):
            failures.append(
                f"retired field {field} lacks no-import rule"
            )

    comment = decisions["sComment"]

    if (
        comment["POSTGRESQL_TABLE"]
        != "bbs_user_admin_notes (planned)"
        or comment["POSTGRESQL_TARGET"] != "note_text"
    ):
        failures.append(
            "sComment has the wrong PostgreSQL target"
        )

    if not contains_all(
        comment["MIGRATION_RULE"],
        (
            "registrierungsmarker",
            "menschliche kommentare",
        ),
    ):
        failures.append(
            "sComment marker filtering is incomplete"
        )

    if not contains_all(
        comment["WRITE_POLICY"],
        (
            "privilegierte",
            "audit",
        ),
    ):
        failures.append(
            "sComment lacks privileged audited writes"
        )

    if not contains_all(
        comment["SECURITY_RULE"],
        (
            "doors",
            "dropfiles",
            "unprivilegierte",
        ),
    ):
        failures.append(
            "sComment is not isolated from legacy disclosure paths"
        )

    if not contains_all(
        comment["CONSISTENCY_RULE"],
        (
            "identität",
            "autorisierung",
            "registrierungszustand",
        ),
    ):
        failures.append(
            "sComment is not isolated from identity state"
        )

    mailbox = decisions["Email"]

    if not contains_all(
        mailbox["LEGACY_SEMANTICS"],
        (
            "boolescher schalter",
            "keine e-mail-adresse",
        ),
    ):
        failures.append(
            "Email is not documented as an internal mailbox flag"
        )

    if (
        mailbox["POSTGRESQL_TABLE"]
        != "bbs_user_mailbox_settings (planned)"
        or mailbox["POSTGRESQL_TARGET"]
        != "private_mailbox_enabled"
    ):
        failures.append(
            "Email has the wrong PostgreSQL target"
        )

    if not contains_all(
        mailbox["MIGRATION_RULE"],
        (
            "booleschen mailboxzustand",
            "internetadresse",
        ),
    ):
        failures.append(
            "Email migration could be confused with contact data"
        )

    if not contains_all(
        mailbox["SECURITY_RULE"],
        (
            "login",
            "rollen",
            "ssh-zugriff",
            "postgreSQL-identität",
        ),
    ):
        failures.append(
            "Email is not isolated from account authorization"
        )

    for field, target in (
        ("iLastFileArea", "last_file_area_id"),
        ("iLastMsgArea", "last_message_area_id"),
    ):
        row = decisions[field]

        if (
            row["POSTGRESQL_TABLE"]
            != "bbs_user_navigation_state (planned)"
            or row["POSTGRESQL_TARGET"] != target
        ):
            failures.append(
                f"{field} has the wrong navigation target"
            )

        combined = " ".join(
            (
                row["MIGRATION_RULE"],
                row["WRITE_POLICY"],
                row["CONSISTENCY_RULE"],
                row["SECURITY_RULE"],
            )
        )

        if not contains_all(
            combined,
            (
                "zugänglich",
                "berechtigung erneut prüfen",
                "gewährt niemals zugriff",
            ),
        ):
            failures.append(
                f"{field} lacks access revalidation"
            )

    for field in (
        "iLastFileGroup",
        "iLastMsgGroup",
    ):
        row = decisions[field]

        if "aus dem gültigen" not in normalized(
            row["MIGRATION_RULE"]
        ):
            failures.append(
                f"{field} lacks derivation from a valid area"
            )

        if "keine zugriffsgruppe" not in normalized(
            row["SECURITY_RULE"]
        ):
            failures.append(
                f"{field} could be confused with authorization groups"
            )

    packet_number = decisions["LastPktNum"]

    if not contains_all(
        packet_number["CONSISTENCY_RULE"],
        (
            "unabhängig",
            "kollisionssicher",
        ),
    ):
        failures.append(
            "LastPktNum lacks collision-safe replacement semantics"
        )

    for field, target in (
        ("OLRext", "packet_extension_counter"),
        ("OLRlast", "last_download_on"),
    ):
        row = decisions[field]

        if (
            row["POSTGRESQL_TABLE"]
            != "bbs_user_offline_reader_state (planned)"
            or row["POSTGRESQL_TARGET"] != target
        ):
            failures.append(
                f"{field} has the wrong offline-reader target"
            )

        if "derselben transaktion" not in normalized(
            row["CONSISTENCY_RULE"]
        ):
            failures.append(
                f"{field} lacks atomic OLR state updates"
            )

    if not contains_all(
        decisions["OLRext"]["WRITE_POLICY"],
        (
            "erfolgreichen erzeugen",
            "atomar erhöhen",
        ),
    ):
        failures.append(
            "OLRext lacks successful atomic increment semantics"
        )

    if not contains_all(
        decisions["OLRlast"]["WRITE_POLICY"],
        (
            "erfolgreicher",
            "setzen",
        ),
    ):
        failures.append(
            "OLRlast lacks successful-download write semantics"
        )

    session_status = decisions["iStatus"]

    if (
        session_status["DECISION_STATUS"] != "session-only"
        or session_status["AUTHORITY"] != "runtime session"
        or session_status["POSTGRESQL_TABLE"] != "bbs_sessions"
        or session_status["POSTGRESQL_TARGET"]
        != "activity_status_code"
    ):
        failures.append(
            "iStatus is not modeled as session-only state"
        )

    if not contains_all(
        session_status["MIGRATION_RULE"],
        (
            "keinen bestandswert",
            "jede sitzung",
            "neutralen status",
        ),
    ):
        failures.append(
            "iStatus migration does not reset session state"
        )

    if not contains_all(
        session_status["CONSISTENCY_RULE"],
        (
            "session_id",
            "niemals",
            "benutzerkonto",
        ),
    ):
        failures.append(
            "iStatus is not bound to a session identifier"
        )

    if not contains_all(
        session_status["SECURITY_RULE"],
        (
            "keine rolle",
            "capability",
            "autorisierungsentscheidung",
        ),
    ):
        failures.append(
            "iStatus is not isolated from authorization"
        )

    if set(ownership) != set(FIELD_ORDER):
        failures.append(
            "generated ownership details have the wrong field set"
        )

    for field in FIELD_ORDER:
        if field not in ownership:
            continue

        decision = decisions[field]
        generated = ownership[field]

        for column in (
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
        ):
            if generated[column] != decision[column]:
                failures.append(
                    f"{field} generated {column} differs "
                    "from decision source"
                )

    markdown = OWNERSHIP_MARKDOWN.read_text(
        encoding="utf-8"
    )
    markdown_normalized = normalized(markdown)

    required_document_fragments = {
        "all fields decided": (
            "offene b5.10-entscheidungen: **0**"
        ),
        "mailbox distinction": (
            "`email` ist im legacy-datensatz **keine "
            "e-mail-adresse**"
        ),
        "navigation revalidation": (
            "gespeicherte bereichsnummern gewähren "
            "niemals zugriff"
        ),
        "session ownership": (
            "`istatus` ist ausschließlich zustand der "
            "aktuellen online-sitzung"
        ),
        "retired count": (
            "vierzehn felder werden nicht nach postgresql "
            "migriert"
        ),
        "whole-record caveat": (
            "strukturgröße und whole-record-verhalten "
            "separat zu berücksichtigen"
        ),
        "reproducible counts": (
            "21 feldern, exakt 51 direkte fundstellen"
        ),
    }

    for name, fragment in required_document_fragments.items():
        if normalized(fragment) not in markdown_normalized:
            failures.append(
                f"documentation lacks required statement: {name}"
            )

    direct_access_count = sum(
        int(row["DIRECT_ACCESS_COUNT"])
        for row in ownership_rows
    )

    print("B5.10 navigation and session ownership")
    print("=======================================")
    print(
        f"Fields documented:                  "
        f"{len(decision_rows)}"
    )
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
        "Fields with direct access:          "
        f"{len(direct_fields)}"
    )
    print(
        "Fields without direct access:       "
        f"{len(FIELD_ORDER) - len(direct_fields)}"
    )
    print(
        "Direct access occurrences:          "
        f"{direct_access_count}"
    )
    print("Generated file comparison:          exact")
    print()

    if failures:
        print("Navigation/session result: FAILED")

        for failure in failures:
            print(f"  - {failure}")

        return 1

    print("Navigation/session result: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
