#!/usr/bin/env python3
"""Verify the legacy user-record and mbsetup user-editor field baseline.

The mbsetup user editor reads and rewrites a complete ``struct userrec`` even
though only part of that record is displayed or editable. This fail-closed
check records both boundaries so that a new legacy field or a newly exposed
editor field cannot bypass the B5.4 PostgreSQL field matrix.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
USERS_HEADER = REPOSITORY_ROOT / "lib" / "users.h"
USER_EDITOR = REPOSITORY_ROOT / "mbsetup" / "m_users.c"
FIELD_MATRIX = REPOSITORY_ROOT / "docs" / "MBSETUP_USER_FIELD_MATRIX.md"

EXPECTED_RECORD_FIELDS = {
    "Archiver", "Charset", "Cls", "Credit", "CrtDef", "Deleted",
    "DoNotDisturb", "DownloadK", "DownloadKToday", "Downloads",
    "DownloadsToday", "Email", "ExpirySec", "FSemacs", "GraphMode",
    "Guest", "Hidden", "HotKeys", "IEMSI", "LastPktNum", "LockedOut",
    "MailScan", "More", "MsgEditor", "Name", "NeverDelete", "OLRext",
    "OLRlast", "OL_ExtInfo", "Paged", "Password", "Protocol", "Security",
    "UploadK", "UploadKToday", "Uploads", "address", "iConnectTime",
    "iLanguage", "iLastFileArea", "iLastFileGroup", "iLastMsgArea",
    "iLastMsgGroup", "iPosted", "iStatus", "iTimeLeft", "iTimeUsed",
    "iTotalCalls", "iTransferTime", "ieASCII8", "ieFILE", "ieMNU",
    "ieNEWS", "ieTAB", "sComment", "sDataPhone", "sDateOfBirth",
    "sExpiryDate", "sHandle", "sLocation", "sProtocol", "sSex",
    "sUserName", "sVoicePhone", "tFirstLoginDate", "tLastLoginDate",
    "tLastPwdChange", "xChat", "xFsMsged", "xHangUps", "xPassword",
    "xScreenLen",
}

EXPECTED_EDITOR_REFERENCES = {
    "Archiver", "Charset", "Cls", "Credit", "Deleted", "DoNotDisturb",
    "DownloadK", "Downloads", "Email", "ExpirySec", "FSemacs",
    "GraphMode", "Guest", "Hidden", "HotKeys", "LockedOut", "MailScan",
    "More", "MsgEditor", "Name", "NeverDelete", "OLRext", "OL_ExtInfo",
    "Security", "UploadK", "Uploads", "address", "iLanguage", "iPosted",
    "iTimeLeft", "iTimeUsed", "iTotalCalls", "ieFILE", "ieNEWS",
    "sComment", "sDataPhone", "sDateOfBirth", "sExpiryDate", "sHandle",
    "sLocation", "sProtocol", "sSex", "sUserName", "sVoicePhone",
    "tFirstLoginDate", "tLastLoginDate", "tLastPwdChange",
}

EXPECTED_DECIDED_TREATMENTS = {
    "Deleted": (
        "bbs_users",
        "account_state / deleted_at",
        "PostgreSQL",
    ),
    "LockedOut": (
        "bbs_users",
        "account_state / locked_reason",
        "PostgreSQL",
    ),
    "Name": (
        "bbs_legacy_mbse_bindings",
        "legacy_name",
        "PostgreSQL",
    ),
    "Password": (
        "—",
        "—",
        "PostgreSQL-Credential",
    ),
    "Security": (
        "bbs_user_roles / bbs_role_capabilities",
        "Rollen- und Capability-Zuordnung",
        "PostgreSQL",
    ),
    "iLanguage": (
        "bbs_user_profiles",
        "language_code",
        "PostgreSQL",
    ),
    "sHandle": (
        "bbs_user_profiles",
        "handle",
        "PostgreSQL",
    ),
    "sUserName": (
        "bbs_user_profiles",
        "display_name",
        "PostgreSQL",
    ),
    "tLastPwdChange": (
        "bbs_password_credentials",
        "changed_at",
        "PostgreSQL",
    ),
    "xPassword": (
        "—",
        "—",
        "PostgreSQL-Credential",
    ),
}

STRUCT_PATTERN = re.compile(
    r"struct\s+userrec\s*\{(.*?)\n\};",
    re.DOTALL,
)
EDITOR_REFERENCE_PATTERN = re.compile(
    r"\busrconfig\.([A-Za-z_][A-Za-z0-9_]*)"
)


def parse_record_fields(text: str) -> set[str]:
    match = STRUCT_PATTERN.search(text)
    if match is None:
        raise ValueError("struct userrec was not found")

    fields: set[str] = set()

    for raw_line in match.group(1).splitlines():
        declaration = raw_line.split("/*", 1)[0].strip()

        if not declaration or not declaration.endswith(";"):
            continue

        declaration = declaration[:-1].strip()

        bitfield = re.search(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*\d+\s*$",
            declaration,
        )
        if bitfield is not None:
            fields.add(bitfield.group(1))
            continue

        ordinary = re.search(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*"
            r"(?:\[[^\]]+\])?(?:\[[^\]]+\])?\s*$",
            declaration,
        )
        if ordinary is None:
            raise ValueError(
                f"cannot parse userrec declaration: {raw_line.strip()}"
            )

        fields.add(ordinary.group(1))

    return fields


def parse_matrix(
    text: str,
) -> tuple[list[str], dict[str, tuple[str, str, str]]]:
    fields: list[str] = []
    decided_treatments: dict[str, tuple[str, str, str]] = {}

    for line in text.splitlines():
        if not line.startswith("| "):
            continue

        if line.startswith("| Legacy-Feld ") or line.startswith("|---"):
            continue

        parts = [
            part.strip()
            for part in re.split(r"(?<!\\)\|", line)
        ]

        if parts and parts[0] == "":
            parts = parts[1:]

        if parts and parts[-1] == "":
            parts = parts[:-1]

        if len(parts) != 7:
            raise ValueError(
                f"matrix row has {len(parts)} columns instead of 7: {line}"
            )

        field = parts[0]

        if not field:
            raise ValueError(f"empty legacy field in matrix row: {line}")

        fields.append(field)

        table = parts[3]
        target = parts[4]
        authority = parts[5]

        if not (
            table == "noch nicht festgelegt"
            and target == "noch nicht festgelegt"
        ):
            decided_treatments[field] = (
                table,
                target,
                authority,
            )

    return fields, decided_treatments


def report_set_difference(
    failures: list[str],
    label: str,
    expected: set[str],
    actual: set[str],
) -> None:
    for missing in sorted(expected - actual):
        failures.append(f"missing {label}: {missing}")

    for added in sorted(actual - expected):
        failures.append(f"untracked {label}: {added}")


def main() -> int:
    failures: list[str] = []

    try:
        header_text = USERS_HEADER.read_text(encoding="utf-8")
        editor_text = USER_EDITOR.read_text(encoding="utf-8")
        matrix_text = FIELD_MATRIX.read_text(encoding="utf-8")
        record_fields = parse_record_fields(header_text)
        matrix_field_list, decided_treatments = parse_matrix(matrix_text)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Field-matrix baseline: FAILED: {exc}", file=sys.stderr)
        return 1

    editor_references = set(
        EDITOR_REFERENCE_PATTERN.findall(editor_text)
    )
    matrix_fields = set(matrix_field_list)
    decided_fields = set(decided_treatments)

    report_set_difference(
        failures,
        "struct userrec field",
        EXPECTED_RECORD_FIELDS,
        record_fields,
    )
    report_set_difference(
        failures,
        "mbsetup user-editor reference",
        EXPECTED_EDITOR_REFERENCES,
        editor_references,
    )
    report_set_difference(
        failures,
        "documented matrix field",
        record_fields,
        matrix_fields,
    )
    report_set_difference(
        failures,
        "documented field treatment",
        set(EXPECTED_DECIDED_TREATMENTS),
        decided_fields,
    )

    for field, expected in sorted(
        EXPECTED_DECIDED_TREATMENTS.items()
    ):
        actual = decided_treatments.get(field)

        if actual is not None and actual != expected:
            failures.append(
                f"changed documented treatment for {field}: "
                f"expected {expected!r}, found {actual!r}"
            )

    if len(matrix_field_list) != len(matrix_fields):
        failures.append(
            "duplicate legacy fields exist in the documented matrix"
        )

    if len(matrix_field_list) != len(record_fields):
        failures.append(
            "documented matrix row count does not match struct userrec"
        )

    if not editor_references <= record_fields:
        failures.append(
            "internal error: editor references unknown userrec fields"
        )

    required_fragments = {
        "whole-record write":
            "fwrite(&usrconfig, sizeof(usrconfig), 1, fil)",
        "disabled password editor":
            "Password editing is disabled until centralized "
            "authentication is available",
        "disabled password display":
            'show_str(14,17,Max_passlen, (char *)"<disabled>")',
    }

    for label, fragment in required_fragments.items():
        if fragment not in editor_text:
            failures.append(
                f"missing protected source invariant: {label}"
            )

    required_matrix_fragments = {
        "read-only phase":
            "Die Phase ist read-only.",
        "provisional mapping status":
            "noch keine Freigabe",
        "canonical login boundary":
            "`bbs_users.login_name` besitzt keine direkte "
            "1:1-Entsprechung",
        "legacy binding":
            "`bbs_legacy_mbse_bindings.legacy_name`",
        "password migration prohibition":
            "Die Felder `Password` und `xPassword` werden niemals "
            "nach PostgreSQL",
        "no automatic write reconciliation":
            "kein automatischer Schreibabgleich statt",
    }

    for label, fragment in required_matrix_fragments.items():
        if fragment not in matrix_text:
            failures.append(
                f"missing protected matrix invariant: {label}"
            )

    if "Password" in editor_references or "xPassword" in editor_references:
        failures.append(
            "legacy password storage became directly exposed in m_users.c"
        )

    hidden_pass_through = record_fields - editor_references

    print("mbsetup user-field baseline")
    print("===========================")
    print(f"struct userrec fields:             {len(record_fields)}")
    print(
        "direct m_users.c field references: "
        f"{len(editor_references)}"
    )
    print(
        "whole-record pass-through fields:  "
        f"{len(hidden_pass_through)}"
    )
    print(
        "documented matrix fields:          "
        f"{len(matrix_field_list)}"
    )
    print(
        "documented decided treatments:     "
        f"{len(decided_treatments)}"
    )
    print("legacy password editing:           disabled")
    print("record write model:                complete struct rewrite")

    if failures:
        print("\nField-matrix result: FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("\nField-matrix result: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
