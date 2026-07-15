#!/usr/bin/env python3
"""Static contract checks for the B4.3.2 registration migration."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "0009_telnet_registration.sql"
VALIDATION = ROOT / "src" / "authd_database_validation.c"


def require(text: str, fragment: str) -> None:
    if fragment not in text:
        raise AssertionError(f"missing migration contract fragment: {fragment}")


def main() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    validation = VALIDATION.read_text(encoding="utf-8")
    statements = [line.strip() for line in sql.splitlines() if line.strip()]

    assert statements[0] == "BEGIN;"
    assert statements[-1] == "COMMIT;"

    digest = hashlib.sha256(MIGRATION.read_bytes()).hexdigest()
    checksum_match = re.search(
        r'"0009_telnet_registration\.sql",\s*"([0-9a-f]{64})"',
        validation,
        re.MULTILINE,
    )
    assert checksum_match is not None
    assert checksum_match.group(1) == digest

    for fragment in (
        "CREATE TABLE public.bbs_registration_attempts",
        "registration_id    UUID PRIMARY KEY DEFAULT gen_random_uuid()",
        "registration_state = 'pending_legacy'",
        "registration_state = 'completed'",
        "registration_state IN ('aborted', 'failed')",
        "CHECK (protocol = 'telnet')",
        "DROP INDEX public.bbs_users_login_name_ci_uq",
        "CREATE UNIQUE INDEX bbs_users_login_name_active_uq",
        "WHERE deleted_at IS NULL",
        "ADD CONSTRAINT bbs_users_deleted_state_ck",
        "GRANT SELECT, INSERT, UPDATE",
        "ON TABLE public.bbs_registration_attempts",
        "GRANT SELECT, INSERT, UPDATE, DELETE",
        "ON TABLE public.bbs_legacy_mbse_bindings",
        "public.bbs_password_credentials",
    ):
        require(sql, fragment)

    for forbidden in (
        "GRANT ALL",
        "ON ALL TABLES",
        "ON ALL SEQUENCES",
        "DELETE\nON TABLE public.bbs_registration_attempts",
    ):
        assert forbidden not in sql

    print("migration 0009 contract tests: OK")


if __name__ == "__main__":
    main()
