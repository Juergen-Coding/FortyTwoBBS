#!/usr/bin/env python3
"""Reject unreviewed direct users.data/users.temp references."""

from __future__ import annotations

import re
import sys
from pathlib import Path

PATTERN = re.compile(r"users\.(?:data|temp)")
SOURCE_DIRS = (
    "lib",
    "mbfido",
    "mbnntp",
    "mbsebbs",
    "mbsetup",
    "mbtask",
    "mbutils",
    "unix",
    "fortytwo-auth/include",
    "fortytwo-auth/src",
    "fortytwo-auth/scripts",
    "script",
)
GATEWAY_PATHS = {
    "fortytwo-auth/include/legacy_userdb.h",
    "fortytwo-auth/src/legacy_userdb.c",
    "fortytwo-auth/src/legacy_userdb_provision.c",
}


def load_allowlist(path: Path) -> dict[str, int]:
    entries: dict[str, int] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ValueError(f"{path}:{line_number}: expected PATH COUNT")
        source_path, count_text = parts
        if source_path in entries:
            raise ValueError(f"{path}:{line_number}: duplicate {source_path}")
        count = int(count_text, 10)
        if count <= 0:
            raise ValueError(f"{path}:{line_number}: count must be positive")
        entries[source_path] = count
    return entries


def scan_sources(root: Path) -> dict[str, int]:
    actual: dict[str, int] = {}
    for source_dir in SOURCE_DIRS:
        directory = root / source_dir
        if not directory.is_dir():
            raise ValueError(f"missing source directory: {directory}")
        for path in sorted(directory.rglob("*")):
            if path.suffix not in {".c", ".h", ".sh", ".py", ".in"} or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if relative in GATEWAY_PATHS:
                continue
            text = path.read_text(encoding="utf-8")
            count = len(PATTERN.findall(text))
            if count:
                actual[relative] = count
    return actual


def main() -> int:
    script = Path(__file__).resolve()
    repository_root = script.parents[2]
    allowlist_path = script.with_name("users_data_access_allowlist.txt")

    try:
        expected = load_allowlist(allowlist_path)
        actual = scan_sources(repository_root)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"users.data access check failed: {error}", file=sys.stderr)
        return 1

    failures: list[str] = []
    for source_path in sorted(set(expected) | set(actual)):
        expected_count = expected.get(source_path, 0)
        actual_count = actual.get(source_path, 0)
        if expected_count != actual_count:
            failures.append(
                f"{source_path}: expected {expected_count}, found {actual_count}"
            )

    if failures:
        print("Unreviewed direct legacy user-database access:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(
            "Route new code through legacy_userdb or update the reviewed "
            "access register and allowlist.",
            file=sys.stderr,
        )
        return 1

    print(
        "users.data direct-access baseline: OK "
        f"({len(actual)} legacy source files)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
