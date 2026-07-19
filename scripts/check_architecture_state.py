#!/usr/bin/env python3
"""Fail-closed architecture-state and changed-path validation."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

STATE_EN = Path("docs/ARCHITECTURE_STATE.md")
STATE_DE = Path("docs/ARCHITECTURE_STATE.de.md")
SECURITY_EN = Path("SECURITY_ARCHITECTURE.md")
SECURITY_DE = Path("SICHERHEITS_ARCHITEKTUR.md")
SECURITY_TEST = Path("fortytwo-auth/tests/security_architecture_test.py")

REQUIRED_FILES = (
    STATE_EN,
    STATE_DE,
    SECURITY_EN,
    SECURITY_DE,
    SECURITY_TEST,
)

EXACT_PATHS = {
    ".gitignore": "repository configuration",
    "Makefile": "legacy build",
    "Makefile.in": "legacy build",
    "configure": "generated legacy build",
    "configure.ac": "legacy build",
    "SETUP.sh": "legacy installation",
    "README.md": "project documentation",
    "LIESMICH.md": "project documentation",
    "TODO": "project planning",
    "SECURITY_ARCHITECTURE.md": "normative architecture",
    "SICHERHEITS_ARCHITEKTUR.md": "normative architecture",
    "fortytwo-auth/Makefile": "authentication build",
    "fortytwo-auth/README": "authentication documentation",
    "fortytwo-auth/README.md": "authentication documentation",
}

KNOWN_PREFIXES = {
    ".github/workflows/": "CI workflow",
    "docs/": "project documentation",
    "scripts/": "repository checks",
    "fortytwo-auth/include/": "authentication interface",
    "fortytwo-auth/src/": "authentication implementation",
    "fortytwo-auth/tests/": "authentication tests",
    "fortytwo-auth/migrations/": "database migrations",
    "fortytwo-auth/protocol/": "protocol contract",
    "fortytwo-auth/scripts/": "authentication tooling",
    "fortytwo-auth/README-": "authentication documentation",
    "include/": "legacy interface",
    "lib/": "legacy implementation",
    "mbaff/": "legacy component",
    "mbcico/": "legacy component",
    "mbfido/": "legacy component",
    "mbmon/": "legacy component",
    "mbnntp/": "legacy component",
    "mbsebbs/": "legacy component",
    "mbsetup/": "legacy component",
    "mbtask/": "legacy component",
    "mbutils/": "legacy component",
    "unix/": "legacy login and utilities",
    "doc/": "upstream documentation",
    "html/": "upstream documentation",
    "lang/": "language data",
    "man/": "manual pages",
    "misc/": "legacy support files",
    "init/": "legacy service files",
}


def fail(message: str, errors: list[str]) -> None:
    errors.append(message)


def run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def lines_from_git(*args: str) -> set[str]:
    return {
        line.strip()
        for line in run_git(*args).splitlines()
        if line.strip()
    }


def collect_changed_paths(base_ref: str | None) -> set[str]:
    changed: set[str] = set()

    if base_ref:
        run_git("rev-parse", "--verify", f"{base_ref}^{{commit}}")
        changed |= lines_from_git(
            "diff",
            "--name-only",
            "--diff-filter=ACDMRTUXB",
            f"{base_ref}...HEAD",
            "--",
        )

    changed |= lines_from_git(
        "diff", "--name-only", "--diff-filter=ACDMRTUXB", "--"
    )
    changed |= lines_from_git(
        "diff", "--cached", "--name-only", "--diff-filter=ACDMRTUXB", "--"
    )
    changed |= lines_from_git(
        "ls-files", "--others", "--exclude-standard"
    )

    return changed


def classify_path(path: str) -> str | None:
    if path in EXACT_PATHS:
        return EXACT_PATHS[path]

    for prefix, classification in KNOWN_PREFIXES.items():
        if path == prefix.rstrip("/") or path.startswith(prefix):
            return classification

    return None


def read_checked(path: Path, errors: list[str]) -> str:
    absolute = ROOT / path

    if not absolute.is_file():
        fail(f"Required file missing: {path}", errors)
        return ""

    try:
        data = absolute.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{path}: invalid UTF-8: {exc}", errors)
        return ""

    if not data:
        fail(f"{path}: file is empty", errors)
        return ""

    if not data.endswith("\n"):
        fail(f"{path}: final newline missing", errors)

    for number, line in enumerate(data.splitlines(), start=1):
        if line.rstrip() != line:
            fail(f"{path}:{number}: trailing whitespace", errors)

    return data


def normalized(text: str) -> str:
    text = re.sub(r"(?<=\w)-\s*\n\s*(?=\w)", "-", text)
    return re.sub(r"\s+", " ", text).strip()


def require_text(
    path: Path,
    text: str,
    required: tuple[str, ...],
    errors: list[str],
) -> None:
    compact = normalized(text)

    for phrase in required:
        if normalized(phrase) not in compact:
            fail(f"{path}: required statement missing: {phrase}", errors)


def extract_metadata(
    path: Path,
    text: str,
    labels: tuple[str, str, str],
    errors: list[str],
) -> tuple[str, str, str] | None:
    milestone_label, commit_label, reviewed_label = labels

    patterns = (
        rf"^- {re.escape(milestone_label)}:\s*(.+?)\s*$",
        rf"^- {re.escape(commit_label)}:\s*`([0-9a-f]{{40}})`\s*$",
        rf"^- {re.escape(reviewed_label)}:\s*(\d{{4}}-\d{{2}}-\d{{2}})\s*$",
    )

    values: list[str] = []

    for pattern in patterns:
        match = re.search(pattern, text, flags=re.MULTILINE)
        if not match:
            fail(f"{path}: metadata field missing or invalid: {pattern}", errors)
            return None
        values.append(match.group(1).strip())

    return values[0], values[1], values[2]


def run_security_architecture_test(errors: list[str]) -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / SECURITY_TEST)],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if result.returncode != 0:
        output = "\n".join(
            part for part in (result.stdout.strip(), result.stderr.strip())
            if part
        )
        fail(
            "Normative security architecture check failed"
            + (f":\n{output}" if output else ""),
            errors,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the current architecture state fail-closed."
    )
    parser.add_argument(
        "--base-ref",
        default=os.environ.get("ARCHITECTURE_BASE_REF"),
        help="Git base commit or ref used to classify changed paths.",
    )
    args = parser.parse_args()

    print("FortyTwo BBS architecture-state validation")
    print("==========================================")
    print()
    print("Checks performed:")
    print("  1. Required architecture and security files exist.")
    print("  2. Checked documents are valid UTF-8 and not empty.")
    print("  3. Final newlines and trailing whitespace are validated.")
    print("  4. Required architecture statements are present in English and German.")
    print("  5. Milestone, baseline commit and review date match in both languages.")
    print("  6. Forbidden alternative identity databases are not named.")
    print("  7. The normative security-architecture test succeeds.")
    print("  8. Every changed path is classified by the fail-closed path policy.")

    if args.base_ref:
        print(f"  9. Changed paths are compared with base reference: {args.base_ref}")
    else:
        print("  9. Working-tree, staged and untracked paths are inspected.")

    print()

    errors: list[str] = []

    for required in REQUIRED_FILES:
        if not (ROOT / required).is_file():
            fail(f"Required file missing: {required}", errors)

    state_en = read_checked(STATE_EN, errors)
    state_de = read_checked(STATE_DE, errors)
    read_checked(SECURITY_EN, errors)
    read_checked(SECURITY_DE, errors)

    require_text(
        STATE_EN,
        state_en,
        (
            "Document class: current implementation state",
            "Normative: no",
            "PostgreSQL 17 or newer is authoritative",
            "`users.data` and other historical MBSE flat files are temporary "
            "legacy compatibility data.",
            "`fortytwo-auth` is not yet integrated into the historical "
            "top-level build.",
            "No public, reproducible and supported FortyTwo BBS runtime build "
            "has yet been approved.",
            "Setuid and setgid runtime files are prohibited.",
            "This current-state document",
        ),
        errors,
    )

    require_text(
        STATE_DE,
        state_de,
        (
            "Dokumentklasse: aktueller Implementierungsstand",
            "Normativ: nein",
            "PostgreSQL 17 oder neuer ist die führende Instanz",
            "`users.data` und andere historische MBSE-Flatfiles sind lediglich "
            "vorübergehende Legacy-Kompatibilitätsdaten.",
            "`fortytwo-auth` ist noch nicht in den historischen Top-Level-Build "
            "integriert.",
            "Ein öffentlicher, reproduzierbarer und unterstützter FortyTwo-BBS-"
            "Laufzeit-Build ist noch nicht freigegeben.",
            "Setuid- und Setgid-Dateien sind in der Laufzeitumgebung verboten.",
            "Dieses Dokument zum aktuellen Implementierungsstand",
        ),
        errors,
    )

    forbidden_databases = re.compile(
        r"\b(sqlite|mysql|mariadb|mongodb)\b",
        flags=re.IGNORECASE,
    )

    for path, text in ((STATE_EN, state_en), (STATE_DE, state_de)):
        match = forbidden_databases.search(text)
        if match:
            fail(
                f"{path}: forbidden alternative database named: "
                f"{match.group(0)}",
                errors,
            )

    metadata_en = extract_metadata(
        STATE_EN,
        state_en,
        ("Current milestone", "Baseline commit", "Last reviewed"),
        errors,
    )
    metadata_de = extract_metadata(
        STATE_DE,
        state_de,
        ("Aktueller Meilenstein", "Ausgangs-Commit", "Zuletzt geprüft"),
        errors,
    )

    if metadata_en and metadata_de and metadata_en != metadata_de:
        fail(
            "English and German architecture-state metadata differ: "
            f"{metadata_en!r} != {metadata_de!r}",
            errors,
        )

    run_security_architecture_test(errors)

    try:
        changed_paths = collect_changed_paths(args.base_ref)
    except RuntimeError as exc:
        fail(str(exc), errors)
        changed_paths = set()

    classified: list[tuple[str, str]] = []
    unknown: list[str] = []

    for path in sorted(changed_paths):
        classification = classify_path(path)
        if classification is None:
            unknown.append(path)
        else:
            classified.append((path, classification))

    if unknown:
        fail(
            "Unclassified changed paths:\n  " + "\n  ".join(unknown),
            errors,
        )

    if errors:
        print("Validation result: FAILED", file=sys.stderr)
        print(
            f"Detected findings: {len(errors)}",
            file=sys.stderr,
        )
        for error in errors:
            print(f"\n- {error}", file=sys.stderr)
        return 1

    print("Validation result: OK")
    print()
    print("Architecture documents:")
    print(f"  English current state: {STATE_EN}")
    print(f"  German current state:  {STATE_DE}")
    print("  Metadata consistency:   OK")
    print("  Required statements:    OK")
    print("  Forbidden databases:    none")
    print()
    print("Normative architecture:")
    print("  Security architecture test: OK")

    if args.base_ref:
        print()
        print("Changed-path comparison:")
        print(f"  Base reference: {args.base_ref}")

    print()
    print(f"Accepted changed paths: {len(classified)}")

    if classified:
        for changed_path, classification in classified:
            print(f"  - Path: {changed_path}")
            print(f"    Classification: {classification}")
            print("    Decision: path classified by B5.1.8; ""no content-safety approval implied")
    else:
        print("  No changed paths detected.")

    print()
    print("Fail-closed path result:")
    print("  Unknown or unclassified changed paths: none")
    print()
    print("Architecture state check: OK")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
