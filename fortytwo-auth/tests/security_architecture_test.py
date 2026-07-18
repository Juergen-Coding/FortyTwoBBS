#!/usr/bin/env python3
"""Regression checks for the normative FortyTwo security architecture."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]

DOCUMENTS = {
    "en": ROOT / "SECURITY_ARCHITECTURE.md",
    "de": ROOT / "SICHERHEITS_ARCHITEKTUR.md",
}


def section(text: str, number: int) -> str:
    match = re.search(
        rf"^## {number}\. .*?(?=^## {number + 1}\. |\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"section {number} is missing")
    return match.group(0)


def normalized(text: str) -> str:
    return " ".join(text.split())


def require(text: str, needle: str, context: str) -> None:
    if normalized(needle) not in normalized(text):
        raise AssertionError(f"{context}: missing {needle!r}")


def reject(text: str, needle: str, context: str) -> None:
    if needle in text:
        raise AssertionError(f"{context}: prohibited {needle!r}")


def main() -> int:
    texts = {name: path.read_text(encoding="utf-8") for name, path in DOCUMENTS.items()}

    en13 = section(texts["en"], 13)
    en16 = section(texts["en"], 16)
    de13 = section(texts["de"], 13)
    de16 = section(texts["de"], 16)

    for label, value in (("English section 13", en13), ("English section 16", en16)):
        require(value, "PostgreSQL 17 or newer", label)
        reject(value, "SQLite", label)

    for label, value in (("German section 13", de13), ("German section 16", de16)):
        require(value, "PostgreSQL 17 oder neuer", label)
        reject(value, "SQLite", label)

    require(en13, "`fortytwo-authd`", "English section 13")
    require(en13, "Unix-domain socket", "English section 13")
    require(en13, "`fortytwo_authd`", "English section 13")
    require(en13, "`users.data`", "English section 13")
    require(en13, "not an equal source of identity truth", "English section 13")

    require(de13, "`fortytwo-authd`", "German section 13")
    require(de13, "Unix-Domain-Socket", "German section 13")
    require(de13, "`fortytwo_authd`", "German section 13")
    require(de13, "`users.data`", "German section 13")
    require(de13, "keine gleichberechtigte Identitätsautorität", "German section 13")

    require(
        texts["en"],
        "the original SQLite target was superseded",
        "English architecture revision",
    )
    require(
        texts["de"],
        "Das ursprüngliche SQLite-Ziel wurde",
        "German architecture revision",
    )
    if texts["en"].count("SQLite") != 1:
        raise AssertionError("English document must contain SQLite only in the revision note")
    if texts["de"].count("SQLite") != 1:
        raise AssertionError("German document must contain SQLite only in the revision note")

    print("security architecture PostgreSQL authority check: OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, UnicodeError) as error:
        print(f"security architecture check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
