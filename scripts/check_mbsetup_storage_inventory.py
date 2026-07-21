#!/usr/bin/env python3
"""Verify the source-controlled mbsetup legacy-storage inventory.

The check is intentionally syntax-based and fail-closed. It records every
literal MBSE_ROOT-relative ``*.data`` path referenced by ``mbsetup/*.c`` and
its owning source files. A new or moved direct legacy-store access must update
both this baseline and the accompanying migration inventory.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MBSETUP_DIRECTORY = REPOSITORY_ROOT / "mbsetup"
DATA_PATH_PATTERN = re.compile(r'"%s/([^"\n]+?\.data)"')

EXPECTED_REFERENCES: dict[str, tuple[str, ...]] = {
    "etc/archiver.data": ("m_archive.c",),
    "etc/config.data": ("m_global.c",),
    "etc/domain.data": ("m_domain.c",),
    "etc/domalias.data": ("m_domalias.c",),
    "etc/fareas.data": (
        "m_farea.c", "m_fdb.c", "m_ff.c", "m_fgroup.c", "m_ngroup.c", "m_ticarea.c",
    ),
    "etc/fgroups.data": ("m_fgroup.c", "m_ngroup.c", "m_node.c", "m_ticarea.c"),
    "etc/fidonet.data": ("m_fido.c", "m_node.c"),
    "etc/hatch.data": ("m_hatch.c", "m_ticarea.c"),
    "etc/ibcsrv.data": ("m_ibc.c",),
    "etc/language.data": ("m_lang.c", "m_menu.c"),
    "etc/limits.data": ("m_limits.c", "m_users.c"),
    "etc/magic.data": ("m_magic.c", "m_ticarea.c"),
    "etc/mareas.data": ("m_marea.c", "m_mgroup.c", "m_node.c"),
    "etc/mgroups.data": ("m_marea.c", "m_mgroup.c", "m_node.c"),
    "etc/modem.data": ("m_modem.c",),
    "etc/newfiles.data": ("m_marea.c", "m_new.c", "m_ngroup.c"),
    "etc/ngroups.data": ("m_new.c", "m_ngroup.c"),
    "etc/nodes.data": (
        "m_fgroup.c", "m_marea.c", "m_mgroup.c", "m_node.c", "m_ticarea.c",
    ),
    "etc/oneline.data": ("m_ol.c",),
    "etc/protocol.data": ("m_protocol.c",),
    "etc/route.data": ("m_route.c",),
    "etc/scanmgr.data": ("m_ff.c", "m_marea.c"),
    "etc/service.data": ("m_service.c",),
    "etc/sysinfo.data": ("m_marea.c",),
    "etc/task.data": ("m_task.c",),
    "etc/tic.data": ("m_farea.c", "m_fdb.c", "m_fgroup.c", "m_node.c", "m_ticarea.c"),
    "etc/ttyinfo.data": ("m_modem.c", "m_tty.c"),
    "etc/users.data": ("m_limits.c", "m_users.c"),
    "etc/virscan.data": ("m_virus.c",),
    "var/fdb/fdb%d.data": ("m_fdb.c",),
    "var/fdb/file%d.data": ("m_farea.c", "m_fdb.c"),
}

EXPECTED_SNAPSHOT_STORES = {
    "etc/archiver.data", "etc/domain.data", "etc/domalias.data", "etc/fareas.data",
    "etc/fgroups.data", "etc/fidonet.data", "etc/hatch.data", "etc/ibcsrv.data",
    "etc/language.data", "etc/limits.data", "etc/magic.data", "etc/mareas.data",
    "etc/mgroups.data", "etc/modem.data", "etc/newfiles.data", "etc/ngroups.data",
    "etc/nodes.data", "etc/oneline.data", "etc/protocol.data", "etc/route.data",
    "etc/scanmgr.data", "etc/service.data", "etc/tic.data", "etc/ttyinfo.data",
    "etc/users.data", "etc/virscan.data",
}

EXPECTED_SPECIAL_STORES = {
    "etc/config.data", "etc/sysinfo.data", "etc/task.data",
    "var/fdb/fdb%d.data", "var/fdb/file%d.data",
}


def collect_references() -> dict[str, tuple[str, ...]]:
    references: dict[str, set[str]] = defaultdict(set)

    for source_path in sorted(MBSETUP_DIRECTORY.glob("*.c")):
        text = source_path.read_text(encoding="utf-8")
        for data_path in DATA_PATH_PATTERN.findall(text):
            references[data_path].add(source_path.name)

    return {
        data_path: tuple(sorted(source_files))
        for data_path, source_files in sorted(references.items())
    }


def main() -> int:
    actual = collect_references()
    failures: list[str] = []

    if actual != EXPECTED_REFERENCES:
        expected_paths = set(EXPECTED_REFERENCES)
        actual_paths = set(actual)
        for missing in sorted(expected_paths - actual_paths):
            failures.append(f"missing legacy-store reference: {missing}")
        for added in sorted(actual_paths - expected_paths):
            failures.append(f"untracked legacy-store reference: {added}")
        for common in sorted(expected_paths & actual_paths):
            if actual[common] != EXPECTED_REFERENCES[common]:
                failures.append(
                    f"owner mismatch for {common}: expected "
                    f"{', '.join(EXPECTED_REFERENCES[common])}; found "
                    f"{', '.join(actual[common])}"
                )

    all_expected = EXPECTED_SNAPSHOT_STORES | EXPECTED_SPECIAL_STORES
    if all_expected != set(EXPECTED_REFERENCES):
        failures.append("internal baseline error: store classifications are incomplete")
    if EXPECTED_SNAPSHOT_STORES & EXPECTED_SPECIAL_STORES:
        failures.append("internal baseline error: store classifications overlap")

    source_modules = {module for modules in actual.values() for module in modules}
    print("mbsetup legacy-storage inventory")
    print("================================")
    print(f"Structured *.data path patterns: {len(actual)}")
    print(f"Snapshot-style stores:           {len(EXPECTED_SNAPSHOT_STORES)}")
    print(f"Special-access stores:           {len(EXPECTED_SPECIAL_STORES)}")
    print(f"Source modules with direct references: {len(source_modules)}")

    if failures:
        print("\nInventory result: FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("\nInventory result: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
