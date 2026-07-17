#!/usr/bin/env python3
"""PTY regression tests for the Telnet gate and visible NEW dialog."""

from __future__ import annotations

import os
import pty
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TIMEOUT = 5.0
PASSWORD = b"long-enough-password"
SHORT_PASSWORD = b"abc123"
MISMATCH_PASSWORD = b"different-long-password"


def read_until(master: int, output: bytearray, needle: bytes) -> None:
    deadline = time.monotonic() + TIMEOUT
    while needle not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"timeout waiting for {needle!r}: {bytes(output)!r}")
        readable, _, _ = select.select([master], [], [], remaining)
        if not readable:
            continue
        chunk = os.read(master, 4096)
        if not chunk:
            raise AssertionError(f"PTY closed before {needle!r}: {bytes(output)!r}")
        output.extend(chunk)


def read_until_count(
    master: int,
    output: bytearray,
    needle: bytes,
    expected_count: int,
) -> None:
    deadline = time.monotonic() + TIMEOUT
    while output.count(needle) < expected_count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(
                f"timeout waiting for occurrence {expected_count} of "
                f"{needle!r}: {bytes(output)!r}"
            )
        readable, _, _ = select.select([master], [], [], remaining)
        if not readable:
            continue
        chunk = os.read(master, 4096)
        if not chunk:
            raise AssertionError(
                f"PTY closed before occurrence {expected_count} of "
                f"{needle!r}: {bytes(output)!r}"
            )
        output.extend(chunk)


def drain(master: int, output: bytearray) -> None:
    while True:
        readable, _, _ = select.select([master], [], [], 0.1)
        if not readable:
            return
        try:
            chunk = os.read(master, 4096)
        except OSError:
            return
        if not chunk:
            return
        output.extend(chunk)


def start_login(binary: Path, root: Path, enabled: bool) -> tuple[subprocess.Popen[bytes], int, bytearray]:
    master, slave = pty.openpty()
    command = [
        str(binary),
        "--protocol", "telnet",
        "--mbse-root", str(root),
        "--socket", str(root / "missing-auth.sock"),
        "--source-ip", "192.0.2.44",
        "--program", "/bin/true",
        "--timeout-ms", "500",
    ]
    if enabled:
        command.extend([
            "--enable-registration",
            "--bbs-users-directory", str(root / "home"),
            "--legacy-security-level", "20",
        ])
    environment = os.environ.copy()
    environment["FORTYTWO_TEST_CHALLENGE_FIXED"] = "1"
    process = subprocess.Popen(
        command,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        env=environment,
    )
    os.close(slave)
    return process, master, bytearray()


def pass_escape_gate(master: int, output: bytearray) -> None:
    read_until(master, output, b"Press ESC twice")
    assert b"FORTYTWO BBS" in output
    assert b"Neue Benutzer / New users: NEW" in output
    assert b"\x1b[2J\x1b[H" in output
    assert output.index(b"FORTYTWO BBS") < output.index(b"Press ESC twice")
    os.write(master, b"\x1b[A")
    time.sleep(0.15)
    drain(master, output)
    if b"Login: " in output:
        raise AssertionError("an ANSI cursor sequence passed the double-ESC gate")
    os.write(master, b"\x1b\x1b")
    read_until(master, output, b"Login: ")


def test_registration_disabled(binary: Path, root: Path) -> None:
    process, master, output = start_login(binary, root, enabled=False)
    try:
        pass_escape_gate(master, output)
        os.write(master, b"NEW\n")
        read_until(master, output, b"New user registration is not enabled.")
        assert process.wait(timeout=TIMEOUT) == 1
        drain(master, output)
        assert b"Registration protection" not in output
    finally:
        os.close(master)
        if process.poll() is None:
            process.kill()
            process.wait()


def test_registration_dialog(binary: Path, root: Path) -> None:
    process, master, output = start_login(binary, root, enabled=True)
    try:
        pass_escape_gate(master, output)
        os.write(master, b"newe\x08\n")
        read_until_count(master, output, b"Answer: ", 1)
        assert b"^H" not in output
        assert b"Registration protection" in output
        assert b"Sie haben 3 Versuche / You have 3 tries" in output
        assert b"Ergaenze die Zahlenreihe / Complete the sequence:" in output
        assert b"3, 6, 10, 15, 21, 28, ?" in output

        # The fixed challenge is 9. Two wrong answers must reuse it.
        os.write(master, b"0\n")
        read_until_count(
            master, output, b"Not correct. Please try again.", 1
        )
        read_until_count(master, output, b"Answer: ", 2)

        os.write(master, b"1\n")
        read_until_count(
            master, output, b"Not correct. Please try again.", 2
        )
        read_until_count(master, output, b"Answer: ", 3)

        os.write(master, b"36\n")
        read_until(master, output, b"New login name: ")
        os.write(master, b"dialogtest\n")
        read_until(master, output, b"Display name: ")
        os.write(master, b"Dialog Test\n")

        read_until_count(master, output, b"New password: ", 1)
        assert b"Passwort: mind. 12 Zeichen" in output
        os.write(master, SHORT_PASSWORD + b"\n")
        read_until(
            master, output,
            b"Passwort ist zu kurz / Password is too short."
        )

        read_until_count(master, output, b"New password: ", 2)
        os.write(master, PASSWORD + b"\n")
        read_until_count(master, output, b"Repeat password: ", 1)
        os.write(master, MISMATCH_PASSWORD + b"\n")
        read_until(
            master, output,
            b"Passwoerter stimmen nicht ueberein"
        )

        read_until_count(master, output, b"New password: ", 3)
        os.write(master, PASSWORD + b"\n")
        read_until_count(master, output, b"Repeat password: ", 2)
        os.write(master, PASSWORD + b"\n")

        read_until(master, output, b"cannot connect to fortytwo-authd")
        assert process.wait(timeout=TIMEOUT) == 1
        drain(master, output)

        assert output.count(b"Registration protection") == 1
        assert output.count(
            b"Sie haben 3 Versuche / You have 3 tries"
        ) == 1
        assert output.count(b"Answer: ") == 3
        assert output.count(b"Passwort: mind. 12 Zeichen") == 3
        assert output.count(b"Repeat password: ") == 2
        assert SHORT_PASSWORD not in output
        assert MISMATCH_PASSWORD not in output
        assert PASSWORD not in output
        assert b"Correct." in output
    finally:
        os.close(master)
        if process.poll() is None:
            process.kill()
            process.wait()


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: fortytwo_login_dialog_test.py LOGIN_BINARY")
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise AssertionError(f"missing login binary: {binary}")

    with tempfile.TemporaryDirectory(prefix="fortytwo-login-dialog-") as temporary:
        root = Path(temporary)
        (root / "home").mkdir(mode=0o770)
        (root / "etc").mkdir(mode=0o770)
        (root / "etc" / "issue").write_bytes(
            b"\x1b[2J\x1b[H\x1b[1;36mFORTYTWO BBS\x1b[0m\n"
            b"Neue Benutzer / New users: NEW\n"
        )
        test_registration_disabled(binary, root)
        test_registration_dialog(binary, root)

    print("fortytwo-login Telnet gate and NEW dialog tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
