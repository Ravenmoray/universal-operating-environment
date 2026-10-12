#!/usr/bin/env python3
"""Cross-compile and inspect project-owned PE fixtures. Never execute PE code.

This is a *format and export* check, not Windows compatibility verification.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
COMPILER = "x86_64-w64-mingw32-gcc"
OBJDUMP = "x86_64-w64-mingw32-objdump"


def check(condition: bool, explanation: str):
    if not condition:
        raise AssertionError(explanation)


def run(command: list[str]):
    outcome = subprocess.run(command, check=False, capture_output=True,
                             text=True, timeout=120)
    if outcome.returncode:
        raise RuntimeError(
            "cross-compiler command failed (exit " + str(outcome.returncode) +
            "):\\n" + " ".join(command) + "\\n" + outcome.stderr
        )
    return outcome.stdout


def parse_pe(path: Path, expect_dll: bool):
    data = path.read_bytes()
    check(len(data) > 128 and data[:2] == b"MZ", "missing DOS MZ header")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    check(offset <= len(data) - 24, "PE header offset out of bounds")
    check(data[offset:offset + 4] == b"PE\x00\x00", "invalid PE header")
    machine, = struct.unpack_from("<H", data, offset + 4)
    optional_magic, = struct.unpack_from("<H", data, offset + 24)
    characteristics, = struct.unpack_from("<H", data, offset + 22)
    check(machine == 0x8664, "not x86-64 PE")
    check(optional_magic == 0x20B, "not PE32+")
    check(bool(characteristics & 0x2000) == expect_dll, "incorrect DLL flag")
    return hashlib.sha256(data).hexdigest()


def main():
    for tool in (COMPILER, OBJDUMP):
        check(shutil.which(tool) is not None, "missing tool: " + tool)
    with tempfile.TemporaryDirectory(prefix="uoe-pe-build-") as directory:
        folder = Path(directory)
        exe = folder / "uoe-windows-client.exe"
        dll = folder / "uoe_text_v1.dll"
        common = [COMPILER, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
        run(common + [str(ROOT / "src/windows_client.c"), "-o", str(exe)])
        run(common + ["-shared", str(ROOT / "src/reference_provider.c"),
                      "-o", str(dll)])
        client_digest = parse_pe(exe, expect_dll=False)
        provider_digest = parse_pe(dll, expect_dll=True)
        exports = run([OBJDUMP, "-p", str(dll)])
        check("uoe_text_normalize_v1" in exports,
              "required interface is not exported by PE DLL")
    print(json.dumps({
        "experiment": "uoe-cross-compile-windows-pe-v0",
        "status": "passed",
        "format": "PE32+ x86-64",
        "client_sha256": client_digest,
        "dll_sha256": provider_digest,
        "required_export": "uoe_text_normalize_v1",
        "executed": False,
        "warning": "Static format and symbol checks only; this does not prove the PE program works under Windows or Wine.",
    }, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
