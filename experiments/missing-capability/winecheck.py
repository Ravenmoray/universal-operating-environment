#!/usr/bin/env python3
"""Run ONLY the UOE-owned PE fixture through Wine on an isolated CI runner.

An untrusted PE file must NOT be substituted. Wine is a compatibility layer,
NOT a security boundary. This test runs on trusted GitHub pushes only.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
COMPILER = "x86_64-w64-mingw32-gcc"


def check(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)


def run(command, *, env=None, timeout=100):
    result = subprocess.run(
        command, capture_output=True, text=True, env=env, timeout=timeout,
        check=False
    )
    if result.returncode:
        raise RuntimeError(
            "Command failed: " + repr(command) +
            "\nstdout:\n" + result.stdout + "\nstderr:\n" + result.stderr
        )
    return result.stdout


def build(output: Path, source: str, shared=False):
    args = [COMPILER, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    if shared:
        args += ["-shared"]
    args += [str(SRC / source), "-o", str(output)]
    run(args)


def winepath(file: Path, env):
    path = run(["winepath", "-w", str(file)], env=env, timeout=100).strip()
    check(bool(path), "Wine path translation failed")
    return path


def execute(exe: Path, dll: Path, text: str, env):
    command = ["xvfb-run", "-a", "wine", str(exe), winepath(dll, env), text]
    return subprocess.run(command, env=env, capture_output=True,
                          timeout=120, check=False)


def sha256(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    for exe in [COMPILER, "wine", "winepath", "xvfb-run"]:
        check(shutil.which(exe) is not None, "required tool is missing: " + exe)

    with tempfile.TemporaryDirectory(prefix="uoe-wine-fixture-") as tmp:
        base = Path(tmp)
        client = base / "windows_client.exe"
        good = base / "good.dll"
        incorrect = base / "incorrect.dll"
        wrong = base / "wrong.dll"
        build(client, "windows_client.c")
        build(good, "reference_provider.c", shared=True)
        build(incorrect, "incorrect_provider.c", shared=True)
        build(wrong, "wrong_symbol_provider.c", shared=True)

        env = os.environ.copy()
        env.update({
            "WINEPREFIX": str(base / "wineprefix"),
            "WINEARCH": "win64",
            "WINEDEBUG": "-all",
            "WINEDLLOVERRIDES": "mscoree,mshtml=",
        })
        # Initialize this disposable Wine prefix before measurements.
        run(["xvfb-run", "-a", "wineboot", "-u"], env=env, timeout=180)

        missing = execute(client, base / "missing.dll", "hello", env)
        check(missing.returncode == 40 and b"UOE_ERR_LIBRARY" in missing.stderr,
              f"missing DLL failure not classified: {missing.returncode} {missing.stderr!r}")

        symbol = execute(client, wrong, "hello", env)
        check(symbol.returncode == 41 and b"UOE_ERR_SYMBOL" in symbol.stderr,
              f"missing symbol failure not classified: {symbol.returncode} {symbol.stderr!r}")

        incorrect_run = execute(client, incorrect, "hello", env)
        check(incorrect_run.returncode == 0 and
              incorrect_run.stdout.strip() != b"UOE/1:HELLO",
              "incorrect provider was not rejected by external test oracle")

        vectors = [("hello", b"UOE/1:HELLO"),
                   ("Mixed 123", b"UOE/1:MIXED 123"),
                   ("!?_-z", b"UOE/1:!?_-Z")]
        for source, expected in vectors:
            result = execute(client, good, source, env)
            check(result.returncode == 0 and result.stdout.strip() == expected,
                  f"Wine execution failed for {source!r}: rc={result.returncode}"
                  f" stdout={result.stdout!r} stderr={result.stderr!r}")
        report = {
            "experiment": "project-owned-windows-pe-under-wine",
            "status": "passed",
            "runtime": run(["wine", "--version"]).strip(),
            "client_sha256": sha256(client),
            "dll_sha256": sha256(good),
            "missing_library_exit": missing.returncode,
            "missing_symbol_exit": symbol.returncode,
            "incorrect_provider_rejected": True,
            "positive_vectors": len(vectors),
            "limitations": [
                "Only a UOE-owned x86-64 PE + DLL fixture was executed.",
                "Wine was not used as a security sandbox.",
                "No proprietary Windows or macOS app was tested.",
                "This test does not assess arbitrary Windows API compatibility.",
                "Reference implementation was predefined; no AI repair occurred."
            ],
        }
        print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
