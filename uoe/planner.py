"""Deterministic candidate planning; no execution and no compatibility guarantees."""
from __future__ import annotations

import platform
import shutil

HOST_ARCH = {
    "amd64": "x86_64", "x86_64": "x86_64",
    "aarch64": "aarch64", "arm64": "aarch64",
    "i386": "x86", "i686": "x86",
}


def plan_inspection(inspection: dict, *, host_os: str | None = None,
                    host_arch: str | None = None,
                    available: dict[str, bool] | None = None) -> dict:
    """Produce proposed launch strategies from *only* observed header data.

    The available parameter is a test/simulation override. In real CLI use it
    defaults to local runtime presence checks; the runner is never executed.
    """
    host_os = (host_os or platform.system()).lower()
    host_arch = HOST_ARCH.get(
        (host_arch or platform.machine()).lower(),
        (host_arch or platform.machine()).lower()
    )
    runtimes = (available if available is not None else {
        "wine": shutil.which("wine") is not None,
        "wasmtime": shutil.which("wasmtime") is not None,
    })
    binary = inspection["binary"]
    fmt, arch = binary["format"], binary["architecture"]
    same_arch = arch == host_arch
    strategies = []

    def add(runner, can_use, reason, constraints):
        strategies.append({
            "runner": runner,
            "state": "candidate" if can_use else "unavailable",
            "reason": reason,
            "constraints": constraints,
            "verified_compatible": False,
        })

    if fmt == "ELF":
        add("native", host_os == "linux" and same_arch,
            "Linux ELF native loader may work only with a matching architecture and OS ABI",
            ["Observed interpreter/library names still require host resolution and behavioral tests"])
    elif fmt == "PE":
        if host_os == "windows":
            add("native", same_arch,
                "Windows native loader may support the executable's architecture",
                ["Windows APIs, DLLs, licensing, signing and security requirements unknown"])
        elif host_os == "linux":
            runner = bool(runtimes.get("wine", False))
            add("wine", runner and same_arch and binary["bits"] == 64,
                "Wine may supply some Windows APIs for this PE binary",
                ["Wine presence is not API compatibility",
                 "PE32+ and host architecture must match for this v0 strategy",
                 "Observed DLL imports still require resolution; dynamic LoadLibrary requirements remain unknown"])
        else:
            add("wine", False, "No PE execution adapter defined for this host",
                ["No supported execution plan currently available"])
    elif fmt == "WASM":
        add("wasmtime", bool(runtimes.get("wasmtime", False)),
            "Wasmtime can execute compatible WebAssembly components or modules",
            ["Imports, WASI requirements and resource permissions still unknown"])
    elif fmt == "Mach-O":
        add("native", host_os == "darwin" and same_arch,
            "Native Apple loader may support the Mach-O binary",
            ["Frameworks, code signing and entitlements still unknown"])
    elif fmt == "Mach-O-fat":
        add("native", False,
            "Universal Mach-O binary slices have not been enumerated",
            ["Inspect individual slices before choosing an execution architecture"])

    return {
        "schema_version": "uoe.plan.v0.1",
        "artifact_sha256": inspection["artifact"]["sha256"],
        "host": {"os": host_os, "architecture": host_arch},
        "strategies": strategies,
        "status": "candidates_found" if any(
            x["state"] == "candidate" for x in strategies
        ) else "unresolved",
        "unresolved": inspection["unknowns"],
        "observed_requirements": inspection.get("static_dependencies", []),
        "execution_attempted": False,
        "note": ("Presence of a compatible-format runtime is not proof that the "
                 "application can execute correctly or safely. All launch "
                 "strategies are unverified until independently tested."),
    }
