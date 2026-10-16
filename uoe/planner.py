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

    scan_status = inspection.get("dependency_scan", {}).get("status")
    if fmt == "ELF":
        # Relocatable objects and separate debug files (scan not complete) are not
        # launchable images, however well their headers match the host.
        scanned = scan_status == "complete_static"
        add("native", scanned and host_os == "linux" and same_arch,
            "Linux ELF native loader may work only with a matching architecture and OS ABI"
            if scanned else
            "Not offered: the ELF scan did not complete (" + str(scan_status) +
            "), so this is not a launchable executable or shared object",
            ["Observed interpreter/library names still require host resolution and behavioral tests"])
    elif fmt == "PE":
        observed = inspection.get("static_dependencies", [])
        notes = []
        delayed = sorted(d["name"] for d in observed if d.get("load_kind") == "delay")
        if delayed:
            notes.append("Delay-loaded DLLs are loaded on first use, so a missing one may "
                         "only fail at run time: " + ", ".join(delayed))
        if any(d["kind"] == "managed_runtime" for d in observed):
            notes.append("Managed (.NET) image: a compatible CLR/.NET runtime is required "
                         "in addition to any PE runner; the target framework is not decoded")
        if host_os == "windows":
            add("native", same_arch,
                "Windows native loader may support the executable's architecture",
                ["Windows APIs, DLLs, licensing, signing and security requirements unknown"] + notes)
        elif host_os == "linux":
            runner = bool(runtimes.get("wine", False))
            add("wine", runner and same_arch and binary["bits"] == 64,
                "Wine may supply some Windows APIs for this PE binary",
                ["Wine presence is not API compatibility",
                 "PE32+ and host architecture must match for this v0 strategy",
                 "Observed DLL imports still require resolution; dynamic LoadLibrary requirements remain unknown"]
                + notes)
        else:
            add("wine", False, "No PE execution adapter defined for this host",
                ["No supported execution plan currently available"] + notes)
    elif fmt == "WASM":
        modules = [d for d in inspection.get("static_dependencies", [])
                   if d["kind"] == "wasm_import_module"]
        constraints = ["Exports, start behavior and resource permissions still unverified"]
        host_modules = sorted(d["name"] or "(empty name)" for d in modules
                              if "interface_hint" not in d)
        if host_modules:
            constraints.append("Non-WASI import modules must be supplied by an embedder "
                               "or linked modules: " + ", ".join(host_modules))
        if len(host_modules) != len(modules):
            constraints.append("WASI preview1 module names observed; per-function support "
                               "and granted permissions need verification")
        add("wasmtime", bool(runtimes.get("wasmtime", False)),
            "Wasmtime can execute compatible WebAssembly components or modules",
            constraints)
    elif fmt in ("Mach-O", "Mach-O-fat"):
        slices = inspection.get("dependency_scan", {}).get("slices", [])
        platforms = {}
        for dep in inspection.get("static_dependencies", []):
            if dep["kind"] == "platform":
                platforms.setdefault(dep.get("slice", {}).get("index", 0), []).append(dep["name"])

        def launchable(image):
            """A decoded executable for the host architecture on a macOS platform."""
            if (image["architecture"] != host_arch or image["status"] != "complete_static"
                    or image["file_type"] != "executable"):
                return False
            names = platforms.get(image.get("index", 0))
            return not names or bool({"macos", "maccatalyst"} & set(names))
        ready = any(launchable(image) for image in slices)
        listing = ", ".join(binary.get("slice_architectures") or [arch]) or "none enumerated"
        add("native", host_os == "darwin" and ready,
            "Native Apple loader may support "
            + ("a slice of this universal binary" if fmt == "Mach-O-fat" else "the Mach-O binary")
            if host_os != "darwin" or ready else
            "Not offered: no decoded executable image for this host architecture and a macOS "
            "platform (dylibs, bundles, objects and other-platform images are not launched this way)",
            ["Slice architectures: " + listing,
             "Frameworks, code signing and entitlements still unknown"]
            if fmt == "Mach-O-fat" else
            ["Frameworks, code signing and entitlements still unknown"])

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
