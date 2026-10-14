"""Bounded, non-executing binary header and static dependency inspection.

This is not a security boundary. It identifies formats, not application
compatibility. Dependency observations are limited to what each format parser
documents (ELF program headers, PE normal imports, WASM import section, Mach-O
load commands); runtime-resolved requirements always remain unknown.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import struct

from .elf import ElfError, inspect_dependencies
from .binary_input import BinaryError
from .macho import CPU_ARCH as MACH_ARCH, MAGICS as MACH_MAGICS
from .macho import inspect_dependencies as inspect_macho_dependencies
from .pe import inspect_dependencies as inspect_pe_dependencies
from .wasm import inspect_dependencies as inspect_wasm_dependencies

HEADER_LIMIT = 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
ARCH = {3: "x86", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
PE_ARCH = {0x014c: "x86", 0x8664: "x86_64", 0xaa64: "aarch64", 0x01c4: "arm"}


class InspectionError(ValueError):
    pass


def _need(data: bytes, offset: int, count: int):
    if offset < 0 or count < 0 or offset + count > len(data):
        raise InspectionError("truncated or invalid executable header")


def _inspect_elf(data: bytes):
    _need(data, 0, 20)
    cls, order = data[4], data[5]
    if cls not in (1, 2) or order not in (1, 2):
        raise InspectionError("invalid ELF class or endianness")
    endian = "<" if order == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    return ("ELF", ARCH.get(machine, f"unknown:{machine}"),
            32 if cls == 1 else 64, "little" if order == 1 else "big",
            "linux-or-unix", [])


def _inspect_pe(data: bytes):
    _need(data, 0x3c, 4)
    offset = struct.unpack_from("<I", data, 0x3c)[0]
    if offset > HEADER_LIMIT - 26:
        raise InspectionError("PE header offset outside inspection window")
    _need(data, offset, 26)
    if data[offset:offset + 4] != b"PE\x00\x00":
        raise InspectionError("invalid PE signature")
    machine = struct.unpack_from("<H", data, offset + 4)[0]
    magic = struct.unpack_from("<H", data, offset + 24)[0]
    if magic not in (0x10b, 0x20b):
        raise InspectionError("invalid or unsupported PE optional header")
    return ("PE", PE_ARCH.get(machine, f"unknown:{machine}"),
            32 if magic == 0x10b else 64, "little", "windows", [])


def _inspect_wasm(data: bytes):
    _need(data, 0, 8)
    if data[4:8] != b"\x01\x00\x00\x00":
        raise InspectionError("unsupported WebAssembly binary version")
    return ("WASM", "wasm32", 32, "little", "wasm", [])


def _inspect_mach(data: bytes):
    magic = data[:4]
    formats = {
        b"\xfe\xed\xfa\xce": (">", 32),
        b"\xce\xfa\xed\xfe": ("<", 32),
        b"\xfe\xed\xfa\xcf": (">", 64),
        b"\xcf\xfa\xed\xfe": ("<", 64)
    }
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                 b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        _need(data, 0, 8)
        return ("Mach-O-fat", "multiple", None, "mixed", "apple", [])
    endian, bits = formats[magic]
    _need(data, 0, 8)
    cpu = struct.unpack_from(endian + "I", data, 4)[0]
    return ("Mach-O", MACH_ARCH.get(cpu, f"unknown:{cpu}"), bits,
            "little" if endian == "<" else "big", "apple", [])


def inspect_file(path: str | Path) -> dict:
    path = Path(path)
    try:
        info = path.stat()
    except OSError as exc:
        raise InspectionError(f"cannot access file: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise InspectionError("only regular files are supported")
    if info.st_size > MAX_FILE_BYTES:
        raise InspectionError("file exceeds 2 GiB v0 inspection limit")
    if info.st_size < 4:
        raise InspectionError("file too small to identify")
    digest = hashlib.sha256()
    dependency_scan = {"status": "not_implemented", "dependencies": [],
                       "scope": "dependency extraction is implemented for ELF, PE, "
                                "WASM and Mach-O"}
    # O_NONBLOCK prevents a path replaced with a FIFO from blocking at open on
    # POSIX. Recheck the opened descriptor rather than trusting the earlier stat.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise InspectionError("only bounded regular files are supported")
        header = handle.read(HEADER_LIMIT)
        digest.update(header)
        total = len(header)
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(block)
            if total > MAX_FILE_BYTES:
                raise InspectionError("file exceeds 2 GiB inspection limit")
            digest.update(block)
        if header.startswith(b"\x7fELF"):
            scanner = inspect_dependencies
        elif header.startswith(b"MZ"):
            scanner = inspect_pe_dependencies
        elif header.startswith(b"\x00asm"):
            scanner = inspect_wasm_dependencies
        elif header[:4] in MACH_MAGICS:
            scanner = inspect_macho_dependencies
        else:
            scanner = None
        if scanner is not None:
            try:
                dependency_scan = scanner(handle, before.st_size)
            except (ElfError, BinaryError) as exc:
                raise InspectionError(str(exc)) from exc
        after = os.fstat(handle.fileno())
        if (total != before.st_size or
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise InspectionError("artifact changed during inspection")
        info = before

    if header.startswith(b"\x7fELF"):
        parser = _inspect_elf
    elif header.startswith(b"MZ"):
        parser = _inspect_pe
    elif header.startswith(b"\x00asm"):
        parser = _inspect_wasm
    elif header[:4] in MACH_MAGICS:
        parser = _inspect_mach
    else:
        raise InspectionError("unrecognized executable format")

    binary_format, arch, bits, endian, family, unknowns = parser(header)
    if binary_format == "ELF":
        unknowns = ["ELF OS ABI compatibility, dynamic loading (dlopen), transitive dependencies, symbol versions, "
                    "library search paths and runtime behavior remain unresolved"]
        unknowns.extend(dependency_scan.get("unknowns", []))
    else:
        unknowns = dependency_scan["unknowns"]
    binary = {
        "format": binary_format,
        "architecture": arch,
        "bits": bits,
        "endianness": endian,
        "ecosystem_hint": family,
    }
    if binary_format == "Mach-O-fat":
        binary["slice_architectures"] = [x["architecture"] for x in dependency_scan["slices"]]
    return {
        "schema_version": "uoe.inspection.v0.3",
        "artifact": {
            "path": str(path.resolve()),
            "sha256": digest.hexdigest(),
            "size_bytes": info.st_size,
        },
        "binary": binary,
        "evidence": ["binary magic and format-specific header fields"],
        "static_dependencies": dependency_scan["dependencies"],
        "dependency_scan": {k: v for k, v in dependency_scan.items() if k != "dependencies"},
        "unknowns": unknowns,
        "execution_attempted": False,
    }
