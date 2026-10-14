"""No binaries are executed by these unit tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from uoe.inspector import InspectionError, inspect_file
from uoe.planner import plan_inspection


def elf(machine=62, endian="<", bits=64):
    blob = bytearray(64)
    blob[0:4] = b"\x7fELF"
    blob[4] = 2 if bits == 64 else 1
    blob[5] = 1 if endian == "<" else 2
    blob[6] = 1
    struct.pack_into(endian + "HHI", blob, 16, 2, machine, 1)
    struct.pack_into(endian + "H", blob, 52 if bits == 64 else 40, 64 if bits == 64 else 52)
    return bytes(blob)


def pe(machine=0x8664, magic=0x20b):
    blob = bytearray(512)
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3c, 0x80)
    blob[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", blob, 0x84, machine)
    struct.pack_into("<H", blob, 0x98, magic)
    return bytes(blob)


def mach(cpu=0x01000007):
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu) + b"\x00" * 32


class UoeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.temp = Path(self.folder.name)

    def make(self, data, name="fixture.bin"):
        path = self.temp / name
        path.write_bytes(data)
        return path

    def test_elf_and_sha256(self):
        data = elf()
        r = inspect_file(self.make(data))
        self.assertEqual(r["binary"]["format"], "ELF")
        self.assertEqual(r["binary"]["architecture"], "x86_64")
        self.assertEqual(r["binary"]["bits"], 64)
        self.assertEqual(r["artifact"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertFalse(r["execution_attempted"])

    def test_big_endian_arm_elf(self):
        r = inspect_file(self.make(elf(machine=40, endian=">", bits=32)))
        self.assertEqual(r["binary"]["architecture"], "arm")
        self.assertEqual(r["binary"]["endianness"], "big")

    def test_pe_and_machine(self):
        r = inspect_file(self.make(pe()))
        self.assertEqual((r["binary"]["format"], r["binary"]["architecture"]),
                         ("PE", "x86_64"))
        self.assertTrue(r["unknowns"])

    def test_pe32(self):
        r = inspect_file(self.make(pe(machine=0x14c, magic=0x10b)))
        self.assertEqual(r["binary"]["bits"], 32)

    def test_wasm(self):
        r = inspect_file(self.make(b"\x00asm\x01\x00\x00\x00"))
        self.assertEqual(r["binary"]["format"], "WASM")

    def test_mach(self):
        r = inspect_file(self.make(mach()))
        self.assertEqual(r["binary"]["architecture"], "x86_64")

    def test_fat_mach_is_explicitly_unresolved(self):
        r = inspect_file(self.make(b"\xca\xfe\xba\xbe\x00\x00\x00\x02"))
        self.assertEqual(r["binary"]["format"], "Mach-O-fat")
        self.assertEqual(r["binary"]["architecture"], "multiple")

    def test_invalid_elf_endianness_rejected(self):
        data = bytearray(elf())
        data[5] = 0
        with self.assertRaises(InspectionError):
            inspect_file(self.make(data))

    def test_invalid_pe_offset_rejected(self):
        data = bytearray(pe())
        struct.pack_into("<I", data, 0x3c, 0xffffffff)
        with self.assertRaises(InspectionError):
            inspect_file(self.make(data))

    def test_invalid_pe_signature_rejected(self):
        data = bytearray(pe())
        data[0x80:0x84] = b"oops"
        with self.assertRaises(InspectionError):
            inspect_file(self.make(data))

    def test_unsupported_wasm_version_rejected(self):
        with self.assertRaises(InspectionError):
            inspect_file(self.make(b"\x00asm\x02\x00\x00\x00"))

    def test_unknown_and_truncated_files_rejected(self):
        for data in (b"NOPE", b"\x7fELF", b"MZ", b"\x00asm"):
            with self.subTest(data=data), self.assertRaises(InspectionError):
                inspect_file(self.make(data))

    def test_reject_directory_and_special_file(self):
        with self.assertRaises(InspectionError):
            inspect_file(self.temp)

    def test_native_candidate_is_not_compatibility_proof(self):
        r = plan_inspection(inspect_file(self.make(elf())), host_os="linux", host_arch="x86_64")
        self.assertEqual(r["status"], "candidates_found")
        self.assertFalse(r["strategies"][0]["verified_compatible"])
        self.assertFalse(r["execution_attempted"])

    def test_cross_arch_native_is_unavailable(self):
        r = plan_inspection(inspect_file(self.make(elf(machine=183))),
                            host_os="linux", host_arch="x86_64")
        self.assertEqual(r["status"], "unresolved")

    def test_wine_candidate_requires_runner_and_matching_arch(self):
        scanned = inspect_file(self.make(pe()))
        r = plan_inspection(scanned, host_os="linux", host_arch="amd64",
                            available={"wine": True})
        self.assertEqual(r["status"], "candidates_found")
        r = plan_inspection(scanned, host_os="linux", host_arch="amd64",
                            available={"wine": False})
        self.assertEqual(r["status"], "unresolved")
        self.assertEqual(r["strategies"][0]["runner"], "wine")

    def test_wasm_runner_not_proof_of_wasi_support(self):
        r = plan_inspection(inspect_file(self.make(b"\x00asm\x01\x00\x00\x00")),
                            host_os="linux", available={"wasmtime": True})
        self.assertTrue(r["unresolved"])
        self.assertFalse(r["strategies"][0]["verified_compatible"])

    def test_fat_mach_has_no_implicit_candidate(self):
        r = plan_inspection(
            inspect_file(self.make(b"\xca\xfe\xba\xbe\x00\x00\x00\x02")),
            host_os="darwin", host_arch="x86_64"
        )
        self.assertEqual(r["status"], "unresolved")

    def test_static_operations_do_not_launch_programs(self):
        with patch.object(subprocess, "run", side_effect=AssertionError("execution attempted")):
            p = self.make(pe())
            scan = inspect_file(p)
            plan_inspection(scan, host_os="linux", available={"wine": True})

    def test_cli_json_inspection(self):
        p = self.make(pe())
        result = subprocess.run([sys.executable, "-m", "uoe", "inspect", str(p)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["binary"]["format"], "PE")

    def test_demo_requires_explicit_execution(self):
        r = subprocess.run([sys.executable, "-m", "uoe", "demo"],
                           capture_output=True, text=True, check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--execute-reviewed-fixture", r.stderr)


if __name__ == "__main__":
    unittest.main()
