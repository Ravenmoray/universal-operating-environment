"""Synthetic and cross-compiled PE import observations; no artifact execution."""
import io
import os
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from uoe.binary_input import BinaryError
from uoe.pe import inspect_dependencies
from uoe.inspector import inspect_file


def fixture(bits=64):
    blob = bytearray(0x600)
    blob[:2] = b'MZ'
    struct.pack_into('<I', blob, 60, 0x80)
    blob[0x80:0x84] = b'PE\0\0'
    optional = 240 if bits == 64 else 224
    struct.pack_into('<HHIIIHH', blob, 0x84, 0x8664 if bits == 64 else 0x14c, 1, 0, 0, 0, optional, 2)
    struct.pack_into('<H', blob, 0x98, 0x20b if bits == 64 else 0x10b)
    struct.pack_into('<II', blob, 0x98 + 32, 0x1000, 0x200)
    struct.pack_into('<II', blob, 0x98 + 56, 0x2000, 0x200)
    struct.pack_into('<I', blob, 0x98 + (108 if bits == 64 else 92), 16)
    directory = 0x98 + (112 if bits == 64 else 96)
    struct.pack_into('<II', blob, directory + 8, 0x1000, 40)
    section = 0x98 + optional
    blob[section:section+8] = b'.idata\0\0'
    struct.pack_into('<IIII', blob, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into('<I', blob, section + 36, 0xc0000040)
    struct.pack_into('<IIIII', blob, 0x200, 0x1080, 0, 0, 0x10b0, 0x10e0)
    blob[0x2b0:0x2b0+12] = b'example.dll\0'
    blob[0x2c0:0x2c0+9] = b'\x07\x00DoWork\0'
    for off in (0x280, 0x2e0):
        struct.pack_into('<QQQ' if bits == 64 else '<III', blob, off,
                         0x10c0, (1 << (bits-1)) | 42, 0)
    return blob


def scan(data):
    return inspect_dependencies(io.BytesIO(data), len(data))


class PeDependencyTests(unittest.TestCase):
    def test_pe32_and_plus_names_ordinals(self):
        for bits in (32, 64):
            row = scan(fixture(bits))['dependencies'][0]
            self.assertEqual(row['name'], 'example.dll')
            self.assertEqual(row['symbols'][0]['name'], 'DoWork')
            self.assertEqual(row['symbols'][1]['ordinal'], 42)
            self.assertEqual(row['evidence']['file_offset'], 0x200)

    def test_unbound_iat_fallback(self):
        data = fixture()
        struct.pack_into('<I', data, 0x200, 0)
        self.assertEqual(scan(data)['dependencies'][0]['symbols'][0]['name'], 'DoWork')
        struct.pack_into('<I', data, 0x204, 1)
        with self.assertRaisesRegex(BinaryError, 'bound'):
            scan(data)

    def test_delay_and_clr_are_explicit_unknowns(self):
        data = fixture()
        for index in (13, 14):
            struct.pack_into('<II', data, 0x98+112+index*8, 0x1000, 32)
        result = scan(data)
        self.assertTrue(any('Delay-import' in x for x in result['unknowns']))
        self.assertTrue(any('CLR' in x for x in result['unknowns']))

    def test_bad_ranges_and_missing_terminators(self):
        for offset, fmt, value in [(60,'<I',0xffffffff), (0x86,'<H',97), (0x98+108,'<I',100),
                                  (0x98+60,'<I',1), (0x188+20,'<I',0xfffffff0),
                                  (0x98+112+8,'<I',0xffffff00), (0x98+112+12,'<I',20),
                                  (0x20c,'<I',0xfffff000), (0x280,'<Q',0x800000000001002a),
                                  (0x280,'<Q',0x100000000), (0x200,'<I',0x13f8)]:
            data = fixture()
            struct.pack_into(fmt, data, offset, value)
            if value == 0x13f8:
                struct.pack_into('<Q', data, 0x5f8, 0x800000000000002a)
            with self.subTest(offset=offset, value=value), self.assertRaises(BinaryError):
                scan(data)

    def test_overlapping_sections_fail(self):
        data = fixture()
        struct.pack_into('<H', data, 0x86, 2)
        data[0x188+40:0x188+80] = data[0x188:0x188+40]
        with self.assertRaisesRegex(BinaryError, 'overlapping'):
            scan(data)

    def test_every_truncation(self):
        data = fixture()
        for end in range(len(data)):
            with self.subTest(end=end), self.assertRaises(BinaryError):
                scan(data[:end])

    def test_seeded_mutations(self):
        rng = random.Random(25)
        for _ in range(1000):
            data = fixture(rng.choice((32,64)))
            for _ in range(rng.randint(1,4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                result = scan(data)
            except BinaryError:
                continue
            self.assertLessEqual(len(result['dependencies']), 256)

    @unittest.skipUnless(shutil.which('objdump'), 'requires GNU objdump')
    def test_synthetic_fixture_matches_objdump(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bits in (32, 64):
                path = Path(tmp) / 'fixture.exe'
                path.write_bytes(fixture(bits))
                output = subprocess.run(['objdump', '-p', str(path)], check=True,
                    capture_output=True, text=True, timeout=10, env=dict(os.environ, LC_ALL='C')).stdout
                self.assertEqual(re.findall(r'DLL Name: (.*)', output), ['example.dll'])
                self.assertIn('DoWork', output)
                self.assertEqual(inspect_file(path)['static_dependencies'][0]['symbols'][0]['name'], 'DoWork')

    @unittest.skipUnless(shutil.which('x86_64-w64-mingw32-gcc'), 'requires MinGW (main CI)')
    def test_compiled_missing_dll_matches_objdump(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'provider.c').write_text('__declspec(dllexport) int uoe_probe(void) { return 42; }')
            (root/'client.c').write_text('__declspec(dllimport) int uoe_probe(void); int main(void) { return uoe_probe(); }')
            cc = 'x86_64-w64-mingw32-gcc'
            subprocess.run([cc, '-shared', str(root/'provider.c'), '-o', str(root/'uoe_fixture.dll'),
                            '-Wl,--out-implib,'+str(root/'libfixture.a')], check=True, capture_output=True, timeout=30)
            subprocess.run([cc, str(root/'client.c'), '-L'+tmp, '-lfixture', '-o', str(root/'client.exe')],
                           check=True, capture_output=True, timeout=30)
            (root/'uoe_fixture.dll').unlink()
            report = inspect_file(root/'client.exe')
            output = subprocess.run(['x86_64-w64-mingw32-objdump', '-p', str(root/'client.exe')],
                                    check=True, capture_output=True, text=True, timeout=10).stdout
            self.assertEqual([x['name'] for x in report['static_dependencies']], re.findall(r'DLL Name: (.*)', output))
            dll = next(x for x in report['static_dependencies'] if x['name']=='uoe_fixture.dll')
            self.assertIn('uoe_probe', [x.get('name') for x in dll['symbols']])
            self.assertFalse(report['execution_attempted'])
