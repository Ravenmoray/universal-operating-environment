"""ELF dependency tests; generated artifacts are never executed."""
import io
import os
from pathlib import Path
import random
import re
import shutil
import struct
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from uoe.elf import ElfError, inspect_dependencies
from uoe.inspector import inspect_file
from uoe.planner import plan_inspection


def fixture(bits=64, endian='<', strings_offset=0x300, padding=0):
    """Section-free executable with independent program-header observations."""
    eh = 64 if bits == 64 else 52
    ph = 56 if bits == 64 else 32
    dyn_size = 16 if bits == 64 else 8
    interp = b'/example/loader\0'
    strings = b'\0libone.so\0libtwo.so\0' + b'\0' * padding
    data = bytearray(strings_offset + len(strings))
    data[:7] = b'\x7fELF' + bytes([2 if bits == 64 else 1, 1 if endian == '<' else 2, 1])
    struct.pack_into(endian + ('HHIQQQIHHHHHH' if bits == 64 else 'HHIIIIIHHHHHH'),
                     data, 16, 2, 62 if bits == 64 else 3, 1, 0, eh, 0, 0, eh, ph, 3, 0, 0, 0)
    segments = [(1, 0, 0x400000, len(data)), (3, 0x200, 0x400200, len(interp)),
                (2, 0x240, 0x400240, 5 * dyn_size)]
    for i, (typ, offset, address, size) in enumerate(segments):
        values = (typ, 4, offset, address, address, size, size, 1) if bits == 64 else (
            typ, offset, address, address, size, size, 4, 1)
        struct.pack_into(endian + ('IIQQQQQQ' if bits == 64 else 'IIIIIIII'), data, eh + i * ph, *values)
    data[0x200:0x200 + len(interp)] = interp
    data[strings_offset:] = strings
    for i, (tag, value) in enumerate([(5, 0x400000 + strings_offset), (10, len(strings)),
                                    (1, 1), (1, 11), (0, 0)]):
        struct.pack_into(endian + ('qQ' if bits == 64 else 'iI'), data, 0x240 + i * dyn_size, tag, value)
    return data


def scan(data):
    return inspect_dependencies(io.BytesIO(data), len(data))


class ElfDependencyTests(unittest.TestCase):
    def test_both_classes_and_byte_orders(self):
        for bits in (32, 64):
            for endian in ('<', '>'):
                with self.subTest(bits=bits, endian=endian):
                    result = scan(fixture(bits, endian))
                    self.assertEqual(result['status'], 'complete_static')
                    self.assertEqual([d['name'] for d in result['dependencies']],
                                     ['/example/loader', 'libone.so', 'libtwo.so'])
                    self.assertEqual(result['dependencies'][1]['evidence']['string_file_offset'], 0x301)

    def test_string_table_beyond_header_window(self):
        self.assertEqual(scan(fixture(strings_offset=2_000_000))['dependencies'][2]['name'], 'libtwo.so')

    def test_string_table_larger_than_read_budget_is_not_read_whole(self):
        # Real executables (e.g. node) have tens of megabytes of .dynstr; only the
        # referenced names should be read, not the table.
        data = fixture(padding=20_000_000)
        result = scan(data)
        self.assertEqual([d['name'] for d in result['dependencies']],
                         ['/example/loader', 'libone.so', 'libtwo.so'])
        self.assertEqual(result['status'], 'complete_static')

    def test_segments_without_file_content_are_reported_not_guessed(self):
        # objcopy --only-keep-debug leaves PT_DYNAMIC/PT_INTERP with p_filesz == 0.
        for label, segment in (('PT_DYNAMIC', 2), ('PT_INTERP', 1)):
            data = fixture()
            struct.pack_into('<Q', data, 64 + segment * 56 + 32, 0)
            struct.pack_into('<Q', data, 64 + segment * 56 + 40, 0)
            with self.subTest(label):
                result = scan(data)
                self.assertEqual(result['status'], 'partial_static')
                self.assertTrue(any(label in x for x in result['unknowns']))
                names = [d['name'] for d in result['dependencies']]
                self.assertEqual(names, ['libone.so', 'libtwo.so'] if label == 'PT_INTERP'
                                 else ['/example/loader'])

    def test_debug_file_report_carries_the_unknown(self):
        data = fixture()
        for segment in (1, 2):
            struct.pack_into('<QQ', data, 64 + segment * 56 + 32, 0, 0)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'debug.elf'
            path.write_bytes(data)
            report = inspect_file(path)
        self.assertEqual(report['dependency_scan']['status'], 'partial_static')
        self.assertEqual(report['static_dependencies'], [])
        self.assertTrue(any('no file content' in x for x in report['unknowns']))
        self.assertTrue(any('dlopen' in x for x in report['unknowns']))

    def test_no_dynamic_segment_has_no_invented_libraries(self):
        data = fixture()
        struct.pack_into('<I', data, 64 + 2 * 56, 0)
        self.assertEqual([d['kind'] for d in scan(data)['dependencies']], ['interpreter'])

    def test_rel_object_scope_is_explicit(self):
        data = fixture()
        struct.pack_into('<H', data, 16, 1)
        self.assertEqual(scan(data)['status'], 'unsupported_object_type')
        self.assertEqual(scan(data)['dependencies'], [])

    def test_malformed_ranges_and_metadata_fail(self):
        cases = [
            (32, '<Q', 2**64-1),             # program table outside file
            (56, '<H', 0xffff),              # extended numbering unsupported
            (56, '<H', 4097),                # table count budget
            (54, '<H', 1),                   # wrong entry size
            (52, '<H', 1),                   # wrong header size
            (20, '<I', 0),                   # invalid version
            (64 + 32, '<Q', 2**64-1),        # load segment file size
            (64 + 40, '<Q', 1),              # load memory smaller than file
            (64 + 16, '<Q', 2**64-1),        # virtual address overflow
            (64 + 56, '<I', 2),              # duplicate dynamic segments
            (0x240 + 8, '<Q', 0x900000),     # unmapped DT_STRTAB
            (0x250 + 8, '<Q', 1_000_001),    # string table exceeds its mapping
            (0x260 + 8, '<Q', 9000),         # needed string out of range
            (0x280, '<q', 1),                # missing DT_NULL
            (0x250, '<q', 5),                # duplicate DT_STRTAB
        ]
        for offset, fmt, value in cases:
            data = fixture()
            struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ElfError):
                scan(data)

    def test_overlapping_mapping_rejected(self):
        data = fixture()
        # Change the interpreter segment into a load inside the first load.
        struct.pack_into('<I', data, 64 + 56, 1)
        with self.assertRaisesRegex(ElfError, 'overlapping'):
            scan(data)

    def test_names_must_be_terminated_nonempty_and_supported(self):
        for offset, value in [(0x20f, 120), (0x301, 0), (0x301, 255), (len(fixture())-1, 120)]:
            data = fixture()
            data[offset] = value
            with self.subTest(offset=offset, value=value), self.assertRaises(ElfError):
                scan(data)

    def test_all_truncations_fail_cleanly(self):
        data = fixture()
        for end in range(len(data)):
            with self.subTest(end=end), self.assertRaises(ElfError):
                scan(data[:end])

    def test_seeded_byte_mutations_never_escape_parser_errors(self):
        rng = random.Random(13)
        original = fixture()
        for _ in range(1000):
            data = original[:]
            for _ in range(rng.randint(1, 4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                result = scan(data)
            except ElfError:
                continue
            self.assertIn(result['status'], ('complete_static', 'partial_static',
                                             'unsupported_object_type'))
            self.assertLessEqual(len(result['dependencies']), 257)

    def test_concurrent_change_is_rejected(self):
        from uoe.inspector import InspectionError
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.elf'
            path.write_bytes(fixture())
            def changed(stream, size):
                with path.open('ab') as out:
                    out.write(b'x')
                return {'status': 'complete_static', 'dependencies': [], 'scope': 'test'}
            with patch('uoe.inspector.inspect_dependencies', side_effect=changed):
                with self.assertRaisesRegex(InspectionError, 'changed during'):
                    inspect_file(path)

    def test_inspector_and_planner_never_execute_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.elf'
            path.write_bytes(fixture())
            with patch.object(subprocess, 'Popen', side_effect=AssertionError('execution')):
                report = inspect_file(path)
                plan = plan_inspection(report, host_os='linux', host_arch='x86_64')
            self.assertEqual(len(plan['observed_requirements']), 3)
            self.assertFalse(plan['execution_attempted'])
            self.assertTrue(any('dlopen' in x for x in report['unknowns']))

    @unittest.skipUnless(sys.platform == 'linux' and shutil.which('cc') and shutil.which('readelf'), 'requires compiler and readelf')
    def test_project_owned_missing_library_matches_readelf(self):
        # Compile a direct dependency, remove it, then inspect without running
        # either the client or shared library. No ldd or loader invocation.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'provider.c').write_text('int uoe_example(void) { return 42; }\n')
            (root / 'client.c').write_text('extern int uoe_example(void); int main(void) { return uoe_example(); }\n')
            library = root / 'libuoe_fixture.so'
            client = root / 'client'
            for cmd in ([shutil.which('cc'), '-shared', '-fPIC', str(root/'provider.c'),
                         '-Wl,-soname,libuoe_fixture.so', '-o', str(library)],
                        [shutil.which('cc'), str(root/'client.c'), '-L'+tmp, '-luoe_fixture', '-o', str(client)]):
                subprocess.run(cmd, check=True, capture_output=True, timeout=30)
            library.unlink()
            env = dict(os.environ, LC_ALL='C')
            dynamic = subprocess.run(['readelf', '-dW', str(client)], env=env, check=True,
                                     capture_output=True, text=True, timeout=10).stdout
            headers = subprocess.run(['readelf', '-lW', str(client)], env=env, check=True,
                                     capture_output=True, text=True, timeout=10).stdout
            report = inspect_file(client)
            libraries = [d['name'] for d in report['static_dependencies'] if d['kind'] == 'shared_library']
            self.assertEqual(libraries, re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic))
            self.assertIn('libuoe_fixture.so', libraries)
            interpreter = [d['name'] for d in report['static_dependencies'] if d['kind'] == 'interpreter']
            self.assertEqual(interpreter, re.findall(r'Requesting program interpreter: (.*?)\]', headers))
            self.assertFalse(report['execution_attempted'])
