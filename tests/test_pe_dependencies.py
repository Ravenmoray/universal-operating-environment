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
import uoe.pe as pe
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


def with_delay(bits=64, attributes=1):
    """The base fixture plus one RVA-based delay-load descriptor (and terminator)."""
    blob = fixture(bits)
    thunks = '<QQQ' if bits == 64 else '<III'
    struct.pack_into('<IIIIIIII', blob, 0x300, attributes, 0x1140, 0x11c0, 0x11a0, 0x1160, 0, 0, 0)
    blob[0x340:0x34c] = b'delayed.dll\0'
    for table in (0x360, 0x3a0):  # import name table and IAT (identical before binding)
        struct.pack_into(thunks, blob, table, 0x1180, (1 << (bits - 1)) | 7, 0)
    struct.pack_into('<H', blob, 0x380, 5)
    blob[0x382:0x38b] = b'LazyCall\0'
    directory = 0x98 + (112 if bits == 64 else 96)
    struct.pack_into('<II', blob, directory + 13 * 8, 0x1100, 64)
    return blob


def big_import_fixture(count, bits=64, dll_name=b'big.dll'):
    """A PE whose single import descriptor names ``count`` symbols from one DLL.

    Realistic size: short names, one hint/name entry each, so the read budget (not the
    symbol count) is what limited the earlier parser to roughly 1,950 names.
    """
    width = 8 if bits == 64 else 4
    ilt_size = (count + 1) * width
    ilt, iat = 0x50, 0x50 + ilt_size
    entries_at = iat + ilt_size
    entries, offsets = bytearray(), []
    for i in range(count):
        offsets.append(entries_at + len(entries))
        name = f'f{i:05d}'.encode() + b'\0'
        entries += struct.pack('<H', i & 0xffff) + name + (b'\0' if len(name) % 2 else b'')
    name_at = entries_at + len(entries)
    content = bytearray(entries_at) + entries + dll_name + b'\0'
    struct.pack_into('<IIIII', content, 0, 0x1000 + ilt, 0, 0, 0x1000 + name_at, 0x1000 + iat)
    thunk = '<Q' if bits == 64 else '<I'
    for table in (ilt, iat):
        for i, offset in enumerate(offsets):
            struct.pack_into(thunk, content, table + i * width, 0x1000 + offset)
    raw = (len(content) + 0x1ff) & ~0x1ff
    blob = bytearray(fixture(bits)[:0x200]) + content + bytes(raw - len(content))
    optional = 240 if bits == 64 else 224
    directory = 0x98 + (112 if bits == 64 else 96)
    struct.pack_into('<II', blob, directory + 8, 0x1000, 40)
    struct.pack_into('<I', blob, 0x98 + 56, 0x1000 + raw)
    section = 0x98 + optional
    struct.pack_into('<IIII', blob, section + 8, raw, 0x1000, raw, 0x200)
    return bytes(blob)


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

    def test_delay_imports_are_observed_and_distinguished(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                result = scan(with_delay(bits))
                self.assertFalse(any('Delay-import' in x for x in result['unknowns']))
                normal, delayed = result['dependencies']
                self.assertEqual((normal['name'], normal['load_kind']), ('example.dll', 'static'))
                self.assertEqual((delayed['name'], delayed['load_kind']), ('delayed.dll', 'delay'))
                self.assertEqual(delayed['symbols'][0]['name'], 'LazyCall')
                self.assertEqual(delayed['symbols'][0]['hint'], 5)
                self.assertEqual(delayed['symbols'][1]['ordinal'], 7)
                self.assertEqual(delayed['evidence']['source'], 'PE_DELAY_IMPORT_DESCRIPTOR')
                self.assertEqual(delayed['evidence']['file_offset'], 0x300)
                self.assertEqual(delayed['evidence']['name_file_offset'], 0x340)

    def test_planner_flags_delay_loaded_dlls_as_conditional(self):
        from uoe.planner import plan_inspection
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'delayed.exe'
            path.write_bytes(with_delay())
            report = inspect_file(path)
        plan = plan_inspection(report, host_os='linux', host_arch='x86_64', available={'wine': True})
        notes = ' '.join(plan['strategies'][0]['constraints'])
        self.assertIn('Delay-loaded DLLs', notes)
        self.assertIn('delayed.dll', notes)
        self.assertNotIn('example.dll', notes.split('Delay-loaded DLLs')[1])
        self.assertFalse(plan['strategies'][0]['verified_compatible'])

    def test_planner_notes_reach_every_host_and_list_delay_dlls_in_sorted_order(self):
        from uoe.planner import plan_inspection
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'delayed.exe'
            path.write_bytes(with_delay())
            report = inspect_file(path)
        for name in ('zeta.dll', 'alpha.dll'):                  # appended out of order
            report['static_dependencies'].append({'kind': 'shared_library', 'name': name, 'status': 'observed',
                                                  'load_kind': 'delay', 'symbols': []})
        for host_os in ('linux', 'windows', 'macos'):
            plan = plan_inspection(report, host_os=host_os, host_arch='x86_64', available={'wine': True})
            notes = ' '.join(plan['strategies'][0]['constraints'])
            with self.subTest(host_os):
                self.assertIn('alpha.dll, delayed.dll, zeta.dll', notes)
                self.assertFalse(plan['strategies'][0]['verified_compatible'])

    def test_delay_only_binaries_have_no_normal_imports(self):
        data = with_delay()
        directory = 0x98 + 112
        struct.pack_into('<II', data, directory + 8, 0, 0)
        result = scan(data)
        self.assertEqual([(d['load_kind'], d['name']) for d in result['dependencies']],
                         [('delay', 'delayed.dll')])

    def test_malformed_delay_descriptors_are_rejected(self):
        directory = 0x98 + 112
        backed, incomplete = 'not uniquely file-backed', 'incomplete PE delay-import descriptor'
        inconsistent = 'inconsistent PE delay-import directory'
        cases = {
            'reserved attribute bits': (lambda b: struct.pack_into('<I', b, 0x300, 3), 'descriptor attributes'),
            'no dll name': (lambda b: struct.pack_into('<I', b, 0x304, 0), incomplete),
            'no name table': (lambda b: struct.pack_into('<I', b, 0x310, 0), incomplete),
            'no address table': (lambda b: struct.pack_into('<I', b, 0x30c, 0), incomplete),
            'directory rva without size': (lambda b: struct.pack_into('<I', b, directory + 13 * 8 + 4, 0), inconsistent),
            'directory size without rva': (lambda b: struct.pack_into('<II', b, directory + 13 * 8, 0, 64), inconsistent),
            'unterminated directory': (lambda b: struct.pack_into('<I', b, directory + 13 * 8 + 4, 32),
                                       'unterminated or oversized PE delay-import directory'),
            'directory larger than its section': (lambda b: struct.pack_into('<I', b, directory + 13 * 8 + 4, 0x4000), backed),
            'name outside file': (lambda b: struct.pack_into('<I', b, 0x304, 0xfffff000), backed),
            'name table outside file': (lambda b: struct.pack_into('<I', b, 0x310, 0xfffff000), backed),
            'name table runs off its section': (lambda b: (
                struct.pack_into('<I', b, 0x310, 0x13f8),
                struct.pack_into('<Q', b, 0x5f8, (1 << 63) | 3)), backed),
            'ordinal reserved bits': (lambda b: struct.pack_into('<Q', b, 0x368, (1 << 63) | (1 << 40) | 7),
                                      'ordinal reserved bits'),
        }
        for label, (mutate, pattern) in cases.items():
            data = with_delay()
            mutate(data)
            with self.subTest(label), self.assertRaisesRegex(BinaryError, pattern):
                scan(data)

    def test_directory_sizes_must_be_file_backed_for_imports_and_delay_imports(self):
        # The declared extent of a descriptor directory is located as a whole, not just its start.
        data = with_delay()
        struct.pack_into('<I', data, 0x98 + 112 + 8 + 4, 0x4000)           # import directory
        with self.assertRaisesRegex(BinaryError, 'not uniquely file-backed'):
            scan(data)

    def test_legacy_pointer_based_delay_descriptors_are_unknowns_not_failures(self):
        data = with_delay(attributes=0)
        result = scan(data)
        # The normal import is still reported; the undecodable legacy descriptor is an unknown.
        self.assertEqual([(d['load_kind'], d['name']) for d in result['dependencies']],
                         [('static', 'example.dll')])
        self.assertTrue(any('Legacy pointer-based' in x for x in result['unknowns']))
        self.assertFalse(any('Legacy pointer-based' in x for x in scan(with_delay())['unknowns']))
        # ...whereas reserved attribute bits are malformed, not merely unsupported.
        for attributes in (2, 3, 0x80000001):
            with self.subTest(attributes=attributes), self.assertRaisesRegex(BinaryError, 'attributes'):
                scan(with_delay(attributes=attributes))

    def test_documented_symbol_limit_is_reachable(self):
        # Earlier, each name read charged the read budget for up to 4 KiB, so a valid PE with
        # about 1,950 named imports was rejected although the documented limit is 4,096.
        for bits in (32, 64):
            with self.subTest(bits=bits, count=pe.MAX_SYMBOLS):
                result = scan(big_import_fixture(pe.MAX_SYMBOLS, bits))
                self.assertEqual(len(result['dependencies'][0]['symbols']), pe.MAX_SYMBOLS)
                self.assertEqual(result['dependencies'][0]['symbols'][-1]['name'], f'f{pe.MAX_SYMBOLS - 1:05d}')
        with self.assertRaisesRegex(BinaryError, 'symbol count limit'):
            scan(big_import_fixture(pe.MAX_SYMBOLS + 1))

    def test_names_are_charged_for_the_bytes_actually_read(self):
        from unittest.mock import patch
        from uoe.binary_input import Reader
        data = big_import_fixture(2300)
        spent = []

        class Recording(Reader):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                spent.append(self)

        with patch.object(pe, 'Reader', Recording):
            inspect_dependencies(io.BytesIO(data), len(data))
        used = 8_000_000 - spent[0].remaining
        # 2,300 names of 7 bytes: one 64-byte chunk per name, plus the lookup table thunks and
        # hints (measured: about 170,000). Charging the 4,097-byte worst case per name would be
        # ~9.4 MB, so a loose bound would still catch it but not a chunk size creeping upwards.
        self.assertLess(used, 250_000)
        self.assertGreater(used, 2300 * 64)

    def test_import_names_may_be_exactly_the_documented_length(self):
        # MAX_NAME bytes plus the NUL fit; one more byte does not. A name that ends exactly at
        # the end of the allowance is the boundary that a chunked reader gets wrong.
        for length, accepted in ((pe.MAX_NAME, True), (pe.MAX_NAME + 1, False)):
            data = big_import_fixture(2, dll_name=b'd' * length)
            with self.subTest(length=length):
                if accepted:
                    self.assertEqual(scan(data)['dependencies'][0]['name'], 'd' * length)
                else:
                    with self.assertRaisesRegex(BinaryError, 'empty, overlong or unterminated PE import name'):
                        scan(data)

    def test_reader_cstring_semantics(self):
        from uoe.binary_input import Reader, StringError

        def read(data, offset=0, available=None, limit=4096, **kw):
            reader = Reader(io.BytesIO(data), len(data))
            return reader.cstring(offset, len(data) - offset if available is None else available, limit, **kw), reader
        # the NUL in the first/last byte of a chunk and the first byte of the next
        for length in (0, 1, 62, 63, 64, 65, 127, 128, 129):
            with self.subTest(length=length):
                value, _ = read(b'a' * length + b'\0' + b'tail')
                self.assertEqual(value, b'a' * length)
        # the allowance: `limit` bytes plus the NUL are fine, one more byte is not
        self.assertEqual(read(b'a' * 10 + b'\0', limit=10)[0], b'a' * 10)
        with self.assertRaises(StringError):
            read(b'a' * 11 + b'\0', limit=10)
        self.assertEqual(read(b'\0', limit=0)[0], b'')
        with self.assertRaises(StringError):
            read(b'a\0', limit=0)
        # the region ends before the NUL (a NUL beyond `available` must not be found)
        with self.assertRaises(StringError):
            read(b'abcdef\0', available=6)
        self.assertEqual(read(b'abcdef\0', available=7)[0], b'abcdef')
        with self.assertRaises(StringError):
            read(b'\0abc', available=0)
        # an offset inside a larger buffer, and the budget is charged for what was read
        value, reader = read(b'xx' + b'name\0' + b'z' * 200, offset=2)
        self.assertEqual((value, reader.remaining), (b'name', 8_000_000 - 64))
        value, reader = read(b'name\0', offset=0)
        self.assertEqual((value, reader.remaining), (b'name', 8_000_000 - 5))

    def test_a_bound_import_with_a_lookup_table_is_read_from_the_lookup_table(self):
        # In a bound image the IAT holds resolved addresses, so only the lookup table has names.
        for bits in (32, 64):
            for stamp in (0, 0x5f5e100):               # TimeDateStamp != 0 marks a bound import
                data = fixture(bits)
                struct.pack_into('<I', data, 0x204, stamp)
                struct.pack_into('<QQQ' if bits == 64 else '<III', data, 0x2e0,
                                 0x7ff812340000 if bits == 64 else 0x77001000,
                                 0x7ff812340010 if bits == 64 else 0x77001010, 0)
                with self.subTest(bits=bits, stamp=stamp):
                    row = scan(data)['dependencies'][0]
                    self.assertEqual([x.get('name') for x in row['symbols']], ['DoWork', None])
                    self.assertEqual(row['symbols'][1]['ordinal'], 42)

    def test_delay_names_come_from_the_name_table_not_the_address_table(self):
        for bits in (32, 64):
            data = with_delay(bits)
            struct.pack_into('<QQQ' if bits == 64 else '<III', data, 0x3a0,       # bound delay IAT
                             0x7ff812340000 if bits == 64 else 0x77001000,
                             0x7ff812340010 if bits == 64 else 0x77001010, 0)
            with self.subTest(bits=bits):
                delayed = scan(data)['dependencies'][1]
                self.assertEqual([x.get('name') for x in delayed['symbols']], ['LazyCall', None])

    def test_truncation_inside_the_delay_tables_reaches_the_delay_parser(self):
        # The every-truncation test fails at the PE section check. Here the file stays whole but
        # the section's file-backed size ends at `cut`: the normal imports (needing bytes up to
        # 0xc9) parse, so any failure between 0xca and the end of the delay tables (0x18a) is the
        # delay-load path hitting data that is not there.
        data = with_delay()
        section = 0x98 + 240
        no_delay = bytearray(data)
        struct.pack_into('<II', no_delay, 0x98 + 112 + 13 * 8, 0, 0)
        for cut in range(0xca, 0x18b):
            cropped = bytearray(data[:0x200 + cut])
            struct.pack_into('<I', cropped, section + 16, cut)
            plain = bytearray(no_delay[:0x200 + cut])
            struct.pack_into('<I', plain, section + 16, cut)
            self.assertEqual(len(scan(bytes(plain))['dependencies']), 1, cut)    # normal import survives
            with self.subTest(cut=cut), self.assertRaisesRegex(
                    BinaryError, 'not uniquely file-backed|empty, overlong or unterminated PE import name'):
                scan(bytes(cropped))
        whole = bytearray(data[:0x200 + 0x18b])
        struct.pack_into('<I', whole, section + 16, 0x18b)
        self.assertEqual([d['load_kind'] for d in scan(bytes(whole))['dependencies']], ['static', 'delay'])

    def test_normal_and_delay_imports_share_the_symbol_and_dll_budgets(self):
        from unittest.mock import patch
        import uoe.pe as pe
        data = with_delay()
        self.assertEqual(len(scan(data)['dependencies']), 2)  # 2 + 2 symbols, 2 DLLs
        with patch.object(pe, 'MAX_SYMBOLS', 3), self.assertRaisesRegex(BinaryError, 'symbol count'):
            scan(data)
        with patch.object(pe, 'MAX_DLLS', 1), self.assertRaisesRegex(BinaryError, 'DLL count'):
            scan(data)

    def test_clr_directory_is_decoded_not_just_flagged(self):
        # A CLR directory smaller than an IMAGE_COR20_HEADER cannot be a managed image;
        # it is now rejected rather than reported as an unenumerated unknown. Positive
        # cases and malformed metadata are covered in test_clr_dependencies.py.
        data = fixture()
        struct.pack_into('<II', data, 0x98 + 112 + 14 * 8, 0x1000, 32)
        with self.assertRaisesRegex(BinaryError, 'CLR'):
            scan(data)

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
        for data in (fixture(), with_delay(), with_delay(32)):
            for end in range(len(data)):
                with self.subTest(size=len(data), end=end), self.assertRaises(BinaryError):
                    scan(data[:end])

    def test_seeded_mutations(self):
        rng = random.Random(25)
        for _ in range(2000):
            data = rng.choice((fixture, with_delay))(rng.choice((32,64)))
            for _ in range(rng.randint(1,4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                result = scan(data)
            except BinaryError:
                continue
            self.assertLessEqual(len(result['dependencies']), 256)
            for dependency in result['dependencies']:
                self.assertIn(dependency['load_kind'], ('static', 'delay'))

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

    @unittest.skipUnless(all(shutil.which(t) for t in ('clang', 'lld-link', 'llvm-dlltool', 'llvm-readobj')),
                         'requires clang, lld-link, llvm-dlltool and llvm-readobj')
    def test_linked_delay_load_images_match_llvm_readobj(self):
        # Project-owned source linked with LLVM's COFF linker against import
        # libraries generated from .def files: no Windows SDK, nothing is executed.
        source = (
            '__declspec(dllimport) unsigned long __stdcall GetCurrentProcessId(void);\n'
            '__declspec(dllimport) void __stdcall ExitProcess(unsigned int);\n'
            '__declspec(dllimport) int __stdcall MessageBoxA(void*, const char*, const char*, unsigned);\n'
            '__declspec(dllimport) void* __stdcall GetDesktopWindow(void);\n'
            'void* __delayLoadHelper2(void* a, void* b) { (void)a; (void)b; return 0; }\n'
            'int mainCRTStartup(void) {\n'
            '  MessageBoxA(GetDesktopWindow(), "x", "y", GetCurrentProcessId());\n'
            '  ExitProcess(0);\n  return 0;\n}\n')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'main.c').write_text(source)
            (root / 'kernel32.def').write_text('LIBRARY kernel32.dll\nEXPORTS\nGetCurrentProcessId\nExitProcess\n')
            (root / 'user32.def').write_text('LIBRARY user32.dll\nEXPORTS\nMessageBoxA\nGetDesktopWindow\n')
            for machine, target in (('i386:x86-64', 'x86_64-pc-windows-msvc'), ('arm64', 'aarch64-pc-windows-msvc')):
                tag = machine.split(':')[0]
                steps = [
                    ['llvm-dlltool', '-m', machine, '-d', str(root / 'kernel32.def'), '-l', str(root / f'k32_{tag}.lib')],
                    ['llvm-dlltool', '-m', machine, '-d', str(root / 'user32.def'), '-l', str(root / f'u32_{tag}.lib')],
                    ['clang', f'--target={target}', '-c', '-O1', '-fno-stack-protector',
                     str(root / 'main.c'), '-o', str(root / f'main_{tag}.obj')],
                    ['lld-link', '/nodefaultlib', '/subsystem:console', '/entry:mainCRTStartup',
                     f'/out:{root / ("delay_" + tag + ".exe")}', str(root / f'main_{tag}.obj'),
                     str(root / f'k32_{tag}.lib'), str(root / f'u32_{tag}.lib'), '/delayload:user32.dll'],
                ]
                for step in steps:
                    done = subprocess.run(step, capture_output=True, text=True, timeout=60)
                    if done.returncode:
                        self.skipTest(f'LLVM cannot build {target} PE here: ' + done.stderr[-200:])
                exe = root / f'delay_{tag}.exe'
                report = inspect_file(exe)
                reference = subprocess.run(['llvm-readobj', '--coff-imports', str(exe)], check=True,
                                           capture_output=True, text=True, timeout=30).stdout
                # Whole blocks, not just DLL names: every symbol, in order, per DLL.
                blocks = re.findall(r'^(Delay)?Import \{\s*\n\s+Name: (.*?)\n(.*?)\n\}', reference, re.S | re.M)
                expected = [('delay' if kind else 'static', name,
                             [symbol for symbol, _ in re.findall(r'Symbol: (.+?) \((\d+)\)', body)])
                            for kind, name, body in blocks]
                self.assertEqual([(d['load_kind'], d['name'], [x['name'] for x in d['symbols']])
                                  for d in report['static_dependencies']], expected)
                self.assertEqual([(kind, name) for kind, name, _ in expected],
                                 [('static', 'kernel32.dll'), ('delay', 'user32.dll')])
                self.assertEqual(sorted(expected[1][2]), ['GetDesktopWindow', 'MessageBoxA'])
                self.assertEqual(sorted(expected[0][2]), ['ExitProcess', 'GetCurrentProcessId'])
                self.assertFalse(report['execution_attempted'])

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
