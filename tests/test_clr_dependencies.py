"""CLR (.NET) metadata observations; generated assemblies are never loaded or run.

The synthetic builder below lays out ECMA-335 metadata by hand with explicit,
independently written row sizes (it deliberately does not reuse uoe.clr's schema
table), so a mistake in the parser's size arithmetic shows up as a wrong offset.
The optional comparison tests use the third-party ``dnfile`` package, if it is
importable, as an independent parser of the same bytes.
"""
import hashlib
import io
import random
import struct
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from uoe.binary_input import BinaryError
from uoe.inspector import inspect_file
from uoe.pe import inspect_dependencies
from uoe.planner import plan_inspection
import uoe.clr as clr

try:
    import dnfile
except ImportError:  # optional independent oracle
    dnfile = None

ECMA_KEY = bytes([0] * 8 + [4] + [0] * 7)       # public key of the ECMA standard
ECMA_TOKEN = 'b77a5c561934e089'                  # its well-known token (mscorlib)
SECTION_RVA = 0x1000


def pad4(data):
    return data + b'\0' * (-len(data) % 4)


def blob_entry(data):
    assert len(data) < 0x80
    return bytes([len(data)]) + data


def build_metadata(assemblies=(), modules=(), *, wide_heaps=0, padding=None, version=b'v4.0.30319',
                   stream_names=('#~', '#Strings', '#GUID', '#Blob'), edit=None):
    """Return metadata bytes. ``assemblies`` = (name, (a, b, c, d), flags, key, culture).

    ``padding`` maps a table id to (row_count, row_size) of zero-filled filler tables
    whose row sizes the *test* supplies (used to force wide indexes).
    """
    w_s = 4 if wide_heaps & 1 else 2
    w_g = 4 if wide_heaps & 2 else 2
    w_b = 4 if wide_heaps & 4 else 2
    strings, blobs = bytearray(b'\0'), bytearray(b'\0')

    def s(text):
        if not text:
            return 0
        offset = len(strings)
        strings.extend(text.encode() + b'\0')
        return offset

    def b(data):
        if not data:
            return 0
        offset = len(blobs)
        blobs.extend(blob_entry(data))
        return offset

    def idx(value, width):
        return value.to_bytes(width, 'little')

    tables = {0x00: [struct.pack('<H', 0) + idx(s('m.dll'), w_s) + idx(1, w_g) + idx(0, w_g) + idx(0, w_g)]}
    tables[0x23] = []
    for name, (v1, v2, v3, v4), flags, key, culture in assemblies:
        tables[0x23].append(struct.pack('<HHHHI', v1, v2, v3, v4, flags) + idx(b(key), w_b)
                            + idx(s(name), w_s) + idx(s(culture), w_s) + idx(0, w_b))
    if modules:
        tables[0x1A] = [idx(s(name), w_s) for name in modules]
    for table, (count, size) in (padding or {}).items():
        tables[table] = [bytes(size)] * count
    present = sorted(t for t, rows in tables.items() if rows)
    valid = sum(1 << t for t in present)
    stream = struct.pack('<IBBBBQQ', 0, 2, 0, wide_heaps, 1, valid, 0)
    stream += b''.join(struct.pack('<I', len(tables[t])) for t in present)
    stream += b''.join(b''.join(tables[t]) for t in present)
    heaps = {'#~': pad4(stream), '#Strings': pad4(bytes(strings)), '#GUID': bytes(16),
             '#Blob': pad4(bytes(blobs))}
    heaps['#-'] = heaps['#~']  # the uncompressed-metadata spelling of the same table stream
    names = list(stream_names)
    version_field = pad4(version + b'\0')
    headers = b''.join(struct.pack('<II', 0, 0) + pad4(n.encode() + b'\0') for n in names)
    start = 16 + len(version_field) + 4 + len(headers)
    out_headers, body = b'', b''
    for n in names:
        data = heaps.get(n, bytes(4))
        out_headers += struct.pack('<II', start + len(body), len(data)) + pad4(n.encode() + b'\0')
        body += data
    root = (struct.pack('<IHHII', 0x424A5342, 1, 1, 0, len(version_field)) + version_field
            + struct.pack('<HH', 0, len(names)) + out_headers + body)
    if edit:
        root = bytearray(root)
        edit(root)
        root = bytes(root)
    return root


def managed_pe(metadata, *, bits=64, flags=1, cor_header=None, directory=(SECTION_RVA, 72)):
    """A one-section PE whose CLR directory points at a CLI header + ``metadata``."""
    header = cor_header or struct.pack('<IHHIIII', 72, 2, 5, SECTION_RVA + 72, len(metadata), flags, 0) + bytes(48)
    content = header + metadata
    raw = (len(content) + 0x1ff) & ~0x1ff
    blob = bytearray(0x200 + raw)
    blob[:2] = b'MZ'
    struct.pack_into('<I', blob, 60, 0x80)
    blob[0x80:0x84] = b'PE\0\0'
    optional = 240 if bits == 64 else 224
    struct.pack_into('<HHIIIHH', blob, 0x84, 0x8664 if bits == 64 else 0x14c, 1, 0, 0, 0, optional, 2)
    struct.pack_into('<H', blob, 0x98, 0x20b if bits == 64 else 0x10b)
    struct.pack_into('<II', blob, 0x98 + 32, 0x1000, 0x200)
    struct.pack_into('<II', blob, 0x98 + 56, 0x1000 + len(content), 0x200)
    struct.pack_into('<I', blob, 0x98 + (108 if bits == 64 else 92), 16)
    struct.pack_into('<II', blob, 0x98 + (112 if bits == 64 else 96) + 14 * 8, *directory)
    section = 0x98 + optional
    blob[section:section + 8] = b'.text\0\0\0'
    struct.pack_into('<IIII', blob, section + 8, len(content), SECTION_RVA, raw, 0x200)
    struct.pack_into('<I', blob, section + 36, 0x60000020)
    blob[0x200:0x200 + len(content)] = content
    return bytes(blob)


def scan(data):
    return inspect_dependencies(io.BytesIO(data), len(data))


def managed(result, kind):
    return [d for d in result['dependencies'] if d['kind'] == kind]


ASSEMBLIES = [
    ('mscorlib', (4, 0, 0, 0), 0, bytes.fromhex(ECMA_TOKEN), ''),   # token form
    ('Lib.Native', (1, 2, 3, 4), 1, ECMA_KEY, 'en-US'),             # PublicKey flag: full key
    ('Plain', (0, 0, 0, 1), 0, b'', ''),                            # no key at all
    ('Tokened', (10, 20, 30, 40), 0, bytes.fromhex('b03f5f7f11d50a3a'), ''),
]


def stream_map(root):
    """{stream name: (offset, size)} read straight from a metadata root."""
    version_length = struct.unpack_from('<I', root, 12)[0]
    count = struct.unpack_from('<H', root, 16 + version_length + 2)[0]
    position, found = 16 + version_length + 4, {}
    for _ in range(count):
        offset, size = struct.unpack_from('<II', root, position)
        end = root.index(b'\0', position + 8)
        found[bytes(root[position + 8:end]).decode()] = (offset, size)
        position += 8 + ((end - (position + 8) + 1 + 3) & ~3)
    return found


class ClrDependencyTests(unittest.TestCase):
    def test_golden_references_header_and_tokens(self):
        data = managed_pe(build_metadata(ASSEMBLIES, ['kernel32.dll', 'libdl.so.2']), flags=0x9)
        result = scan(data)
        self.assertFalse(any('CLR directory present' in x for x in result['unknowns']))
        self.assertTrue(any('Managed assembly references' in x for x in result['unknowns']))
        runtime = managed(result, 'managed_runtime')[0]
        self.assertEqual((runtime['name'], runtime['cor_header_version']), ('v4.0.30319', '2.5'))
        self.assertEqual((runtime['flags'], runtime['flags_raw']), (['ILONLY', 'STRONGNAMESIGNED'], 9))
        rows = managed(result, 'managed_assembly')
        self.assertEqual([r['name'] for r in rows], ['mscorlib', 'Lib.Native', 'Plain', 'Tokened'])
        self.assertEqual([r['version'] for r in rows], ['4.0.0.0', '1.2.3.4', '0.0.0.1', '10.20.30.40'])
        self.assertEqual([r['culture'] for r in rows], [None, 'en-US', None, None])
        # Token form is reported as is; a full key (PublicKey flag) is hashed per ECMA-335
        # II.6.2.1.3. The ECMA standard key's token is the well-known mscorlib token.
        self.assertEqual([r['public_key_token'] for r in rows],
                         [ECMA_TOKEN, ECMA_TOKEN, None, 'b03f5f7f11d50a3a'])
        self.assertEqual(rows[1]['public_key_token'], hashlib.sha1(ECMA_KEY).digest()[-8:][::-1].hex())
        self.assertEqual([r['name'] for r in managed(result, 'native_module_reference')],
                         ['kernel32.dll', 'libdl.so.2'])

    def test_unflagged_key_blob_that_is_not_a_token_is_rejected(self):
        data = managed_pe(build_metadata([('Bad', (1, 0, 0, 0), 0, ECMA_KEY, '')]))
        with self.assertRaisesRegex(BinaryError, 'token length'):
            scan(data)

    def test_offsets_point_at_the_observed_bytes(self):
        data = managed_pe(build_metadata(ASSEMBLIES[1:], ['native.dll']))
        result = scan(data)
        for kind in ('managed_assembly', 'native_module_reference'):
            for row in managed(result, kind):
                at = row['evidence']['name_file_offset']
                self.assertEqual(data[at:at + len(row['name'].encode())], row['name'].encode())
        first = managed(result, 'managed_assembly')[0]
        self.assertEqual(struct.unpack_from('<HHHH', data, first['evidence']['file_offset']), (1, 2, 3, 4))
        self.assertEqual(managed(result, 'managed_runtime')[0]['evidence']['file_offset'], 0x200)

    def test_32_and_64_bit_images_and_no_references(self):
        for bits in (32, 64):
            result = scan(managed_pe(build_metadata(), bits=bits))
            self.assertEqual([d['kind'] for d in result['dependencies']], ['managed_runtime'])

    def test_all_header_flag_names(self):
        data = managed_pe(build_metadata(), flags=0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x10000 | 0x20000 | 0x400000)
        runtime = managed(scan(data), 'managed_runtime')[0]
        self.assertEqual(runtime['flags'], ['ILONLY', '32BITREQUIRED', 'IL_LIBRARY', 'STRONGNAMESIGNED',
                                            'NATIVE_ENTRYPOINT', 'TRACKDEBUGDATA', '32BITPREFERRED',
                                            'unknown:0x400000'])

    def test_wide_heap_indexes(self):
        for wide in (1, 2, 4, 7):
            with self.subTest(wide_heaps=wide):
                data = managed_pe(build_metadata(ASSEMBLIES[1:], ['a.dll'], wide_heaps=wide))
                result = scan(data)
                self.assertEqual([r['name'] for r in managed(result, 'managed_assembly')],
                                 ['Lib.Native', 'Plain', 'Tokened'])
                self.assertEqual([r['name'] for r in managed(result, 'native_module_reference')], ['a.dll'])

    def test_wide_table_and_coded_indexes_shift_the_row_offsets(self):
        # Row sizes are written out by hand from ECMA-335 II.22 -- not derived by uoe.
        scenarios = {
            # 20,000 TypeDefs push the 2-bit TypeDefOrRef coded index to 4 bytes (limit 2**14):
            # TypeDef = 4 flags + 2 name + 2 namespace + 4 extends + 2 field + 2 method.
            'wide TypeDefOrRef': {0x02: (20000, 16)},
            # 70,000 Fields need 4-byte Field indexes. Field = 2 flags + 2 name + 2 signature.
            # The one TypeDef = 4 + 2 + 2 + 2 (extends) + 4 (FieldList) + 2 (MethodList).
            'wide Field index': {0x04: (70000, 6), 0x02: (1, 16)},
            # 3,000 MethodDefs exceed 2**11, so the 5-bit HasCustomAttribute index is 4 bytes
            # (CustomAttributeType, 3 bits, stays 2). MethodDef = 4 rva + 2 + 2 + 2 name + 2 sig
            # + 2 params; CustomAttribute = 4 parent + 2 type + 2 value.
            'wide HasCustomAttribute': {0x06: (3000, 14), 0x0C: (5, 8)},
        }
        for label, padding in scenarios.items():
            with self.subTest(label):
                data = managed_pe(build_metadata(ASSEMBLIES[1:], ['x.dll'], padding=padding))
                result = scan(data)
                self.assertEqual([r['name'] for r in managed(result, 'managed_assembly')],
                                 ['Lib.Native', 'Plain', 'Tokened'])
                self.assertEqual(managed(result, 'managed_assembly')[0]['version'], '1.2.3.4')
                self.assertEqual([r['name'] for r in managed(result, 'native_module_reference')], ['x.dll'])
        # A table whose rows are narrower than the spec's formula says cannot be read as if
        # it were well formed: the declared tables then overrun the stream.
        wrong = managed_pe(build_metadata(ASSEMBLIES[1:], padding={0x02: (20000, 14)}))
        with self.assertRaises(BinaryError):
            scan(wrong)

    def test_extra_data_flag_and_uncompressed_stream_name(self):
        data = managed_pe(build_metadata(ASSEMBLIES[1:], stream_names=('#-', '#Strings', '#GUID', '#Blob')))
        self.assertEqual(len(managed(scan(data), 'managed_assembly')), 3)

    def test_malformed_headers_and_metadata_are_rejected(self):
        good = build_metadata(ASSEMBLIES[1:], ['m.dll'])

        def meta(edit=None, **kwargs):
            return managed_pe(build_metadata(ASSEMBLIES[1:], ['m.dll'], edit=edit, **kwargs))

        def poke(offset, fmt, value):
            return lambda root: struct.pack_into(fmt, root, offset, value)

        def header(**changes):
            fields = dict(cb=72, major=2, minor=5, rva=SECTION_RVA + 72, size=len(good), flags=1)
            fields.update(changes)
            return struct.pack('<IHHIII', fields['cb'], fields['major'], fields['minor'], fields['rva'],
                               fields['size'], fields['flags']) + bytes(52)
        version_end = 16 + 12
        cases = {
            'wrong header size': managed_pe(good, cor_header=header(cb=64)),
            'directory too small': managed_pe(good, directory=(SECTION_RVA, 71)),
            'no metadata directory': managed_pe(good, cor_header=header(rva=0, size=0)),
            'metadata beyond section': managed_pe(good, cor_header=header(size=0x10000)),
            'bad signature': meta(poke(0, '<I', 0x424A5343)),
            'version length not multiple of 4': meta(poke(12, '<I', 10)),
            'version length zero': meta(poke(12, '<I', 0)),
            'version length too large': meta(poke(12, '<I', 1024)),
            'zero streams': meta(poke(version_end + 2, '<H', 0)),
            'too many streams': meta(poke(version_end + 2, '<H', 17)),
            'stream outside metadata': meta(poke(version_end + 4, '<I', 0x7ffffff0)),
            'stream length outside metadata': meta(poke(version_end + 8, '<I', 0x7ffffff0)),
            'duplicate stream': meta(stream_names=('#~', '#Strings', '#Strings', '#Blob')),
            'no table stream': meta(stream_names=('#Strings', '#GUID', '#Blob')),
            'both table streams': meta(stream_names=('#~', '#-', '#Strings', '#Blob')),
            'missing strings heap': meta(stream_names=('#~', '#GUID', '#Blob')),
            'missing blob heap': meta(stream_names=('#~', '#Strings', '#GUID')),
            'non-UTF-8 version': meta(poke(16, 'B', 0xff)),
            'non-ASCII stream name': meta(poke(version_end + 4 + 8, 'B', 0xe9)),
        }
        for label, data in cases.items():
            with self.subTest(label), self.assertRaises(BinaryError):
                scan(data)

    def test_malformed_tables_and_heaps_are_rejected(self):
        # Layout with tables Module(0x00), ModuleRef(0x1A), AssemblyRef(0x23): after the
        # 24-byte header and three row counts (+24, +28, +32) come the Module row (10 bytes),
        # one ModuleRef row (2) and then the AssemblyRef rows (20 bytes each, name index at +14,
        # key blob index at +12).
        def build(edit):
            return managed_pe(build_metadata(ASSEMBLIES[1:], ['m.dll'], edit=edit))

        def patch_table(delta, fmt, value):
            def apply(root):
                struct.pack_into(fmt, root, stream_map(root)['#~'][0] + delta, value)
            return apply
        first_ref = 24 + 12 + 10 + 2
        cases = {
            'row count beyond limit': build(patch_table(32, '<I', 1 << 25)),
            'ModuleRef rows beyond the stream': build(patch_table(28, '<I', 400)),
            'string index outside heap': build(patch_table(first_ref + 14, '<H', 0x7000)),
            'blob index outside heap': build(patch_table(first_ref + 12, '<H', 0x7000)),
            'empty assembly name': build(patch_table(first_ref + 14, '<H', 0)),
            'invalid blob length prefix': build(
                lambda root: root.__setitem__(stream_map(root)['#Blob'][0] + 1, 0xe0)),
        }
        for label, data in cases.items():
            with self.subTest(label), self.assertRaises(BinaryError):
                scan(data)
        # Claiming wide heap indexes over narrow data must not yield the original answer.
        narrow = bytearray(build_metadata(ASSEMBLIES[1:], ['m.dll']))
        narrow[stream_map(narrow)['#~'][0] + 6] = 7
        try:
            names = [r['name'] for r in managed(scan(managed_pe(bytes(narrow))), 'managed_assembly')]
        except BinaryError:
            names = None
        self.assertNotEqual(names, ['Lib.Native', 'Plain', 'Tokened'])

    def test_budgets_are_enforced(self):
        many = [(f'a{i}', (1, 0, 0, 0), 0, b'', '') for i in range(clr.MAX_ASSEMBLY_REFS + 1)]
        with self.assertRaisesRegex(BinaryError, 'assembly reference limit'):
            scan(managed_pe(build_metadata(many)))
        self.assertEqual(len(managed(scan(managed_pe(build_metadata(many[:-1]))), 'managed_assembly')),
                         clr.MAX_ASSEMBLY_REFS)
        mods = [f'm{i}.dll' for i in range(clr.MAX_MODULE_REFS + 1)]
        with self.assertRaisesRegex(BinaryError, 'module reference limit'):
            scan(managed_pe(build_metadata(modules=mods)))
        with patch.object(clr, 'MAX_STREAMS', 3), self.assertRaises(BinaryError):
            scan(managed_pe(build_metadata(ASSEMBLIES[1:])))

    def test_inconsistent_clr_directory(self):
        good = build_metadata(ASSEMBLIES[1:])
        for directory in ((SECTION_RVA, 0), (0, 72)):
            with self.subTest(directory=directory), self.assertRaises(BinaryError):
                scan(managed_pe(good, directory=directory))

    def test_every_truncation_fails(self):
        data = managed_pe(build_metadata(ASSEMBLIES[1:], ['k.dll']))
        for end in range(len(data)):
            with self.subTest(end=end), self.assertRaises(BinaryError):
                scan(data[:end])

    def test_seeded_mutations_fail_cleanly_or_report_bounded_results(self):
        rng = random.Random(53)
        original = managed_pe(build_metadata(ASSEMBLIES[1:], ['k.dll', 'u.dll']))
        window = range(0x98, 0x200 + 72 + 400)
        accepted = 0
        for _ in range(3000):
            data = bytearray(original)
            for _ in range(rng.randint(1, 4)):
                data[rng.choice(window)] = rng.randrange(256)
            try:
                result = scan(bytes(data))
            except BinaryError:
                continue
            accepted += 1
            for row in result['dependencies']:
                self.assertIsInstance(row['name'], str)
                if row['kind'] == 'managed_assembly':
                    self.assertTrue(row['name'])
        self.assertGreater(accepted, 100)

    def test_inspector_and_planner_carry_the_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'app.exe'
            path.write_bytes(managed_pe(build_metadata(ASSEMBLIES[1:], ['k.dll'])))
            with patch.object(subprocess, 'Popen', side_effect=AssertionError('execution')), \
                    patch.object(subprocess, 'run', side_effect=AssertionError('execution')):
                report = inspect_file(path)
                plan = plan_inspection(report, host_os='linux', host_arch='x86_64', available={'wine': True})
        kinds = [d['kind'] for d in report['static_dependencies']]
        self.assertEqual(kinds[0], 'managed_runtime')
        self.assertEqual(kinds.count('managed_assembly'), 3)
        self.assertEqual(plan['observed_requirements'], report['static_dependencies'])
        self.assertFalse(report['execution_attempted'])
        self.assertTrue(any('GAC' in x for x in report['unknowns']))

    def test_planner_notes_managed_images_without_inventing_a_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'app.exe'
            path.write_bytes(managed_pe(build_metadata(ASSEMBLIES[1:])))
            report = inspect_file(path)
        for host_os in ('linux', 'windows'):
            plan = plan_inspection(report, host_os=host_os, host_arch='x86_64', available={'wine': True})
            self.assertEqual(len(plan['strategies']), 1)
            self.assertFalse(plan['strategies'][0]['verified_compatible'])
            self.assertTrue(any('.NET' in c for c in plan['strategies'][0]['constraints']), host_os)

    @unittest.skipUnless(dnfile, 'requires the optional dnfile package')
    def test_synthetic_assemblies_agree_with_dnfile(self):
        variants = {
            'plain': build_metadata(ASSEMBLIES[1:], ['k.dll', 'libdl.so']),
            'wide heaps': build_metadata(ASSEMBLIES[1:], ['k.dll'], wide_heaps=7),
            'wide TypeDefOrRef': build_metadata(ASSEMBLIES[1:], ['k.dll'], padding={0x02: (20000, 16)}),
            'wide Field index': build_metadata(ASSEMBLIES[1:], ['k.dll'], padding={0x04: (70000, 6), 0x02: (1, 16)}),
        }
        for label, metadata in variants.items():
            with self.subTest(label):
                data = managed_pe(metadata, flags=9)
                ours = scan(data)
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / 'x.dll'
                    path.write_bytes(data)
                    pe = dnfile.dnPE(str(path))
                    rows = pe.net.mdtables.AssemblyRef.rows
                    def text(item):  # dnfile returns bytes or str depending on version
                        return item.value.decode() if isinstance(item.value, bytes) else item.value
                    refs = [(text(r.Name), f'{r.MajorVersion}.{r.MinorVersion}.{r.BuildNumber}.{r.RevisionNumber}')
                            for r in rows]
                    modules = [text(r.Name) for r in (pe.net.mdtables.ModuleRef.rows
                                                      if pe.net.mdtables.ModuleRef else [])]
                self.assertEqual([(r['name'], r['version']) for r in managed(ours, 'managed_assembly')], refs)
                self.assertEqual([r['name'] for r in managed(ours, 'native_module_reference')], modules)


if __name__ == '__main__':
    unittest.main()
