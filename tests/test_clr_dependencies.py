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


def blob_entry(data, prefix=1):
    """A #Blob heap entry with an ECMA-335 II.24.2.4 compressed length of ``prefix`` bytes."""
    n = len(data)
    if prefix == 1:
        assert n < 0x80
        return bytes([n]) + data
    if prefix == 2:
        assert n < 0x4000
        return bytes([0x80 | (n >> 8), n & 0xff]) + data
    assert prefix == 4 and n < 0x20000000
    return bytes([0xC0 | (n >> 24), (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]) + data


def build_metadata(assemblies=(), modules=(), *, wide_heaps=0, padding=None, version=b'v4.0.30319',
                   stream_names=('#~', '#Strings', '#GUID', '#Blob'), edit=None, extra_data=False,
                   blob_prefix=None):
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
        blobs.extend(blob_entry(data, blob_prefix or (1 if len(data) < 0x80 else 2)))
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
    stream = struct.pack('<IBBBBQQ', 0, 2, 0, wide_heaps | (0x40 if extra_data else 0), 1, valid, 0)
    stream += b''.join(struct.pack('<I', len(tables[t])) for t in present)
    stream += b'\xde\xad\xbe\xef' if extra_data else b''
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


def stream_header(root, name):
    """Position of the (offset, size) pair of stream ``name`` in the stream headers of a metadata root."""
    version_length = struct.unpack_from('<I', root, 12)[0]
    count = struct.unpack_from('<H', root, 16 + version_length + 2)[0]
    position = 16 + version_length + 4
    for _ in range(count):
        end = root.index(b'\0', position + 8)
        if bytes(root[position + 8:end]).decode() == name:
            return position
        position += 8 + ((end - (position + 8) + 1 + 3) & ~3)
    raise KeyError(name)


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

    def test_uncompressed_table_stream_name_is_accepted(self):
        data = managed_pe(build_metadata(ASSEMBLIES[1:], stream_names=('#-', '#Strings', '#GUID', '#Blob')))
        self.assertEqual(len(managed(scan(data), 'managed_assembly')), 3)

    def expect_rejections(self, cases):
        for label, (data, pattern) in cases.items():
            with self.subTest(label), self.assertRaisesRegex(BinaryError, pattern):
                scan(data)

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
        self.expect_rejections({
            'wrong header size': (managed_pe(good, cor_header=header(cb=64)), 'unexpected CLR header size'),
            'oversized header size': (managed_pe(good, cor_header=header(cb=80)), 'unexpected CLR header size'),
            'directory too small': (managed_pe(good, directory=(SECTION_RVA, 71)), 'truncated CLR header directory'),
            'no metadata directory': (managed_pe(good, cor_header=header(rva=0, size=0)), 'no metadata directory'),
            'metadata beyond section': (managed_pe(good, cor_header=header(size=0x10000)), 'not uniquely file-backed'),
            'bad signature': (meta(poke(0, '<I', 0x424A5343)), 'invalid CLR metadata signature'),
            'version length not multiple of 4': (meta(poke(12, '<I', 10)), 'metadata version length'),
            'version length zero': (meta(poke(12, '<I', 0)), 'metadata version length'),
            'version length too large': (meta(poke(12, '<I', 1024)), 'metadata version length'),
            'zero streams': (meta(poke(version_end + 2, '<H', 0)), 'stream count'),
            'too many streams': (meta(poke(version_end + 2, '<H', 17)), 'stream count'),
            'stream outside metadata': (meta(poke(version_end + 4, '<I', 0x7ffffff0)), 'stream outside the metadata'),
            'stream length outside metadata': (meta(poke(version_end + 8, '<I', 0x7ffffff0)), 'stream outside the metadata'),
            'duplicate stream': (meta(stream_names=('#~', '#Strings', '#Strings', '#Blob')), 'duplicate CLR metadata stream'),
            'no table stream': (meta(stream_names=('#Strings', '#GUID', '#Blob')), 'exactly one table stream'),
            'both table streams': (meta(stream_names=('#~', '#-', '#Strings', '#Blob')), 'exactly one table stream'),
            'missing strings heap': (meta(stream_names=('#~', '#GUID', '#Blob')), 'lacks the #Strings stream'),
            'missing blob heap': (meta(stream_names=('#~', '#Strings', '#GUID')), 'lacks the #Blob stream'),
            'non-UTF-8 version': (meta(poke(16, 'B', 0xff)), 'non-UTF-8 CLR metadata version'),
            'non-ASCII stream name': (meta(poke(version_end + 4 + 8, 'B', 0xe9)), 'non-ASCII CLR stream name'),
        })

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
        self.expect_rejections({
            'row count beyond limit': (build(patch_table(32, '<I', 1 << 25)), 'row count limit exceeded'),
            'ModuleRef rows beyond the stream': (build(patch_table(28, '<I', 400)), 'table data outside the table stream'),
            'string index outside heap': (build(patch_table(first_ref + 14, '<H', 0x7000)), 'string index outside'),
            'blob index outside heap': (build(patch_table(first_ref + 12, '<H', 0x7000)), 'blob index outside'),
            'empty assembly name': (build(patch_table(first_ref + 14, '<H', 0)), 'empty CLR assembly reference name'),
            'empty module name': (managed_pe(build_metadata(ASSEMBLIES[1:], ['']) ), 'empty CLR module reference name'),
            # lengths whose high prefix bits a wrong mask would silently drop, shrinking them under the budget
            'two-byte prefix length above the budget': (managed_pe(build_metadata(
                [('Big', (1, 0, 0, 0), 1, bytes(9000), '')], blob_prefix=2)), 'blob outside its heap or over budget'),
            'four-byte prefix length above the budget': (managed_pe(build_metadata(
                [('Big', (1, 0, 0, 0), 1, bytes(8), '')], blob_prefix=4,
                edit=lambda root: root.__setitem__(slice(stream_map(root)['#Blob'][0] + 1,
                                                         stream_map(root)['#Blob'][0] + 5), b'\xd0\x00\x00\x08'))),
             'blob outside its heap or over budget'),
            'invalid blob length prefix': (build(
                lambda root: root.__setitem__(stream_map(root)['#Blob'][0] + 1, 0xe0)), 'invalid CLR blob length prefix'),
            'blob larger than its budget': (managed_pe(build_metadata(
                [('Big', (1, 0, 0, 0), 1, bytes(5000), '')], blob_prefix=2)), 'blob outside its heap or over budget'),
            'blob running past the heap': (build(
                lambda root: root.__setitem__(stream_map(root)['#Blob'][0] + 1, 0x7f)), 'blob outside its heap'),
        })
        # Claiming wide heap indexes over narrow data must not yield the original answer.
        narrow = bytearray(build_metadata(ASSEMBLIES[1:], ['m.dll']))
        narrow[stream_map(narrow)['#~'][0] + 6] = 7
        try:
            names = [r['name'] for r in managed(scan(managed_pe(bytes(narrow))), 'managed_assembly')]
        except BinaryError:
            names = None
        self.assertNotEqual(names, ['Lib.Native', 'Plain', 'Tokened'])

    def test_heaps_must_start_with_the_empty_entry_when_they_are_used(self):
        # ECMA-335 II.24.2.3-4: entry 0 of #Strings and #Blob is the empty string/blob, which is
        # what index 0 means. A heap that starts with anything else would turn a null index into
        # a made-up key or culture (the dnfile differential fuzz found the blob case).
        plain = [('Plain', (0, 0, 0, 1), 0, b'', '')]
        tokened = [('Tok', (1, 0, 0, 0), 0, bytes.fromhex(ECMA_TOKEN), ''), plain[0]]
        self.assertIsNone(managed(scan(managed_pe(build_metadata(plain))), 'managed_assembly')[0]['public_key_token'])

        def start_of(heap, value, assemblies=tokened, **kwargs):
            def edit(root):
                root[stream_map(root)[heap][0]] = value
            return managed_pe(build_metadata(assemblies, edit=edit, **kwargs))
        self.expect_rejections({
            # 0x08 + the next 8 bytes would be reported as the key of a reference that has none
            'blob heap starts with a plausible length': (start_of('#Blob', 8), r'#Blob heap does not begin with the empty entry'),
            'blob heap starts with a long length': (start_of('#Blob', 0x7f), r'#Blob heap does not begin'),
            'blob heap starts with a short length': (start_of('#Blob', 5, plain), r'#Blob heap does not begin'),
            'strings heap starts with a character': (start_of('#Strings', ord('x')), r'#Strings heap does not begin with the empty entry'),
        })
        # The check runs when a heap is first used, so a file that never consults it is unaffected.
        for heap in ('#Blob', '#Strings'):
            with self.subTest('unused ' + heap):
                self.assertEqual(managed(scan(start_of(heap, 0x7f, [])), 'managed_assembly'), [])

    def test_metadata_structure_rejections_are_pinned_by_message(self):
        good = build_metadata(ASSEMBLIES[1:], ['m.dll'])
        header_size = lambda size: struct.pack('<IHHIII', 72, 2, 5, SECTION_RVA + 72, size, 1) + bytes(52)
        second_header = 16 + 12 + 4 + 12                      # root, version, flags/count, first ('#~') header

        def meta(edit=None, **kwargs):
            return managed_pe(build_metadata(ASSEMBLIES[1:], ['m.dll'], edit=edit, **kwargs))

        def poke(position, fmt, value):
            return lambda root: struct.pack_into(fmt, root, position, value)
        table_header = 16 + 12 + 4                            # position of the '#~' stream header

        def strings_cut_before_nul(root):
            offset, length = stream_map(root)['#Strings']
            end = offset + bytes(root[offset:offset + length]).index(b'Tokened') + len('Tokened')
            struct.pack_into('<I', root, stream_header(root, '#Strings') + 4, end - offset)

        def corrupt_name(root):
            root[root.index(b'Lib.Native')] = 0xff
        self.expect_rejections({
            'directory too small for the root': (managed_pe(good, cor_header=header_size(8)),
                                                 'metadata range outside the metadata directory'),
            # the first stream is emptied so the directory can end inside the second stream's header
            'directory ends inside a stream header': (managed_pe(
                build_metadata(ASSEMBLIES[1:], ['m.dll'], edit=lambda root: struct.pack_into('<II', root, table_header, 0, 0)),
                cor_header=header_size(second_header + 4)), 'truncated CLR stream header'),
            'unterminated version': (meta(lambda root: root.__setitem__(slice(26, 28), b'xx')),
                                     'unterminated CLR metadata version'),
            'empty stream name': (meta(poke(table_header + 8, 'B', 0)), 'empty or unterminated CLR stream name'),
            'stream name without a NUL in 32 bytes': (meta(lambda root: root.__setitem__(
                slice(table_header + 8, table_header + 8 + 32), b'A' * 32)), 'empty or unterminated CLR stream name'),
            'table stream shorter than its header': (meta(poke(table_header + 4, '<I', 20)), 'truncated CLR table stream'),
            'row counts beyond a short table stream': (meta(poke(table_header + 4, '<I', 30)),
                                                       'row counts outside the table stream'),
            'non-UTF-8 name in #Strings': (meta(corrupt_name), 'non-UTF-8 CLR string'),
            'name running to the end of #Strings': (meta(strings_cut_before_nul), 'unterminated or overlong CLR string'),
        })

    def test_limits_accept_the_limit_and_reject_one_past_it(self):
        def with_count(value):
            def edit(root):
                struct.pack_into('<I', root, stream_map(root)['#~'][0] + 32, value)
            return managed_pe(build_metadata(ASSEMBLIES[1:], ['m.dll'], edit=edit))
        # 2^24 rows is within the row cap (and then simply does not fit); one more is over it.
        self.expect_rejections({
            '2**24 rows reaches the data check': (with_count(clr.MAX_TABLE_ROWS), 'table data outside the table stream'),
            '2**24 + 1 rows hits the cap': (with_count(clr.MAX_TABLE_ROWS + 1), 'row count limit exceeded'),
        })
        for length, accepted in ((clr.MAX_VERSION, True), (clr.MAX_VERSION + 4, False)):
            data = managed_pe(build_metadata(ASSEMBLIES[1:], version=b'v' + b'x' * (length - 2)))
            with self.subTest(version_length=length):
                if accepted:
                    self.assertEqual(managed(scan(data), 'managed_runtime')[0]['name'], 'v' + 'x' * (length - 2))
                else:
                    with self.assertRaisesRegex(BinaryError, 'metadata version length'):
                        scan(data)
        for size, accepted in ((clr.MAX_BLOB, True), (clr.MAX_BLOB + 1, False)):
            data = managed_pe(build_metadata([('Big', (1, 0, 0, 0), 1, bytes(size), '')]))
            with self.subTest(blob=size):
                if accepted:
                    self.assertEqual(managed(scan(data), 'managed_assembly')[0]['name'], 'Big')
                else:
                    with self.assertRaisesRegex(BinaryError, 'over budget'):
                        scan(data)

    def test_blob_bounds_are_exact(self):
        token = [('Tok', (1, 0, 0, 0), 0, bytes.fromhex(ECMA_TOKEN), '')]   # blob heap: 00 08 <8 bytes> (10 bytes)

        def heap_length(length):
            def edit(root):
                struct.pack_into('<I', root, stream_header(root, '#Blob') + 4, length)
            return managed_pe(build_metadata(token, edit=edit))
        self.assertEqual(managed(scan(heap_length(10)), 'managed_assembly')[0]['public_key_token'], ECMA_TOKEN)
        # one byte short: index 1 + a 1-byte length prefix + 8 bytes of data no longer fits
        with self.assertRaisesRegex(BinaryError, 'blob outside its heap'):
            scan(heap_length(9))

        # An index equal to the heap length is outside it even when another stream follows the heap.
        def index_at_end(root):
            heap_size = stream_map(root)['#Blob'][1]
            row = stream_map(root)['#~'][0] + 24 + 12 + 10 + 2        # first AssemblyRef row (after Module and ModuleRef)
            struct.pack_into('<H', root, row + 12, heap_size)
        data = managed_pe(build_metadata(token, ['m.dll'], edit=index_at_end,
                                         stream_names=('#~', '#Blob', '#Strings', '#GUID')))
        with self.assertRaisesRegex(BinaryError, 'blob index outside'):
            scan(data)

    def test_budgets_are_enforced(self):
        many = [(f'a{i}', (1, 0, 0, 0), 0, b'', '') for i in range(clr.MAX_ASSEMBLY_REFS + 1)]
        with self.assertRaisesRegex(BinaryError, 'assembly reference limit'):
            scan(managed_pe(build_metadata(many)))
        self.assertEqual(len(managed(scan(managed_pe(build_metadata(many[:-1]))), 'managed_assembly')),
                         clr.MAX_ASSEMBLY_REFS)
        mods = [f'm{i}.dll' for i in range(clr.MAX_MODULE_REFS + 1)]
        with self.assertRaisesRegex(BinaryError, 'module reference limit'):
            scan(managed_pe(build_metadata(modules=mods)))
        self.assertEqual(len(managed(scan(managed_pe(build_metadata(modules=mods[:-1]))),
                                     'native_module_reference')), clr.MAX_MODULE_REFS)
        with patch.object(clr, 'MAX_STREAMS', 3), self.assertRaisesRegex(BinaryError, 'stream count'):
            scan(managed_pe(build_metadata(ASSEMBLIES[1:])))
        # MAX_STREAMS is a boundary: the standard four streams pass at exactly four.
        with patch.object(clr, 'MAX_STREAMS', 4):
            self.assertEqual(len(managed(scan(managed_pe(build_metadata(ASSEMBLIES[1:]))), 'managed_assembly')), 3)

    def test_inconsistent_clr_directory(self):
        good = build_metadata(ASSEMBLIES[1:])
        for directory in ((SECTION_RVA, 0), (0, 72)):
            with self.subTest(directory=directory), self.assertRaisesRegex(BinaryError, 'inconsistent PE CLR directory'):
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

    # Hand-written from ECMA-335 II.22, deliberately NOT derived from uoe.clr.SCHEMA:
    # table id -> (fixed bytes, #Strings columns, #GUID columns, #Blob columns, index columns).
    # Every simple or coded index is 2 bytes while all row counts stay small.
    ROW_FORMULAS = {
        0x01: (0, 2, 0, 0, 1), 0x02: (4, 2, 0, 0, 3), 0x03: (0, 0, 0, 0, 1), 0x04: (2, 1, 0, 1, 0),
        0x05: (0, 0, 0, 0, 1), 0x06: (8, 1, 0, 1, 1), 0x07: (0, 0, 0, 0, 1), 0x08: (4, 1, 0, 0, 0),
        0x09: (0, 0, 0, 0, 2), 0x0A: (0, 1, 0, 1, 1), 0x0B: (2, 0, 0, 1, 1), 0x0C: (0, 0, 0, 1, 2),
        0x0D: (0, 0, 0, 1, 1), 0x0E: (2, 0, 0, 1, 1), 0x0F: (6, 0, 0, 0, 1), 0x10: (4, 0, 0, 0, 1),
        0x11: (0, 0, 0, 1, 0), 0x12: (0, 0, 0, 0, 2), 0x13: (0, 0, 0, 0, 1), 0x14: (2, 1, 0, 0, 1),
        0x15: (0, 0, 0, 0, 2), 0x16: (0, 0, 0, 0, 1), 0x17: (2, 1, 0, 1, 0), 0x18: (2, 0, 0, 0, 2),
        0x19: (0, 0, 0, 0, 3), 0x1B: (0, 0, 0, 1, 0), 0x1C: (2, 1, 0, 0, 2), 0x1D: (4, 0, 0, 0, 1),
        0x1E: (8, 0, 0, 0, 0), 0x1F: (4, 0, 0, 0, 0), 0x20: (16, 2, 0, 1, 0), 0x21: (4, 0, 0, 0, 0),
        0x22: (12, 0, 0, 0, 0),
    }

    @staticmethod
    def row_size(table, wide_heaps):
        fixed, strings, guids, blobs, indexes = ClrDependencyTests.ROW_FORMULAS[table]
        return (fixed + strings * (4 if wide_heaps & 1 else 2) + guids * (4 if wide_heaps & 2 else 2)
                + blobs * (4 if wide_heaps & 4 else 2) + indexes * 2)

    def test_every_pre_assemblyref_table_has_its_hand_written_row_size(self):
        # A single wrong row size in any of these tables silently misplaces AssemblyRef, so
        # every table 0x01-0x22 is populated (Module, ModuleRef and AssemblyRef come from the
        # builder) under all eight HeapSizes combinations, with and without the extra-data dword.
        for wide in range(8):
            for extra in (False, True):
                with self.subTest(wide_heaps=wide, extra_data=extra):
                    padding = {table: (3, self.row_size(table, wide)) for table in self.ROW_FORMULAS}
                    data = managed_pe(build_metadata(ASSEMBLIES[1:], ['m.dll'], wide_heaps=wide,
                                                     padding=padding, extra_data=extra))
                    result = scan(data)
                    self.assertEqual([r['name'] for r in managed(result, 'managed_assembly')],
                                     ['Lib.Native', 'Plain', 'Tokened'])
                    self.assertEqual([r['version'] for r in managed(result, 'managed_assembly')],
                                     ['1.2.3.4', '0.0.0.1', '10.20.30.40'])
                    self.assertEqual([r['name'] for r in managed(result, 'native_module_reference')], ['m.dll'])

    def test_a_wrong_row_size_in_any_table_is_detected(self):
        # The negative control for the test above: one byte too many in a single table makes
        # the declared tables overrun or shift, so the answer must not come back unchanged.
        for table in self.ROW_FORMULAS:
            with self.subTest(table=hex(table)):
                padding = {t: (3, self.row_size(t, 0)) for t in self.ROW_FORMULAS}
                padding[table] = (3, padding[table][1] + 1)
                try:
                    names = [r['name'] for r in managed(scan(managed_pe(build_metadata(
                        ASSEMBLIES[1:], ['m.dll'], padding=padding))), 'managed_assembly')]
                except BinaryError:
                    continue
                self.assertNotEqual(names, ['Lib.Native', 'Plain', 'Tokened'])

    # Coded indexes used by tables that precede AssemblyRef (ECMA-335 II.24.2.6), transcribed
    # separately from uoe.clr: (name, tag bits, member tables, consumer table, consumer row
    # size as a function of this index's width). The consumer's other columns stay narrow.
    CODED_CASES = [
        ('TypeDefOrRef', 2, [0x02, 0x01, 0x1B], 0x09, lambda w: 2 + w),
        ('TypeDefOrRef', 2, [0x02, 0x01, 0x1B], 0x14, lambda w: 4 + w),        # Event.EventType
        ('TypeDefOrRef', 2, [0x02, 0x01, 0x1B], 0x02, lambda w: 12 + w),       # TypeDef.Extends
        ('HasConstant', 2, [0x04, 0x08, 0x17], 0x0B, lambda w: 4 + w),
        ('HasCustomAttribute', 5, [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14,
                                   0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B],
         0x0C, lambda w: w + 4),
        ('HasFieldMarshal', 1, [0x04, 0x08], 0x0D, lambda w: w + 2),
        ('HasDeclSecurity', 2, [0x02, 0x06, 0x20], 0x0E, lambda w: w + 4),
        ('MemberRefParent', 3, [0x02, 0x01, 0x1A, 0x06, 0x1B], 0x0A, lambda w: w + 4),
        ('HasSemantics', 1, [0x14, 0x17], 0x18, lambda w: 4 + w),
        ('MethodDefOrRef', 1, [0x06, 0x0A], 0x19, lambda w: 2 + 2 * w),
        ('MemberForwarded', 1, [0x04, 0x06], 0x1C, lambda w: 6 + w),
        # Parent is already 4 bytes here (MethodDef/MemberRef >= 2048 rows), so 4 + type + 2.
        ('CustomAttributeType', 3, [0x06, 0x0A], 0x0C, lambda w: 4 + w + 2),
        ('ResolutionScope', 2, [0x00, 0x1A, 0x23, 0x01], 0x01, lambda w: w + 4),
    ]

    @staticmethod
    def big_table_row_size(table, rows):
        """Row size of a table that is itself made large; mostly independent of the width under test."""
        if table == 0x02:      # TypeDef: its own Extends is a TypeDefOrRef (2 bits)
            return 12 + (4 if rows >= 1 << 14 else 2)
        if table == 0x01:      # TypeRef: its own ResolutionScope (2 bits)
            return (4 if rows >= 1 << 14 else 2) + 4
        fixed = {0x04: 6, 0x06: 14, 0x08: 6, 0x09: 4, 0x0A: 6, 0x0E: 6, 0x11: 2, 0x14: 6,
                 0x17: 6, 0x1B: 2, 0x20: 22}
        return fixed.get(table, 4)   # tables after AssemblyRef: contents are never read

    def test_wide_index_thresholds_are_exact(self):
        # ECMA-335 II.24.2.6: an index is 2 bytes iff every table it may address has fewer than
        # 2**(16 - tag_bits) rows (simple indexes: fewer than 65,536). For EVERY coded index and
        # EVERY member table that can be made large, check one row below and exactly at the
        # threshold: the consumer table's row size flips with the width, so a wrong membership,
        # tag-bit count or comparison misplaces AssemblyRef. dnfile compares with <= here and is
        # deliberately not consulted. Module (always one row), ModuleRef (capped at 512 rows) and
        # AssemblyRef (capped at 1,024) cannot be raised to a threshold through this builder.
        unreachable = {0x00, 0x1A, 0x23}
        checked = 0
        for name, bits, members, consumer, consumer_size in self.CODED_CASES:
            limit = 1 << (16 - bits)
            for table in members:
                if table in unreachable:
                    continue
                for rows in (limit - 1, limit):
                    width = 4 if rows >= limit else 2
                    if table == consumer:      # a self-referencing table, e.g. TypeRef.ResolutionScope
                        padding = {table: (rows, consumer_size(width))}
                    else:
                        padding = {table: (rows, self.big_table_row_size(table, rows)),
                                   consumer: (3, consumer_size(width))}
                    with self.subTest(name, table=hex(table), rows=rows):
                        data = managed_pe(build_metadata(ASSEMBLIES[1:], ['m.dll'], padding=padding))
                        result = scan(data)
                        self.assertEqual([r['name'] for r in managed(result, 'managed_assembly')],
                                         ['Lib.Native', 'Plain', 'Tokened'])
                    checked += 1
        self.assertGreater(checked, 80)

    def test_a_coded_index_does_not_widen_for_tables_it_cannot_name(self):
        # ResolutionScope (TypeRef.ResolutionScope) can name Module, ModuleRef, AssemblyRef and
        # TypeRef - not TypeDef or TypeSpec - although TypeDefOrRef has the same tag width.
        for table in (0x02, 0x1B):
            rows = 1 << 14                                          # the 2-bit threshold
            padding = {table: (rows, self.big_table_row_size(table, rows)), 0x01: (3, 2 + 4)}
            with self.subTest(table=hex(table)):
                result = scan(managed_pe(build_metadata(ASSEMBLIES[1:], ['m.dll'], padding=padding)))
                self.assertEqual([r['name'] for r in managed(result, 'managed_assembly')],
                                 ['Lib.Native', 'Plain', 'Tokened'])

    # Simple (non-coded) table indexes in tables that precede AssemblyRef, from ECMA-335 II.22:
    # (consumer table, indexed table, consumer row size as a function of that index's width).
    # ImplMap.ImportScope (-> ModuleRef) is the one omitted: ModuleRef is capped at 512 rows.
    SIMPLE_CASES = [
        (0x02, 0x04, lambda w: 12 + w),    # TypeDef.FieldList
        (0x02, 0x06, lambda w: 12 + w),    # TypeDef.MethodList
        (0x03, 0x04, lambda w: w),         # FieldPtr
        (0x05, 0x06, lambda w: w),         # MethodPtr
        (0x06, 0x08, lambda w: 12 + w),    # MethodDef.ParamList
        (0x07, 0x08, lambda w: w),         # ParamPtr
        (0x09, 0x02, lambda w: w + 4),     # InterfaceImpl.Class (its TypeDefOrRef is wide: TypeDef >= 16,384 rows)
        (0x0F, 0x02, lambda w: 6 + w),     # ClassLayout.Parent
        (0x10, 0x04, lambda w: 4 + w),     # FieldLayout.Field
        (0x12, 0x02, lambda w: w + 2),     # EventMap.Parent
        (0x12, 0x14, lambda w: 2 + w),     # EventMap.EventList
        (0x13, 0x14, lambda w: w),         # EventPtr
        (0x15, 0x02, lambda w: w + 2),     # PropertyMap.Parent
        (0x15, 0x17, lambda w: 2 + w),     # PropertyMap.PropertyList
        (0x16, 0x17, lambda w: w),         # PropertyPtr
        (0x18, 0x06, lambda w: w + 4),     # MethodSemantics.Method (HasSemantics stays narrow: no Event/Property rows)
        (0x19, 0x02, lambda w: w + 4),     # MethodImpl.Class
        (0x1D, 0x04, lambda w: 4 + w),     # FieldRVA.Field
    ]

    def test_simple_index_widths_flip_at_65536_rows_in_every_consumer(self):
        for consumer, table, consumer_size in self.SIMPLE_CASES:
            for rows in (65535, 65536):
                width = 4 if rows >= 65536 else 2
                padding = {table: (rows, self.big_table_row_size(table, rows)), consumer: (3, consumer_size(width))}
                with self.subTest(consumer=hex(consumer), table=hex(table), rows=rows):
                    result = scan(managed_pe(build_metadata(ASSEMBLIES[1:], ['m.dll'], padding=padding)))
                    self.assertEqual([r['name'] for r in managed(result, 'managed_assembly')],
                                     ['Lib.Native', 'Plain', 'Tokened'])

    def test_extra_data_dword_is_skipped_not_misread(self):
        plain = scan(managed_pe(build_metadata(ASSEMBLIES[1:], ['m.dll'])))
        extra = scan(managed_pe(build_metadata(ASSEMBLIES[1:], ['m.dll'], extra_data=True)))
        self.assertEqual([r['name'] for r in managed(extra, 'managed_assembly')],
                         [r['name'] for r in managed(plain, 'managed_assembly')])
        # ...and the dword really shifts the table data: pretending it is absent breaks the read.
        data = bytearray(build_metadata(ASSEMBLIES[1:], ['m.dll'], extra_data=True))
        data[stream_map(data)['#~'][0] + 6] &= ~0x40
        try:
            names = [r['name'] for r in managed(scan(managed_pe(bytes(data))), 'managed_assembly')]
        except BinaryError:
            names = None
        self.assertNotEqual(names, ['Lib.Native', 'Plain', 'Tokened'])

    def test_two_and_four_byte_compressed_blob_lengths(self):
        full_key = bytes(range(160))                      # needs the 2-byte prefix (>= 0x80)
        expected = hashlib.sha1(full_key).digest()[-8:][::-1].hex()
        for prefix in (None, 2, 4):
            with self.subTest(prefix=prefix or 'automatic'):
                rows = scan(managed_pe(build_metadata(
                    [('Strong', (1, 0, 0, 0), 1, full_key, '')], blob_prefix=prefix)))
                self.assertEqual(managed(rows, 'managed_assembly')[0]['public_key_token'], expected)
        # a 4-byte prefix on a small token is legal (non-minimal) and decodes the same way
        token = bytes.fromhex('b03f5f7f11d50a3a')
        rows = scan(managed_pe(build_metadata([('Tok', (1, 0, 0, 0), 0, token, '')], blob_prefix=4)))
        self.assertEqual(managed(rows, 'managed_assembly')[0]['public_key_token'], 'b03f5f7f11d50a3a')

    def test_truncation_inside_the_metadata_reaches_the_clr_parser(self):
        # The earlier every-truncation test fails at the PE section check. Here the file is
        # intact but the section's raw (file-backed) size ends at `cut`, so the CLR directory
        # parses until the first byte it needs is missing.
        content_start = 0x200
        data = managed_pe(build_metadata(ASSEMBLIES[1:], ['k.dll']))
        section = 0x98 + 240
        full = struct.unpack_from('<I', data, section + 16)[0]
        # the parser needs the whole declared metadata directory to be file-backed
        needed = 72 + struct.unpack_from('<I', data, content_start + 8 + 4)[0]
        self.assertLessEqual(needed, full)
        for cut in range(0, needed):
            cropped = bytearray(data[:content_start + cut])
            struct.pack_into('<I', cropped, section + 16, cut)
            with self.subTest(cut=cut), self.assertRaises(BinaryError):
                scan(bytes(cropped))
        cropped = bytearray(data[:content_start + needed])
        struct.pack_into('<I', cropped, section + 16, needed)
        self.assertEqual(len(managed(scan(bytes(cropped)), 'managed_assembly')), 3)

    def test_planner_adds_no_dotnet_note_to_native_pe_files(self):
        from tests.test_pe_dependencies import fixture
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'native.exe'
            path.write_bytes(bytes(fixture()))
            report = inspect_file(path)
        for host_os in ('linux', 'windows'):
            plan = plan_inspection(report, host_os=host_os, host_arch='x86_64', available={'wine': True})
            notes = ' '.join(plan['strategies'][0]['constraints'])
            self.assertNotIn('.NET', notes)
            self.assertNotIn('Delay-loaded', notes)

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
