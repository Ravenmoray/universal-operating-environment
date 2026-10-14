"""Bounded CLR (.NET) metadata observations for PE images; nothing is loaded or run.

Based on ECMA-335 (CLI): the CLI header (II.25.3.3), the metadata root and stream
headers (II.24.2), and the ``#~``/``#-`` table stream (II.24.2.6, II.22). Only
three things are decoded: header facts, ``AssemblyRef`` rows and ``ModuleRef``
rows. To find them the row size of every earlier table is computed from the
schema, but no other table's contents are read.
"""
import hashlib
import struct

from .binary_input import BinaryError, StringError

CLI_HEADER_SIZE = 72
MAX_STREAMS = 16
MAX_VERSION = 256
MAX_TABLE_ROWS = 1 << 24
MAX_ASSEMBLY_REFS = 1024
MAX_MODULE_REFS = 512
MAX_NAME = 4096
MAX_BLOB = 4096

ASSEMBLY_REF, MODULE_REF = 0x23, 0x1A
FLAGS = ((0x1, 'ILONLY'), (0x2, '32BITREQUIRED'), (0x4, 'IL_LIBRARY'), (0x8, 'STRONGNAMESIGNED'),
         (0x10, 'NATIVE_ENTRYPOINT'), (0x10000, 'TRACKDEBUGDATA'), (0x20000, '32BITPREFERRED'))
ASSEMBLY_FLAG_PUBLIC_KEY = 0x1

# Coded index definitions: (tag bits, [table ids by tag value]); None = unused tag.
# Only indexes used by tables that precede AssemblyRef are needed (e.g. Implementation is not).
CODED = {
    'TypeDefOrRef': (2, [0x02, 0x01, 0x1B]),
    'HasConstant': (2, [0x04, 0x08, 0x17]),
    'HasCustomAttribute': (5, [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14,
                               0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B]),
    'HasFieldMarshal': (1, [0x04, 0x08]),
    'HasDeclSecurity': (2, [0x02, 0x06, 0x20]),
    'MemberRefParent': (3, [0x02, 0x01, 0x1A, 0x06, 0x1B]),
    'HasSemantics': (1, [0x14, 0x17]),
    'MethodDefOrRef': (1, [0x06, 0x0A]),
    'MemberForwarded': (1, [0x04, 0x06]),
    'CustomAttributeType': (3, [None, None, 0x06, 0x0A, None]),
    'ResolutionScope': (2, [0x00, 0x1A, 0x23, 0x01]),
}

# Column types: an int is a fixed byte width; 'S' 'G' 'B' are #Strings/#GUID/#Blob
# heap indexes; ('T', id) is a simple index into table id; ('C', name) a coded index.
# Tables 0x00-0x22 are all that precede AssemblyRef, so only they are described.
SCHEMA = {
    0x00: [2, 'S', 'G', 'G', 'G'],                                              # Module
    0x01: [('C', 'ResolutionScope'), 'S', 'S'],                                 # TypeRef
    0x02: [4, 'S', 'S', ('C', 'TypeDefOrRef'), ('T', 0x04), ('T', 0x06)],       # TypeDef
    0x03: [('T', 0x04)],                                                        # FieldPtr
    0x04: [2, 'S', 'B'],                                                        # Field
    0x05: [('T', 0x06)],                                                        # MethodPtr
    0x06: [4, 2, 2, 'S', 'B', ('T', 0x08)],                                     # MethodDef
    0x07: [('T', 0x08)],                                                        # ParamPtr
    0x08: [2, 2, 'S'],                                                          # Param
    0x09: [('T', 0x02), ('C', 'TypeDefOrRef')],                                 # InterfaceImpl
    0x0A: [('C', 'MemberRefParent'), 'S', 'B'],                                 # MemberRef
    0x0B: [2, ('C', 'HasConstant'), 'B'],                                       # Constant
    0x0C: [('C', 'HasCustomAttribute'), ('C', 'CustomAttributeType'), 'B'],     # CustomAttribute
    0x0D: [('C', 'HasFieldMarshal'), 'B'],                                      # FieldMarshal
    0x0E: [2, ('C', 'HasDeclSecurity'), 'B'],                                   # DeclSecurity
    0x0F: [2, 4, ('T', 0x02)],                                                  # ClassLayout
    0x10: [4, ('T', 0x04)],                                                     # FieldLayout
    0x11: ['B'],                                                                # StandAloneSig
    0x12: [('T', 0x02), ('T', 0x14)],                                           # EventMap
    0x13: [('T', 0x14)],                                                        # EventPtr
    0x14: [2, 'S', ('C', 'TypeDefOrRef')],                                      # Event
    0x15: [('T', 0x02), ('T', 0x17)],                                           # PropertyMap
    0x16: [('T', 0x17)],                                                        # PropertyPtr
    0x17: [2, 'S', 'B'],                                                        # Property
    0x18: [2, ('T', 0x06), ('C', 'HasSemantics')],                              # MethodSemantics
    0x19: [('T', 0x02), ('C', 'MethodDefOrRef'), ('C', 'MethodDefOrRef')],      # MethodImpl
    0x1A: ['S'],                                                                # ModuleRef
    0x1B: ['B'],                                                                # TypeSpec
    0x1C: [2, ('C', 'MemberForwarded'), 'S', ('T', 0x1A)],                      # ImplMap
    0x1D: [4, ('T', 0x04)],                                                     # FieldRVA
    0x1E: [4, 4],                                                               # EncLog
    0x1F: [4],                                                                  # EncMap
    0x20: [4, 2, 2, 2, 2, 4, 'B', 'S', 'S'],                                    # Assembly
    0x21: [4],                                                                  # AssemblyProcessor
    0x22: [4, 4, 4],                                                            # AssemblyOS
    0x23: [2, 2, 2, 2, 4, 'B', 'S', 'S', 'B'],                                  # AssemblyRef
}


def _flag_names(value):
    names = [name for bit, name in FLAGS if value & bit]
    unknown = value & ~sum(bit for bit, _ in FLAGS)
    return names + ([f'unknown:0x{unknown:x}'] if unknown else [])


def _row_layout(rows, heap_sizes):
    """Return {table id: row size in bytes} for every table preceding AssemblyRef."""
    string_width = 4 if heap_sizes & 0x01 else 2
    guid_width = 4 if heap_sizes & 0x02 else 2
    blob_width = 4 if heap_sizes & 0x04 else 2

    def simple(table):
        return 4 if rows.get(table, 0) >= 1 << 16 else 2

    def coded(name):
        bits, tables = CODED[name]
        biggest = max((rows.get(t, 0) for t in tables if t is not None), default=0)
        return 4 if biggest >= 1 << (16 - bits) else 2

    sizes = {}
    for table, columns in SCHEMA.items():
        total = 0
        for column in columns:
            if isinstance(column, int):
                total += column
            elif column == 'S':
                total += string_width
            elif column == 'G':
                total += guid_width
            elif column == 'B':
                total += blob_width
            elif column[0] == 'T':
                total += simple(column[1])
            else:
                total += coded(column[1])
        sizes[table] = total
    return sizes


def inspect_clr(reader, locate, rva, size):
    """Observe CLI header facts, AssemblyRef rows and ModuleRef rows.

    ``locate(rva, size)`` maps an RVA range to (file offset, bytes remaining in
    its file-backed region) and raises BinaryError when it is not uniquely mapped.
    Returns (dependencies, unknowns).
    """
    if size < CLI_HEADER_SIZE:
        raise BinaryError('truncated CLR header directory')
    header_offset, _ = locate(rva, CLI_HEADER_SIZE)
    cb, major, minor, md_rva, md_size, flags = struct.unpack(
        '<IHHIII', reader.read(header_offset, 20))
    if cb != CLI_HEADER_SIZE:
        raise BinaryError('unexpected CLR header size')
    if not md_rva or not md_size:
        raise BinaryError('CLR header has no metadata directory')
    base, _ = locate(md_rva, md_size)

    def at(offset, count):
        if offset < 0 or count < 0 or offset + count > md_size:
            raise BinaryError('CLR metadata range outside the metadata directory')
        return reader.read(base + offset, count)

    signature, _, _, _, version_length = struct.unpack('<IHHII', at(0, 16))
    if signature != 0x424A5342:
        raise BinaryError('invalid CLR metadata signature')
    if not 4 <= version_length <= MAX_VERSION or version_length % 4:
        raise BinaryError('invalid CLR metadata version length')
    raw_version = at(16, version_length)
    if b'\0' not in raw_version:
        raise BinaryError('unterminated CLR metadata version')
    try:
        metadata_version = raw_version.split(b'\0', 1)[0].decode('utf-8')
    except UnicodeDecodeError as exc:
        raise BinaryError('non-UTF-8 CLR metadata version') from exc
    stream_count = struct.unpack('<H', at(16 + version_length + 2, 2))[0]
    if not 1 <= stream_count <= MAX_STREAMS:
        raise BinaryError('invalid CLR metadata stream count')

    streams, position = {}, 16 + version_length + 4
    for _ in range(stream_count):
        head = at(position, min(8 + 32, md_size - position))
        if len(head) < 12:
            raise BinaryError('truncated CLR stream header')
        offset, length = struct.unpack_from('<II', head)
        end = head.find(b'\0', 8, 8 + 32)
        if end < 0 or end == 8:
            raise BinaryError('empty or unterminated CLR stream name')
        try:
            name = head[8:end].decode('ascii')
        except UnicodeDecodeError as exc:
            raise BinaryError('non-ASCII CLR stream name') from exc
        if name in streams:
            raise BinaryError('duplicate CLR metadata stream')
        if offset > md_size or length > md_size - offset:
            raise BinaryError('CLR stream outside the metadata directory')
        streams[name] = (offset, length)
        position += 8 + ((end - 8 + 1 + 3) & ~3)

    tables = [streams[n] for n in ('#~', '#-') if n in streams]
    if len(tables) != 1:
        raise BinaryError('CLR metadata needs exactly one table stream')
    table_offset, table_length = tables[0]
    if table_length < 24:
        raise BinaryError('truncated CLR table stream')
    _, _, _, heap_sizes, _, valid, _ = struct.unpack('<IBBBBQQ', at(table_offset, 24))
    present = [bit for bit in range(64) if valid >> bit & 1]
    cursor = 24 + 4 * len(present) + (4 if heap_sizes & 0x40 else 0)
    if cursor > table_length:
        raise BinaryError('CLR table row counts outside the table stream')
    counts = struct.unpack(f'<{len(present)}I', at(table_offset + 24, 4 * len(present)))
    rows = dict(zip(present, counts))
    if any(count > MAX_TABLE_ROWS for count in counts):
        raise BinaryError('CLR table row count limit exceeded')

    sizes = _row_layout(rows, heap_sizes)
    starts = {}
    for table in sorted(SCHEMA):
        starts[table] = cursor
        cursor += rows.get(table, 0) * sizes[table]
        if cursor > table_length:
            raise BinaryError('CLR table data outside the table stream')

    def heap(name):
        if name not in streams:
            raise BinaryError(f'CLR metadata lacks the {name} stream')
        return streams[name]

    def text(index):
        start, length = heap('#Strings')
        if index >= length:
            raise BinaryError('CLR string index outside the #Strings heap')
        try:
            raw = reader.cstring(base + start + index, length - index, MAX_NAME)
        except StringError as exc:
            raise BinaryError('unterminated or overlong CLR string') from exc
        try:
            return raw.decode('utf-8'), start + index
        except UnicodeDecodeError as exc:
            raise BinaryError('non-UTF-8 CLR string') from exc

    def blob(index):
        start, length = heap('#Blob')
        if index >= length:
            raise BinaryError('CLR blob index outside the #Blob heap')
        first = at(start + index, 1)[0]
        if first < 0x80:
            prefix, size_ = 1, first
        elif first < 0xC0:
            prefix, size_ = 2, ((first & 0x3F) << 8) | at(start + index + 1, 1)[0]
        elif first < 0xE0:
            tail = at(start + index + 1, 3)
            prefix, size_ = 4, ((first & 0x1F) << 24) | (tail[0] << 16) | (tail[1] << 8) | tail[2]
        else:
            raise BinaryError('invalid CLR blob length prefix')
        if size_ > MAX_BLOB or index + prefix + size_ > length:
            raise BinaryError('CLR blob outside its heap or over budget')
        return at(start + index + prefix, size_)

    string_width = 4 if heap_sizes & 0x01 else 2
    blob_width = 4 if heap_sizes & 0x04 else 2

    def column(row, offset, width):
        return int.from_bytes(row[offset:offset + width], 'little')

    dependencies = [{
        'kind': 'managed_runtime', 'name': metadata_version, 'status': 'observed',
        'cor_header_version': f'{major}.{minor}', 'flags': _flag_names(flags), 'flags_raw': flags,
        'evidence': {'source': 'IMAGE_COR20_HEADER', 'file_offset': header_offset},
    }]

    count = rows.get(ASSEMBLY_REF, 0)
    if count > MAX_ASSEMBLY_REFS:
        raise BinaryError('CLR assembly reference limit exceeded')
    row_size = sizes[ASSEMBLY_REF]
    for i in range(count):
        row_start = table_offset + starts[ASSEMBLY_REF] + i * row_size
        row = at(row_start, row_size)
        v_major, v_minor, v_build, v_revision, asm_flags = struct.unpack_from('<HHHHI', row)
        key_index = column(row, 12, blob_width)
        name_index = column(row, 12 + blob_width, string_width)
        culture_index = column(row, 12 + blob_width + string_width, string_width)
        name, name_at = text(name_index)
        if not name:
            raise BinaryError('empty CLR assembly reference name')
        culture, _ = text(culture_index)
        key = blob(key_index)  # index 0 is the empty blob only if the heap's first byte is 0
        if not key:
            token = None
        elif asm_flags & ASSEMBLY_FLAG_PUBLIC_KEY:
            token = hashlib.sha1(key).digest()[-8:][::-1].hex()
        elif len(key) == 8:
            token = key.hex()
        else:
            raise BinaryError('unexpected CLR public key token length')
        dependencies.append({
            'kind': 'managed_assembly', 'name': name, 'status': 'observed',
            'version': f'{v_major}.{v_minor}.{v_build}.{v_revision}',
            'culture': culture or None, 'public_key_token': token,
            'evidence': {'source': 'METADATA_ASSEMBLYREF', 'file_offset': base + row_start,
                         'name_file_offset': base + name_at},
        })

    count = rows.get(MODULE_REF, 0)
    if count > MAX_MODULE_REFS:
        raise BinaryError('CLR module reference limit exceeded')
    row_size = sizes[MODULE_REF]
    for i in range(count):
        row_start = table_offset + starts[MODULE_REF] + i * row_size
        name, name_at = text(column(at(row_start, row_size), 0, string_width))
        if not name:
            raise BinaryError('empty CLR module reference name')
        dependencies.append({
            'kind': 'native_module_reference', 'name': name, 'status': 'observed',
            'evidence': {'source': 'METADATA_MODULEREF', 'file_offset': base + row_start,
                         'name_file_offset': base + name_at},
        })

    unknowns = ['Managed assembly references are read from metadata only; GAC/probing/deps.json '
                'resolution, reflection and dynamic loading, the target framework and the '
                'native targets of individual P/Invoke methods are not resolved']
    return dependencies, unknowns
