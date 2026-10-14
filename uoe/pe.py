"""Bounded PE32/PE32+ normal imports; no loading, DLL search or execution."""
import struct
from .binary_input import BinaryError, Reader
from .clr import inspect_clr

MAX_DLLS = 256
MAX_SYMBOLS = 4096
MAX_NAME = 4096


def inspect_dependencies(stream, file_size):
    reader = Reader(stream, file_size)
    dos = reader.read(0, 64)
    if dos[:2] != b'MZ':
        raise BinaryError('invalid DOS signature')
    peoff = struct.unpack_from('<I', dos, 60)[0]
    if peoff < 64:
        raise BinaryError('invalid PE header offset')
    coff = reader.read(peoff, 24)
    if coff[:4] != b'PE\0\0':
        raise BinaryError('invalid PE signature')
    section_count = struct.unpack_from('<H', coff, 6)[0]
    optional_size = struct.unpack_from('<H', coff, 20)[0]
    if section_count > 96 or not 2 <= optional_size <= 4096:
        raise BinaryError('PE header limit exceeded')
    optional = reader.read(peoff + 24, optional_size)
    magic = struct.unpack_from('<H', optional)[0]
    if magic not in (0x10b, 0x20b):
        raise BinaryError('unsupported PE optional header')
    wide = magic == 0x20b
    directory_offset = 112 if wide else 96
    if optional_size < directory_offset:
        raise BinaryError('truncated PE optional header')
    directory_count = struct.unpack_from('<I', optional, directory_offset - 4)[0]
    if directory_count > (optional_size - directory_offset) // 8:
        raise BinaryError('PE directory count exceeds optional header')
    header_size = struct.unpack_from('<I', optional, 60)[0]
    section_offset = peoff + 24 + optional_size
    if header_size < section_offset + section_count * 40 or header_size > file_size:
        raise BinaryError('invalid PE SizeOfHeaders')
    regions = [(0, header_size, 0)]
    sections = reader.read(section_offset, section_count * 40)
    for i in range(section_count):
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', sections, i * 40 + 8)
        if raw_size:
            if raw_offset < header_size or raw_offset + raw_size > file_size or rva < header_size:
                raise BinaryError('invalid PE section range')
            if rva + max(raw_size, virtual_size) > 1 << 32:
                raise BinaryError('PE section RVA overflow')
            regions.append((rva, raw_size, raw_offset))
    regions.sort()
    for left, right in zip(regions, regions[1:]):
        if left[0] + left[1] > right[0]:
            raise BinaryError('ambiguous overlapping PE RVA mappings')

    def locate(rva, size=1):
        matches = [(offset + rva - base, length - (rva - base))
                   for base, length, offset in regions
                   if base <= rva and rva + size <= base + length]
        if len(matches) != 1 or rva + size > 1 << 32:
            raise BinaryError('PE RVA is not uniquely file-backed')
        return matches[0]

    def name(rva):
        offset, remaining = locate(rva)
        data = reader.read(offset, min(MAX_NAME + 1, remaining))
        end = data.find(b'\0')
        if end <= 0:
            raise BinaryError('empty, overlong or unterminated PE import name')
        try:
            return data[:end].decode('ascii'), offset
        except UnicodeError as exc:
            raise BinaryError('non-ASCII PE import name') from exc

    def directory(index):
        return struct.unpack_from('<II', optional, directory_offset + index * 8) if index < directory_count else (0, 0)

    unknowns = ['LoadLibrary/GetProcAddress, forwarded exports, API-set resolution, transitive DLLs and runtime behavior remain unresolved']
    width = 8 if wide else 4
    counts = {'symbols': 0, 'dlls': 0}

    def symbols(table):
        """Read one import lookup/name table (zero-terminated thunk array)."""
        found = []
        for j in range(MAX_SYMBOLS + 1):
            thunk_offset, _ = locate(table + j * width, width)
            value = int.from_bytes(reader.read(thunk_offset, width), 'little')
            if value == 0:
                return found
            counts['symbols'] += 1
            if counts['symbols'] > MAX_SYMBOLS:
                raise BinaryError('PE symbol count limit exceeded')
            flag = 1 << (width * 8 - 1)
            if value & flag:
                if value & ~(flag | 0xffff):
                    raise BinaryError('invalid PE ordinal reserved bits')
                symbol = {'ordinal': value & 0xffff}
            else:
                if value > 0x7fffffff:
                    raise BinaryError('invalid PE name RVA reserved bits')
                hint_offset, _ = locate(value, 2)
                hint = int.from_bytes(reader.read(hint_offset, 2), 'little')
                symbol_name, symbol_offset = name(value + 2)
                symbol = {'name': symbol_name, 'hint': hint, 'name_file_offset': symbol_offset}
            found.append({**symbol, 'file_offset': thunk_offset})
        raise BinaryError('unterminated PE import lookup table')

    def descriptors(index, entry_size, label):
        """Yield (file offset, raw fields) for a zero-terminated descriptor array."""
        rva, size = directory(index)
        if bool(rva) != bool(size):
            raise BinaryError(f'inconsistent PE {label} directory')
        if not rva:
            return
        base, _ = locate(rva, size)
        for i in range(min(size // entry_size, MAX_DLLS + 1)):
            offset = base + i * entry_size
            fields = struct.unpack('<' + 'I' * (entry_size // 4), reader.read(offset, entry_size))
            if not any(fields):
                return
            counts['dlls'] += 1
            if counts['dlls'] > MAX_DLLS:
                raise BinaryError('PE DLL count limit exceeded')
            yield offset, fields
        raise BinaryError(f'unterminated or oversized PE {label} directory')

    dependencies = []
    for offset, (lookup, timestamp, forwarder, dll_rva, iat) in descriptors(1, 20, 'import'):
        if not dll_rva or not iat:
            raise BinaryError('incomplete PE import descriptor')
        dll, dll_offset = name(dll_rva)
        # A bound IAT contains addresses rather than original import names.
        if not lookup and timestamp:
            raise BinaryError('bound PE imports without lookup table are unsupported')
        dependencies.append({'kind': 'shared_library', 'name': dll, 'status': 'observed',
                             'load_kind': 'static', 'symbols': symbols(lookup or iat),
                             'evidence': {'source': 'PE_IMPORT_DESCRIPTOR',
                                          'file_offset': offset, 'name_file_offset': dll_offset}})
    # Delay-load descriptors (IMAGE_DELAYLOAD_DESCRIPTOR): the DLL is loaded on
    # first call, not at process start. Only the RVA-based form is supported.
    for offset, (attributes, dll_rva, _, iat, names_rva, _, _, _) in descriptors(13, 32, 'delay-import'):
        if attributes != 1:
            raise BinaryError('unsupported PE delay-import descriptor attributes')
        if not dll_rva or not iat or not names_rva:
            raise BinaryError('incomplete PE delay-import descriptor')
        dll, dll_offset = name(dll_rva)
        dependencies.append({'kind': 'shared_library', 'name': dll, 'status': 'observed',
                             'load_kind': 'delay', 'symbols': symbols(names_rva),
                             'evidence': {'source': 'PE_DELAY_IMPORT_DESCRIPTOR',
                                          'file_offset': offset, 'name_file_offset': dll_offset}})
    clr_rva, clr_size = directory(14)
    if bool(clr_rva) != bool(clr_size):
        raise BinaryError('inconsistent PE CLR directory')
    if clr_rva:
        managed, notes = inspect_clr(reader, locate, clr_rva, clr_size)
        dependencies.extend(managed)
        unknowns.extend(notes)
    return {'status': 'complete_static', 'dependencies': dependencies, 'unknowns': unknowns,
            'scope': 'normal and delay-load PE import descriptors with named/ordinal imports, '
                     'plus CLR header facts, assembly references and module references'}
