"""Bounded PE32/PE32+ normal imports; no loading, DLL search or execution."""
import struct
from .binary_input import BinaryError, Reader

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
    if any(directory(13)):
        unknowns.append('Delay-import directory present; delay-loaded imports are not enumerated')
    if any(directory(14)):
        unknowns.append('CLR directory present; managed assembly references are not enumerated')
    dependencies = []
    import_rva, import_size = directory(1)
    if bool(import_rva) != bool(import_size):
        raise BinaryError('inconsistent PE import directory')
    if import_rva:
        directory_file, _ = locate(import_rva, import_size)
        terminated = False
        symbol_count = 0
        for i in range(min(import_size // 20, MAX_DLLS + 1)):
            offset = directory_file + i * 20
            lookup, timestamp, forwarder, dll_rva, iat = struct.unpack('<IIIII', reader.read(offset, 20))
            if not any((lookup, timestamp, forwarder, dll_rva, iat)):
                terminated = True
                break
            if i == MAX_DLLS:
                raise BinaryError('PE DLL count limit exceeded')
            if not dll_rva or not iat:
                raise BinaryError('incomplete PE import descriptor')
            dll, dll_offset = name(dll_rva)
            symbols = []
            # A bound IAT contains addresses rather than original import names.
            if not lookup and timestamp:
                raise BinaryError('bound PE imports without lookup table are unsupported')
            thunk = lookup or iat
            width = 8 if wide else 4
            for j in range(MAX_SYMBOLS + 1):
                thunk_offset, _ = locate(thunk + j * width, width)
                value = int.from_bytes(reader.read(thunk_offset, width), 'little')
                if value == 0:
                    break
                symbol_count += 1
                if symbol_count > MAX_SYMBOLS:
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
                symbols.append({**symbol, 'file_offset': thunk_offset})
            else:
                raise BinaryError('unterminated PE import lookup table')
            dependencies.append({'kind': 'shared_library', 'name': dll, 'status': 'observed',
                                 'symbols': symbols, 'evidence': {'source': 'PE_IMPORT_DESCRIPTOR',
                                 'file_offset': offset, 'name_file_offset': dll_offset}})
        if not terminated:
            raise BinaryError('unterminated or oversized PE import directory')
    return {'status': 'complete_static', 'dependencies': dependencies, 'unknowns': unknowns,
            'scope': 'normal PE import descriptors and named/ordinal imports only'}
