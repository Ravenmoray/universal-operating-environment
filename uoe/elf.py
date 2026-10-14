"""Bounded ELF program-header dependency observations; never load or run input.

Based on the System V gABI program header and dynamic linking definitions.
Only ET_EXEC/ET_DYN program-header dependencies are covered, not loader behavior.
"""
import struct

MAX_PROGRAM_HEADERS = 4096
MAX_DYNAMIC_ENTRIES = 4096
MAX_STRING_TABLE = 1_000_000
MAX_NAME = 4096
MAX_NEEDED = 256
MAX_READ_BYTES = 8_000_000


class ElfError(ValueError):
    pass


def inspect_dependencies(stream, file_size):
    consumed = 0

    def read(offset, size):
        nonlocal consumed
        if offset < 0 or size < 0 or offset > file_size or size > file_size - offset:
            raise ElfError('ELF range outside file')
        consumed += size
        if consumed > MAX_READ_BYTES:
            raise ElfError('ELF inspection read budget exceeded')
        stream.seek(offset)
        data = stream.read(size)
        if len(data) != size:
            raise ElfError('truncated ELF range')
        return data

    ident = read(0, 16)
    if ident[:4] != b'\x7fELF' or ident[4] not in (1, 2) or ident[5] not in (1, 2) or ident[6] != 1:
        raise ElfError('invalid ELF identification')
    bits = 64 if ident[4] == 2 else 32
    endian = '<' if ident[5] == 1 else '>'
    header_format = endian + ('HHIQQQIHHHHHH' if bits == 64 else 'HHIIIIIHHHHHH')
    fields = struct.unpack(header_format, read(16, struct.calcsize(header_format)))
    kind, _, version, _, phoff, _, _, ehsize, phentsize, phnum, _, _, _ = fields
    expected_header = 64 if bits == 64 else 52
    expected_ph = 56 if bits == 64 else 32
    if version != 1 or ehsize != expected_header:
        raise ElfError('invalid ELF header version or size')
    if phnum == 0xffff:
        raise ElfError('extended ELF program-header numbering is unsupported')
    if phnum > MAX_PROGRAM_HEADERS:
        raise ElfError('ELF program-header limit exceeded')
    if kind not in (2, 3):
        return {'status': 'unsupported_object_type', 'dependencies': [],
                'scope': 'ET_EXEC and ET_DYN program headers only'}
    if phnum and (phentsize != expected_ph or phoff < ehsize):
        raise ElfError('invalid ELF program-header table')
    table = read(phoff, phnum * expected_ph) if phnum else b''
    segments = []
    for i in range(phnum):
        row = struct.unpack_from(endian + ('IIQQQQQQ' if bits == 64 else 'IIIIIIII'),
                                 table, i * expected_ph)
        if bits == 64:
            typ, _, offset, address, _, size, memory_size, _ = row
        else:
            typ, offset, address, _, size, memory_size, _, _ = row
        if typ in (1, 2, 3):
            if offset > file_size or size > file_size - offset:
                raise ElfError('ELF segment outside file')
            if size > memory_size:
                raise ElfError('ELF segment file size exceeds memory size')
            if address + memory_size > 1 << bits:
                raise ElfError('ELF segment address overflow')
        segments.append((typ, offset, address, size))

    loads = [s for s in segments if s[0] == 1 and s[3]]
    ordered = sorted(loads, key=lambda s: s[2])
    for left, right in zip(ordered, ordered[1:]):
        if left[2] + left[3] > right[2]:
            raise ElfError('overlapping ELF file-backed load mappings are unsupported')

    def name(data, offset=0):
        if offset >= len(data):
            raise ElfError('ELF string offset outside table')
        end = data.find(b'\0', offset, min(len(data), offset + MAX_NAME + 1))
        if end < 0 or end == offset:
            raise ElfError('empty, overlong or unterminated ELF dependency name')
        try:
            return data[offset:end].decode('utf-8')
        except UnicodeError as exc:
            raise ElfError('non-UTF-8 ELF dependency names are unsupported') from exc

    result = []
    interps = [s for s in segments if s[0] == 3]
    dynamics = [s for s in segments if s[0] == 2]
    if len(interps) > 1 or len(dynamics) > 1:
        raise ElfError('duplicate ELF interpreter or dynamic segment')
    if interps:
        _, offset, _, size = interps[0]
        if size < 2 or size > MAX_NAME + 1:
            raise ElfError('invalid ELF interpreter size')
        data = read(offset, size)
        if data[-1:] != b'\0' or b'\0' in data[:-1]:
            raise ElfError('invalid ELF interpreter terminator')
        result.append({'kind': 'interpreter', 'name': name(data), 'status': 'observed',
                       'evidence': {'source': 'PT_INTERP', 'file_offset': offset}})
    if dynamics:
        _, offset, _, size = dynamics[0]
        entry_size = 16 if bits == 64 else 8
        if not size or size % entry_size or size // entry_size > MAX_DYNAMIC_ENTRIES:
            raise ElfError('invalid or oversized ELF dynamic table')
        dynamic = read(offset, size)
        needed, tags = [], {}
        terminated = False
        for pos in range(0, size, entry_size):
            tag, value = struct.unpack_from(endian + ('qQ' if bits == 64 else 'iI'), dynamic, pos)
            if tag == 0:
                terminated = True
                break
            if tag == 1:
                needed.append((value, offset + pos))
                if len(needed) > MAX_NEEDED:
                    raise ElfError('ELF dependency count limit exceeded')
            elif tag in (5, 10):
                if tag in tags:
                    raise ElfError('duplicate ELF string table metadata')
                tags[tag] = value
        if not terminated:
            raise ElfError('unterminated ELF dynamic table')
        if needed:
            if 5 not in tags or 10 not in tags or not 0 < tags[10] <= MAX_STRING_TABLE:
                raise ElfError('missing or oversized ELF string table')
            address, length = tags[5], tags[10]
            mappings = [s for s in loads if s[2] <= address and
                        address + length <= s[2] + s[3]]
            if len(mappings) != 1:
                raise ElfError('ELF string table lacks one file-backed load mapping')
            _, load_offset, load_address, _ = mappings[0]
            string_offset = load_offset + address - load_address
            strings = read(string_offset, length)
            if strings[0] != 0 or strings[-1] != 0:
                raise ElfError('invalid ELF string table boundary')
            for index, entry_offset in needed:
                result.append({'kind': 'shared_library', 'name': name(strings, index),
                               'status': 'observed', 'evidence': {
                                   'source': 'DT_NEEDED', 'file_offset': entry_offset,
                                   'string_file_offset': string_offset + index}})
    return {'status': 'complete_static', 'dependencies': result,
            'scope': 'PT_INTERP and direct DT_NEEDED only; no library resolution or execution'}
