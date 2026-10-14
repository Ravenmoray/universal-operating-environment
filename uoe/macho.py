"""Bounded Mach-O load-command dependency observations; never load or run input.

Based on Apple's <mach-o/loader.h> and <mach-o/fat.h> layouts. Thin 32/64-bit
images of either byte order and universal (fat) containers are covered. Only
dependent-library, dynamic-linker, runtime-search-path and platform-version load
commands are decoded; segments, symbols, bindings and signatures are not.
"""
import struct
from .binary_input import BinaryError, Reader

MAX_SLICES = 16
MAX_COMMANDS = 4096
MAX_COMMAND_BYTES = 1_048_576
MAX_DEPENDENCIES = 512
MAX_NAME = 4096
MAX_READ_BYTES = 17_000_000

THIN_MAGICS = {
    b'\xfe\xed\xfa\xce': ('>', 32), b'\xce\xfa\xed\xfe': ('<', 32),
    b'\xfe\xed\xfa\xcf': ('>', 64), b'\xcf\xfa\xed\xfe': ('<', 64),
}
FAT_MAGICS = {b'\xca\xfe\xba\xbe': False, b'\xca\xfe\xba\xbf': True}
# Fat headers are big-endian on disk. These byte-swapped spellings are not
# produced by standard tools and are classified but not decoded.
SWAPPED_FAT_MAGICS = (b'\xbe\xba\xfe\xca', b'\xbf\xba\xfe\xca')
MAGICS = tuple(THIN_MAGICS) + tuple(FAT_MAGICS) + SWAPPED_FAT_MAGICS

CPU_ARCH = {7: 'x86', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'aarch64'}
FILE_TYPES = {2: 'executable', 6: 'dylib', 7: 'dylinker', 8: 'bundle'}

DYLIB_COMMANDS = {
    0x0c: ('LC_LOAD_DYLIB', 'strong'),
    0x80000018: ('LC_LOAD_WEAK_DYLIB', 'weak'),
    0x8000001f: ('LC_REEXPORT_DYLIB', 'reexport'),
    0x20: ('LC_LAZY_LOAD_DYLIB', 'lazy'),
    0x80000023: ('LC_LOAD_UPWARD_DYLIB', 'upward'),
}
LC_LOAD_DYLINKER = 0x0e
LC_RPATH = 0x8000001c
LC_BUILD_VERSION = 0x32
VERSION_MIN_COMMANDS = {
    0x24: ('LC_VERSION_MIN_MACOSX', 'macos'), 0x25: ('LC_VERSION_MIN_IPHONEOS', 'ios'),
    0x2f: ('LC_VERSION_MIN_TVOS', 'tvos'), 0x30: ('LC_VERSION_MIN_WATCHOS', 'watchos'),
}
PLATFORMS = {1: 'macos', 2: 'ios', 3: 'tvos', 4: 'watchos', 5: 'bridgeos',
             6: 'maccatalyst', 7: 'ios-simulator', 8: 'tvos-simulator',
             9: 'watchos-simulator', 10: 'driverkit', 11: 'visionos',
             12: 'visionos-simulator'}


def architecture(cpu_type):
    return CPU_ARCH.get(cpu_type, f'unknown:{cpu_type}')


def _version(value):
    return f'{value >> 16}.{(value >> 8) & 0xff}.{value & 0xff}'


def _string(command, offset, minimum):
    if offset < minimum or offset >= len(command):
        raise BinaryError('invalid Mach-O load command string offset')
    end = command.find(b'\0', offset, min(len(command), offset + MAX_NAME + 1))
    if end < 0 or end == offset:
        raise BinaryError('empty, overlong or unterminated Mach-O string')
    try:
        return command[offset:end].decode('utf-8')
    except UnicodeDecodeError as exc:
        raise BinaryError('non-UTF-8 Mach-O string') from exc


def _thin(reader, base, size, slice_info=None):
    """Decode one thin image occupying [base, base + size) of the file."""
    if size < 28:
        raise BinaryError('truncated Mach-O header')
    magic = reader.read(base, 4)
    if magic not in THIN_MAGICS:
        raise BinaryError('invalid or unsupported Mach-O image magic')
    endian, bits = THIN_MAGICS[magic]
    header_size = 32 if bits == 64 else 28
    if size < header_size:
        raise BinaryError('truncated Mach-O header')
    header = reader.read(base, header_size)
    _, cpu_type, cpu_subtype, file_type, count, commands_size, _ = struct.unpack_from(
        endian + '7I', header)
    if count > MAX_COMMANDS or commands_size > MAX_COMMAND_BYTES:
        raise BinaryError('Mach-O load command limit exceeded')
    if count * 8 > commands_size or header_size + commands_size > size:
        raise BinaryError('invalid Mach-O load command table')
    info = {'architecture': architecture(cpu_type), 'cpu_type': cpu_type,
            'cpu_subtype': cpu_subtype, 'bits': bits,
            'endianness': 'little' if endian == '<' else 'big',
            'file_type': FILE_TYPES.get(file_type, f'unsupported:{file_type}'),
            'file_offset': base, 'size_bytes': size}
    if slice_info is not None:
        info.update(slice_info)
    if file_type not in FILE_TYPES:
        info['status'] = 'unsupported_object_type'
        return info, []
    table = reader.read(base + header_size, commands_size)
    alignment = 8 if bits == 64 else 4
    command_base = base + header_size
    results, dedicated = [], set()
    position = 0
    for _ in range(count):
        if position + 8 > commands_size:
            raise BinaryError('Mach-O load command outside table')
        command, command_size = struct.unpack_from(endian + 'II', table, position)
        if (command_size < 8 or command_size % alignment
                or position + command_size > commands_size):
            raise BinaryError('invalid Mach-O load command size')
        body = table[position:position + command_size]
        origin = command_base + position
        entry = None
        if command in DYLIB_COMMANDS:
            if command_size < 24:
                raise BinaryError('truncated Mach-O dylib command')
            offset, _, current, compatibility = struct.unpack_from(endian + 'IIII', body, 8)
            source, load_kind = DYLIB_COMMANDS[command]
            entry = {'kind': 'shared_library', 'name': _string(body, offset, 24),
                     'status': 'observed', 'load_kind': load_kind,
                     'current_version': _version(current),
                     'compatibility_version': _version(compatibility),
                     'evidence': {'source': source, 'file_offset': origin,
                                  'name_file_offset': origin + offset}}
        elif command == LC_LOAD_DYLINKER:
            if command_size < 12 or command in dedicated:
                raise BinaryError('invalid or duplicate Mach-O dynamic linker command')
            dedicated.add(command)
            offset = struct.unpack_from(endian + 'I', body, 8)[0]
            entry = {'kind': 'interpreter', 'name': _string(body, offset, 12),
                     'status': 'observed',
                     'evidence': {'source': 'LC_LOAD_DYLINKER', 'file_offset': origin,
                                  'name_file_offset': origin + offset}}
        elif command == LC_RPATH:
            if command_size < 12:
                raise BinaryError('truncated Mach-O rpath command')
            offset = struct.unpack_from(endian + 'I', body, 8)[0]
            entry = {'kind': 'runtime_search_path', 'name': _string(body, offset, 12),
                     'status': 'observed',
                     'evidence': {'source': 'LC_RPATH', 'file_offset': origin,
                                  'name_file_offset': origin + offset}}
        elif command == LC_BUILD_VERSION:
            if command_size < 24:
                raise BinaryError('truncated Mach-O build version command')
            platform, minimum, sdk = struct.unpack_from(endian + 'III', body, 8)
            entry = {'kind': 'platform', 'name': PLATFORMS.get(platform, f'unknown:{platform}'),
                     'status': 'observed', 'minimum_os_version': _version(minimum),
                     'sdk_version': _version(sdk),
                     'evidence': {'source': 'LC_BUILD_VERSION', 'file_offset': origin}}
        elif command in VERSION_MIN_COMMANDS:
            if command_size < 16:
                raise BinaryError('truncated Mach-O version-min command')
            minimum, sdk = struct.unpack_from(endian + 'II', body, 8)
            source, platform = VERSION_MIN_COMMANDS[command]
            entry = {'kind': 'platform', 'name': platform, 'status': 'observed',
                     'minimum_os_version': _version(minimum), 'sdk_version': _version(sdk),
                     'evidence': {'source': source, 'file_offset': origin}}
        if entry is not None:
            if slice_info is not None:
                entry['slice'] = {'index': slice_info['index'],
                                  'architecture': info['architecture']}
            results.append(entry)
            if len(results) > MAX_DEPENDENCIES:
                raise BinaryError('Mach-O dependency count limit exceeded')
        position += command_size
    if position != commands_size:
        raise BinaryError('Mach-O command table has unconsumed bytes')
    info['status'] = 'complete_static'
    return info, results


def inspect_dependencies(stream, file_size):
    reader = Reader(stream, file_size, MAX_READ_BYTES)
    magic = reader.read(0, 4)
    scope = ('dylib, dynamic linker, rpath and platform-version load commands only; '
             'no library resolution or execution')
    unknowns = ['Library presence, @rpath/@loader_path/@executable_path resolution, the dyld '
                'shared cache, dlopen-loaded libraries, symbol bindings, code signing, '
                'entitlements and runtime behavior remain unresolved']
    if magic in SWAPPED_FAT_MAGICS:
        return {'status': 'unsupported_fat_byte_order', 'dependencies': [], 'slices': [],
                'unknowns': unknowns + ['Universal header uses a nonstandard byte order'],
                'scope': scope}
    if magic in THIN_MAGICS:
        info, dependencies = _thin(reader, 0, file_size)
        return {'status': info['status'], 'dependencies': dependencies, 'slices': [info],
                'unknowns': unknowns, 'scope': scope}
    if magic not in FAT_MAGICS:
        raise BinaryError('invalid Mach-O magic')

    wide = FAT_MAGICS[magic]
    count = struct.unpack('>I', reader.read(4, 4))[0]
    if not 1 <= count <= MAX_SLICES:
        raise BinaryError('invalid or oversized universal binary slice count')
    row = 32 if wide else 20
    table_end = 8 + count * row
    table = reader.read(8, count * row)
    ranges, seen, declared_architectures = [], set(), []
    for index in range(count):
        if wide:
            cpu_type, cpu_subtype, offset, size, align, reserved = struct.unpack_from(
                '>IIQQII', table, index * row)
            if reserved:
                raise BinaryError('nonzero reserved field in universal slice')
        else:
            cpu_type, cpu_subtype, offset, size, align = struct.unpack_from(
                '>IIIII', table, index * row)
        if align > 31 or offset < table_end or size < 28 or offset + size > file_size:
            raise BinaryError('invalid universal binary slice range')
        if offset % (1 << align):
            raise BinaryError('universal binary slice violates declared alignment')
        if (cpu_type, cpu_subtype) in seen:
            raise BinaryError('duplicate universal binary architecture')
        seen.add((cpu_type, cpu_subtype))
        declared_architectures.append((cpu_type, cpu_subtype))
        ranges.append((offset, size, index))
    for left, right in zip(sorted(ranges), sorted(ranges)[1:]):
        if left[0] + left[1] > right[0]:
            raise BinaryError('overlapping universal binary slices')

    slices, dependencies = [], []
    for offset, size, index in sorted(ranges, key=lambda item: item[2]):
        info, found = _thin(reader, offset, size, {'index': index})
        if (info['cpu_type'], info['cpu_subtype']) != declared_architectures[index]:
            raise BinaryError('universal binary architecture disagrees with slice header')
        slices.append(info)
        dependencies.extend(found)
    status = ('complete_static' if all(s['status'] == 'complete_static' for s in slices)
              else 'partial_static')
    return {'status': status, 'dependencies': dependencies, 'slices': slices,
            'unknowns': unknowns, 'scope': scope}
