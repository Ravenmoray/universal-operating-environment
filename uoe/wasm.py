"""Bounded WebAssembly core-module import observations; never compile or run input.

Based on the WebAssembly Core Specification binary format: module header,
section framing, unsigned LEB128 integers and the import section. Only the
section framing and the import section are decoded; function bodies, types,
exports and data are neither parsed nor validated.
"""
from .binary_input import BinaryError, Reader

MAX_SECTIONS = 4096
MAX_IMPORTS = 4096
MAX_MODULES = 256
MAX_NAME = 4096
MAX_CUSTOM_NAME = 64

# Non-custom sections must appear at most once, in this order. Section ids are
# type=1 import=2 function=3 table=4 memory=5 global=6 export=7 start=8
# element=9 code=10 data=11 datacount=12 tag=13; tag sits between memory and
# global and datacount precedes code.
SECTION_ORDER = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 13: 6, 6: 7, 7: 8,
                 8: 9, 9: 10, 12: 11, 10: 12, 11: 13}
IMPORT_SECTION = 2
CUSTOM_SECTION = 0
NUMERIC_TYPES = {0x7f, 0x7e, 0x7d, 0x7c, 0x7b}
# Single-byte abstract heap types (also the shorthand non-null-free reference
# types): exn, array, struct, i31, eq, any, extern, func, none, noextern,
# nofunc, noexn. 0x63/0x64 introduce (ref null ht) and (ref ht).
ABSTRACT_HEAP_TYPES = set(range(0x69, 0x75))
REFERENCE_PREFIXES = {0x63, 0x64}
WASI_PREVIEW1_MODULES = {'wasi_snapshot_preview1', 'wasi_unstable'}
DYNAMIC_LINKING_SECTIONS = {'dylink.0', 'dylink'}
KINDS = {0: 'function', 1: 'table', 2: 'memory', 3: 'global', 4: 'tag'}


def _leb(data, pos, bits=32):
    """Decode an unsigned LEB128 value of at most ``bits`` bits."""
    value = 0
    for index in range((bits + 6) // 7):
        if pos >= len(data):
            raise BinaryError('truncated WASM integer')
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7f) << (7 * index)
        if not byte & 0x80:
            if value >> bits:
                raise BinaryError('WASM integer exceeds its declared width')
            return value, pos
    raise BinaryError('overlong WASM integer encoding')


def _signed_leb(data, pos, bits):
    """Decode a signed LEB128 value that must fit in ``bits`` bits."""
    value = shift = 0
    for _ in range((bits + 6) // 7):
        if pos >= len(data):
            raise BinaryError('truncated WASM integer')
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                value -= 1 << shift
            if not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
                raise BinaryError('WASM integer exceeds its declared width')
            return value, pos
    raise BinaryError('overlong WASM integer encoding')


def _heap_type(data, pos):
    index, pos = _signed_leb(data, pos, 33)
    # Abstract heap types are negative s33 values, including when padded.
    # Matching only their one-byte spellings rejects legal multi-byte forms.
    if index < 0 and index not in {byte - 128 for byte in ABSTRACT_HEAP_TYPES}:
        raise BinaryError('unsupported WASM heap type')
    return pos


def _reference_type(data, pos):
    if pos >= len(data):
        raise BinaryError('truncated WASM reference type')
    if data[pos] in ABSTRACT_HEAP_TYPES:
        return pos + 1
    if data[pos] in REFERENCE_PREFIXES:
        return _heap_type(data, pos + 1)
    raise BinaryError('unsupported WASM reference type')


def _value_type(data, pos):
    if pos < len(data) and data[pos] in NUMERIC_TYPES:
        return pos + 1
    return _reference_type(data, pos)


def _name(data, pos):
    length, pos = _leb(data, pos)
    if length > MAX_NAME or pos + length > len(data):
        raise BinaryError('invalid or oversized WASM name')
    try:
        text = data[pos:pos + length].decode('utf-8')
    except UnicodeDecodeError as exc:
        raise BinaryError('non-UTF-8 WASM name') from exc
    return text, pos, pos + length


def _limits(data, pos):
    flags = data[pos] if pos < len(data) else None
    if flags is None:
        raise BinaryError('truncated WASM limits')
    if flags > 7:
        raise BinaryError('unsupported WASM limits flags')
    bits = 64 if flags & 4 else 32
    _, pos = _leb(data, pos + 1, bits)
    if flags & 1:
        _, pos = _leb(data, pos, bits)
    return pos


def _import_description(payload, pos):
    """Return (kind, extra fields, next position) for one import descriptor."""
    if pos >= len(payload):
        raise BinaryError('truncated WASM import descriptor')
    tag = payload[pos]
    pos += 1
    if tag not in KINDS:
        raise BinaryError('unsupported WASM import kind')
    extra = {}
    if tag == 0:
        extra['type_index'], pos = _leb(payload, pos)
    elif tag == 1:
        pos = _limits(payload, _reference_type(payload, pos))
    elif tag == 2:
        pos = _limits(payload, pos)
    elif tag == 3:
        pos = _value_type(payload, pos)
        if pos >= len(payload) or payload[pos] > 1:
            raise BinaryError('unsupported WASM global mutability')
        extra['mutable'] = bool(payload[pos])
        pos += 1
    else:
        if pos >= len(payload) or payload[pos] != 0:
            raise BinaryError('unsupported WASM tag attribute')
        extra['type_index'], pos = _leb(payload, pos + 1)
    return KINDS[tag], extra, pos


def inspect_dependencies(stream, file_size):
    reader = Reader(stream, file_size)
    if reader.read(0, 8) != b'\0asm\x01\0\0\0':
        raise BinaryError('unsupported WebAssembly header or version')

    position, rank, sections = 8, 0, 0
    import_section, dynamic_linking = None, False
    while position < file_size:
        sections += 1
        if sections > MAX_SECTIONS:
            raise BinaryError('WASM section count limit exceeded')
        head = reader.read(position, min(6, file_size - position))
        section_id = head[0]
        if section_id > 13:
            raise BinaryError('unknown WASM section id')
        length, after = _leb(head, 1)
        start = position + after
        end = start + length
        if end > file_size:
            raise BinaryError('WASM section extends beyond file')
        if section_id == CUSTOM_SECTION:
            prefix = reader.read(start, min(length, 5 + MAX_CUSTOM_NAME))
            name_length, name_start = _leb(prefix, 0)
            if name_start + name_length > length:
                raise BinaryError('WASM custom section name exceeds its section')
            if name_length <= MAX_CUSTOM_NAME:
                try:
                    label = prefix[name_start:name_start + name_length].decode('utf-8')
                except UnicodeDecodeError as exc:
                    raise BinaryError('non-UTF-8 WASM custom section name') from exc
                dynamic_linking = dynamic_linking or label in DYNAMIC_LINKING_SECTIONS
        else:
            if SECTION_ORDER[section_id] <= rank:
                raise BinaryError('WASM sections are duplicated or out of order')
            rank = SECTION_ORDER[section_id]
            if section_id == IMPORT_SECTION:
                import_section = (start, length)
        position = end

    modules, total = {}, 0
    if import_section:
        start, length = import_section
        payload = reader.read(start, length)
        count, pos = _leb(payload, 0)
        if count > MAX_IMPORTS:
            raise BinaryError('WASM import count limit exceeded')
        for _ in range(count):
            entry = pos
            module, module_start, pos = _name(payload, pos)
            field, _, pos = _name(payload, pos)
            kind, extra, pos = _import_description(payload, pos)
            dependency = modules.get(module)
            if dependency is None:
                if len(modules) >= MAX_MODULES:
                    raise BinaryError('WASM import module limit exceeded')
                dependency = modules[module] = {
                    'kind': 'wasm_import_module', 'name': module, 'status': 'observed',
                    'symbols': [], 'evidence': {
                        'source': 'WASM_IMPORT_SECTION', 'file_offset': start + entry,
                        'name_file_offset': start + module_start}}
                if module in WASI_PREVIEW1_MODULES:
                    dependency['interface_hint'] = 'wasi_preview1'
            dependency['symbols'].append({'name': field, 'kind': kind,
                                          'file_offset': start + entry, **extra})
            total += 1
        if pos != len(payload):
            raise BinaryError('trailing bytes in WASM import section')

    unknowns = ['Import signatures (type section), exports, start function, '
                'host embedder behavior and runtime behavior are not analyzed']
    if modules:
        unknowns.append('Imports are supplied by an embedder at instantiation; '
                        'observed names do not show that any runtime provides them')
    if any('interface_hint' in item for item in modules.values()):
        unknowns.append('WASI preview1 module names observed; ABI conformance, '
                        'per-function support and granted permissions remain unverified')
    if dynamic_linking:
        unknowns.append('Dynamic-linking custom section present; side-module '
                        'dependencies are not enumerated')
    return {'status': 'complete_static', 'dependencies': list(modules.values()),
            'unknowns': unknowns, 'section_count': sections, 'import_count': total,
            'dynamic_linking_section': dynamic_linking,
            'scope': 'core module section framing and import section only; '
                     'no compilation, instantiation or execution'}
