"""Bounded core-module import scan (MVP/reference-types import descriptors).

This is not a WebAssembly validator and does not instantiate a module.
"""
from .binary_input import BinaryError, Reader

MAX_IMPORTS = 4096
MAX_SECTIONS = 4096
MAX_IMPORT_BYTES = 1_000_000


class Cursor:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, size):
        if size > len(self.data) - self.pos:
            raise BinaryError('truncated WASM import section')
        result = self.data[self.pos:self.pos+size]
        self.pos += size
        return result

    def byte(self):
        return self.take(1)[0]

    def u32(self):
        return decode_u32(self.byte)

    def name(self):
        size = self.u32()
        if size > 4096:
            raise BinaryError('WASM name limit exceeded')
        try:
            return self.take(size).decode('utf-8')
        except UnicodeError as exc:
            raise BinaryError('invalid UTF-8 WASM name') from exc


def decode_u32(byte):
    result = 0
    for i in range(5):
        value = byte()
        if i == 4 and value > 15:
            raise BinaryError('WASM u32 LEB overflow')
        result |= (value & 127) << (7*i)
        if value < 128:
            return result
    raise BinaryError('unterminated WASM u32 LEB')


def inspect_dependencies(stream, file_size):
    reader = Reader(stream, file_size)
    if reader.read(0, 8) != b'\0asm\x01\0\0\0':
        raise BinaryError('unsupported WASM header; only core version-1 modules supported')
    position, last_order, sections = 8, 0, 0
    order = {i:i for i in range(1,10)} | {12:10,10:11,11:12}
    dependencies = []
    seen = set()

    def byte():
        nonlocal position
        result = reader.read(position, 1)[0]
        position += 1
        return result

    while position < file_size:
        sections += 1
        if sections > MAX_SECTIONS:
            raise BinaryError('WASM section count limit exceeded')
        ident = byte()
        length = decode_u32(byte)
        offset = position
        if length > file_size - position:
            raise BinaryError('WASM section exceeds file')
        if ident:
            if ident not in order:
                raise BinaryError('unsupported WASM section extension')
            if ident in seen or order[ident] <= last_order:
                raise BinaryError('duplicate or out-of-order WASM section')
            seen.add(ident)
            last_order = order[ident]
        if ident == 2:
            if length > MAX_IMPORT_BYTES:
                raise BinaryError('WASM import-section byte limit exceeded')
            cursor = Cursor(reader.read(position, length))
            count = cursor.u32()
            if count > MAX_IMPORTS:
                raise BinaryError('WASM import count limit exceeded')
            for _ in range(count):
                entry_offset = offset + cursor.pos
                module, name = cursor.name(), cursor.name()
                kind = cursor.byte()
                descriptor = {}
                if kind == 0:
                    descriptor = {'type_index': cursor.u32()}
                elif kind in (1,2):
                    if kind == 1:
                        ref = cursor.byte()
                        if ref not in (0x70,0x6f):
                            raise BinaryError('unsupported WASM table reference type')
                        descriptor['element_type'] = 'funcref' if ref == 0x70 else 'externref'
                    flags = cursor.byte()
                    if flags not in (0,1):
                        raise BinaryError('unsupported WASM limits (shared/memory64/extensions)')
                    minimum = cursor.u32()
                    maximum = cursor.u32() if flags else None
                    if maximum is not None and minimum > maximum:
                        raise BinaryError('invalid WASM limit range')
                    if kind == 2 and (minimum > 65536 or maximum is not None and maximum > 65536):
                        raise BinaryError('WASM memory32 page limit exceeded')
                    descriptor.update(minimum=minimum, maximum=maximum)
                elif kind == 3:
                    value, mutable = cursor.byte(), cursor.byte()
                    values = {0x7f:'i32',0x7e:'i64',0x7d:'f32',0x7c:'f64',0x7b:'v128',0x70:'funcref',0x6f:'externref'}
                    if value not in values or mutable not in (0,1):
                        raise BinaryError('unsupported WASM global type')
                    descriptor = {'value_type': values[value], 'mutable': bool(mutable)}
                else:
                    raise BinaryError('unsupported WASM import descriptor kind')
                dependencies.append({'kind':'wasm_import', 'module':module, 'name':name,
                    'import_kind':('function','table','memory','global')[kind],
                    'descriptor':descriptor, 'status':'observed',
                    'interface_hint': module if module in ('wasi_snapshot_preview1','wasi_unstable') else None,
                    'evidence':{'source':'WASM_IMPORT_SECTION','file_offset':entry_offset}})
            if cursor.pos != length:
                raise BinaryError('trailing bytes in WASM import section')
        position += length
    return {'status':'complete_static', 'dependencies':dependencies,
            'scope':'core version-1 MVP/reference-types import descriptors only; no module validation',
            'unknowns':['Defined memories, code/type validity, WASI permissions, host implementations and runtime behavior are not validated; components and newer import extensions are unsupported']}
