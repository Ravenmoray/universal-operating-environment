"""Core-module imports, bounded malformed inputs and independent Node validation."""
import io
import json
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest
from uoe.binary_input import BinaryError
from uoe.wasm import inspect_dependencies

HEADER = b'\0asm\x01\0\0\0'


def u32(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def name(value):
    data = value.encode('utf-8')
    return u32(len(data)) + data


def section(ident, data):
    return bytes([ident]) + u32(len(data)) + data


def fixture():
    imports = [("wasi_snapshot_preview1", "fd_write", b'\0\0'),
               ('env', 'table', b'\1\x70\0\1'),
               ('env', 'memory', b'\2\1\1\2'),
               ('env', 'counter', b'\3\x7f\1')]
    payload = u32(len(imports)) + b''.join(name(m)+name(n)+d for m,n,d in imports)
    return HEADER + section(1, b'\1\x60\0\0') + section(2,payload)


def scan(data):
    return inspect_dependencies(io.BytesIO(data),len(data))


class WasmDependencyTests(unittest.TestCase):
    def test_all_supported_import_kinds(self):
        result = scan(fixture())['dependencies']
        self.assertEqual([x['import_kind'] for x in result], ['function','table','memory','global'])
        self.assertEqual(result[0]['interface_hint'], 'wasi_snapshot_preview1')
        self.assertIsNone(result[1]['interface_hint'])
        self.assertEqual(result[2]['descriptor'], {'minimum':1,'maximum':2})

    def test_header_only_has_no_imports(self):
        self.assertEqual(scan(HEADER)['dependencies'], [])

    def test_custom_sections_and_unicode_empty_names(self):
        custom = section(0,name('[')*4)
        data = HEADER + custom + section(2,b'\1'+name('λ')+name('')+b'\0\0')+custom
        self.assertEqual(scan(data)['dependencies'][0]['module'],'λ')

    def test_malformed_leb_lengths_counts_and_order(self):
        invalid = [HEADER+b'\2\xff\xff\xff\xff\x1f', HEADER+b'\2\x80',
                   HEADER+section(2,u32(4097)), HEADER+section(2,b'\0x'),
                   HEADER+section(2,b'\0')+section(2,b'\0'),
                   HEADER+section(3,b'\0')+section(2,b'\0'),
                   HEADER+section(13,b''), HEADER+section(2,b'\1\1\xff\0\0\0'),
                   HEADER+section(2,b'\1'+u32(4097)), HEADER+b'\2'+u32(1000001)+b'x'*1000001]
        for i,data in enumerate(invalid):
            with self.subTest(case=i),self.assertRaises(BinaryError): scan(data)

    def test_unsupported_or_invalid_descriptors_fail(self):
        for descriptor in (b'\4\0', b'\2\4\0', b'\2\1\2\1', b'\3\x7f\2', b'\1\x01\0\0'):
            with self.subTest(descriptor=descriptor),self.assertRaises(BinaryError):
                scan(HEADER+section(2,b'\1'+name('env')+name('x')+descriptor))

    def test_truncations_reject_except_complete_section_boundaries(self):
        data = fixture()
        for end in range(len(data)):
            if end in (8,14): continue # complete modules with no imports
            with self.subTest(end=end),self.assertRaises(BinaryError): scan(data[:end])

    def test_seeded_mutations(self):
        rng=random.Random(26)
        for _ in range(1000):
            data=bytearray(fixture())
            for _ in range(rng.randint(1,4)): data[rng.randrange(len(data))]=rng.randrange(256)
            try: result=scan(data)
            except BinaryError: continue
            self.assertLessEqual(len(result['dependencies']),4096)

    @unittest.skipUnless(shutil.which('node'), 'requires Node WebAssembly validator')
    def test_node_imports_agree_without_instantiation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'fixture.wasm';path.write_bytes(fixture())
            script="const fs=require('fs');const m=new WebAssembly.Module(fs.readFileSync(process.argv[1]));console.log(JSON.stringify(WebAssembly.Module.imports(m)));"
            result=subprocess.run(['node','-e',script,str(path)],check=True,text=True,capture_output=True,timeout=10)
            observed=[{'module':d['module'],'name':d['name'],'kind':d['import_kind']} for d in scan(fixture())['dependencies']]
            self.assertEqual(observed,json.loads(result.stdout))
