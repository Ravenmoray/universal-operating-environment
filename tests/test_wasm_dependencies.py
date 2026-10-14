"""WebAssembly import observations; generated modules are never instantiated or run.

The optional comparison tests ask Node.js (V8) only to *compile* a module and list
its declared imports (``WebAssembly.Module.imports``). Compilation does not run
the start function or any exported code.
"""
import io
import json
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from uoe.binary_input import BinaryError
from uoe.inspector import InspectionError, inspect_file
from uoe.planner import plan_inspection
from uoe.wasm import (MAX_IMPORTS, MAX_MODULES, inspect_dependencies)

HEADER = b'\0asm\x01\0\0\0'


def leb(value):
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def name(text):
    raw = text.encode('utf-8') if isinstance(text, str) else text
    return leb(len(raw)) + raw


def section(section_id, payload):
    return bytes([section_id]) + leb(len(payload)) + payload


def vec(items):
    return leb(len(items)) + b''.join(items)


def imports(*entries):
    return section(2, vec(entries))


def entry(module, field, description):
    return name(module) + name(field) + description


FUNC = lambda index=0: b'\0' + leb(index)
TABLE = b'\x01\x70\x00' + leb(1)
MEMORY = b'\x02\x01' + leb(1) + leb(2)
GLOBAL = lambda mutable=True: b'\x03\x7f' + bytes([1 if mutable else 0])
TAG = b'\x04\0' + leb(0)
TYPES = section(1, vec([b'\x60\0\0', b'\x60\x01\x7f\0']))


def golden():
    return HEADER + TYPES + imports(
        entry('env', 'host_log', FUNC(0)),
        entry('env', 'memory', MEMORY),
        entry('wasi_snapshot_preview1', 'proc_exit', FUNC(1)),
        entry('env', 'table', TABLE),
        entry('env', 'counter', GLOBAL()),
        entry('', '', FUNC(0)),
        entry('exc', 'tag', TAG),
    )


def scan(data):
    return inspect_dependencies(io.BytesIO(data), len(data))


def flatten(report_dependencies):
    return [(d['name'], s['name'], s['kind'])
            for d in report_dependencies for s in d['symbols']]


class WasmDependencyTests(unittest.TestCase):
    def test_golden_modules_symbols_and_order(self):
        result = scan(golden())
        self.assertEqual(result['status'], 'complete_static')
        self.assertEqual([d['name'] for d in result['dependencies']],
                         ['env', 'wasi_snapshot_preview1', '', 'exc'])
        self.assertEqual(flatten(result['dependencies']), [
            ('env', 'host_log', 'function'), ('env', 'memory', 'memory'),
            ('env', 'table', 'table'), ('env', 'counter', 'global'),
            ('wasi_snapshot_preview1', 'proc_exit', 'function'),
            ('', '', 'function'), ('exc', 'tag', 'tag')])
        self.assertEqual((result['import_count'], result['section_count']), (7, 2))
        env = result['dependencies'][0]
        self.assertEqual(env['symbols'][0]['type_index'], 0)
        self.assertIs(env['symbols'][3]['mutable'], True)
        self.assertNotIn('interface_hint', env)

    def test_offsets_point_at_the_observed_bytes(self):
        data = golden()
        for dependency in scan(data)['dependencies']:
            start = dependency['evidence']['name_file_offset']
            raw = dependency['name'].encode()
            self.assertEqual(data[start:start + len(raw)], raw)
            self.assertEqual(dependency['evidence']['source'], 'WASM_IMPORT_SECTION')
            first = dependency['symbols'][0]['file_offset']
            self.assertEqual(first, dependency['evidence']['file_offset'])
            self.assertEqual(data[first:first + len(raw) + 1], name(raw))

    def test_wasi_preview1_hint_is_a_name_hint_only(self):
        dependencies = scan(golden())['dependencies']
        hinted = {d['name'] for d in dependencies if 'interface_hint' in d}
        self.assertEqual(hinted, {'wasi_snapshot_preview1'})
        result = scan(HEADER + imports(entry('wasi_unstable', 'fd_write', FUNC())))
        self.assertEqual(result['dependencies'][0]['interface_hint'], 'wasi_preview1')
        self.assertTrue(any('WASI preview1' in x and 'unverified' in x for x in result['unknowns']))

    def test_empty_and_import_free_modules(self):
        for data in (HEADER, HEADER + TYPES, HEADER + imports()):
            with self.subTest(size=len(data)):
                result = scan(data)
                self.assertEqual((result['status'], result['dependencies']),
                                 ('complete_static', []))
        self.assertEqual(scan(HEADER)['section_count'], 0)

    def test_alternative_leb_forms_and_limits_flags(self):
        # Non-canonical (padded) LEB128 is legal; wide and shared limits decode.
        padded = b'\x80\x80\x80\x80\x00'
        for description in (b'\0' + padded, b'\x02\x07' + leb(1) + leb(2),
                            b'\x02\x04' + b'\x01' * 1, b'\x02\x03' + leb(1) + leb(2)):
            data = HEADER + imports(entry('m', 'f', description))
            with self.subTest(description=description):
                self.assertEqual(scan(data)['import_count'], 1)

    def test_gc_and_exception_handling_reference_types(self):
        accepted = {
            'anyref table': b'\x01\x6e\x00' + leb(1),
            'typed table': b'\x01\x63' + leb(3) + b'\x00' + leb(1),
            'exnref global': b'\x03\x69\x00',
            'non-null typed global': b'\x03\x64' + leb(200) + b'\x01',
            'signed heap index 64': b'\x03\x63\xc0\x00\x00',
            'abstract heap global': b'\x03\x64\x73\x00',
            'padded abstract heap global': b'\x03\x63\xf0\x7f\x00',
            'v128 global': b'\x03\x7b\x00',
        }
        for label, description in accepted.items():
            with self.subTest(label):
                self.assertEqual(scan(HEADER + imports(entry('m', 'f', description)))['import_count'], 1)
        rejected = {
            'negative heap index': b'\x03\x63\x7f\x00',
            'heap index beyond 32 bits': b'\x03\x64\xff\xff\xff\xff\x1f\x00',
            'truncated reference prefix': b'\x03\x63',
            'unknown reference prefix': b'\x03\x62\x00\x00',
            'numeric type as table element': b'\x01\x7f\x00' + leb(1),
        }
        for label, description in rejected.items():
            with self.subTest(label), self.assertRaises(BinaryError):
                scan(HEADER + imports(entry('m', 'f', description)))

    def test_custom_sections_and_dynamic_linking_marker(self):
        producers = section(0, name('producers') + b'\0')
        dylink = section(0, name('dylink.0') + b'\x01\x00')
        result = scan(HEADER + producers + TYPES + dylink)
        self.assertTrue(result['dynamic_linking_section'])
        self.assertTrue(any('Dynamic-linking' in x for x in result['unknowns']))
        self.assertFalse(scan(HEADER + producers)['dynamic_linking_section'])
        longest = section(0, name('x' * 200))
        self.assertEqual(scan(HEADER + longest)['section_count'], 1)

    def test_possible_relocatable_objects_are_flagged_not_misclassified(self):
        body = TYPES + imports(entry('env', 'f', FUNC(0)))
        for label, extra in (('linking', section(0, name('linking') + b'\x02')),
                             ('reloc.CODE', section(0, name('reloc.CODE') + b'\x00'))):
            with self.subTest(label):
                result = scan(HEADER + body + extra)
                self.assertTrue(result['linker_sections'])
                self.assertTrue(any('unlinked relocatable object' in x for x in result['unknowns']))
                # Not reclassified: a linked module built with --emit-relocs keeps these
                # sections and has real imports, so the scan still reports them.
                self.assertEqual(result['status'], 'complete_static')
                self.assertEqual(len(result['dependencies']), 1)
        plain = scan(HEADER + body)
        self.assertFalse(plain['linker_sections'])
        self.assertFalse(any('relocatable' in x for x in plain['unknowns']))

    @unittest.skipUnless(shutil.which('clang') and shutil.which('wasm-ld'), 'requires clang with the wasm backend')
    def test_compiled_relocatable_object_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'm.c').write_text(
                '__attribute__((import_module("env"), import_name("host_log"))) extern void host_log(int);\n'
                'int run(int x) { host_log(x); return x; }\n')
            build = subprocess.run(['clang', '--target=wasm32', '-nostdlib', '-O1', '-c',
                                    str(root / 'm.c'), '-o', str(root / 'm.o')],
                                   capture_output=True, text=True, timeout=60)
            if build.returncode:
                self.skipTest('clang cannot target wasm32 here: ' + build.stderr[-200:])
            report = inspect_file(root / 'm.o')
            self.assertTrue(report['dependency_scan']['linker_sections'])
            self.assertTrue(any('unlinked relocatable object' in x for x in report['unknowns']))

    def test_malformed_containers_are_rejected(self):
        good_imports = imports(entry('m', 'f', FUNC()))
        cases = {
            'bad magic': b'\0asn\x01\0\0\0',
            'component version': b'\0asm\x0d\0\x01\0',
            'future version': b'\0asm\x02\0\0\0',
            'unknown section id': HEADER + section(14, b''),
            'duplicate import section': HEADER + good_imports + good_imports,
            'out-of-order sections': HEADER + section(3, b'\0') + good_imports,
            'section beyond file': HEADER + bytes([1]) + leb(10) + b'\0',
            'truncated section length': HEADER + bytes([1, 0x80]),
            'overlong section length': HEADER + bytes([1, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]),
            'section length beyond 32 bits': HEADER + bytes([1, 0xff, 0xff, 0xff, 0xff, 0x7f]),
            'empty custom section': HEADER + section(0, b''),
            'custom name beyond section': HEADER + section(0, leb(9) + b'abc'),
            'non-UTF-8 custom name': HEADER + section(0, name(b'\xff\xfe')),
        }
        for label, data in cases.items():
            with self.subTest(label), self.assertRaises(BinaryError):
                scan(data)

    def test_malformed_imports_are_rejected(self):
        def one(description, module='m', field='f'):
            return HEADER + imports(entry(module, field, description))
        cases = {
            'non-UTF-8 module': HEADER + imports(name(b'\xff') + name('f') + FUNC()),
            'non-UTF-8 field': HEADER + imports(name('m') + name(b'\xc0\x80') + FUNC()),
            'oversized name': HEADER + imports(name('m' * 4097) + name('f') + FUNC()),
            'name beyond payload': HEADER + section(2, leb(1) + leb(50) + b'abc'),
            'unknown import kind': one(b'\x05\x00'),
            'truncated descriptor': HEADER + section(2, leb(1) + name('m') + name('f')),
            'truncated function index': one(b'\0'),
            'unterminated function index': one(b'\0\x80\x80\x80\x80\x80\x00'),
            'function index beyond 32 bits': one(b'\0\xff\xff\xff\xff\x1f'),
            'bad table reference type': one(b'\x01\x7f\x00' + leb(1)),
            'unsupported limits flags': one(b'\x02\x08' + leb(1)),
            'truncated limits': one(b'\x02'),
            'missing maximum': one(b'\x02\x01' + leb(1)),
            'bad global value type': one(b'\x03\x01\x00'),
            'bad global mutability': one(b'\x03\x7f\x02'),
            'bad tag attribute': one(b'\x04\x01\x00'),
            'trailing import bytes': HEADER + section(2, leb(0) + b'\0'),
            'count exceeds payload': HEADER + section(2, leb(2) + entry('m', 'f', FUNC())),
        }
        for label, data in cases.items():
            with self.subTest(label), self.assertRaises(BinaryError):
                scan(data)

    def test_budgets_are_enforced(self):
        many_imports = [entry('m', f'f{i}', FUNC()) for i in range(MAX_IMPORTS + 1)]
        with self.assertRaisesRegex(BinaryError, 'import count'):
            scan(HEADER + imports(*many_imports))
        accepted = scan(HEADER + imports(*many_imports[:MAX_IMPORTS]))
        self.assertEqual(accepted['import_count'], MAX_IMPORTS)
        many_modules = [entry(f'm{i}', 'f', FUNC()) for i in range(MAX_MODULES + 1)]
        with self.assertRaisesRegex(BinaryError, 'module limit'):
            scan(HEADER + imports(*many_modules))
        with self.assertRaisesRegex(BinaryError, 'section count'):
            scan(HEADER + section(0, name('a')) * 4097)

    def test_truncations_never_invent_imports(self):
        data = golden()
        full = flatten(scan(data)['dependencies'])
        accepted = 0
        for end in range(len(data)):
            try:
                result = scan(data[:end])
            except BinaryError:
                continue
            accepted += 1
            # A prefix ending on a section boundary is itself a valid module.
            self.assertTrue(set(flatten(result['dependencies'])) <= set(full), end)
        self.assertGreaterEqual(accepted, 2)

    def test_seeded_mutations_fail_cleanly_or_report_bounded_results(self):
        rng = random.Random(31)
        original = golden()
        accepted = 0
        for _ in range(2000):
            data = bytearray(original)
            for _ in range(rng.randint(1, 4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                result = scan(bytes(data))
            except BinaryError:
                continue
            accepted += 1
            self.assertEqual(result['status'], 'complete_static')
            self.assertLessEqual(result['import_count'], MAX_IMPORTS)
            for dependency in result['dependencies']:
                self.assertIsInstance(dependency['name'], str)
                for symbol in dependency['symbols']:
                    self.assertIn(symbol['kind'], ('function', 'table', 'memory', 'global', 'tag'))
        self.assertGreater(accepted, 0)

    def write(self, data, name='module.wasm'):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / name
        path.write_bytes(data)
        return path

    def test_inspector_report_and_planner_constraints(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('execution')), \
                patch.object(subprocess, 'run', side_effect=AssertionError('execution')):
            report = inspect_file(self.write(golden()))
            plan = plan_inspection(report, host_os='linux', host_arch='x86_64',
                                   available={'wasmtime': True})
        self.assertEqual(report['binary']['format'], 'WASM')
        self.assertEqual(report['dependency_scan']['status'], 'complete_static')
        self.assertNotIn('dependencies', report['dependency_scan'])
        self.assertEqual(len(report['static_dependencies']), 4)
        self.assertFalse(report['execution_attempted'])
        self.assertEqual(plan['observed_requirements'], report['static_dependencies'])
        constraints = ' '.join(plan['strategies'][0]['constraints'])
        self.assertIn('Non-WASI import modules', constraints)
        self.assertIn('exc', constraints)
        self.assertIn('WASI preview1', constraints)
        self.assertFalse(plan['strategies'][0]['verified_compatible'])
        self.assertTrue(plan['unresolved'])

    def test_core_header_does_not_establish_memory_address_width(self):
        # Version 1 covers memory32 and memory64; defined memories are not scanned.
        for data in (HEADER, HEADER + imports(entry('env', 'memory', b'\x02\x04\x01'))):
            with self.subTest(data=data):
                report = inspect_file(self.write(data))
                self.assertEqual(report['binary']['architecture'], 'wasm')
                self.assertIsNone(report['binary']['bits'])

    def test_inspector_wraps_malformed_modules(self):
        with self.assertRaises(InspectionError):
            inspect_file(self.write(HEADER + section(9, b'\0') + section(9, b'\0')))
        with self.assertRaises(InspectionError):
            inspect_file(self.write(b'\0asm'))

    @unittest.skipUnless(shutil.which('node'), 'requires Node.js for comparison')
    def test_padded_abstract_heap_type_matches_v8(self):
        data = HEADER + imports(entry('env', 'callback', b'\x03\x63\xf0\x7f\x00'))
        self.assertEqual(flatten(scan(data)['dependencies']),
                         [(r['module'], r['name'], r['kind'])
                          for r in v8_imports(self.write(data))])

    @unittest.skipUnless(shutil.which('node'), 'requires Node.js for comparison')
    def test_declared_imports_match_v8_for_synthetic_modules(self):
        for label, data in (('golden', golden()),
                            ('wasi', HEADER + TYPES + imports(entry('wasi_snapshot_preview1', 'fd_write', FUNC(1))))):
            with self.subTest(label):
                expected = v8_imports(self.write(data))
                observed = [{'module': d['name'], 'name': s['name'], 'kind': s['kind']}
                            for d in scan(data)['dependencies'] for s in d['symbols']]
                self.assertEqual(observed, group_by_module(expected))

    @unittest.skipUnless(shutil.which('node'), 'requires Node.js for comparison')
    def test_mutated_modules_agree_with_v8(self):
        """Differential check: nothing V8 compiles may be rejected or misreported."""
        rng = random.Random(41)
        seeds = [golden(), HEADER + TYPES + imports(entry('a', 'b', FUNC(1)), entry('a', 'c', MEMORY))]
        cases = []
        for _ in range(3000):
            data = bytearray(rng.choice(seeds))
            for _ in range(rng.randint(1, 3)):
                kind = rng.random()
                if kind < 0.7:
                    data[rng.randrange(len(data))] = rng.randrange(256)
                elif kind < 0.85:
                    del data[rng.randrange(8, len(data))]
                else:
                    data.insert(rng.randrange(8, len(data)), rng.randrange(256))
            cases.append(bytes(data))
        script = ('const rows=require("fs").readFileSync(0,"utf8").split("\\n").filter(Boolean);'
                  'console.log(JSON.stringify(rows.map(h=>{try{'
                  'return WebAssembly.Module.imports(new WebAssembly.Module(Buffer.from(h,"hex")));'
                  '}catch(e){return null}})));')
        outcome = subprocess.run(['node', '-e', script], input='\n'.join(c.hex() for c in cases),
                                 check=True, capture_output=True, text=True, timeout=120).stdout
        agreed = 0
        for data, expected in zip(cases, json.loads(outcome)):
            if expected is None:
                continue  # we do not validate function bodies or semantics
            try:
                found = scan(data)
            except BinaryError as exc:
                self.fail(f'V8 accepted a module we rejected ({exc}): {data.hex()}')
            observed = [{'module': d['name'], 'name': s['name'], 'kind': s['kind']}
                        for d in found['dependencies'] for s in d['symbols']]
            self.assertEqual(observed, group_by_module(expected), data.hex())
            agreed += 1
        self.assertGreater(agreed, 100)

    @unittest.skipUnless(shutil.which('clang') and shutil.which('wasm-ld') and shutil.which('node'),
                         'requires clang, wasm-ld and Node.js')
    def test_compiled_module_matches_v8(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'm.c').write_text(
                '__attribute__((import_module("env"), import_name("host_log"))) extern void host_log(int);\n'
                '__attribute__((import_module("wasi_snapshot_preview1"), import_name("proc_exit"))) extern void proc_exit(int);\n'
                '__attribute__((export_name("run"))) int run(int x) { host_log(x); proc_exit(0); return x; }\n')
            build = subprocess.run(
                ['clang', '--target=wasm32', '-nostdlib', '-O1', '-Wl,--no-entry',
                 '-Wl,--allow-undefined', '-Wl,--export=run', str(root / 'm.c'),
                 '-o', str(root / 'm.wasm')],
                capture_output=True, text=True, timeout=60)
            if build.returncode:
                self.skipTest('clang cannot target wasm32 here: ' + build.stderr[-200:])
            report = inspect_file(root / 'm.wasm')
            observed = [(d['name'], s['name'], s['kind'])
                        for d in report['static_dependencies'] for s in d['symbols']]
            expected = [(r['module'], r['name'], r['kind']) for r in group_by_module(v8_imports(root / 'm.wasm'))]
            self.assertEqual(observed, expected)
            self.assertIn(('env', 'host_log', 'function'), observed)
            self.assertFalse(report['execution_attempted'])


def group_by_module(rows):
    """V8 lists imports in declaration order; uoe groups them by module in first-appearance order."""
    order = list(dict.fromkeys(row['module'] for row in rows))
    return [row for module in order for row in rows if row['module'] == module]


def v8_imports(path):
    script = ('const fs=require("fs");'
              'const m=new WebAssembly.Module(fs.readFileSync(process.argv[1]));'
              'console.log(JSON.stringify(WebAssembly.Module.imports(m)));')
    out = subprocess.run(['node', '-e', script, str(path)], check=True,
                         capture_output=True, text=True, timeout=30).stdout
    return json.loads(out)


if __name__ == '__main__':
    unittest.main()
