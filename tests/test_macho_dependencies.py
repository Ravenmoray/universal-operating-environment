"""Mach-O load-command observations; generated or linked images are never executed.

The optional comparison test links tiny project-owned images with LLVM's
Mach-O linker against a hand-written text stub (so no Apple SDK or macOS host is
involved), then compares the observations with ``llvm-objdump --macho``. The
images are only parsed; nothing is loaded.
"""
import io
import random
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from uoe.binary_input import BinaryError
from uoe.inspector import InspectionError, inspect_file
from uoe.macho import MAX_COMMANDS, MAX_SLICES, inspect_dependencies
from uoe.planner import plan_inspection

X86_64, ARM64, I386 = 0x01000007, 0x0100000c, 7


def find_tool(base):
    """Locate an LLVM tool by its plain or versioned name (e.g. llvm-lipo-18)."""
    for name in [base] + [f'{base}-{version}' for version in range(21, 13, -1)]:
        found = shutil.which(name)
        if found:
            return found
    return None


LIPO, LD64 = find_tool('llvm-lipo'), find_tool('ld64.lld')


def pad(data, alignment):
    return data + b'\0' * (-len(data) % alignment)


def dylib(endian, command, path, alignment, current=0x010203, compat=0x010000):
    raw = path.encode() + b'\0'
    size = len(pad(b'\0' * 24 + raw, alignment))
    return pad(struct.pack(endian + 'IIIIII', command, size, 24, 2, current, compat) + raw, alignment)


def lc_str(endian, command, text, alignment):
    raw = text.encode() + b'\0'
    size = len(pad(b'\0' * 12 + raw, alignment))
    return pad(struct.pack(endian + 'III', command, size, 12) + raw, alignment)


def build_version(endian, platform=1, minimum=0x0d0000, sdk=0x0e0200):
    return struct.pack(endian + 'IIIIII', 0x32, 24, platform, minimum, sdk, 0)


def version_min(endian, command, version, sdk):
    return struct.pack(endian + 'IIII', command, 16, version, sdk)


def uuid(endian):
    return struct.pack(endian + 'II', 0x1b, 24) + bytes(range(16))


def thin(bits=64, endian='<', cpu=X86_64, commands=None, file_type=2, subtype=None):
    if subtype is None:
        subtype = 0 if cpu == ARM64 else 3
    alignment = 8 if bits == 64 else 4
    if commands is None:
        commands = [
            uuid(endian),
            dylib(endian, 0x0d, '/usr/lib/libself.dylib', alignment),  # LC_ID_DYLIB
            lc_str(endian, 0x0e, '/usr/lib/dyld', alignment),
            build_version(endian),
            dylib(endian, 0x0c, '/usr/lib/libSystem.B.dylib', alignment, 0x04e40100, 0x010000),
            dylib(endian, 0x80000018, '@rpath/libweak.dylib', alignment),
            dylib(endian, 0x8000001f, '/usr/lib/libre.dylib', alignment),
            dylib(endian, 0x20, '/usr/lib/liblazy.dylib', alignment),
            dylib(endian, 0x80000023, '/usr/lib/libup.dylib', alignment),
            lc_str(endian, 0x8000001c, '@loader_path/../Frameworks', alignment),
        ]
    body = b''.join(commands)
    magic = {('<', 32): b'\xce\xfa\xed\xfe', ('<', 64): b'\xcf\xfa\xed\xfe',
             ('>', 32): b'\xfe\xed\xfa\xce', ('>', 64): b'\xfe\xed\xfa\xcf'}[(endian, bits)]
    header = magic + struct.pack(endian + '6I', cpu, subtype, file_type, len(commands), len(body), 0)
    return header + (b'\0\0\0\0' if bits == 64 else b'') + body


def fat(images, wide=False, align=4):
    row = 32 if wide else 20
    offset = 8 + row * len(images)
    table, body = b'', b''
    for cpu, subtype, image in images:
        start = len(pad(b'\0' * (offset + len(body)), 1 << align))
        padding = start - offset - len(body)
        body += b'\0' * padding
        fields = (cpu, subtype, start, len(image), align)
        table += struct.pack('>IIQQII', *fields, 0) if wide else struct.pack('>IIIII', *fields)
        body += image
    magic = b'\xca\xfe\xba\xbf' if wide else b'\xca\xfe\xba\xbe'
    return magic + struct.pack('>I', len(images)) + table + body


def scan(data):
    return inspect_dependencies(io.BytesIO(data), len(data))


def names(result, kind):
    return [d['name'] for d in result['dependencies'] if d['kind'] == kind]


class MachoDependencyTests(unittest.TestCase):
    def test_all_widths_and_byte_orders(self):
        for bits in (32, 64):
            for endian in ('<', '>'):
                with self.subTest(bits=bits, endian=endian):
                    result = scan(thin(bits, endian))
                    self.assertEqual(result['status'], 'complete_static')
                    self.assertEqual(names(result, 'interpreter'), ['/usr/lib/dyld'])
                    self.assertEqual(names(result, 'shared_library'), [
                        '/usr/lib/libSystem.B.dylib', '@rpath/libweak.dylib',
                        '/usr/lib/libre.dylib', '/usr/lib/liblazy.dylib', '/usr/lib/libup.dylib'])
                    self.assertEqual(names(result, 'runtime_search_path'),
                                     ['@loader_path/../Frameworks'])
                    kinds = [d['load_kind'] for d in result['dependencies']
                             if d['kind'] == 'shared_library']
                    self.assertEqual(kinds, ['strong', 'weak', 'reexport', 'lazy', 'upward'])
                    self.assertEqual(result['slices'][0]['bits'], bits)
                    self.assertEqual(result['slices'][0]['endianness'],
                                     'little' if endian == '<' else 'big')

    def test_own_install_name_is_identity_not_a_dependency(self):
        result = scan(thin())
        self.assertNotIn('/usr/lib/libself.dylib', [d['name'] for d in result['dependencies']])
        self.assertEqual(len(names(result, 'shared_library')), 5)

    def test_versions_platforms_and_offsets(self):
        data = thin()
        result = scan(data)
        system = next(d for d in result['dependencies'] if d['name'].endswith('libSystem.B.dylib'))
        self.assertEqual((system['current_version'], system['compatibility_version']),
                         ('1252.1.0', '1.0.0'))
        platform = next(d for d in result['dependencies'] if d['kind'] == 'platform')
        self.assertEqual((platform['name'], platform['minimum_os_version'], platform['sdk_version']),
                         ('macos', '13.0.0', '14.2.0'))
        for dependency in result['dependencies']:
            evidence = dependency['evidence']
            command = struct.unpack_from('<I', data, evidence['file_offset'])[0]
            self.assertNotEqual(command, 0)
            if 'name_file_offset' in evidence:
                at = evidence['name_file_offset']
                end = data.index(b'\0', at)
                self.assertEqual(data[at:end].decode(), dependency['name'])

    def test_legacy_version_min_commands(self):
        for command, name in ((0x24, 'macos'), (0x25, 'ios'), (0x2f, 'tvos'), (0x30, 'watchos')):
            data = thin(commands=[version_min('<', command, 0x000a0f00, 0x000a1000)])
            row = scan(data)['dependencies'][0]
            self.assertEqual((row['name'], row['minimum_os_version'], row['sdk_version']),
                             (name, '10.15.0', '10.16.0'))
        unknown = scan(thin(commands=[build_version('<', platform=99)]))['dependencies'][0]
        self.assertEqual(unknown['name'], 'unknown:99')

    def test_unsupported_file_types_are_explicit(self):
        for file_type in (0, 1, 4, 5, 10, 11):
            result = scan(thin(file_type=file_type))
            self.assertEqual((result['status'], result['dependencies']),
                             ('unsupported_object_type', []))
        for file_type in (2, 6, 7, 8):
            self.assertEqual(scan(thin(file_type=file_type))['status'], 'complete_static')

    def test_empty_command_table(self):
        result = scan(thin(commands=[]))
        self.assertEqual((result['status'], result['dependencies']), ('complete_static', []))

    def test_universal_binary_slices_and_attribution(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                data = fat([(X86_64, 3, thin(64, '<', X86_64)),
                            (ARM64, 0, thin(64, '<', ARM64, commands=[
                                lc_str('<', 0x0e, '/usr/lib/dyld', 8),
                                dylib('<', 0x0c, '/usr/lib/libarm.dylib', 8)])),
                            (I386, 3, thin(32, '<', I386, commands=[]))], wide=wide)
                result = scan(data)
                self.assertEqual(result['status'], 'complete_static')
                self.assertEqual([s['architecture'] for s in result['slices']],
                                 ['x86_64', 'aarch64', 'x86'])
                self.assertEqual([s['index'] for s in result['slices']], [0, 1, 2])
                arm = [d for d in result['dependencies'] if d['slice']['architecture'] == 'aarch64']
                self.assertEqual([d['name'] for d in arm],
                                 ['/usr/lib/dyld', '/usr/lib/libarm.dylib'])
                for dependency in arm:
                    offset = dependency['evidence']['name_file_offset']
                    self.assertEqual(data[offset:offset + len(dependency['name'])],
                                     dependency['name'].encode())
                    self.assertGreaterEqual(offset, result['slices'][1]['file_offset'])

    def test_universal_binary_with_unsupported_slice_is_partial(self):
        data = fat([(X86_64, 3, thin(file_type=2)), (ARM64, 0, thin(cpu=ARM64, file_type=1))])
        result = scan(data)
        self.assertEqual(result['status'], 'partial_static')
        self.assertEqual({d['slice']['architecture'] for d in result['dependencies']}, {'x86_64'})

    def test_swapped_fat_spelling_is_classified_but_not_decoded(self):
        data = b'\xbe\xba\xfe\xca' + struct.pack('<I', 1) + bytes(20)
        result = scan(data)
        self.assertEqual((result['status'], result['dependencies']), ('unsupported_fat_byte_order', []))

    def test_malformed_thin_images_are_rejected(self):
        def with_commands(*commands, **kwargs):
            return thin(commands=list(commands), **kwargs)
        good = dylib('<', 0x0c, '/usr/lib/libx.dylib', 8)
        base = thin()

        def patched(offset, fmt, value):
            data = bytearray(base)
            struct.pack_into(fmt, data, offset, value)
            return bytes(data)
        cases = {
            'bad magic': b'\xcf\xfa\xed\xff' + bytes(60),
            'header truncated': thin()[:20],
            'ncmds beyond limit': patched(16, '<I', MAX_COMMANDS + 1),
            'ncmds exceeds table': patched(16, '<I', 10_000),
            'sizeofcmds beyond file': patched(20, '<I', 1_000_000),
            'sizeofcmds beyond limit': patched(20, '<I', 1_048_577),
            'zero command size': with_commands(struct.pack('<II', 0x0c, 0) + bytes(16)),
            'tiny command size': with_commands(struct.pack('<II', 0x0c, 4)),
            'misaligned command size': with_commands(struct.pack('<II', 0x0c, 28) + bytes(20)),
            'command beyond table': with_commands(struct.pack('<II', 0x0c, 4096) + bytes(16)),
            'truncated dylib command': with_commands(struct.pack('<II', 0x0c, 16) + bytes(8)),
            'name offset before struct': with_commands(
                struct.pack('<IIIIII', 0x0c, 32, 8, 0, 0, 0) + b'x\0' + bytes(6)),
            'name offset beyond command': with_commands(
                struct.pack('<IIIIII', 0x0c, 32, 99, 0, 0, 0) + bytes(8)),
            'empty name': with_commands(
                struct.pack('<IIIIII', 0x0c, 32, 24, 0, 0, 0) + bytes(8)),
            'unterminated name': with_commands(
                struct.pack('<IIIIII', 0x0c, 32, 24, 0, 0, 0) + b'abcdefgh'),
            'non-UTF-8 name': with_commands(
                struct.pack('<IIIIII', 0x0c, 32, 24, 0, 0, 0) + b'\xff\xfe\0' + bytes(5)),
            'duplicate dynamic linker': with_commands(
                lc_str('<', 0x0e, '/usr/lib/dyld', 8), lc_str('<', 0x0e, '/usr/lib/dyld', 8)),
            'truncated dyld command': with_commands(struct.pack('<II', 0x0e, 8)),
            'truncated rpath': with_commands(struct.pack('<II', 0x8000001c, 8)),
            'truncated build version': with_commands(struct.pack('<IIII', 0x32, 16, 1, 0)),
            'truncated version min': with_commands(struct.pack('<II', 0x24, 8)),
            'dependency budget': with_commands(*[dylib('<', 0x0c, f'/l/{i}.dylib', 8)
                                                 for i in range(513)]),
        }
        self.assertEqual(scan(with_commands(good))['dependencies'][0]['name'], '/usr/lib/libx.dylib')
        for label, data in cases.items():
            with self.subTest(label), self.assertRaises(BinaryError):
                scan(data)

    def test_malformed_universal_binaries_are_rejected(self):
        image = thin()
        base = fat([(X86_64, 3, image), (ARM64, 0, thin(cpu=ARM64))])

        def patched(offset, fmt, value, source=base):
            data = bytearray(source)
            struct.pack_into(fmt, data, offset, value)
            return bytes(data)
        wide = fat([(X86_64, 3, image)], wide=True)
        cases = {
            'bare header only': b'\xca\xfe\xba\xbe\x00\x00\x00\x02',
            'zero slices': patched(4, '>I', 0),
            'too many slices': patched(4, '>I', MAX_SLICES + 1),
            'slice table beyond file': patched(4, '>I', 12),
            'slice offset inside table': patched(16, '>I', 8),
            'slice beyond file': patched(20, '>I', 10_000_000),
            'tiny slice': patched(20, '>I', 4),
            'absurd alignment': patched(24, '>I', 40),
            'duplicate architecture': patched(28, '>I', X86_64, patched(32, '>I', 3)),
            'overlapping slices': patched(36, '>I', struct.unpack_from('>I', base, 16)[0] + 16),
            'wide reserved field': patched(8 + 28, '>I', 1, wide),
            'nested universal image': fat([(X86_64, 3, fat([(X86_64, 3, image)]))]),
            'slice is not mach-o': fat([(X86_64, 3, b'NOTMACHO' * 8)]),
            # Java class files share the 0xCAFEBABE magic: major 52, minor 0.
            'java class file': b'\xca\xfe\xba\xbe\x00\x00\x00\x34' + bytes(200),
        }
        for label, data in cases.items():
            with self.subTest(label), self.assertRaises(BinaryError):
                scan(data)
        with self.assertRaisesRegex(BinaryError, 'overlapping'):
            scan(cases['overlapping slices'])
        with self.assertRaisesRegex(BinaryError, 'duplicate'):
            scan(cases['duplicate architecture'])

    def test_every_truncation_fails(self):
        for data in (thin(), thin(32, '>'), fat([(X86_64, 3, thin()), (ARM64, 0, thin(cpu=ARM64))])):
            for end in range(len(data)):
                with self.subTest(size=len(data), end=end), self.assertRaises(BinaryError):
                    scan(data[:end])

    def test_universal_metadata_must_match_the_contained_image(self):
        for wide in (False, True):
            for cpu, subtype in ((ARM64, 3), (X86_64, 4)):
                with self.subTest(wide=wide, cpu=cpu, subtype=subtype):
                    with self.assertRaisesRegex(BinaryError, 'architecture'):
                        scan(fat([(cpu, subtype, thin(cpu=X86_64, subtype=3))], wide=wide))

    def test_universal_slice_must_obey_declared_alignment(self):
        for wide in (False, True):
            data = bytearray(fat([(X86_64, 3, thin())], wide=wide))
            # Keep the valid offset but claim 4 KiB alignment instead of 16 bytes.
            struct.pack_into('>I', data, 8 + (24 if wide else 16), 12)
            with self.subTest(wide=wide), self.assertRaisesRegex(BinaryError, 'align'):
                scan(data)

    def test_declared_commands_must_consume_the_table(self):
        data = bytearray(thin())
        struct.pack_into('<I', data, 16, 0)
        with self.assertRaisesRegex(BinaryError, 'command table'):
            scan(data)

    def test_seeded_mutations_fail_cleanly_or_report_bounded_results(self):
        rng = random.Random(37)
        originals = [thin(), thin(32, '>'), fat([(X86_64, 3, thin()), (ARM64, 0, thin(cpu=ARM64))])]
        accepted = 0
        for _ in range(3000):
            data = bytearray(rng.choice(originals))
            for _ in range(rng.randint(1, 4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            try:
                result = scan(bytes(data))
            except BinaryError:
                continue
            accepted += 1
            self.assertIn(result['status'], ('complete_static', 'partial_static',
                                             'unsupported_object_type', 'unsupported_fat_byte_order'))
            self.assertLessEqual(len(result['slices']), MAX_SLICES)
            for dependency in result['dependencies']:
                self.assertIsInstance(dependency['name'], str)
        self.assertGreater(accepted, 100)

    def write(self, data, name='image'):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / name
        path.write_bytes(data)
        return path

    def test_inspector_report_and_planner_for_thin_image(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('execution')), \
                patch.object(subprocess, 'run', side_effect=AssertionError('execution')):
            report = inspect_file(self.write(thin()))
            plan = plan_inspection(report, host_os='darwin', host_arch='x86_64')
        self.assertEqual((report['binary']['format'], report['binary']['architecture']),
                         ('Mach-O', 'x86_64'))
        self.assertEqual(report['dependency_scan']['status'], 'complete_static')
        self.assertNotIn('slice_architectures', report['binary'])
        self.assertEqual(plan['observed_requirements'], report['static_dependencies'])
        self.assertEqual(plan['status'], 'candidates_found')
        self.assertFalse(plan['strategies'][0]['verified_compatible'])
        self.assertTrue(any('@rpath' in x for x in report['unknowns']))
        self.assertFalse(report['execution_attempted'])

    def plan_for(self, data, host_arch='x86_64', host_os='darwin'):
        report = inspect_file(self.write(data))
        return report, plan_inspection(report, host_os=host_os, host_arch=host_arch)

    def test_planner_offers_native_only_for_a_decoded_macos_executable(self):
        launchable = {
            'macOS executable': thin(commands=[build_version('<', platform=1)]),
            'Mac Catalyst executable': thin(commands=[build_version('<', platform=6)]),
            'executable without platform info': thin(commands=[]),
        }
        for label, data in launchable.items():
            with self.subTest(label):
                _, plan = self.plan_for(data)
                self.assertEqual(plan['strategies'][0]['state'], 'candidate')
        not_launchable = {
            'dylib': thin(file_type=6),
            'bundle': thin(file_type=8),
            'relocatable object': thin(file_type=1),
            'iOS executable': thin(commands=[build_version('<', platform=2)]),
            'watchOS executable': thin(commands=[build_version('<', platform=4)]),
            'iOS simulator executable': thin(commands=[build_version('<', platform=7)]),
            'legacy iOS version-min': thin(commands=[version_min('<', 0x25, 0x100000, 0x100000)]),
        }
        for label, data in not_launchable.items():
            with self.subTest(label):
                _, plan = self.plan_for(data)
                self.assertEqual(plan['strategies'][0]['state'], 'unavailable')
                self.assertEqual(plan['status'], 'unresolved')
                self.assertFalse(plan['strategies'][0]['verified_compatible'])

    def test_planner_requires_a_decoded_executable_slice_for_the_host(self):
        both = fat([(X86_64, 3, thin()), (ARM64, 0, thin(cpu=ARM64))])
        for host_arch, expected in (('x86_64', 'candidate'), ('arm64', 'candidate'), ('i386', 'unavailable')):
            self.assertEqual(self.plan_for(both, host_arch)[1]['strategies'][0]['state'], expected, host_arch)
        # the host-matching slice is only an object file: nothing launchable for this host
        mixed = fat([(X86_64, 3, thin()), (ARM64, 0, thin(cpu=ARM64, file_type=1))])
        self.assertEqual(self.plan_for(mixed, 'x86_64')[1]['strategies'][0]['state'], 'candidate')
        self.assertEqual(self.plan_for(mixed, 'arm64')[1]['strategies'][0]['state'], 'unavailable')
        # a dylib slice for the host architecture is not launchable either
        library = fat([(X86_64, 3, thin(file_type=6))])
        self.assertEqual(self.plan_for(library, 'x86_64')[1]['strategies'][0]['state'], 'unavailable')
        # platform is judged per slice
        platforms = fat([(X86_64, 3, thin(commands=[build_version('<', platform=1)])),
                         (ARM64, 0, thin(cpu=ARM64, commands=[build_version('<', platform=2)]))])
        self.assertEqual(self.plan_for(platforms, 'x86_64')[1]['strategies'][0]['state'], 'candidate')
        self.assertEqual(self.plan_for(platforms, 'arm64')[1]['strategies'][0]['state'], 'unavailable')

    def test_unsupported_images_and_slices_say_so_in_unknowns(self):
        report, _ = self.plan_for(thin(file_type=1))
        self.assertEqual(report['dependency_scan']['status'], 'unsupported_object_type')
        self.assertTrue(any('file type unsupported:1' in x for x in report['unknowns']))
        report, plan = self.plan_for(fat([(X86_64, 3, thin()), (ARM64, 0, thin(cpu=ARM64, file_type=1))]))
        self.assertEqual(report['dependency_scan']['status'], 'partial_static')
        self.assertTrue(any('slice 1 (aarch64)' in x for x in report['unknowns']))
        self.assertTrue(any('slice 1 (aarch64)' in x for x in plan['unresolved']))
        self.assertFalse(any('slice 0' in x for x in report['unknowns']))

    def test_universal_file_of_only_unsupported_slices_is_unsupported_not_partial(self):
        data = fat([(X86_64, 3, thin(file_type=1)), (ARM64, 0, thin(cpu=ARM64, file_type=1))])
        result = scan(data)
        self.assertEqual((result['status'], result['dependencies']), ('unsupported_object_type', []))
        self.assertEqual(sum('outside dependency inspection scope' in x for x in result['unknowns']), 2)

    def test_build_version_and_version_min_sizes_are_validated(self):
        short = struct.pack('<IIIIII', 0x32, 24, 1, 0x0d0000, 0x0e0000, 5)  # claims 5 tools, has room for 0
        with self.assertRaisesRegex(BinaryError, 'tool list'):
            scan(thin(commands=[short]))
        with_tool = struct.pack('<IIIIII', 0x32, 32, 1, 0x0d0000, 0x0e0000, 1) + struct.pack('<II', 3, 0x10000)
        self.assertEqual(scan(thin(commands=[with_tool]))['dependencies'][0]['name'], 'macos')
        padded = struct.pack('<IIII', 0x24, 24, 0x0a0f00, 0x0a1000) + bytes(8)
        with self.assertRaisesRegex(BinaryError, 'version-min'):
            scan(thin(commands=[padded]))

    def test_cpu_labels_are_complete_for_common_apple_types(self):
        for cpu, label in ((0x0200000c, 'arm64_32'), (18, 'ppc'), (0x01000012, 'ppc64'),
                           (0x01000099, 'unknown:0x1000099')):
            self.assertEqual(scan(thin(cpu=cpu, file_type=1))['slices'][0]['architecture'], label)

    def test_fat_error_messages_name_the_real_problem(self):
        java = b'\xca\xfe\xba\xbe\x00\x00\x00\x34' + bytes(200)
        with self.assertRaisesRegex(BinaryError, 'Java class'):
            scan(java)
        archive = fat([(X86_64, 3, b'!<arch>\n' + bytes(64))])
        with self.assertRaisesRegex(BinaryError, r'slice 0 is not a Mach-O image .*archive'):
            scan(archive)

    def test_inspector_and_planner_for_universal_binary(self):
        report = inspect_file(self.write(fat([(X86_64, 3, thin()), (ARM64, 0, thin(cpu=ARM64))])))
        self.assertEqual(report['binary']['format'], 'Mach-O-fat')
        self.assertEqual(report['binary']['architecture'], 'multiple')
        self.assertEqual(report['binary']['slice_architectures'], ['x86_64', 'aarch64'])
        cases = [('darwin', 'x86_64', True), ('darwin', 'arm64', True),
                 ('darwin', 'i386', False), ('linux', 'x86_64', False)]
        for host_os, host_arch, expected in cases:
            with self.subTest(host_os=host_os, host_arch=host_arch):
                plan = plan_inspection(report, host_os=host_os, host_arch=host_arch)
                self.assertEqual(plan['status'], 'candidates_found' if expected else 'unresolved')
                self.assertFalse(plan['strategies'][0]['verified_compatible'])
        self.assertIn('x86_64, aarch64', ' '.join(plan['strategies'][0]['constraints']))

    def test_inspector_wraps_malformed_images(self):
        with self.assertRaises(InspectionError):
            inspect_file(self.write(b'\xca\xfe\xba\xbe\x00\x00\x00\x02'))
        with self.assertRaises(InspectionError):
            inspect_file(self.write(thin()[:40]))

    @unittest.skipUnless(shutil.which('clang') and shutil.which('llvm-objdump') and LIPO and LD64,
                         'requires clang, ld64.lld, llvm-objdump and llvm-lipo')
    def test_linked_images_match_llvm_objdump(self):
        linker = LD64

        def stub(directory, install, symbol):
            path = Path(directory) / (Path(install).stem + '.tbd')
            path.write_text(
                '--- !tapi-tbd\ntbd-version: 4\ntargets: [ x86_64-macos, arm64-macos ]\n'
                f"install-name: '{install}'\ncurrent-version: 1.2.3\ncompatibility-version: 1.0\n"
                'exports:\n  - targets: [ x86_64-macos, arm64-macos ]\n'
                f'    symbols: [ {symbol} ]\n...\n')
            return path
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            strong = stub(root, '/usr/local/lib/libuoefix.dylib', '_uoe_probe')
            weak = stub(root, '/usr/local/lib/libweakfix.dylib', '_uoe_weak')
            (root / 'client.c').write_text(
                'int uoe_probe(void);\n'
                'extern int uoe_weak(void) __attribute__((weak_import));\n'
                'int main(void) { return uoe_probe() + (uoe_weak ? uoe_weak() : 0); }\n')
            images = {}
            for arch, target in (('x86_64', 'x86_64-apple-macos13'), ('arm64', 'arm64-apple-macos13')):
                subprocess.run(['clang', f'--target={target}', '-c', str(root / 'client.c'),
                                '-o', str(root / f'{arch}.o')], check=True, capture_output=True, timeout=60)
                linked = subprocess.run(
                    [linker, '-arch', arch, '-platform_version', 'macos', '13.0', '14.2',
                     '-o', str(root / arch), str(root / f'{arch}.o'), str(strong),
                     '-weak_library', str(weak), '-rpath', '@loader_path/../lib',
                     '-rpath', '/opt/uoe/lib', '-no_uuid', '-e', '_main',
                     '-U', 'dyld_stub_binder'], capture_output=True, text=True, timeout=60)
                if linked.returncode:
                    self.skipTest('this LLVM linker cannot produce Mach-O here: ' + linked.stderr[-200:])
                images[arch] = root / arch
            subprocess.run([LIPO, '-create', str(images['x86_64']), str(images['arm64']),
                            '-output', str(root / 'universal')], check=True, capture_output=True, timeout=30)

            def reference(path, arch=None):
                command = ['llvm-objdump', '--macho']
                if arch:
                    command += ['--arch', arch]
                libraries = subprocess.run(command + ['--dylibs-used', str(path)], check=True,
                                           capture_output=True, text=True, timeout=30).stdout
                rpaths = subprocess.run(command + ['--rpaths', str(path)], check=True,
                                        capture_output=True, text=True, timeout=30).stdout
                used = [line.strip().split(' (')[0] for line in libraries.splitlines()
                        if line.startswith('\t')]
                weak_used = [line.strip().split(' (')[0] for line in libraries.splitlines()
                             if line.startswith('\t') and line.rstrip().endswith(', weak)')]
                paths = [line for line in rpaths.splitlines() if line and not line.endswith(':')]
                return used, weak_used, paths
            for arch, path in images.items():
                report = inspect_file(path)
                used, weak_used, paths = reference(path)
                libraries = [d for d in report['static_dependencies'] if d['kind'] == 'shared_library']
                self.assertEqual([d['name'] for d in libraries], used)
                self.assertEqual([d['name'] for d in libraries if d['load_kind'] == 'weak'], weak_used)
                self.assertEqual([d['name'] for d in report['static_dependencies']
                                  if d['kind'] == 'runtime_search_path'], paths)
                self.assertEqual([d['name'] for d in report['static_dependencies']
                                  if d['kind'] == 'interpreter'], ['/usr/lib/dyld'])
                platform = next(d for d in report['static_dependencies'] if d['kind'] == 'platform')
                self.assertEqual((platform['name'], platform['minimum_os_version'], platform['sdk_version']),
                                 ('macos', '13.0.0', '14.2.0'))
                self.assertFalse(report['execution_attempted'])
            report = inspect_file(root / 'universal')
            self.assertEqual(report['binary']['slice_architectures'], ['x86_64', 'aarch64'])
            for arch, llvm_arch in (('x86_64', 'x86_64'), ('aarch64', 'arm64')):
                used, weak_used, paths = reference(root / 'universal', llvm_arch)
                ours = [d for d in report['static_dependencies']
                        if d['slice']['architecture'] == arch]
                self.assertEqual([d['name'] for d in ours if d['kind'] == 'shared_library'], used)
                self.assertEqual([d['name'] for d in ours if d['kind'] == 'runtime_search_path'], paths)


if __name__ == '__main__':
    unittest.main()
