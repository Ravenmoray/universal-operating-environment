"""Seeded differential fuzzing of the WASM and Mach-O parsers against reference tools.

Usage:
  python3 tests/fuzz_differential.py wasm   [--seed N] [--count N] [--seed-file FILE ...]
  python3 tests/fuzz_differential.py macho  [--seed N] [--count N] [--seed-file FILE ...]

Mutated copies of small seed inputs are only *parsed*, never executed:
  wasm    reference = Node.js (V8) WebAssembly.Module.imports, which compiles
          without instantiating. A module V8 accepts must be accepted by uoe and
          report the same imports.
  macho   reference = llvm-objdump --macho. Where uoe reports a complete static
          scan and llvm-objdump succeeds, the dependent-library and rpath lists
          must agree.

uoe is deliberately stricter than the references in a few places (non-UTF-8
strings, resource budgets, unsupported file types); those rejections are counted,
not failures. Any V8-accepted module that uoe rejects or misreports, and any
disagreeing Mach-O list, exits with status 1 and prints the offending input in hex.
Results describe the seeds, count and tool versions used; they are not a coverage claim.
"""
import argparse
import collections
import io
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from uoe.binary_input import BinaryError  # noqa: E402
import uoe.macho as macho  # noqa: E402
import uoe.wasm as wasm  # noqa: E402

V8_SCRIPT = ('const rows=require("fs").readFileSync(0,"utf8").split("\\n").filter(Boolean);'
             'console.log(JSON.stringify(rows.map(h=>{try{return WebAssembly.Module.imports('
             'new WebAssembly.Module(Buffer.from(h,"hex")))}catch(e){return null}})));')


def group_by_module(rows):
    """V8 lists imports in declaration order; uoe groups them by module in first-appearance order."""
    order = list(dict.fromkeys(row['module'] for row in rows))
    return [row for module in order for row in rows if row['module'] == module]


def mutate(rng, seeds, window=None):
    data = bytearray(rng.choice(seeds))
    for _ in range(rng.randint(1, 3)):
        limit = min(len(data), window) if window else len(data)
        mode = rng.random()
        if mode < 0.7 or limit < 12:
            data[rng.randrange(limit)] = rng.randrange(256)
        elif mode < 0.85:
            del data[rng.randrange(8, limit)]
        else:
            data.insert(rng.randrange(8, limit), rng.randrange(256))
    return bytes(data)


def fuzz_wasm(args):
    if not shutil.which('node'):
        print('node is required for the wasm reference'); return 2
    from test_wasm_dependencies import (HEADER, MEMORY, TYPES, FUNC, entry, golden, imports)
    seeds = [golden(), HEADER + TYPES + imports(entry('a', 'b', FUNC(1)), entry('a', 'c', MEMORY))]
    seeds += [Path(p).read_bytes() for p in args.seed_file]
    rng = random.Random(args.seed)
    cases = [mutate(rng, seeds) for _ in range(args.count)]
    out = subprocess.run(['node', '-e', V8_SCRIPT], input='\n'.join(c.hex() for c in cases),
                         capture_output=True, text=True, check=True, timeout=600).stdout
    stats, bad = collections.Counter(), []
    for data, expected in zip(cases, json.loads(out)):
        try:
            report = wasm.inspect_dependencies(io.BytesIO(data), len(data))
            observed = [{'module': d['name'], 'name': s['name'], 'kind': s['kind']}
                        for d in report['dependencies'] for s in d['symbols']]
        except BinaryError as exc:
            observed, error = None, str(exc)
        if expected is None:
            stats['v8_rejected_ours_accepted' if observed is not None else 'both_rejected'] += 1
        elif observed is None:
            stats['FALSE_REJECTION'] += 1; bad.append((error, data.hex()))
        elif observed != group_by_module(expected):
            stats['MISREPORTED'] += 1; bad.append(('imports differ', data.hex()))
        else:
            stats['both_accepted_and_agree'] += 1
    return finish(stats, bad)


def fuzz_macho(args):
    if not shutil.which('llvm-objdump'):
        print('llvm-objdump is required for the macho reference'); return 2
    import struct
    from test_macho_dependencies import ARM64, X86_64, build_version, dylib, fat, lc_str, thin

    def rich(bits, endian, cpu):
        # Undecoded filler (like segment commands in real images) gives mutations
        # somewhere harmless to land, so more mutated inputs remain well formed.
        align = 8 if bits == 64 else 4
        filler = struct.pack(endian + 'II', 0x19, 400) + bytes(392)
        return thin(bits, endian, cpu, commands=[
            filler, lc_str(endian, 0x0e, '/usr/lib/dyld', align), build_version(endian),
            dylib(endian, 0x0c, '/usr/lib/libSystem.B.dylib', align),
            dylib(endian, 0x80000018, '@rpath/libweak.dylib', align),
            lc_str(endian, 0x8000001c, '@loader_path/../lib', align), filler])
    seeds = [thin(), thin(32, '>'), rich(64, '<', X86_64), rich(32, '>', 7),
             fat([(X86_64, 3, rich(64, '<', X86_64)), (ARM64, 0, rich(64, '<', ARM64))])]
    seeds += [Path(p).read_bytes() for p in args.seed_file]
    rng = random.Random(args.seed)
    stats, bad = collections.Counter(), []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'case'
        for _ in range(args.count):
            data = mutate(rng, seeds, window=2400)
            path.write_bytes(data)
            def objdump(*options):
                done = subprocess.run(['llvm-objdump', '--macho', '--arch', 'all', *options, str(path)],
                                      capture_output=True, timeout=60)
                return done.returncode, done.stdout.decode('utf-8', 'replace').split('\n')
            code, lines = objdump('--dylibs-used', '--rpaths')
            _, identity = objdump('--dylib-id')
            try:
                report = macho.inspect_dependencies(io.BytesIO(data), len(data))
            except BinaryError:
                stats['uoe_rejected'] += 1
                continue
            if report['status'] != 'complete_static':
                stats['outside_scope_or_partial'] += 1
                continue
            reference = [line.strip().split(' (')[0] for line in lines
                         if line.strip() and not line.rstrip().endswith(':')
                         and not line.startswith(str(path))]
            # --dylibs-used also lists a dylib's own LC_ID_DYLIB (an identity, not a requirement).
            for line in identity:
                if line.strip() and not line.rstrip().endswith(':') and line.strip() in reference:
                    reference.remove(line.strip())
            if code or not reference and report['dependencies']:
                stats['reference_rejected'] += 1
                continue
            ours = [d['name'] for d in report['dependencies']
                    if d['kind'] in ('shared_library', 'runtime_search_path')]
            # llvm-objdump prints one name per line, so a name containing a control character
            # (e.g. a mutated newline) cannot be compared faithfully; do not call that a disagreement.
            if any(ord(ch) < 32 or ord(ch) == 127 for name in ours for ch in name):
                stats['control_characters_skipped'] += 1
                continue
            ours, reference = sorted(ours), sorted(reference)
            if ours == reference:
                stats['agree'] += 1
            else:
                stats['DISAGREE'] += 1; bad.append((f'{ours} != {reference}', data.hex()))
    return finish(stats, bad)


def finish(stats, bad):
    print(json.dumps(dict(stats), sort_keys=True))
    for reason, data in bad[:5]:
        print('  ', reason, data[:240])
    return 1 if bad else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('format', choices=('wasm', 'macho'))
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--count', type=int, default=5000)
    parser.add_argument('--seed-file', action='append', default=[],
                        help='extra real input to mutate (repeatable)')
    args = parser.parse_args(argv)
    return fuzz_wasm(args) if args.format == 'wasm' else fuzz_macho(args)


if __name__ == '__main__':
    raise SystemExit(main())
