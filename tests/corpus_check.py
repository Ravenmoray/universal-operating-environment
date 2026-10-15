"""Compare static dependency extraction with independent tools over local files.

Usage: python3 tests/corpus_check.py PATH [PATH ...] [--limit N] [--json] [--fail-on-reject]

Files are only read, never executed. Reference tools are optional; a comparison
is skipped (and counted) when its tool is missing:

  ELF     readelf (binutils): NEEDED entries and the program interpreter
  PE      llvm-readobj --coff-imports: DLL names, delay-load vs static, imported symbol names;
          for managed images, dnfile (optional pip package) assembly/module references
  WASM    Node.js WebAssembly.Module.imports (compiles; never instantiates)
  Mach-O  llvm-objdump --macho --dylibs-used --rpaths

Exit status is 1 when any file crashes the parser or disagrees with its
reference. By default a file the parser *rejects* is listed with its reason but is
not a failure: corrupt and hostile files are expected to be rejected. Pass
--fail-on-reject when the corpus is known to be valid (for example a CI runner's own
system binaries) so that a parser that wrongly rejects valid files cannot pass.
Results describe only the files you point this at; they are not a coverage claim.
"""
import argparse
import collections
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from uoe.inspector import InspectionError, inspect_file  # noqa: E402

NODE_SCRIPT = ('const m=new WebAssembly.Module(require("fs").readFileSync(process.argv[1]));'
               'console.log(JSON.stringify(WebAssembly.Module.imports(m)))')
PE_SUFFIXES = ('.exe', '.dll', '.pyd', '.sys', '.ocx', '.efi')


def group_by_module(rows):
    """V8 lists imports in declaration order; uoe groups them by module in first-appearance order."""
    order = list(dict.fromkeys(row['module'] for row in rows))
    return [row for module in order for row in rows if row['module'] == module]


def run(command):
    return subprocess.run(command, capture_output=True, text=True, errors='replace',
                          timeout=120, env=dict(os.environ, LC_ALL='C'))


def candidates(paths):
    seen = set()  # a symlinked root (e.g. /lib -> /usr/lib) or hard link must count once
    for root in paths:
        # Absolute, so a file named like an option (``--eval=...``) can never be parsed as
        # one by the reference tools it is handed to (node, readelf, llvm-*).
        root = Path(os.path.abspath(root))
        files = [root] if root.is_file() else (
            Path(dirpath) / name for dirpath, _, names in os.walk(root) for name in sorted(names))
        for path in files:
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                identity = (path.stat().st_dev, path.stat().st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                with path.open('rb') as handle:
                    head = handle.read(8)
            except OSError:
                continue
            if head.startswith(b'\x7fELF'):
                yield 'ELF', path
            elif head.startswith(b'MZ') and path.suffix.lower() in PE_SUFFIXES:
                yield 'PE', path
            elif head.startswith(b'\0asm'):
                yield 'WASM', path
            elif head[:4] in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
                              b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
                yield 'Mach-O', path


def reference_elf(path):
    if not shutil.which('readelf'):
        return None
    dynamic, headers = run(['readelf', '-dW', str(path)]), run(['readelf', '-lW', str(path)])
    if dynamic.returncode or headers.returncode:
        return 'rejected'       # empty output from a failed run must not pass as "no libraries"
    return (re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic.stdout),
            re.findall(r'Requesting program interpreter: (.*?)\]', headers.stdout))


def observed_elf(report):
    deps = report['static_dependencies']
    return ([d['name'] for d in deps if d['kind'] == 'shared_library'],
            [d['name'] for d in deps if d['kind'] == 'interpreter'])


def reference_pe(path):
    if not shutil.which('llvm-readobj'):
        return None
    done = run(['llvm-readobj', '--coff-imports', str(path)])
    if done.returncode:
        return 'rejected'       # empty output from a failed run must not pass as "no imports"
    out = done.stdout
    # Top-level blocks start in column 0; nested "  Import {" entries inside a
    # DelayImport block are indented and are not separate DLLs.
    blocks = re.findall(r'^(Delay)?Import \{\s*\n\s+Name: (.*?)\n(.*?)\n\}', out, re.S | re.M)
    return [('delay' if delay else 'static', name,
             [n for n, _ in re.findall(r'Symbol: (.+?) \((\d+)\)', body)])
            for delay, name, body in blocks]


def observed_pe(report):
    return [(d['load_kind'], d['name'], [s['name'] for s in d['symbols'] if 'name' in s])
            for d in report['static_dependencies'] if d['kind'] == 'shared_library']


class ReferenceIncomplete(Exception):
    """dnfile read the file only partly, so it cannot serve as a reference for it."""


def clr_facts(dn):
    """Assembly references and module references of a parsed ``dnfile.dnPE``, as uoe reports them."""
    import hashlib

    def text(item):
        return item.value.decode() if isinstance(item.value, bytes) else item.value
    if dn.net.metadata.struct.NumberOfStreams != len(dn.net.metadata.streams_list):
        raise ReferenceIncomplete('dnfile stopped before reading every declared metadata stream')
    for stream in dn.net.metadata.streams_list:
        # dnfile matches the whole 8-byte padded name field, so a stream whose NUL padding is
        # not all zero (which CoreCLR and uoe accept) falls into a generic stream and is lost.
        if type(stream).__name__ == 'GenericStream' and bytes(stream.struct.Name).split(b'\0')[0] in (
                b'#~', b'#-', b'#Strings', b'#US', b'#GUID', b'#Blob'):
            raise ReferenceIncomplete('dnfile did not recognise a standard metadata stream')
    tables = dn.net.mdtables
    assemblies = []
    for row in (tables.AssemblyRef.rows if tables.AssemblyRef else []):
        key = bytes(row.PublicKey.value) if row.PublicKey is not None and row.PublicKey.value else b''
        token = (hashlib.sha1(key).digest()[-8:][::-1].hex() if row.Flags.afPublicKey else key.hex()) if key else None
        assemblies.append((text(row.Name), f'{row.MajorVersion}.{row.MinorVersion}.{row.BuildNumber}.{row.RevisionNumber}',
                           text(row.Culture) or None, token))
    modules = [text(row.Name) for row in (tables.ModuleRef.rows if tables.ModuleRef else [])]
    return assemblies, modules


def reference_clr(path):
    """Managed references via the optional dnfile package (None when not importable)."""
    try:
        import dnfile
    except ImportError:
        return None
    try:
        parsed = dnfile.dnPE(str(path))
    except Exception:       # dnfile itself could not parse the file
        return 'rejected'
    try:
        return clr_facts(parsed)
    except ReferenceIncomplete:
        return 'rejected'


def observed_clr(report):
    deps = report['static_dependencies']
    return ([(d['name'], d['version'], d['culture'], d['public_key_token'])
             for d in deps if d['kind'] == 'managed_assembly'],
            [d['name'] for d in deps if d['kind'] == 'native_module_reference'])


def reference_wasm(path):
    if not shutil.which('node'):
        return None
    done = run(['node', '-e', NODE_SCRIPT, str(path)])
    return group_by_module(json.loads(done.stdout)) if done.returncode == 0 else 'rejected'


def observed_wasm(report):
    return [{'module': d['name'], 'name': s['name'], 'kind': s['kind']}
            for d in report['static_dependencies'] for s in d['symbols']]


def reference_macho(path):
    if not shutil.which('llvm-objdump'):
        return None
    done = run(['llvm-objdump', '--macho', '--arch', 'all', '--dylibs-used', '--rpaths', str(path)])
    names = [line.strip().split(' (')[0] for line in done.stdout.split('\n')
             if line.strip() and not line.rstrip().endswith(':') and not line.startswith(str(path))]
    # --dylibs-used lists a dylib's own install name (LC_ID_DYLIB), which is its
    # identity rather than a requirement; remove it once per architecture.
    identity = run(['llvm-objdump', '--macho', '--arch', 'all', '--dylib-id', str(path)])
    for line in identity.stdout.split('\n'):
        if line.strip() and not line.rstrip().endswith(':') and line.strip() in names:
            names.remove(line.strip())
    return sorted(names) if done.returncode == 0 and (names or identity.stdout.strip()) else 'rejected'


def observed_macho(report):
    return sorted(d['name'] for d in report['static_dependencies']
                  if d['kind'] in ('shared_library', 'runtime_search_path'))


COMPARERS = {'ELF': (reference_elf, observed_elf), 'PE': (reference_pe, observed_pe),
             'WASM': (reference_wasm, observed_wasm), 'Mach-O': (reference_macho, observed_macho)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('paths', nargs='+')
    parser.add_argument('--limit', type=int, default=0, help='stop after N files per format')
    parser.add_argument('--json', action='store_true', help='print the full machine-readable result')
    parser.add_argument('--fail-on-reject', action='store_true',
                        help='exit 1 if the parser rejects any file (use only on corpora known to be valid)')
    args = parser.parse_args(argv)

    summary = {fmt: collections.Counter() for fmt in COMPARERS}
    problems = collections.defaultdict(list)
    for fmt, path in candidates(args.paths):
        counts = summary[fmt]
        if args.limit and counts['files'] >= args.limit:
            continue
        counts['files'] += 1
        try:
            report = inspect_file(path)
        except InspectionError as exc:
            counts['rejected'] += 1
            problems[fmt + ' rejected'].append(f'{path}: {exc}')
            continue
        except Exception as exc:  # a crash is always a defect
            counts['crashed'] += 1
            problems[fmt + ' crashed'].append(f'{path}: {exc!r}')
            continue
        status = report['dependency_scan']['status']
        if status in ('unsupported_object_type', 'unsupported_fat_byte_order'):
            counts['unsupported_scope'] += 1
            continue
        if status in ('partial_static',):
            counts['partial'] += 1
            continue
        if fmt == 'PE' and any(d['kind'] == 'managed_runtime' for d in report['static_dependencies']):
            counts['managed'] += 1
            managed = reference_clr(path)
            if managed is None:
                counts['managed_no_reference_tool'] += 1
            elif managed == 'rejected':
                counts['managed_reference_also_rejected'] += 1
            elif managed == observed_clr(report):
                counts['managed_matched'] += 1
            else:
                counts['disagreed'] += 1
                problems[fmt + ' managed disagreed'].append(str(path))
        reference, observed = COMPARERS[fmt]
        expected = reference(path)
        if expected is None:
            counts['no_reference_tool'] += 1
        elif expected == 'rejected':
            counts['reference_also_rejected'] += 1
        elif expected == observed(report):
            counts['matched'] += 1
        else:
            counts['disagreed'] += 1
            problems[fmt + ' disagreed'].append(str(path))
    result = {'summary': {fmt: dict(c) for fmt, c in summary.items() if c},
              'details': {kind: rows[:50] for kind, rows in problems.items()}}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for fmt, counts in result['summary'].items():
            print(f'{fmt:7} ' + ', '.join(f'{k}={v}' for k, v in sorted(counts.items())))
        for kind, rows in result['details'].items():
            print(f'-- {kind} ({len(problems[kind])}); first {min(5, len(rows))}:')
            for row in rows[:5]:
                print('   ', row)
    failed = any(counts['crashed'] or counts['disagreed'] or (args.fail_on_reject and counts['rejected'])
                 for counts in summary.values())
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
