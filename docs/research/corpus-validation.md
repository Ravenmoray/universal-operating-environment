# Corpus and differential validation of the static parsers

Unit tests built from the author's own understanding of a format can share the
author's blind spots. This note records two independent-oracle checks run against the
v0.3 parsers, **what they found**, and what they cannot show. Both are reproducible
with scripts in `tests/` that only *read* files.

> **Safety.** The reference tools (`readelf`, `llvm-readobj`, `llvm-objdump`, Node.js and
> the optional `dnfile`/`pefile` Python packages) parse the files too, and V8 compiles
> WebAssembly. Run these scripts only on trusted corpora or inside a disposable,
> isolated environment — never on untrusted downloads on a workstation. The scripts never
> execute the inputs. File names are passed to the reference tools as absolute paths so
> that a file named like an option cannot be read as one.

## 1. Real-world corpus comparison

```
python3 tests/corpus_check.py PATH [PATH ...]      # add --json for machine-readable output
```

Each file is classified by magic, inspected with `uoe`, and compared with an
independent reference:

| Format | Reference | Compared |
| --- | --- | --- |
| ELF | GNU `readelf -dW` / `-lW` | `NEEDED` entries and program interpreter, in order |
| PE | `llvm-readobj --coff-imports` | DLL names, order and imported symbol names |
| .NET (PE with a CLR header) | [`dnfile`](https://github.com/mandiant/dnfile) 0.18.0, optional | `AssemblyRef` name, version, culture and public-key token; `ModuleRef` names |
| WASM | Node.js `WebAssembly.Module.imports` | module, name and kind of every import |
| Mach-O | `llvm-objdump --macho` | dylib and rpath lists across all slices (own `LC_ID_DYLIB` excluded) |

Files are de-duplicated by device/inode. A file `uoe` rejects is listed with its
reason; a crash or a disagreement with the reference makes the script exit 1.

**Run recorded for this note** (ephemeral Ubuntu cloud container image, commit base
`7a37aea` plus the v0.3 WASM/Mach-O increment; `python3 tests/corpus_check.py /usr /opt
/root/.cache /root/.local /lib`):

| Format | Files | Exactly matched | Partial | Out of scope | Rejected / crashed / disagreed |
| --- | ---: | ---: | ---: | ---: | ---: |
| ELF | 4,492 | 4,049 | 277 | 166 | 0 / 0 / 0 |
| PE | 52 | 52 | — | — | 0 / 0 / 0 |
| WASM | 3 | 3 | — | — | 0 / 0 / 0 |
| Mach-O | 15 | 7 | — | 8 | 0 / 0 / 0 |

- *Partial* ELF files are separate debug files (`/usr/lib/debug/.build-id/*.debug`)
  whose `PT_DYNAMIC` has no file content; they are reported `partial_static`.
- *Out of scope* are relocatable objects (ELF `ET_REL`; Mach-O `MH_OBJECT` such as Go
  `.syso` files), reported `unsupported_object_type`.
- The PE files are Python packaging launchers (x86, x64, ARM64) and vendor
  executables, including large Rust-built binaries. The seven matched Mach-O files
  are real executables, dylibs and one universal bundle built by their vendors.
- The three WASM modules include a dynamically-linked build with a `GOT.mem` import
  module.

Tool versions: GNU readelf 2.42, LLVM 18.1.3 (`llvm-readobj`, `llvm-objdump`),
Node.js v22.22.0, Python 3.13.16, Linux 6.18 x86-64. Counts depend on whatever the
image contained and **are not a coverage claim**: the corpus is dominated by one
distribution's build outputs, is not redistributable and is not committed.

## 2. Seeded differential fuzzing

```
python3 tests/fuzz_differential.py wasm  --seed 101 --count 20000
python3 tests/fuzz_differential.py macho --seed 101 --count 3000
python3 tests/fuzz_differential.py clr   --seed 101 --count 5000     # needs: pip install dnfile==0.18.0
```

Small seed inputs are mutated (byte replacement, deletion, insertion; for `clr`, byte
replacement biased towards the CLI header, metadata root, stream headers and table header)
and parsed.
The contract checked is one-sided on purpose: `uoe` may be *stricter* than the
reference, but must never reject or misreport something the reference accepts.

| Run | Outcome |
| --- | --- |
| WASM vs V8, 20,000 cases | 1,074 accepted by both with identical imports; 17,749 rejected by both; 1,177 rejected by V8 but accepted by `uoe` (expected: function bodies and semantics are not validated); **0** V8-accepted modules rejected or misreported |
| Mach-O vs `llvm-objdump`, 3,000 cases | 849 agree; 1,783 rejected by `uoe` (stricter: structure, budgets, UTF-8); 351 rejected by the reference only; 17 outside the scan's scope; **0** disagreements |

This is seeded mutation of small inputs with a fixed PRNG, **not coverage-guided
fuzzing**, and it covers only the structures the seeds contain. It does not replace
the sustained fuzzing the [delivery plan](../roadmap/v1-delivery-plan.md) requires.

## 3. PE delay-load imports and .NET references

The 52 PE files in the first corpus run contained **no** delay-load directory and
**no** CLR directory, so those paths had no real-file evidence at all until fixtures
were found or built. Sources, all used read-only and not committed (their licenses
were not reviewed for redistribution; they are fetched only for local parsing):

- **Real MSVC-built delay-load files:** 103 PE files (mostly `.pyd` extension modules)
  extracted from twelve PyPI `win_amd64` wheels (cffi, cryptography, greenlet, grpcio,
  lxml, markupsafe, numpy, orjson, pillow, psutil, pywin32, pyzmq). Three of them
  (`win32api.pyd`, `win32evtlog.pyd`, `propsys.pyd`, all from pywin32) have a
  delay-import table, each naming one delayed DLL (`POWRPROF.dll`, `wevtapi.dll`,
  `SHELL32.dll`) with a non-empty bound-delay-import table and no unload table.
- **Real managed assemblies:** `Python.Runtime.dll` (pythonnet 3.2.1, a .NET Standard 2.0
  library with five P/Invoke module references) and `ClrLoader.dll` for x86 and amd64
  (clr_loader 0.3.1).
- **Linker output we control:** a PE built with `lld-link` (x86-64) with `user32.dll`
  delay-loaded, also built (x86-64 and ARM64) by the unit tests.

References: `llvm-readobj --coff-imports` for imports and delay imports (DLL names,
delay vs static, symbol names in order) and [`dnfile`](https://github.com/mandiant/dnfile)
0.18.0 (with `pefile` 2024.8.26) for assembly and module references (name, version,
culture, public-key token).

| Check | Result |
| --- | --- |
| `corpus_check.py` over those files (107 PE files: 103 from wheels, 3 managed, 1 `lld-link` build) vs `llvm-readobj` | 107 / 107 matched, including all 3 MSVC delay-load files and the `lld-link` file; 0 rejected |
| The 3 managed assemblies vs `dnfile` | 3 / 3 matched on assembly refs (name, version, culture, token) and module refs |
| `fuzz_differential.py clr --seed 101 --count 5000` (3 synthetic seeds: narrow heaps, all heap indexes wide, no modules) | 1,960 accepted by both with identical facts; 1,551 rejected by both; 1,361 rejected by `uoe` only (stricter); 128 accepted by `uoe` where `dnfile` failed or read the metadata incompletely (not compared); **0** mismatches, **0** crashes |
| `fuzz_differential.py clr --seed 102 --count 3000 --seed-file …` (the 3 synthetic seeds plus the 3 real assemblies) | 1,815 accepted by both with identical facts; 595 rejected by both; 550 rejected by `uoe` only (stricter); 40 accepted by `uoe` where `dnfile` failed or read the metadata incompletely (not compared); **0** mismatches, **0** crashes |

Further runs of the same tool during development (seeds 1–4 at 3,000 cases and seeds
11–12 at 4,000, 20,000 cases in all, after the fixes below) also found no mismatch.

Treat the sample sizes honestly: three delay-load files from one project, and three
managed images from two small packages, all with narrow heaps. There is no
`System.Private.CoreLib`-scale assembly, no ReadyToRun or single-file bundle, and no
.NET Framework 2.0 metadata (`v2.0.50727`) in the set. Of the coded indexes whose width
depends on row counts, only `HasCustomAttribute` is wide in a real file
(`Python.Runtime.dll`: `MethodDef` has 3,920 and `Param` 3,276 rows, above the 2,048
threshold); wide heap indexes and wide simple indexes appear only in the synthetic
unit-test fixtures (hand-computed row sizes, cross-checked with `dnfile`).

The CLR fuzz enforces only a one-sided contract, and a weaker one than WASM's, because
`dnfile` is a lenient analysis library rather than a loader: `uoe` may be stricter than
`dnfile`, but where both accept an input the assembly references (name, version,
culture, token) and module references must be identical, and `uoe` must never raise
anything but a clean rejection. The rejections it recorded are of the deliberate kinds;
the most frequent were non-UTF-8 strings, a stream or table running past its declared
bounds, blob indexes outside the heap, non-UTF-8 version strings, non-ASCII stream names,
row-count budgets and a CLI header size other than 72. Inputs `dnfile` cannot parse or
reads incompletely (it stops at a zero-size stream, and does not recognise a stream whose
name padding is not all NUL; `uoe` accepts both, reading a stream name up to its first
NUL without checking the padding) are counted separately and are **not** compared, so
"0 mismatches" excludes them.

## Defects these checks found

Recorded because the failures are as informative as the passes.

1. **ELF string-table cap rejected mainstream executables.** The parser read the whole
   `DT_STRTAB` and capped it at 1,000,000 bytes. 12 of the first 3,000 files — pandoc
   (`DT_STRSZ` ≈ 41 MB), Node.js (≈ 7.8 MB for v22; v20 and v21 also failed), rclone
   (≈ 2.7 MB) and GCC's `lto-dump` (≈ 1.2 MB) — failed with "missing or oversized ELF
   string table" although `readelf` listed their libraries. Fixed by reading only the boundary
   bytes and each referenced name; regression-tested with a 20 MB table.
2. **Separate debug files raised errors.** 273 of the first 3,000 files had
   `PT_DYNAMIC`/`PT_INTERP` with zero file size (`objcopy --only-keep-debug`). They now
   produce `partial_static` with an explicit unknown instead of an error or a guess.
   **This fix was incomplete when first written** (see the audit section below): it
   handled zero-size segments but still rejected debug files whose segment offsets lie
   beyond the end of the file, which is what `objcopy --only-keep-debug` normally produces.
3. **WASM GC/exception-handling reference types were rejected.** The differential fuzz
   found modules V8 accepts (tables/globals of `anyref`, `exnref`, `nofunc`, typed
   `(ref null $t)`) that the first WASM decoder refused. Decoder extended; cases are
   permanent tests.

4. **The corpus tool silently skipped Python extension modules.** `corpus_check.py` did
   not treat `.pyd` files as PE, so a scan of the twelve Windows wheels saw 9 PE files
   instead of 103 and found no delay-load files. Fixed; `.pyd` is now in the suffix list.
5. **A blob index of 0 was assumed to mean "no key".** The first `dnfile` fuzz compared
   only names and versions and reported nothing. Adding culture and public-key token
   to the comparison exposed it: when the first byte of `#Blob` (which ECMA-335 requires
   to be 0) is mutated, `uoe` still reported "no token" for a reference whose key index is
   0, while `dnfile` decoded the byte. Index 0 is now decoded like any other index, so
   such a heap is rejected. A comparison that omits a field cannot find errors in it.

Also recorded, because they were *not* parser defects but would have looked like
them: `llvm-objdump --dylibs-used` lists a dylib's own `LC_ID_DYLIB` (identity, not a
requirement); `llvm-readobj --coff-imports` prints each imported symbol as
`Symbol: Name (hint)`; and Python's
`str.splitlines()` splits on `0x1c`–`0x1e`, which broke a fuzz comparison on a path
containing mutated control characters. The first Mach-O comparison also double-counted
because `/lib` is a symlink to `/usr/lib`; the script now de-duplicates by inode.

## Independent audit of the merged change

After the WebAssembly/Mach-O change merged, an independent adversarial review of the
merged code was run with separate reviewers for WASM correctness, Mach-O correctness
and ELF/integration regressions. Their findings were treated as claims to reproduce, not
as facts. Reproduced and fixed:

- **The ELF debug-file fix above was incomplete** (the most serious). A file made the
  ordinary way — `gcc -s hello.c; objcopy --only-keep-debug` — was still rejected with
  "ELF segment outside file". For 150 debug files made from `/usr/bin`, 33 were
  rejected; after the fix, 149 are `partial_static` and 1 (a static Go binary) is
  `complete_static`. The corpus run missed it because its debug files happened to have
  offsets inside the file; the lesson is that the corpus is not the spec.
- **`plan` ignored the scan outcome.** ELF debug files and relocatable objects, Mach-O
  dylibs, bundles, objects, and iOS/watchOS/simulator images all still received a
  "native candidate". `plan` now requires a completed scan, and for Mach-O a decoded
  executable on a macOS platform.
- Mach-O: unsupported images and slices left no trace in `unknowns`; a universal file of
  only unsupported slices was `partial_static`; `LC_BUILD_VERSION`/`LC_VERSION_MIN_*`
  sizes were not validated (`llvm-objdump` rejects them); `arm64_32`, PowerPC and
  unknown CPU types were labelled with decimal junk; two behavior changes were
  undocumented and two error messages did not say what was wrong.
- WASM: a possible unlinked relocatable object looked like any other module.
- Tooling: `corpus_check.py` could not fail on wrongly rejected files (so CI would have
  stayed green with the string-table bug) — it now has `--fail-on-reject`, used on the
  CI runner's own binaries, where a real run compared 400 of 400 files with no
  rejections; the Mach-O fuzzer reported false disagreements for names containing a
  newline and for dylib `--seed-file` inputs; and the WASM comparisons sorted imports,
  hiding order and grouping errors (they now compare in order: 1,074 mutated modules and
  all three real modules still agree with V8).

Reported but not changed, as deliberate or out of scope: `cpu_subtype`
(`arm64e`/`x86_64h`) is not part of the architecture label, and the legacy iOS
version-min command cannot distinguish the simulator.

## Independent review of the PE/.NET increment

Before this branch was pushed, separate reviewers examined the PE/delay-load and the
CLR code and tests. They found no blocking defect in the parsers' results, and their
findings were again treated as claims to reproduce. Reproduced and fixed:

- **A valid PE with about 1,950 named imports was rejected**, although the documented
  limit is 4,096 symbols: every name read charged the 8,000,000-byte read budget for up
  to 4 KiB. Names are now read in 64-byte chunks and charged for the bytes read. Tests
  cover 2,300 and exactly 4,096 symbols (and 4,097 failing on the symbol limit); with the
  old read, the 2,300-symbol file fails.
- **A legacy pointer-based delay-import descriptor (`Attributes == 0`) failed the whole
  file.** It is valid, so it is now an unknown and the rest of the file is reported.
- **`corpus_check.py` could be made to run code from a file name.** `Path('.') / name`
  drops the `./`, so scanning a relative root containing a file named
  `--eval=…` handed Node an option it evaluates. Paths are now absolute; a test
  reproduces it (it fails without the fix).
- **Test gaps**: the row-size tests exercised only some tables; rejection tests asserted
  only the exception type, so any `BinaryError` satisfied them; the "every truncation"
  tests failed at the PE section check and never reached the CLR or delay parsers;
  coded-index widening was tested at one point rather than at the exact threshold; and
  the extra-data header flag and the 2- and 4-byte blob length forms were untested.
  These now have tests (see [PE notes](pe-dependencies.md)); the legacy-form, bound-import
  and truncation paths too.
- **Documentation inaccuracies**: the behavior-change list omitted the legacy descriptor
  case, the planner notes and the report-scope change; a count of PE files in the
  wheels was wrong (see defect 4); a claim that the real files exercised wide
  coded indexes was false for all but one index (see above); and the intro and
  safety note omitted the Python packages used as references.

## What this does and does not show

It shows that, on these files, the extracted library/import lists agree with
independent tools and that no mutated input crashed a parser or was misreported
where a reference could judge it. It does **not** show: correctness on hostile or
adversarially-crafted input beyond the seeds; that the references are right (they
may share assumptions, and `readelf`/`llvm-*` can differ from a real dynamic loader);
that any listed library exists or is compatible; or anything about execution.
The parsers are pure Python, so the concern is logic errors and resource exhaustion
rather than memory corruption, but that is an argument, not a substitute for the
sustained fuzzing and independently hosted corpus still listed in the roadmap.
