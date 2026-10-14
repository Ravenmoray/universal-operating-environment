# Corpus and differential validation of the static parsers

Unit tests built from the author's own understanding of a format can share the
author's blind spots. This note records two independent-oracle checks run against the
v0.3 parsers, **what they found**, and what they cannot show. Both are reproducible
with scripts in `tests/` that only *read* files.

> **Safety.** The reference tools (`readelf`, `llvm-readobj`, `llvm-objdump`, Node.js)
> parse the files too, and V8 compiles WebAssembly. Run these scripts only on trusted
> corpora or inside a disposable, isolated environment — never on untrusted downloads
> on a workstation. The scripts never execute the inputs.

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
```

Small seed inputs are mutated (byte replacement, deletion, insertion) and parsed.
The contract checked is one-sided on purpose: `uoe` may be *stricter* than the
reference, but must never reject or misreport something the reference accepts.

| Run | Outcome |
| --- | --- |
| WASM vs V8, 20,000 cases | 1,074 accepted by both with identical imports; 17,749 rejected by both; 1,177 rejected by V8 but accepted by `uoe` (expected: function bodies and semantics are not validated); **0** V8-accepted modules rejected or misreported |
| Mach-O vs `llvm-objdump`, 3,000 cases | 849 agree; 1,783 rejected by `uoe` (stricter: structure, budgets, UTF-8); 351 rejected by the reference only; 17 outside the scan's scope; **0** disagreements |

This is seeded mutation of small inputs with a fixed PRNG, **not coverage-guided
fuzzing**, and it covers only the structures the seeds contain. It does not replace
the sustained fuzzing the [delivery plan](../roadmap/v1-delivery-plan.md) requires.

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

Also recorded, because they were *not* parser defects but would have looked like
them: `llvm-objdump --dylibs-used` lists a dylib's own `LC_ID_DYLIB` (identity, not a
requirement); `llvm-readobj` prints `Symbol: Name (hint)`; and Python's
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
