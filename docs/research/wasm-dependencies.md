# WebAssembly import observations — v0.3 increment

Implements a bounded subset of the
[WebAssembly Core Specification binary format](https://webassembly.github.io/spec/core/binary/modules.html):
the module header, section framing, unsigned/signed LEB128 integers and the
**import section**. Nothing is compiled, instantiated or run by `inspect` or `plan`.

## Behavior

`python3 -m uoe inspect FILE.wasm` walks every section header, checks the container
structure, then decodes the import section. Imports are grouped by module name in
first-appearance order, one `static_dependencies` entry per module:

```json
{"kind": "wasm_import_module", "name": "wasi_snapshot_preview1", "status": "observed",
 "interface_hint": "wasi_preview1",
 "symbols": [{"name": "proc_exit", "kind": "function", "type_index": 1, "file_offset": 51}],
 "evidence": {"source": "WASM_IMPORT_SECTION", "file_offset": 51, "name_file_offset": 52}}
```

- Symbol `kind` is `function`, `table`, `memory`, `global` or `tag`. Function and tag
  imports carry their `type_index`; global imports carry `mutable`.
- `file_offset` is the absolute offset of the import entry; `name_file_offset` is the
  first byte of the module name.
- `interface_hint: "wasi_preview1"` is attached only when the module name is
  `wasi_snapshot_preview1` or `wasi_unstable`. **It is a name convention, not proof
  of ABI conformance, runtime support or granted permissions.**
- Empty module and field names are legal in WebAssembly and are reported as `""`.
- `dependency_scan` also reports `section_count`, `import_count` and
  `dynamic_linking_section` (true when a `dylink.0`/`dylink` custom section exists;
  its side-module needs are *not* enumerated).

`plan` copies these into `observed_requirements` and adds Wasmtime constraints: the
non-WASI import modules that an embedder or linked module must supply, and whether
WASI preview1 names were observed. Finding Wasmtime on the host remains a candidate,
never a compatibility verdict.

## Scope and exclusions

- Core module version 1 only. Component-model binaries (version bytes `0d 00 01 00`)
  are rejected as unsupported rather than guessed at.
- The core header does not establish a memory address width. Reports use
  `architecture: "wasm"` and `bits: null`, preserving the correction from PR #26;
  defined memories are not analyzed and memory64 import encodings are supported.
- Not decoded: the type section (so import *signatures* are unknown), function
  bodies, exports, the start function, element/data segments and custom-section
  payloads. No validation beyond what finding the imports requires.
- Section ids above 13, duplicated or out-of-order non-custom sections, a section
  that overruns the file, LEB128 integers longer than their width allows or
  exceeding it, non-UTF-8 import names, non-UTF-8 custom-section names of up to 64
  bytes (longer custom-section names are length-checked but not decoded), and trailing
  bytes in the import section all fail with an explicit error. (Legal padded LEB128
  forms are accepted.)
- A `linking` or `reloc.*` custom section sets `dependency_scan.linker_sections` and adds
  an unknown: the file may be an **unlinked relocatable object** (for example `clang -c`
  output), whose imports are linker placeholders rather than requirements of an
  embedder. It is not reclassified, because a fully linked module built with
  `--emit-relocs` keeps those sections and has real imports.
- Import encodings handled: function/table/memory/global/tag; limits flags 0–7
  (maximum, shared, 64-bit index); numeric and vector value types; reference types
  including the abstract heap shorthands and typed `(ref [null] $t)` forms from the
  GC and exception-handling proposals. Newer or unknown encodings (for example the
  custom-page-size limits flag) are **rejected**, not skipped.

## Bounds

4,096 sections, 4,096 imports, 256 distinct module names, 4,096 bytes per name, a
64-byte window for custom-section names and 8,000,000 parser-read bytes. Over-budget
input fails; it is never truncated silently.

## Evidence

Run `python3 -m unittest tests.test_wasm_dependencies -v`. The tests build modules
byte by byte and are never instantiated:

- golden grouping, ordering, kinds, type indices and byte offsets;
- 31 container and import malformations, budget edges, every truncation
  (a prefix ending on a section boundary is itself a valid module and must never
  report an import the full module lacks), and 2,000 seeded mutations (seed 31);
- GC/EH reference-type encodings, accepted and rejected;
- legal padded signed abstract heap types, independently checked against V8;
- agreement with **V8** (`WebAssembly.Module.imports`, Node.js) on the synthetic
  golden module, on a module built by `clang --target=wasm32`, and on 3,000
  mutated modules (seed 41, 156 accepted by V8 — every one accepted by `uoe` with
  identical imports). V8 only compiles; it does not instantiate or run the module.

Beyond the unit tests, see [corpus and differential validation](corpus-validation.md):
the three real-world modules available on the development machine (including a
dynamically-linked module with a `GOT.mem` import module) matched V8 exactly, and a
20,000-case differential fuzz found no module V8 accepts that `uoe` rejects.

That fuzz originally *did* find a defect: modules importing tables or globals of the
newer reference types (`anyref`, `exnref`, typed references) were rejected. They are
now decoded, and the cases are permanent regression tests.

## What this does not establish

A module's imports are only its declared requirements on an embedder. Nothing here
shows that Wasmtime, a browser or any host supplies them, that a signature matches,
or that the module is valid, safe or terminates. Component-model dependencies,
dynamic-linking side modules and host-specific import conventions remain future work.
