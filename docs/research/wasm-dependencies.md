# WebAssembly import observations — v0.3 increment

Based on the [WebAssembly core binary format](https://www.w3.org/TR/wasm-core-2/).
The supported subset is version-1 core-module MVP/reference-types import
encodings: function type indices, tables, memory32 limits and global types.
Newer descriptor extensions, shared memory and memory64 imports are rejected
explicitly. Components are unsupported. The file version alone does not identify
the WebAssembly feature set, so the generic binary architecture is now `wasm`
with no claimed bit width; defined memory sections are not analyzed.

Each dependency includes module/name, import kind, the supported descriptor and
file-offset evidence. Exact `wasi_snapshot_preview1` and `wasi_unstable` module
names receive an interface hint, not a permission or compatibility claim.

Budgets: 4,096 sections, 4,096 imports, 4,096 bytes per name, 1,000,000 bytes in the
import section, five bytes per u32 LEB and 8,000,000 actual read bytes. Other
section payloads are skipped by validated file ranges. Standard section order,
duplicates, integer overflow, UTF-8 and import payload consumption are checked.
`complete_static` covers imports only, not validation of code, types or defined
memories. A module with no imports still has unknown runtime requirements.

Tests exercise all four import kinds, Unicode/empty names, section boundaries,
malformed counts/types/LEBs, truncations and 1,000 seeded mutations (seed 26).
Node's `WebAssembly.Module.imports` independently agrees on a project-owned
synthetic module. Node compiles that fixture for validation but never instantiates
it or runs its code. The UOE inspector itself invokes no external runtime.

Run `python3 -m unittest discover -s tests -p test_wasm_dependencies.py -v`.
The independent Node check is explicitly skipped where Node is unavailable.
