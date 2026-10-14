# PE imports, delay-load imports and CLR references — v0.3 increment

Implements, for PE32 and PE32+, the [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
**normal import descriptors**, **delay-load import descriptors**
(`IMAGE_DELAYLOAD_DESCRIPTOR`, data directory 13) and a bounded reading of the **CLR
(.NET) header and metadata** ([ECMA-335](https://ecma-international.org/publications-and-standards/standards/ecma-335/),
data directory 14). Nothing is loaded, resolved or run.

## Imports

The inspector reports each DLL, named symbols with hints, ordinal imports and source
offsets. RVA references must map unambiguously into file-backed headers or sections.
An unbound IAT can substitute for a missing lookup table; a bound IAT without a lookup
table is explicitly unsupported.

Every `shared_library` entry carries `load_kind`: `static` for a normal import
(`PE_IMPORT_DESCRIPTOR`) or `delay` for a delay-load import
(`PE_DELAY_IMPORT_DESCRIPTOR`). A delay-loaded DLL is mapped on first call rather than
at process start, so it is a conditional requirement; both are reported, normal imports
first. Only the RVA-based descriptor form (`Attributes == 1`, what every current
linker emits) is decoded; the legacy VA-based form, a descriptor without an import name
table, or a bound/unload table are not guessed at (the bound and unload tables are
ignored, never followed). The MSVC convention is that the directory size includes the
all-zero terminator descriptor, and the terminator must lie within the declared size.

## CLR (.NET) references

When the CLR directory is present, `static_dependencies` also gains:

| `kind` | Source | Fields |
| --- | --- | --- |
| `managed_runtime` | `IMAGE_COR20_HEADER` | `name` = metadata version string (e.g. `v4.0.30319`), `cor_header_version`, `flags` (names) and `flags_raw` |
| `managed_assembly` | `AssemblyRef` table | `name`, `version` (`a.b.c.d`), `culture`, `public_key_token` (8-byte token as stored, or computed from a full key per ECMA-335 II.6.2.1.3) |
| `native_module_reference` | `ModuleRef` table | `name` as written; these are the native libraries named by P/Invoke declarations (or secondary modules of a multi-module assembly) |

To locate those two tables the parser computes the row size of every earlier metadata
table from the ECMA-335 schema (heap-index widths from `HeapSizes`, simple and coded
index widths from the row counts), so wide indexes in large assemblies are handled. It
reads only the root, the stream headers, the table-stream header and the rows it
reports, plus each referenced name or key blob. Both `#~` and `#-` table streams are
accepted.

Not decoded: the target framework (a custom attribute), type/member references,
P/Invoke targets per method (`ImplMap`), resources, strong-name validity, and anything
about how the runtime would resolve an assembly (GAC, probing, `deps.json`,
`runtimeconfig.json`), reflection or dynamic loading. Those stay in `unknowns`.

## Budgets and rejections

96 sections, 4,096 optional-header bytes, 256 import or delay-import descriptors
(shared across both), 4,096 total imported symbols (shared), 4,096 bytes per name and
8,000,000 parser-read bytes. CLR: 16 metadata streams, 1,024 assembly references, 512
module references, 2^24 rows per table, 4,096-byte blobs and strings. Missing
terminators, out-of-range data, overlapping RVA mappings, invalid name encodings,
reserved ordinal/name bits, a CLR header that is not 72 bytes, a bad `BSJB` signature,
duplicate or missing metadata streams, indexes outside their heap, table data that
overruns the table stream, empty assembly names and public-key blobs that are neither
a token nor a flagged full key all fail.

**Behavior changes in this increment:** delay-load and CLR directories were previously
only flagged as unknowns. They are now decoded, so a malformed one (for example a
CLR directory shorter than 72 bytes) is an error. `shared_library` entries from PE
files gained `load_kind`.

`complete_static` means only that this scan completed. LoadLibrary/GetProcAddress,
forwarded exports, API sets, transitive DLLs and host DLL resolution remain unknown.

## Validation

- Synthetic PE32/PE32+ fixtures with named/ordinal imports, fallback and bound-IAT
  cases, delay descriptors, malformed ranges and terminators, every truncation, and
  seeded mutations (seed 25, 2,000 cases over both fixtures).
- GNU objdump comparison of the synthetic fixtures; a main-branch MinGW CI test builds a
  project-owned DLL and client, removes the DLL and compares inspection to MinGW
  objdump (skipped locally when MinGW is unavailable).
- **Delay-load, real linker output:** project-owned C is compiled with `clang` and linked
  with `lld-link` for x86-64 and ARM64 against import libraries made by `llvm-dlltool`
  from `.def` files (no Windows SDK), with `user32.dll` delay-loaded; the DLL list,
  load kind and symbols are compared with `llvm-readobj --coff-imports`.
- **CLR, independent parser:** `tests/test_clr_dependencies.py` builds ECMA-335
  metadata with row sizes written out by hand (including cases that force wide
  `TypeDefOrRef`, `Field` and `HasCustomAttribute` indexes and wide heap indexes) and,
  when the optional `dnfile` package is installed, checks the same bytes with it. The
  ECMA standard public key is pinned to its well-known token `b77a5c561934e089`.
- Real files and differential fuzzing: see [corpus and differential validation](corpus-validation.md).

Run `python3 -m unittest discover -s tests -p 'test_pe_dependencies.py' -v` and
`python3 -m unittest tests.test_clr_dependencies -v`. This is an experimental parser
subset, not full PE or CLI validation, and not a sandbox. Report shape:
[inspection report reference](inspection-report.md).
