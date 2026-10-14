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
linker emits) is decoded. The legacy pointer-based form (`Attributes == 0`) is valid but
is not decoded: it is skipped and reported as an unknown, and the rest of the file is
still reported. Any other `Attributes` value, or a descriptor without a DLL name, import
address table or import name table, is malformed and fails. The bound and unload tables
are ignored, never followed. The MSVC convention is that the directory size includes the
all-zero terminator descriptor, and the terminator must lie within the declared size.

## CLR (.NET) references

When the CLR directory is present, `static_dependencies` also gains:

| `kind` | Source | Fields |
| --- | --- | --- |
| `managed_runtime` | `IMAGE_COR20_HEADER` | `name` = metadata version string (e.g. `v4.0.30319`), `cor_header_version`, `flags` (names) and `flags_raw` |
| `managed_assembly` | `AssemblyRef` table | `name`, `version` (`a.b.c.d`), `culture`, `public_key_token` (8-byte token as stored, or computed from a full key per ECMA-335 II.6.2.1.3) |
| `native_module_reference` | `ModuleRef` table | `name` as written; these are the native libraries named by P/Invoke declarations (or secondary modules of a multi-module assembly) |

`culture` is `null` for the invariant culture and `public_key_token` is `null` when the
reference carries no key. `flags` names the recognised `COMIMAGE_FLAGS_*` bits and
`flags_raw` is the unmodified value (unrecognised bits appear as `unknown:0x…`).

To locate those two tables the parser computes the row size of every earlier metadata
table (every table up to and including `AssemblyRef`, `0x00`–`0x23`) from the ECMA-335 schema:
heap-index widths from `HeapSizes`, simple and coded index widths from the row counts
(a coded index is 4 bytes when any table it can name has at least `1 << (16 - tag bits)`
rows, a simple table index when the table has at least 65,536 rows). It reads only the
root, the stream headers, the table-stream header and the rows it reports, plus each
referenced name or key blob. Both `#~` and `#-` table streams are accepted. Index 0 of
`#Blob` is decoded like any other index; ECMA-335 requires a zero byte there, and a heap
that starts with anything else is rejected rather than read as "no key".

Not decoded: the target framework (a custom attribute), type/member references,
P/Invoke targets per method (`ImplMap`), resources, strong-name validity, and anything
about how the runtime would resolve an assembly (GAC, probing, `deps.json`,
`runtimeconfig.json`), reflection or dynamic loading. A managed image's `unknowns` says
so in one entry; the other items are simply not examined.

## Budgets and rejections

96 sections, 4,096 optional-header bytes, 256 import or delay-import descriptors
(shared across both), 4,096 total imported symbols (shared), 4,096 bytes per name and
8,000,000 parser-read bytes. Names are read in 64-byte chunks and charged for the bytes
actually read, so the documented 4,096-symbol limit is reachable; an earlier version
charged up to 4 KiB per name and rejected a valid file with about 1,950 named imports
on the read budget. CLR: 16 metadata streams, 1,024 assembly references, 512
module references, 2^24 rows per table, 4,096-byte blobs and strings. Missing
terminators, out-of-range data, overlapping RVA mappings, invalid name encodings,
reserved ordinal/name bits, a CLR header that is not 72 bytes, a bad `BSJB` signature,
duplicate or missing metadata streams, indexes outside their heap, table data that
overruns the table stream, empty assembly names and public-key blobs that are neither
a token nor a flagged full key all fail.

**Behavior changes in this increment:**

- Delay-load and CLR directories were previously only flagged as unknowns. They are now
  decoded, so a malformed one (for example a CLR directory shorter than 72 bytes, or a
  delay descriptor with reserved `Attributes` bits) is an error. A legacy pointer-based
  delay descriptor is the exception: it becomes an unknown, not an error.
- `shared_library` entries from PE files gained `load_kind`; managed images add
  `managed_runtime`, `managed_assembly` and `native_module_reference` entries.
- The report's PE `scope` string now says delay-load and CLR facts are included.
- `plan` adds a note for delay-loaded DLLs (a missing one may only fail at run time) and
  for managed images (a compatible CLR/.NET runtime is needed in addition to a PE runner).
  It does not change which candidates are produced.
- PE name reads are charged to the read budget by bytes actually read (above).

`complete_static` means only that this scan completed. LoadLibrary/GetProcAddress,
forwarded exports, API sets, transitive DLLs and host DLL resolution remain unknown.

## Validation

- Synthetic PE32/PE32+ fixtures with named/ordinal imports, fallback and bound-IAT
  cases, delay descriptors (including the legacy form and truncation inside the delay
  tables), malformed ranges and terminators, every truncation, a 4,096-symbol file, and
  seeded mutations (seed 25, 2,000 cases over both fixtures).
- GNU objdump comparison of the synthetic fixtures; a main-branch MinGW CI test builds a
  project-owned DLL and client, removes the DLL and compares inspection to MinGW
  objdump (skipped locally when MinGW is unavailable).
- **Delay-load, real linker output:** project-owned C is compiled with `clang` and linked
  with `lld-link` for x86-64 and ARM64 against import libraries made by `llvm-dlltool`
  from `.def` files (no Windows SDK), with `user32.dll` delay-loaded; the DLL list,
  load kind and every symbol name, in order, are compared with
  `llvm-readobj --coff-imports`.
- **CLR, independent parser:** `tests/test_clr_dependencies.py` builds ECMA-335
  metadata with row sizes written out by hand — one case per table in that range, each with
  all eight heap-width combinations and with the optional extra-data dword — checks
  every coded index at the exact row count where it widens (one row below stays
  narrow), the 1-, 2- and 4-byte blob length forms, the 2^24-row limit and each
  rejection by its message, and, when the optional `dnfile` package is installed,
  checks the same bytes with it. The ECMA standard public key is pinned to its
  well-known token `b77a5c561934e089`. To test the tests, a throwaway mutation harness
  made 177 single-edit mutants of `uoe/clr.py` (changed column widths, tag-bit counts,
  comparisons, constants and masks, dropped checks) and ran the PE and CLR suites against
  each; 164 were caught. The 13 survivors are equivalent mutants: eleven swap the first
  two members of a coded-index definition (the width depends only on the largest member,
  never its order), one drops a placeholder `None` entry, and one narrows the 2-byte
  blob-length range to a region the 4,096-byte blob budget already rejects. The harness
  is not committed.
- Real files and differential fuzzing (`tests/fuzz_differential.py clr`): see
  [corpus and differential validation](corpus-validation.md).

Run `python3 -m unittest tests.test_pe_dependencies tests.test_clr_dependencies -v`
(the `dnfile`, `llvm-readobj`/`lld-link` and MinGW comparisons are skipped when the tool
is absent). This is an experimental parser
subset, not full PE or CLI validation, and not a sandbox. Report shape:
[inspection report reference](inspection-report.md).
