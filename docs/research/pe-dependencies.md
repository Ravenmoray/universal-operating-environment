# PE normal imports — v0.3 increment

Implements the [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
normal import descriptors and import lookup tables for PE32 and PE32+.

The non-executing inspector reports each DLL, named symbols with hints, ordinal
imports and source offsets. RVA references must map unambiguously into file-backed
headers or sections. An unbound IAT can substitute for a missing lookup table;
a bound IAT without a lookup table is explicitly unsupported.

Budgets: 96 sections, 4,096 optional-header bytes, 256 DLL descriptors, 4,096 total
imported symbols, 4,096 bytes per name and 8,000,000 parser-read bytes. Missing
terminators, out-of-range data, overlapping RVA mappings, invalid name encodings
and reserved ordinal/name bits fail. Delayed imports and CLR directories are
flagged when present; they are not enumerated. LoadLibrary, forwarded exports,
API sets, transitive dependencies and host DLL resolution remain unknown.
`complete_static` means only the stated normal-import scan completed.

Validation: both widths with named/ordinal golden imports; fallback/bound-IAT
cases; malformed ranges; every truncation of a synthetic fixture; 1,000 seeded
mutations (seed 25); and GNU objdump comparison. A main-branch MinGW CI test builds
a project-owned DLL and client, removes the DLL and compares inspection to MinGW
objdump. Neither the DLL nor the client is launched. The compiler test is skipped
locally when MinGW is unavailable and explicitly run in the cross-compile workflow.

Real-world check: [corpus and differential validation](corpus-validation.md) compared
52 PE files (x86, x86-64 and ARM64, including large Rust-built executables) against
`llvm-readobj --coff-imports` for DLL names, order and imported symbol names. Report
shape: [inspection report reference](inspection-report.md).

Run `python3 -m unittest discover -s tests -p test_pe_dependencies.py -v`.
This is an experimental parser subset, not full PE validation or a sandbox.
