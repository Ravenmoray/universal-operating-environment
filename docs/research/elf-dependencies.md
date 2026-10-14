# ELF dependency observations — first v0.3 increment

Related: #13. This implements a bounded subset of the System V gABI:
[program headers](https://gabi.xinuos.com/elf/07-pheader.html) and
[dynamic linking](https://gabi.xinuos.com/elf/08-dynamic.html).

## Behavior

`python3 -m uoe inspect FILE` reads PT_INTERP and direct DT_NEEDED entries from
ET_EXEC/ET_DYN files. The parser handles ELF32/ELF64 and either byte order, uses
program headers (section headers are unnecessary), and maps the DT_STRTAB virtual
address through a file-backed PT_LOAD range. It preserves DT_NEEDED order.

The package is marked `0.3.0.dev2` (development, not a published release).
The `uoe.inspection.v0.3` report ([reference](inspection-report.md)) retains the
earlier top-level fields and adds `dependency_scan`. Each `static_dependencies` entry has a kind (`interpreter` or
`shared_library`), name, `observed` status and source file offset. DT_NEEDED also
records its string's file offset. `plan` carries these as `observed_requirements`.
No inspected file, loader, `ldd`, or library is executed. Library presence and
search paths are not resolved; a name is not a verified capability contract.

`complete_static` means completion of this narrow PT_INTERP/DT_NEEDED scan, not
complete requirements discovery or a valid executable. Relocatable objects have
`unsupported_object_type`. A `PT_INTERP` or `PT_DYNAMIC` segment whose file size is
zero — the shape of a separate debug file made with `objcopy --only-keep-debug` — has
no content to observe, so the scan is `partial_static` with the reason in `unknowns`
rather than an error or an invented empty result. Such a segment keeps its original
`p_offset` even though it has no content, and that offset may lie beyond the end of the
much smaller debug file, so segments with a zero file size are not range-checked
against the file. `plan` does not offer a native strategy for a `partial_static` or
`unsupported_object_type` ELF file: it is not a launchable image. Dynamic loading,
transitive libraries, symbol versions, OS ABI compatibility and runtime behavior
remain explicit unknowns. The original demo loads its project library via dlopen;
that requirement correctly remains declared rather than statically discovered.

## Bounds and exclusions

At most 4,096 program headers, 4,096 dynamic entries, 256 DT_NEEDED entries,
4,096 name bytes and 8,000,000 parser-read bytes. There is deliberately no cap on
`DT_STRSZ` itself: only the string-table boundary bytes and each referenced name are
read, so the table must merely lie inside one file-backed `PT_LOAD` mapping. (An
earlier 1,000,000-byte cap, which read the whole table, wrongly rejected real
executables: `DT_STRSZ` is about 41 MB for pandoc, 7.8 MB for Node.js, 2.7 MB for
rclone and 1.2 MB for GCC's `lto-dump`.)
The existing whole-file SHA-256 pass retains its 2 GiB limit and bounded chunks.
Inspection uses one open descriptor and rejects detected size/timestamp changes;
this is not an immutable snapshot guarantee against hostile concurrent writers.

Ranges are checked against file size before reads. Overflowing addresses,
ambiguous overlapping file-backed load mappings, duplicate interpreter/dynamic
segments or string-table tags, unterminated strings/tables and invalid UTF-8 names
fail explicitly. Extended program-header numbering and overlapping load mappings
are unsupported rather than guessed. Packed/embedded binaries and loader-specific
extensions are not validated. This parser is not a security boundary.

## Reproduce the evidence

```
python3 -m unittest discover -s tests -p 'test_elf_dependencies.py' -v
python3 -m unittest discover -s tests -v
```

The fixtures are project-owned, generated in tests, and never executed:

- Four class/byte-order combinations with golden interpreter and library names.
- A string table beyond the original 1 MiB header window, and a 20 MB table that
  would have exceeded the old whole-table read.
- Program headers with zero-size `PT_DYNAMIC`/`PT_INTERP` (debug-file shape).
- Malformed ranges, table metadata, overlapping mappings, string terminators,
  unsupported object types and every truncation of the base synthetic fixture.
- 1,000 reproducible byte-mutation cases (seed 13), allowing explicit ElfError
  rejection while checking accepted report shape; not an exhaustive fuzz claim.
- A compiled Linux client linked to a tiny project-owned shared library. The test
  removes that library, inspects the client, and compares library/interpreter
  observations to GNU readelf. The client and provider are never launched.
- A regression for file modification during inspection, and a subprocess trap
  around inspect/plan to detect unintended execution.

The compiler/readelf comparison runs on Linux when both tools exist (including
GitHub Ubuntu runners); it is explicitly skipped otherwise.

Real-world check: [corpus and differential validation](corpus-validation.md) compared
thousands of distribution and vendor ELF files against `readelf`, which is how the
string-table and debug-file defects above were found. Remaining v0.3 work is sustained
(coverage-guided) fuzzing and a corpus that is independent of this one machine.
