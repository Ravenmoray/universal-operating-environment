# ELF dependency observations — first v0.3 increment

Related: #13. This implements a bounded subset of the System V gABI:
[program headers](https://gabi.xinuos.com/elf/07-pheader.html) and
[dynamic linking](https://gabi.xinuos.com/elf/08-dynamic.html).

## Behavior

`python3 -m uoe inspect FILE` reads PT_INTERP and direct DT_NEEDED entries from
ET_EXEC/ET_DYN files. The parser handles ELF32/ELF64 and either byte order, uses
program headers (section headers are unnecessary), and maps the DT_STRTAB virtual
address through a file-backed PT_LOAD range. It preserves DT_NEEDED order.

The package is marked `0.3.0.dev1` (development, not a published release).
The `uoe.inspection.v0.3` report retains the earlier top-level fields and adds
`dependency_scan`. Each `static_dependencies` entry has a kind (`interpreter` or
`shared_library`), name, `observed` status and source file offset. DT_NEEDED also
records its string's file offset. `plan` carries these as `observed_requirements`.
No inspected file, loader, `ldd`, or library is executed. Library presence and
search paths are not resolved; a name is not a verified capability contract.

`complete_static` means completion of this narrow PT_INTERP/DT_NEEDED scan, not
complete requirements discovery or a valid executable. Relocatable objects have
`unsupported_object_type`; other formats have `not_implemented`. Dynamic loading,
transitive libraries, symbol versions, OS ABI compatibility and runtime behavior
remain explicit unknowns. The original demo loads its project library via dlopen;
that requirement correctly remains declared rather than statically discovered.

## Bounds and exclusions

At most 4,096 program headers, 4,096 dynamic entries, 256 DT_NEEDED entries,
1,000,000 string-table bytes, 4,096 name bytes and 8,000,000 parser-read bytes.
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
- A string table beyond the original 1 MiB header window.
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
GitHub Ubuntu runners); it is explicitly skipped otherwise. Completing v0.3 still
requires other formats, more parser corpus coverage and sustained fuzz testing.
