# Inspection report reference (`uoe.inspection.v0.3`)

Reference for the JSON printed by `python3 -m uoe inspect FILE` and carried into
`plan` as `observed_requirements`. The version string stays `uoe.inspection.v0.3`
while v0.3 is in development; additions inside it (new `kind`s and statuses) are
additive. The schema is **unapproved and not yet in `schemas/`**; see
[schemas/README.md](../../schemas/README.md).

Neither command runs the input, loads it, or resolves any name it contains. A
report is a set of *observations with file offsets*, not a compatibility verdict.

## Top-level fields

| Field | Meaning |
| --- | --- |
| `schema_version` | `uoe.inspection.v0.3` |
| `artifact` | `path` (resolved), `sha256` of the whole file, `size_bytes` |
| `binary` | `format` (`ELF`, `PE`, `WASM`, `Mach-O`, `Mach-O-fat`), `architecture`, `bits`, `endianness`, `ecosystem_hint`; universal Mach-O adds `slice_architectures` |
| `evidence` | what the classification rests on (magic and header fields) |
| `static_dependencies` | observed requirements; see below |
| `dependency_scan` | `status`, `scope`, `unknowns` and format extras (everything except the dependency list) |
| `unknowns` | requirements this scan cannot determine; always non-empty for supported formats |
| `execution_attempted` | always `false` |

## `dependency_scan.status`

| Status | Meaning |
| --- | --- |
| `complete_static` | The documented scan for this format finished. It does **not** mean the file is valid or that requirements are complete. |
| `partial_static` | The scan finished but part of the content could not be observed: an ELF `PT_INTERP`/`PT_DYNAMIC` with no file content (typically a separate debug file), or a universal Mach-O with some unsupported slices. The reason is in `unknowns` (for Mach-O, one entry per unsupported slice). |
| `unsupported_object_type` | A valid header whose object type is outside the scan (ELF relocatable objects; Mach-O objects and other non-executable file types, including a universal binary whose slices are all such). No dependencies are invented, and `plan` does not offer a launch strategy for it. |
| `unsupported_fat_byte_order` | Mach-O universal header in the nonstandard byte-swapped spelling; classified but not decoded. |
| `not_implemented` | Reserved for formats without a dependency parser. |

Malformed input is an **error** (exit status 2, message on stderr), never a partial report.

## `static_dependencies` entries

Every entry has `kind`, `name`, `status` (always `observed`) and `evidence` with a
`source` (the structure the observation came from) and absolute `file_offset`. Offsets
let a reviewer find the exact bytes with an independent tool.

| `kind` | Formats | `name` is | Extra fields | `evidence.source` |
| --- | --- | --- | --- | --- |
| `interpreter` | ELF, Mach-O | program interpreter / dynamic linker path | — | `PT_INTERP`, `LC_LOAD_DYLINKER` |
| `shared_library` | ELF, PE, Mach-O | library name as written in the file | PE: `load_kind` (`static`, `delay`) and `symbols` (named with `hint`, or `ordinal`); Mach-O: `load_kind`, `current_version`, `compatibility_version`; ELF: `string_file_offset` in evidence | `DT_NEEDED`, `PE_IMPORT_DESCRIPTOR`, `PE_DELAY_IMPORT_DESCRIPTOR`, `LC_LOAD_*_DYLIB`, `LC_REEXPORT_DYLIB` |
| `wasm_import_module` | WASM | import module name (may be `""`) | `symbols` (`name`, `kind`, `type_index`/`mutable`), optional `interface_hint` | `WASM_IMPORT_SECTION` |
| `runtime_search_path` | Mach-O | an `LC_RPATH` entry | — | `LC_RPATH` |
| `platform` | Mach-O | `macos`, `ios`, … or `unknown:N` | `minimum_os_version`, `sdk_version` | `LC_BUILD_VERSION`, `LC_VERSION_MIN_*` |
| `managed_runtime` | PE (.NET) | CLR metadata version string, e.g. `v4.0.30319` (a format version, not the runtime or framework the image needs) | `cor_header_version`, `flags`, `flags_raw` | `IMAGE_COR20_HEADER` |
| `managed_assembly` | PE (.NET) | referenced assembly name | `version`, `culture`, `public_key_token` | `METADATA_ASSEMBLYREF` |
| `native_module_reference` | PE (.NET) | a `ModuleRef` row: usually a native library named by a P/Invoke declaration, but also a secondary module of a multi-module assembly (the `ImplMap` table that tells them apart is not read) | — | `METADATA_MODULEREF` |

In universal Mach-O files each entry also has `slice: {index, architecture}`.

PE and .NET details: `load_kind` is `static` for a normal import and `delay` for a
delay-load import (loaded on first call, so a conditional requirement). For
`managed_assembly`, `culture` is `null` for the invariant culture and `public_key_token`
is `null` when the reference carries no key; otherwise it is the stored 8-byte token, or
the token computed from the full public key when the reference carries one. For
`managed_runtime`, `flags` names the recognised `COMIMAGE_FLAGS_*` bits (unrecognised
bits appear as `unknown:0x…`) and `flags_raw` is the unmodified header value.
`native_module_reference` names are written as the metadata gives them (for example
`kernel32.dll` or `libdl.so`), not resolved to a file. The `managed_runtime` string is the
same `v4.0.30319` for `Python.Runtime.dll` (which references `netstandard` 2.0) and for
`ClrLoader.dll` (which references `mscorlib` 4.0.0.0), so it does not identify what the
image requires; the target framework is a custom attribute that is not decoded.

Names are exactly what the file says. A name is **not** a verified capability
contract, does not show the library is installed, and is not resolved against any
search path.

## Limits, in one place

All parsers fail rather than truncate when a budget is exceeded. Per-format budgets are
listed in [ELF](elf-dependencies.md), [PE](pe-dependencies.md),
[WASM](wasm-dependencies.md) and [Mach-O](macho-dependencies.md). Common to all: files
over 2 GiB are refused, the SHA-256 pass streams in 1 MiB blocks, and a change in
size/timestamps while reading is rejected (this detects, but is not an immutable
snapshot against a hostile concurrent writer).

## Evidence for these shapes

[Corpus and differential validation](corpus-validation.md) records how each format's
output was compared against independent tools, including the defects that comparison
found.
