# Mach-O load-command observations — v0.3 increment

Decodes a bounded subset of Apple's `<mach-o/loader.h>` and `<mach-o/fat.h>` layouts
for thin 32/64-bit images of either byte order and for universal (fat) containers.
Nothing is loaded, linked, resolved or run by `inspect` or `plan`.

## Behavior

For `MH_EXECUTE`, `MH_DYLIB`, `MH_DYLINKER` and `MH_BUNDLE` images, the load-command
table is walked and these commands become `static_dependencies` entries (offsets are
absolute file offsets):

| Load command | `kind` | Extra fields |
| --- | --- | --- |
| `LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`, `LC_REEXPORT_DYLIB`, `LC_LAZY_LOAD_DYLIB`, `LC_LOAD_UPWARD_DYLIB` | `shared_library` | `load_kind` (`strong`, `weak`, `reexport`, `lazy`, `upward`), `current_version`, `compatibility_version` |
| `LC_LOAD_DYLINKER` | `interpreter` | — |
| `LC_RPATH` | `runtime_search_path` | — |
| `LC_BUILD_VERSION`, `LC_VERSION_MIN_{MACOSX,IPHONEOS,TVOS,WATCHOS}` | `platform` | `minimum_os_version`, `sdk_version` |

Each entry has `evidence.source` (the command name), the command's `file_offset` and,
for string-bearing commands, `name_file_offset`. Versions use the packed
`xxxx.yy.zz` encoding rendered as `major.minor.patch`.

`LC_ID_DYLIB` is a dylib's *own* install name — its identity, not a requirement — and
is deliberately not reported. (`llvm-objdump --dylibs-used` prints it as the first
line for dylibs; the comparison tooling accounts for that.)

**Universal binaries.** The big-endian `FAT_MAGIC`/`FAT_MAGIC_64` tables are decoded,
every slice is bounds-checked and aligned to its declared boundary, and each slice
must begin with a thin Mach-O magic whose CPU type/subtype matches the fat table.
`binary.slice_architectures` lists the slice architectures in file order,
`dependency_scan.slices` holds each slice's CPU type/subtype, file type, offset, size and
status, and every dependency carries `slice: {index, architecture}`. `plan` offers a
native candidate on macOS only when a slice matches the host architecture; it does not
model Rosetta or any other translation.

Scan status: `complete_static`; `unsupported_object_type` (relocatable objects, core
files, debug companions and other types outside the list above — their commands are
not decoded); `partial_static` (a universal binary where some slices are
unsupported); `unsupported_fat_byte_order` (the nonstandard byte-swapped
`be ba fe ca` spelling, which is classified but not decoded).

## Behavior change in this increment

Previously any file beginning `ca fe ba be` was reported as `Mach-O-fat` from its
8-byte header alone. A universal binary must now contain a valid slice table with
in-bounds, non-overlapping slices that each start with a Mach-O magic, so a bare
header — and Java class files, which share the `0xCAFEBABE` magic — are rejected with
a clear error.

## Bounds and rejections

At most 16 slices, 4,096 load commands, 1 MiB of load-command bytes, 512 reported
dependencies per image, 4,096 bytes per string and 17,000,000 parser-read bytes.
Rejected explicitly: bad magic, a command table that does not fit its image,
command sizes below 8 or not a multiple of the pointer width, commands that overrun
the table or leave declared command-table bytes unconsumed, string offsets outside
their command, empty/unterminated/non-UTF-8 strings,
duplicate dynamic-linker commands, truncated command bodies, duplicate or overlapping
universal slices, nonzero reserved `fat_arch_64` fields and absurd alignments.

## Not covered (reported as unknowns)

Whether a named library exists; `@rpath`/`@loader_path`/`@executable_path` expansion;
the dyld shared cache; `dlopen`-loaded libraries; symbol bindings and chained fixups;
code signatures, entitlements and notarization; and runtime behavior. A library name
is an observation, not a verified capability contract.

## Evidence

Run `python3 -m unittest tests.test_macho_dependencies -v`:

- golden images for both widths and both byte orders, all five dylib command flavors,
  versions, platforms, offsets that point at the observed bytes, and the
  `LC_ID_DYLIB` exclusion;
- universal binaries in 32-bit and 64-bit table forms, per-slice attribution, mixed
  supported/unsupported slices, and 14 malformed-universal cases (including a Java
  class header);
- 22 malformed thin-image cases, every truncation of thin and universal fixtures
  (each must fail), and 3,000 seeded mutations (seed 37);
- real linked images: tiny project-owned programs compiled with `clang` and linked
  with LLVM's Mach-O linker (`ld64.lld`) against a hand-written text stub for x86-64
  and arm64, plus a universal binary made by `llvm-lipo`, compared with
  `llvm-objdump --macho` for libraries, weak flags, rpaths, dynamic linker and
  platform. No Apple SDK or macOS host is involved and nothing is loaded.
  The test skips with a stated reason when those LLVM tools are missing.

See [corpus and differential validation](corpus-validation.md) for the comparison on
real vendor-built files (executables, dylibs and a universal bundle) and the seeded
differential fuzz against `llvm-objdump`.

## What this does not establish

Observed dependencies do not show that a Mach-O image can run anywhere, that its
libraries are available, or that it is safe. Linux-hosted inspection of an Apple
binary is static analysis only.
