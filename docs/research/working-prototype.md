# UOE v0.1 — Working CLI Vertical Slice

**Status: experimental.** This is a usable command-line program, not an operating system, universal compatibility layer, or sandbox. It has no third-party Python runtime dependencies.

## Try it from a repository checkout

Python 3.10+ is sufficient for static inspection and planning. The controlled execution demo additionally needs Linux and a C compiler.

```sh
python3 -m uoe --help
python3 -m uoe inspect /bin/ls
python3 -m uoe plan /bin/ls
python3 -m uoe demo --execute-reviewed-fixture
```

**Inspect** computes a SHA-256 and reads basic ELF, PE32/PE32+, Mach-O and WebAssembly headers. It does not execute the selected file. Its output includes observed facts, ecosystem hints, unknowns and limits.

**Plan** suggests native, Wine or Wasmtime runners when basic host prerequisites appear present. It reports *unverified candidates* and unresolved dependencies. Merely finding Wine or Wasmtime does not demonstrate compatibility.

**Demo** is an explicitly authorized exception: it compiles a fixed, project-owned Linux client, inspects it, proposes a native runner, invokes the existing missing-capability test harness, and returns one machine-readable JSON report of inspection, planning and verification. It does not accept arbitrary executable inputs. Only run it on a trusted project checkout.

## Optional editable installation

```sh
python3 -m pip install -e .
uoe inspect /bin/ls
```

The installed demo still requires the checked-in project-owned C fixture. No LLM or remote service is required for inspection and planning.

## Scope and limitations

- The prototype identifies binary headers; it does not yet enumerate DLL imports, ELF DT_NEEDED, Mach-O load commands or WASI imports.
- Static headers cannot identify every runtime-loaded dependency, including the fixture's dynamically loaded DLL.
- Runtime presence does not establish API compatibility, permission to run, licensing, or safety.
- Fat Mach-O slices remain unresolved. Files larger than 2 GiB are refused in this v0 experiment.
- User-supplied programs are **never executed** by inspect or plan. The explicit demo is not a sandbox.
- The static planner does not yet join inspected artifact digests to signed capability evidence. The demo exposes the separately tested Capability Graph evidence.

## Next acceptance milestone

Bind a digest-identified artifact to independently sourced requirement claims, then consult test-scoped Capability Graph providers before proposing execution. Compare against a simple dependency registry. Preserve a clear distinction between *candidate*, *behaviorally tested*, and *safe and authorized to execute*.

Related: [Capability Graph proposal](../rfcs/proposals/minimal-capability-graph.md), [Experiment 002](../../experiments/missing-capability/README.md), [AI evaluation methodology](003-ai-adapter-evaluation.md).
