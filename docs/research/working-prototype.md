# UOE Experimental CLI — v0.1 to v0.2

## New in v0.2 — Digest-bound capability planning

The v0.2 branch adds a **caller-declared** requirements document, a read-only graph validation and planning library, and a verifiable SHA-256 binding to the selected file. Both the executable and declarations must match byte-for-byte. The graph validates relations and claims of passing tests **internally**; it does not authenticate their real-world origin.

From a trusted Linux repository checkout with a C compiler:

```sh
python3 -m uoe demo --execute-reviewed-fixture --export-dir /tmp/uoe-v02-example
python3 -m uoe plan /tmp/uoe-v02-example/uoe-demo-client \
  --claims /tmp/uoe-v02-example/claims.json \
  --graph /tmp/uoe-v02-example/graph.json \
  --host-id host:linux-fixture
```

The `demo` command refuses an already existing export directory to avoid overwriting files. It builds **only project-owned reviewed C source**, then exports the built ELF plus the generated declaration/graph. Re-run from a different export path on subsequent attempts.

The second command is entirely **read-only**. It returns the original generic runner proposal plus a `capability_graph` section identifying the exact declared capability, matched graph edges, evidence references and two separately test-backed candidates (reference and disclosed nonblind AI-authored adapter).

Important distinctions:

- The executable digest is verified locally, but the declaration was made by the demo itself. This does **not** demonstrate automated extraction of a dependency.
- The host ID is selected by the caller and **not attested** as the real physical machine.
- Graph evidence of successful tests is taken from the supplied JSON. It is **not** cryptographically signed or independently authenticated.
- For deliberate v0.2 resource bounds, capability planning accepts at most **64 declared requirements, 512 graph nodes, and 256 graph edges**. These research limits will be reconsidered with indexed queries and fuzz testing.
- `test_backed_candidate` means internal evidence consistency, **not** authorized execution, safety or general compatibility.
- Changing the executable invalidates the claims, even if the file retains the same name.

Verification: [v0.2 CI run 38395865631](https://github.com/Ravenmoray/universal-operating-environment/actions/runs/38395865631) passed 41 unit tests and a separately executed review-only demo/claims round trip.

See the [evidence-gated path to v1](../roadmap/v1-delivery-plan.md) and [implementation issue #12](https://github.com/Ravenmoray/universal-operating-environment/issues/12).

---
## Original v0.1 vertical slice

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
