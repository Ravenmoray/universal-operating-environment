# UOE v0.2 → v1.0: Evidence-Gated Delivery Plan

**Status: proposed roadmap, not a claim that a universal OS exists.**
**Date:** 2026-10-13

## What v1 means

v1.0 should be a **developer research preview of a host-neutral operating environment**, not a new kernel or an assertion that arbitrary Windows/macOS/Linux programs are compatible. Linux is the first integration host for development convenience; public contracts should remain host-independent. The project's central idea is **understanding and resolving capabilities**, with deterministic policies and traceable evidence.

v1 must enable a useful, reproducible workflow:

1. Inspect a user-selected software artifact *without executing it*.
2. Identify evidence-backed requirements or explicitly identify what remains unknown.
3. Find locally or remotely described candidate providers, runtimes, and target hosts.
4. Propose and explain a plan with a traceable artifact digest, requirements, constraints and evidence.
5. Ask for explicit authorization before running anything, with isolated execution for untrusted artifacts.
6. Verify intended behavior against independently defined tests; record failure just as carefully as success.
7. Retain the verified recipe and the knowledge needed to reproduce it on another clean environment.
8. Permit optional model-neutral AI diagnosis and candidate engineering without making an AI model a security authority.

## Proposed phases and objective gates

| Phase | Deliverable | Minimum gate | Main risks |
| --- | --- | --- | --- |
| **0.1 — CLI foundation** | `inspect`, `plan`, explicit reviewed `demo` | Header fixtures, malformed-input tests, no execution by inspect/plan | Misleading runtime-confidence claims |
| **0.2 — Evidence binding** | SHA-256-bound requirement documents, graph-backed provider candidates, host-scoped evidence | Digest mutation rejected; mismatched/forged claims rejected; deterministic output; trusted demo integrated | **Current** graph evidence is untrusted self-report; host is caller-selected |
| **0.3 — Actual requirements** | ELF program interpreter and DT_NEEDED; PE imports; Mach-O dependency commands; WASM imports/WASI model | Golden and malformed binary fixtures, offset/size validation, regressions and fuzzing; dynamic imports explicitly unknown | Parser memory safety and hidden runtime dependencies |
| **0.4 — Adapter contracts** | Versioned native/Wine/WASM/emulation/VM adapter descriptors and host capabilities | Plan determinism; unsupported arch/ABI/API rejected or unresolved; real adapter availability tests | Confusing installed runtime with tested compatibility |
| **0.5 — Authorized execution** | Trust tiers, execution policy, isolation, resource budgets, network/filesystem rules, audit logs | Negative privilege tests; no unreviewed binary launch in PR CI; deny by default; report and rollback | Unsafe execution of unknown programs or generated code |
| **0.6 — Verifiable knowledge** | Indexed, immutable experiment records, signed subject-bound attestations, solution reuse | Provenance chain valid; tampering invalidates claims; second independently provisioned host reproduces | False confidence, test evidence laundering |
| **0.7 — Optional AI repair loop** | Model-neutral diagnosis and candidate adapter generation within strict tool limits | Blinded tests with held-out oracle and non-AI baselines; failures retained; no self-approval | Model leakage, reproducibility and hallucinated APIs |
| **0.8 — Cross-runtime integration** | Project-owned ELF, PE-on-Wine, WASM test programs using comparable capability contracts | Independently observed behavior and error cases on at least two execution backends | Platform-specific assumptions hidden inside contracts |
| **0.9 — Release candidate** | Installable CLI, reproducible documentation, safety review, stable schemas | Regression, adversarial and fuzz evidence; versioned migration path; review all known security issues | Packaging and operational failures |
| **1.0 — Research preview** | A reproducible, documented user-facing capability execution workflow | All essential gates pass or explicitly scoped exclusions accepted and documented | Overclaiming universal execution |

## Test policy for all milestones

- **State what each test proves and what it does not.** Passing a parser test is not program compatibility. `test_backed_candidate` is not a trusted attestation.
- **Static tests** may run on untrusted pull requests only when they do not run contributed binaries or generated source; preserve low privileges and no secrets.
- **Execution tests** use reviewed project-owned fixtures on trusted runners; untrusted software needs stronger disposable isolation before it is ever executed.
- **Negative tests** cover unsupported ABI, architecture, missing imports, wrong symbol, wrong semantics, changed digests, fake test claims, stale host scope, malformed inputs, and policy denials.
- **Deterministic tests** repeat identical conditions and deliberately reorder declarations/graph nodes to reveal accidental dependence on input ordering.
- **Cross-host tests** must use independently provisioned hosts, not simply new directories on one machine.
- **Fuzzing** must include parser time/memory bounds, malformed containers and nested formats; use precise crash and false-positive counts with seeds and versions.
- **Behavioral compatibility tests** use a separate oracle that does not accept merely 'the process launched'. Preserve known failures as permanent regression cases.
- **Supply-chain checks** document dependency versions, license conditions, build recipes, SBOM inputs and signed evidence; assess CycloneDX, SPDX, in-toto before inventing formats.
- **AI evaluations** distinguish test design from model output, block benchmark leakage when claims are blinded, and compare costs, correctness and repair steps against a no-graph baseline.

## Release interpretation

The original vision—'Any software. Any computer. One intelligent environment.'—remains a **direction**, not an acceptance criterion claiming impossible general coverage. v1 can succeed as a powerful research preview while explicitly refusing applications that require unsupported proprietary APIs, DRM, unknown drivers or unavailable hardware.

## Next delivery sequence

PRs #11 and #20 established the v0.2 baseline. Shared graph hardening is merged
and v0.3 adds static requirement extraction for ELF, PE, WebAssembly and Mach-O,
each compared with independent tools ([validation record](../research/corpus-validation.md)).
No tagged release or production compatibility claim is implied.

1. **Continue hardening the shared graph implementation (#21).** The single validator,
   bounded JSON reader, candidate-pair budget and initial mutation tests are implemented. Keep one validator/planner
   in `uoe.graph`, with the original experiment as a compatibility entry point.
   Run old and new tests in CI whenever that implementation changes. Keep #21
   open for bounded performance/fuzz work and the remaining trust-boundary audit.
2. **Finish v0.3 (#13).** ELF (PT_INTERP/DT_NEEDED), PE (normal imports),
   WebAssembly (import section) and Mach-O (dylib, dynamic-linker, rpath, platform and
   universal-slice commands) extraction are implemented, bounded, and compared with
   readelf, objdump/llvm-readobj, V8 and llvm-objdump on project-owned fixtures,
   real vendor files and seeded differential fuzzing. Do not call the full v0.3
   phase complete until the remaining gates pass: sustained coverage-guided fuzzing,
   a corpus independent of one machine, and observation (not just flagging) of PE
   delay-load imports, CLR references, WebAssembly import signatures and Mach-O bindings.
3. **Formalize adapters (#14).** Feed observed requirements into versioned
   native/Wine/WASM descriptors, preserving unknown and unsupported outcomes.
4. **Build execution controls before broadening execution (#15).** Isolation and
   denial tests precede unknown binaries or generated adapters. Continue using
   reviewed project-owned fixtures for current demonstrations.
5. **Prove reuse, then AI value (#16–#18).** Signed evidence and separate-host
   replay come before blinded repair trials and expanded compatibility benchmarks.
6. **Release only the scope supported by evidence (#19).** v1 remains a developer
   research preview with documented environments and exclusions.

Each implementation PR should include its evidence, remaining limitations and
linked issue. Existing research issues remain open until their actual acceptance
criteria are met; merging code does not approve a draft RFC.

### CI trust boundary

Python unit tests on a pull request also execute contributor-controlled code.
Use disposable hosted runners, read-only tokens, no repository secrets and no
persisted checkout credentials for those tests. Skipping compiled fixtures alone
is not an isolation guarantee. Complete the broader workflow audit under #21.
