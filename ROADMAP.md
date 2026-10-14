# Roadmap

All milestones are research goals; no feature is complete until demonstrated and documented.

## M0 — Public foundation
- [x] Create public repository
- [x] Adopt AGPL-3.0-or-later for project-original code and documentation
- [x] Publish charter, architecture draft and RFC 0001
- [x] Publish [draft RFC 0002](docs/rfcs/0002-capability-centered-computing.md) for public discussion
- [ ] Review and refine threat model
- [ ] Agree contributor governance
- [ ] Enable private vulnerability reporting and CI

## M1 — Static artifact inspection
- [ ] Detect ELF, PE, Mach-O and WASM reliably
- [ ] Define versioned manifest schema
- [ ] Extract static dependencies with evidence and uncertainty
- [ ] Establish a legally redistributable test-fixture corpus

**Success criterion:** reproducible reports for representative benign files, without executing those files.

## Capability Graph research (parallel, not a production milestone)
- [x] Publish [minimal graph proposal](docs/rfcs/proposals/minimal-capability-graph.md) for review
- [x] Implement a [read-only evidence-bound planning experiment](experiments/capability-graph/README.md) with negative tests and CI
- [ ] Compare the experiment against CycloneDX/SPDX or a simple dependency baseline
- [ ] Design independently authenticated evidence and real behavioral integration tests

## UOE v0.1 working CLI (prototype; review and testing ongoing)
- [x] Create [read-only multi-format inspector](docs/research/working-prototype.md) with bounded ELF, PE, Mach-O and WASM header analysis
- [x] Expose a deterministic runner planner with candidate and unresolved states
- [x] Implement opt-in project-owned Linux end-to-end demo (inspection → planning → verified fixture)
- [x] Validate 21 inspector/planner tests and the controlled demo in GitHub CI
- [x] Review [prototype PR #11](https://github.com/Ravenmoray/universal-operating-environment/pull/11) for merge into `main`
- [ ] Parse actual imports, dynamic libraries, interpreter and WASI requirements
- [x] Bind artifact SHA-256 and declared capability claims to evidence-backed graph providers

## v0.2 prototype — evidence binding (merged)
- [x] Add [digest-bound capability claims and graph join](docs/research/working-prototype.md), with exact artifact SHA-256 comparison
- [x] Reject mismatched requirements, graph links and unauthenticated host scope; report explicit evidence limitations
- [x] Extend controlled demo to export artifact/claims/graph and independently replan it in CI
- [x] Pass 41 combined unit tests and the reviewed demo round-trip ([CI run](https://github.com/Ravenmoray/universal-operating-environment/actions/runs/38395865631))
- [x] Review and merge v0.2 on top of v0.1 without treating caller-supplied evidence as attested

## v0.3 incremental delivery
- [x] Consolidate graph validation and add JSON/fan-out budgets with mutation tests
- [x] Extract ELF PT_INTERP and direct DT_NEEDED with file-offset evidence
- [x] Test 32/64-bit, both byte orders, malformed inputs and a project-owned missing-library fixture against readelf
- [ ] Extend sustained fuzzing, benchmarks and independent corpus coverage
- [ ] Extract PE, WASM and Mach-O dependencies in separate changes

The ELF increment does not complete M1 or the full v0.3 milestone.

## Planning v0.3 → v1.0
See [proposed release phases and gates](docs/roadmap/v1-delivery-plan.md):
- [v0.3 static dependency extraction](https://github.com/Ravenmoray/universal-operating-environment/issues/13)
- [v0.4 adapter and host contracts](https://github.com/Ravenmoray/universal-operating-environment/issues/14)
- [v0.5 security isolation](https://github.com/Ravenmoray/universal-operating-environment/issues/15)
- [v0.6 signed evidence and recipe replay](https://github.com/Ravenmoray/universal-operating-environment/issues/16)
- [v0.7 blinded AI repair benchmarks](https://github.com/Ravenmoray/universal-operating-environment/issues/17)
- [v0.8 cross-runtime test matrix](https://github.com/Ravenmoray/universal-operating-environment/issues/18)
- [v0.9–v1.0 release gates](https://github.com/Ravenmoray/universal-operating-environment/issues/19)

## M2 — Execution planning
- [ ] Define runner-adapter interface and host capability model
- [ ] Evaluate native Linux, Wine and Wasmtime options
- [ ] Explain strategies, prerequisites, confidence and gaps
- [ ] Keep planning deterministic and side-effect free

## Controlled native fixture (pre-M3; not untrusted execution)
- [x] Demonstrate project-owned ELF client with missing shared-library dependency
- [x] Detect missing library, wrong symbol, and wrong behavior against an external oracle
- [x] Run clean rebuild and connect test evidence to a graph candidate
- [x] Cross-compile project-owned Windows PE executable/DLL from the same C interface contract; static format/export validation only
- [ ] Replicate on a truly independent machine or VM
- [x] Evaluate a disclosed **nonblind** [AI-authored adapter](experiments/missing-capability/agent_candidate_v0.c) under the existing oracle (17 assertions per clean build)
- [ ] Test a **blinded** AI-generated adapter with separately controlled validation, repeated trials, independent host and provenance ([issue #10](https://github.com/Ravenmoray/universal-operating-environment/issues/10))
- [x] Execute project-owned Windows PE/DLL fixtures under Wine 9.0 on a trusted ephemeral Linux CI runner; verify missing DLL, absent export, incorrect behavior, correct reference and nonblind AI candidate ([run 38324324417](https://github.com/Ravenmoray/universal-operating-environment/actions/runs/38324324417))
- [ ] Design isolated, permissioned execution for genuinely untrusted artifacts (Wine alone is not a security boundary)

## M3 — Controlled execution
- [ ] Implement consent, isolation, resource bounds and audit records
- [ ] Test ELF, Windows PE through Wine, and WASM executions
- [ ] Record outcomes and limitations, not simply success labels

## M4 — AI and system knowledge
- [ ] Integrate model-neutral AI tools
- [ ] Index design records, tests, interface contracts and compatibility findings
- [ ] Test proposed repair workflows against deterministic validation

## M5 — Operating environment
- [ ] Explore desktop/server interface
- [ ] Explore distributed resources and non-Linux host support
