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
- [ ] Test AI-generated adapter with independent validation and provenance ([issue #10](https://github.com/Ravenmoray/universal-operating-environment/issues/10))
- [ ] Run a project-owned Windows PE/DLL fixture through a constrained Wine environment

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
