# Roadmap

All milestones are research goals; no feature is complete until demonstrated and documented.

## M0 — Public foundation
- [x] Create public repository
- [x] Adopt AGPL-3.0-or-later for project-original code and documentation
- [x] Publish charter, architecture draft and RFC 0001
- [ ] Review and refine threat model
- [ ] Agree contributor governance
- [ ] Enable private vulnerability reporting and CI

## M1 — Static artifact inspection
- [ ] Detect ELF, PE, Mach-O and WASM reliably
- [ ] Define versioned manifest schema
- [ ] Extract static dependencies with evidence and uncertainty
- [ ] Establish a legally redistributable test-fixture corpus

**Success criterion:** reproducible reports for representative benign files, without executing those files.

## M2 — Execution planning
- [ ] Define runner-adapter interface and host capability model
- [ ] Evaluate native Linux, Wine and Wasmtime options
- [ ] Explain strategies, prerequisites, confidence and gaps
- [ ] Keep planning deterministic and side-effect free

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
