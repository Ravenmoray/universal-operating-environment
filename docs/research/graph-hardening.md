# Graph input and CI hardening

The shared graph implementation keeps schema `0.1.0`. Its evidence checks are
consistency checks, not authenticated attestations. Related: issue #21.

## Limits and validation

- Graph and claims files: at most 1,000,000 bytes read, plus one byte to detect
  overflow. Duplicate JSON keys, non-finite constants and invalid UTF-8 fail.
- JSON nesting: maximum 32 levels, checked before JSON object allocation.
- Graph: at most 10,000 nodes and 10,000 edges; identifiers/references/labels at
  most 4,096 characters; at most 64 evidence references per edge.
- Planning: at most 100,000 provider/host edge pairs across requirements, checked
  before candidate allocation. Over-budget inputs fail rather than being truncated.
- The integrated v0.2 claims planner retains its stricter 512-node/256-edge and
  64-requirement limits. These are experimental budgets, not scalability promises.

Run `python3 -m unittest discover -s tests -v` and
`python3 tests/benchmark_graph.py`. The benchmark constructs synthetic parallel
claims at the 100,000-pair boundary and rejects 102,010 pairs. One local run used
about 1.00 seconds (with tracemalloc enabled), 3,546,129 peak traced bytes, and
0.002 seconds for rejection. These are measurements, not portable timing limits;
CI gives the benchmark a 20-second process deadline. Python allocation tracking
is not a complete resident-memory measurement or a security sandbox.

Regression tests include 400 seeded malformed-field mutations (seed 21), JSON
rejections, exact limits, input reordering and the original graph semantic tests.
This is a reproducible initial mutation corpus, not exhaustive fuzzing.

## Workflow audit and changes

All six checked-in workflows now declare `contents: read`, disable persisted
checkout credentials and use job timeouts. No checked-in workflow references
repository secrets, `pull_request_target`, privileged `workflow_run` triggers or
self-hosted runners. Pull-request Python tests still execute contributor code.

Native ELF/Wine experiments and cross-compilation now run from `main` only,
including a job-level ref gate for manual dispatch. The integrated native demo
also requires `main` and a non-PR event. Ordinary PR tests use hosted runners;
static fixture compilation must never run the resulting artifact.

This audit covers checked-in YAML only. It does not verify GitHub organization
settings, branch protection, contributor approvals, runner-image supply chains
or administrator-managed secrets. Action dependencies still use upstream major
version tags; immutable action pinning and dependency update policy remain
follow-ups. Hardening here does not authorize execution of unknown binaries.

## Remaining work under #21

Broader fuzz campaigns and measured CPU/RSS limits; standards comparison with
SPDX/CycloneDX/in-toto; action pinning/update policy; and owner review of repository
settings. Keep the issue open until these remaining acceptance questions are
resolved or explicitly scoped into follow-ups.
