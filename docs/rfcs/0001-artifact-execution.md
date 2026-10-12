# RFC 0001 — Artifact Inspection and Execution Planning

**Status:** Draft  
**Date:** 2026-10-12

## Problem

Operating-system labels and CPU targets are crude proxies for a program's true runtime requirements. UOE needs to understand an artifact well enough to explain feasible execution paths without assuming it must run on its originally targeted host.

## Phase A — Static inspection

Input: artifact bytes, optional provenance, optional platform metadata.

Output: a versioned manifest of format, architecture, observed imports/dependencies, detected interfaces, evidence, uncertainty and unknowns.

**Hard constraint:** inspecting must never execute input artifacts.

## Phase B — Planning

Input: artifact manifest, local host descriptor, available runners, policy constraints.

Output: candidate execution strategies (native, compatibility, emulation, virtualization or unresolved), with prerequisites, trade-offs and precise reasons for rejection.

## Acceptance criteria

1. Handle representative ELF, PE, Mach-O and WASM files without running them.
2. Handle malformed or unknown files without crashes and without guessing unsupported details.
3. Tag inferred requirements separately from observed metadata.
4. Produce deterministic planning results for equivalent inputs and registry versions.
5. Provide human-readable explanations and machine-readable output.
6. Document reproducible, redistributable fixtures.

## Open decisions

Manifest schema, version negotiation, runner registry design, safe parsing boundaries, isolation, software licenses, proprietary OS APIs and test oracle design.
