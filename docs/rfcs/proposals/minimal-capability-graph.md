# RFC Proposal — A Minimal Capability Graph with Evidence-Bound Claims

**Status:** Draft (not accepted)  
**Date:** 2026-10-12  
**Discussion:** [Issue #9](https://github.com/Ravenmoray/universal-operating-environment/issues/9)  
**AI assistance:** Drafted with AI assistance; submitted for public technical review.  
**Related:** [RFC 0001](../0001-artifact-execution.md), [RFC 0002](../0002-capability-centered-computing.md)

## Summary

Represent software requirements and potential providers as a small, versioned graph with explicit evidence, then produce deterministic, **non-executing** candidate plans. The graph should never confuse a proposed provider, a documented interface, and behavior independently demonstrated by tests.

This is a first experiment to determine whether capability-centered computing adds anything beyond familiar dependency manifests and runtime launchers.

## Problem

The statement “this is a Windows application” gives less detail than “this artifact requires a specific version of an interface with defined calling conventions.” The latter suggests multiple potential strategies: native implementation, compatibility shim, emulator, VM, or remote host.

However, mapping program requirements to purported providers is dangerous when relationships are guesses. UOE needs a compact way to ask:
- What is required, and how was that learned?
- What provider *claims* to supply it?
- On what host has the provider been tested?
- What unknowns prevent the system from claiming anything stronger?

## Prior art and non-goals

Before inventing a graph interchange format, compare against:
- [CycloneDX 1.7](https://cyclonedx.org/specification/overview/) — components, services, dependency relationships, evidence and supply-chain inventory.
- [in-toto attestations](https://github.com/in-toto/attestation/blob/main/spec/README.md) — verifiable provenance and typed evidence bound to software subjects.
- [WebAssembly WIT](https://github.com/WebAssembly/component-model/blob/main/design/mvp/WIT.md) — machine-readable interface types.
- Existing executable inspectors, software package metadata, package URLs and SPDX licenses.

A production UOE graph should likely **import and reference these standards**, not duplicate them.

This experiment will not inspect binary files, prove arbitrary compatibility, dynamically generate code, evaluate model weights, enforce sandboxing, run executables, or claim verified performance.

## Smallest proposed model

Five **node kinds**: `artifact`, `capability`, `provider`, `host`, and `evidence`.

Three **directed relationships**:

- `artifact --requires--> capability`
- `provider --provides--> capability`
- `provider --available_on--> host`

Each edge is a claim, not necessarily a fact. Required edge fields: `id`, `source`, `relationship`, `target`, `status`, `evidence`.

Permitted statuses: `inferred`, `documented`, `observed`, `tested`, `rejected`.

Every non-rejected claim references source evidence; even a rejected claim has an evidence record explaining the rejection. Evidence includes origin type, reference, result, and the exact subject/relation/object triple that it supports. A `tested` claim **must** point to matching evidence of type `test` with result `pass`. A model hypothesis can be documented as an inference but can never, by itself, become a passing test.

An artifact and a provider are distinct concepts; the latter is a potential means of fulfilling a contract, not necessarily a single executable. A capability identifier is versioned (e.g., `capability:example.echo@1`) and must eventually point to a meaningful interface contract. For this v0 experiment, **only exact identifiers match**. Implicit semver or equivalence reasoning is prohibited.

## Candidate planning rules

Given a valid graph, one artifact and one host:

1. Find its required capability edges.
2. Find provider `provides` edges targeting the **exact same capability**.
3. Find each provider's `available_on` edge for the selected host.
4. Exclude rejected relationships.
5. Rank candidates with `tested` evidence on both the provider and host edges ahead of candidates relying on weaker evidence.
6. Report missing capabilities explicitly. Do not infer that lack of a graph edge means lack of a possible real-world solution.
7. Produce stable JSON output sorted by capability and provider identity.

The highest ranking is **test-backed candidate**, not “compatible” or “safe to run.” The test can be narrow, stale, fraudulent or inapplicable beyond the documented scope. The system does not gain execution authority by planning.

## Trust boundaries

- Untrusted graph files cannot cause process execution, remote calls, package installation, filesystem mutation, or new privileges.
- A `tested` claim requires linked passing test evidence matching the claim's exact triple; this verifies **internal consistency only**, not cryptographic authenticity.
- Production trust will need in-toto-style signed attestations, revocation, time-bound environment scope and independent validation.
- A missing result is `unresolved`, not `false`.
- A generated candidate implementation is distinct from running the original artifact.
- A human or higher-trust policy engine must authorize any future execution. AI model prose never counts as authorization.

## Experiment layout

An isolated implementation lives in [experiments/capability-graph](../../../experiments/capability-graph/README.md) with a versioned JSON Schema, one fake demo graph and a Python standard-library read-only planner. Fixture names are **illustrations**, not assertions of actual Windows/Linux compatibility.

## Falsification plan

Tests must show that the prototype:
- rejects dangling edges, duplicate identifiers, malformed references, and mismatched evidence;
- refuses to promote an inferred or documented claim into `tested`;
- returns unresolved when no provider exists, including with version mismatch;
- never treats rejected provider/host links as viable;
- gives deterministic results regardless of the input ordering;
- never launches the described artifact;
- distinguishes candidate quality without calling anything “proven compatible.”

Beyond these structural tests, UOE must ultimately compare the model with a simple dependency registry or CycloneDX-only implementation. If there is no measurable benefit, reduce or abandon the custom graph.

## Open questions

How do we define capability identity and behavioral equivalence? Should artifact/host conditions live in claim scopes rather than node properties? How do we encode negative knowledge without forbidding newly discovered solutions? When and how should we adopt SPDX, CycloneDX, WIT and in-toto rather than maintaining custom schemas? Which independent test oracle establishes a provider's real behavior?

## Decision requested

Approve **research on this small model**, not the model itself. Keep the RFC in Draft; publish test results and competing proposals before deciding whether the Capability Graph should become a core UOE abstraction.
