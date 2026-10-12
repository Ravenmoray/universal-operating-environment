# Evidence, testing, and standards reuse (research policy)

**Status:** Proposed engineering practice; no claims of production-grade validation.

UOE's central challenge is not just finding execution paths. It is **knowing what has been established about them, under what conditions**.

## Layers of claims

| Claim | Example | What it establishes |
| --- | --- | --- |
| Hypothesis | An AI suggests a DLL adapter might work | Something worth testing, **not compatibility** |
| Documented requirement | Interface specification says a function is expected | A published contract, with version and source |
| Observed behavior | An inspector reports an import, a trace records a failure | A fact about one inspected artifact or observation |
| Test-backed candidate | A provider passes a defined test on a described host | Evidence bounded to the test, versions and environment |
| Independently verified execution | A reproducible execution follows an authorized plan and an external behavioral oracle | Behavior in specified conditions; still not universal correctness |
| Operational confidence | Continued, monitored use under documented conditions | More evidence of reliability, not a guarantee |

No agent may promote an inference to a test result. A passing self-authored test is not sufficient evidence of behavioral equivalence to closed software; use independent behavioral contracts where possible.

## Minimum tests for each component

1. **Nominal:** expected success under specified, reproducible inputs.
2. **Negative:** missing requirement, unavailable provider, unsupported version.
3. **Malformed/adversarial:** invalid inputs, evidence laundering, broken references, privilege boundary violations.
4. **Determinism:** same versions, policy and inputs produce the same candidate explanation.
5. **Regression:** previous failures become durable cases and cannot be silently erased.
6. **Independent integration:** execution, when authorized, is isolated and tested against external observable behavior.
7. **Provenance:** claims retain source, digest, environment, software versions, test definitions and limitations.

A green CI badge means **these tests pass**, not that an unknown executable is safe or compatible.

## Standards UOE should evaluate before creating its own formats

- [CycloneDX 1.7](https://cyclonedx.org/specification/overview/) already models software components, services, dependencies, inventories and evidence. Compare UOE graph queries against a CycloneDX-based baseline.
- [SPDX 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/) defines component identities, licenses, relationships and provenance across systems. Prefer interoperation over duplicate identity schemes.
- [in-toto Attestation Framework](https://github.com/in-toto/attestation/blob/main/spec/README.md) provides a mechanism for authenticating typed claims about artifact subjects. A JSON field marked `tested` is not a signed attestation.
- [WebAssembly WIT](https://github.com/WebAssembly/component-model/blob/main/design/mvp/WIT.md) provides machine-readable imported and exported interface contracts. Its capabilities are relevant, but its contracts cannot be assumed to describe every native OS API.

**Open design question:** What additional semantics does UOE genuinely require beyond these standards? If the answer is nothing substantial, adapt the standards rather than introducing a custom graph format.

## Current experiment

The [Capability Graph v0](../../experiments/capability-graph/README.md) establishes only *internal-consistency checks and deterministic static planning*. Its demonstration evidence is fictional fixture data. The next falsifiable milestone is a real interface test with project-owned software and a reproducible control group.

See [draft proposal](../rfcs/proposals/minimal-capability-graph.md) and [issue #9](https://github.com/Ravenmoray/universal-operating-environment/issues/9).
