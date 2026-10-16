# Proposal: Exact-scope execution authorization contract

**Status:** Draft
**Author(s):** Submitted through Ravenmoray's authorized GitHub identity
**AI assistance:** Substantial design, reference model and tests by OpenAI Codex
**Related issue:** [v0.5 #15](https://github.com/Ravenmoray/universal-operating-environment/issues/15)
**Created:** 2026-10-15
**Target areas:** Security, controller interface

> A data-only proposal for review, not an approved architecture, execution engine,
> launch permit format, or proof of secure isolation. No v0.5 gate is completed.

## Summary

Bind each approval to one exact, bounded execution request and require a future
controller to recheck it at an atomic consume-and-start boundary. A deterministic
reference predicate produces only `deny` or `eligible`; it never launches code.
The first profile deliberately supports only offline disposable-VM workloads
with no host mounts, secrets, devices or elevated privileges.

## Problem / user need

A candidate plan, model recommendation or previously passing test must not become
permission to run a changed artifact, adapter, image, command or resource scope.
Consent can also become stale after a host or policy change. Issue #15 asks for
typed requests and deterministic controls; this small contract can be reviewed
before v0.4 adapter implementation and without unfinished v0.3 parser details.

## Relevant current behavior and prior art

At main `def2124ed2f1e6c570ce88c99d56be907ba6fe25`, inspect/plan are non-executing;
the explicit demo is limited to project-owned fixtures. There is no general
execution controller or authenticated approval service. [SECURITY.md](../../../SECURITY.md)
and [RFC 0002](../0002-capability-centered-computing.md#7-safety-correctness-and-legal-constraints)
already require independent policy and scoped execution. This proposal refines
that existing boundary; it does not replace a mature policy engine or define a
new signature protocol. Authentication and evidence standards remain separate
work under [#16](https://github.com/Ravenmoray/universal-operating-environment/issues/16).

## Proposed design

### Data and trust ownership

The normative v0 profile is illustrated by the [example](../../../experiments/authorization-contract/example.json)
and [reference predicate](../../../experiments/authorization-contract/model.py).
Unknown keys and unsupported versions are rejected, including apparent approval
or model-confidence fields inside the request. These are decoded JSON objects,
not a wire protocol. A future decoder must bound bytes/depth, reject duplicate
keys, and validate before constructing these inputs. This model is not that decoder.

| Input | Owner and meaning |
| --- | --- |
| `request` | Untrusted proposal. Exact keys: schema version, request ID, artifact/adapter/image/host-snapshot SHA-256 identities, policy revision, ordered argv, limits, rights. No shell, environment, URL, host path or discovery instructions. |
| `approval` | Approval-service record: unique approval ID, full request as `subject`, issued-at and exclusive expires-at integer times. Merely presenting this object is insufficient. |
| `context` | Trusted controller snapshot: authenticated/revoked/consumed status for this exact approval record, current policy revision and host snapshot, and readiness of the exact isolated configuration. Never accepted from model, graph, artifact or caller labels. |
| `now` | Trusted nonnegative integer time in seconds supplied by the controller; caller clocks are not authority. |
| result | `decision`, stable `reason`, `execution_attempted: false`. Positive `eligible` is neither permission to launch nor compatibility evidence. |

The approval service must authenticate the **whole immutable record**, including
subject, ID and validity window. `approval_authenticated` is an explicit test
assumption, not signature verification. The context must describe the same
approval ID, subject, host and isolation configuration being evaluated. A future
implementation must use trusted handles or authenticated records, not booleans
sent over an untrusted channel. Evidence signatures do not confer execution rights.

Digests are 64 lowercase hex characters. IDs/revisions use 1–128 ASCII letters,
digits, `.`, `_`, `:`, `-`. `argv` is an ordered list of at most 32 strings, each
at most 1,024 Unicode code points with no NUL. It excludes the executable name:
the pinned adapter selects a fixed entry point for the pinned artifact. No shell
expansion is permitted. All other invocation settings, including environment,
working directory and loader/search paths, must be fixed by the pinned adapter
and VM image. New dynamic settings require a revised contract and new consent.
Adapter pinning binds code identity; it does not certify that code as safe.

Every resource limit is an explicit positive integer (booleans are rejected).
Research ceilings: CPU 60,000 ms, wall 60,000 ms, memory 1 GiB, writable guest disk
1 GiB, and 16 processes. These are proposed test ceilings, not measured safe host
budgets. The controller must account for the entire guest workload, including
children; unsupported enforcement means deny. The disk limit covers all writable
guest storage; image storage and control-plane quotas need separate host policy.

Rights must exactly equal `network: "none"`, empty `host_mounts`, `secrets`,
`devices` lists, and `privileged: false`. Even authenticated consent cannot enable
unsupported rights. Input artifacts are staged by digest into guest-owned storage;
no host directory is shared. There are no implicit downloads, inherited host
environment, credentials, devices or external outputs. Safe bounded output export
is future controller work, not a permission implied by this profile.

### Deterministic decision order

The first matching row decides the result. Object key order is irrelevant;
argument order remains significant. There is no ranking, model call or fallback.

| Check | Reason on denial |
| --- | --- |
| Request keys, version, types, bounds or offline rights invalid | `invalid_request` |
| Trusted context shape/types or clock invalid | `invalid_context` |
| Approval shape/types, subject or validity interval invalid | `invalid_approval` |
| Exact approval record not independently authenticated | `unauthenticated_approval` |
| Revoked approval | `revoked_approval` |
| Previously consumed approval | `consumed_approval` |
| Time outside `issued_at <= now < expires_at` | `outside_approval_window` |
| Full validated request differs from approval subject | `subject_mismatch` |
| Current policy revision differs | `policy_changed` |
| Current host snapshot differs | `host_changed` |
| Required isolated configuration not ready | `isolation_unavailable` |
| All above checks pass | `eligible`, reason `matched` |

Unknown or missing approval/context denies. Full structural equality binds every
request field, including ordered arguments and all resource limits. It is not a
canonical JSON/signature scheme. Adding fields requires a version change; a
smaller resource request also requires renewed consent in this conservative draft.
Any error or unavailable trusted service must fail closed in a real controller.

### Required future controller protocol

1. Freeze artifact, adapter, image and host configuration by trusted identity;
   verify bytes at use time and retain immutable handles. Reject mutable paths,
   label-only host identities and substituted images.
2. Present the complete request and effective rights to the authorized human or
   independent policy principal. An AI may propose, never issue/verify approvals
   or supply trusted context. Keep approval service credentials out of model tools.
3. At start, obtain fresh trusted context, reevaluate policy and authorization,
   prepare enforced isolation, and durably reserve the approval exactly once.
   Reservation and transition to start must be serialized across workers. Recheck
   cancellation, expiry, revocation, host/policy state and handles at that boundary.
4. No process may start unless all checks, enforcement and durable audit writes
   succeed. The audit binds request/approval IDs, exact subject, policy, host,
   outcome, reason and trusted time; do not log secret values or model prose.
5. Treat reservation as consumption even if setup/start crashes. Retry requires
   new consent. Recovery cannot reuse a permit. Cancellation before start denies;
   after start it terminates the isolated workload and records partial effects.
   VM disposal cannot undo remote or external effects; this profile forbids them.

The pure predicate has no persistent store, synchronization, launcher, revocation
subscription or audit sink. Its tests **do not demonstrate atomic single-use,
TOCTOU resistance, cancellation, crash recovery, or that unauthorized execution
cannot start**. Those need independent controller integration tests and security
review before any artifact launch. If reliable revocation serialization or a
trusted clock is unavailable, execution must remain disabled.

## Alternatives considered

- Reuse graph candidate/test status as authority: contradicts untrusted evidence
  and independent approval; reject.
- Broad reusable approvals and subset resource matching: operationally convenient,
  but enlarge delegation/replay semantics; defer until exact binding is reviewed.
- Adopt an established policy engine immediately: reasonable for implementation,
  but still needs an explicit controller protocol. This model supplies a small
  conformance target without choosing a policy engine or authentication system.
- Wait for v0.3/v0.4: necessary for integrated execution, unnecessary for reviewing
  consent semantics over opaque pinned identities.

## Risks, security, privacy, and licensing

A controller that accepts caller-controlled context makes this design meaningless.
Identity pinning, trusted time, enforcement, authenticated approval storage,
reservation, audit durability and revocation races remain blockers. VM presence
alone is not enforcement; Wine and containers alone do not meet this proposal.
The reference model must not be imported into `uoe` as a security boundary.
Original proposal/code are AGPL-3.0-or-later; no third-party implementation reused.
No existing execution behavior or repository security policy changes here.

## Validation / falsifiable experiment

Run `python3 -m unittest discover -s tests -p test_authorization_contract.py -v`.
The data-only tests cover exact binding mutations, all required/unknown fields,
rights escalation even with matching consent, stale host/policy, authentication,
revocation/consumption flags, time/resource boundaries, malformed values, stable
ordering and input immutability. A valid positive control prevents an always-deny
implementation from passing. No inspected/generated native artifacts are run.

Compared with a naive `approved: true` flag, the predicate must deny a changed
subject and unsupported rights. Any positive result after such a mutation falsifies
the contract model. This is a semantic comparison, not a performance benchmark or
security certification. Authenticated-record forgery and concurrent replay require
future tests against real services; fixture booleans cannot establish either.

## Implications for documentation and system knowledge

Keep this proposal experimental and preserve denial cases as contract vectors.
[#14](https://github.com/Ravenmoray/universal-operating-environment/issues/14) may
later map adapter/host contracts into these opaque identities, without treating
candidate discovery as permission. [#17](https://github.com/Ravenmoray/universal-operating-environment/issues/17)
can reuse deterministic denials when testing AI proposals. [#18](https://github.com/Ravenmoray/universal-operating-environment/issues/18)
and [#19](https://github.com/Ravenmoray/universal-operating-environment/issues/19)
still require independent behavioral/security evidence. This work neither closes
[#15](https://github.com/Ravenmoray/universal-operating-environment/issues/15) nor
replaces [#21](https://github.com/Ravenmoray/universal-operating-environment/issues/21)'s
CI trust-boundary audit. No parser, graph validator, active branch or CI workflow
is changed.

## Open questions

- Which existing approval transport and policy engine fit the trust model?
- How should host-snapshot identity and configuration freshness be established?
- What mechanism serializes revocation, expiry, cancellation and consumption at start?
- What controller evidence proves that every denied operation starts zero processes?
- Are the proposed limits usable once whole-VM accounting is measured?

## Decision record

- **Decision:** Pending; Draft, including if merged.
- **Rationale:** Pending maintainer and independent security review.
- **Links to evidence / review:** Contract tests only; no execution/security gate satisfied.
