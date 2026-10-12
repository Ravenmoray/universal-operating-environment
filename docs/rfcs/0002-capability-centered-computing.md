# RFC 0002 — Capability-Centered Computing: Rethinking the Operating Environment

**Status:** Draft — public discussion, not an accepted architecture  
**Discussion:** [GitHub issue #7](https://github.com/Ravenmoray/universal-operating-environment/issues/7)  
**Date:** 2026-10-12  
**Authors:** UOE project discussion  
**Scope:** Architectural direction and a falsifiable research program  
**Related:** [Project vision](../../VISION.md) · [RFC 0001: Artifact Inspection and Execution Planning](0001-artifact-execution.md) · [Roadmap](../../ROADMAP.md)

> **Central proposition:** Software should be understood primarily by what it does, what it needs, and what it guarantees—not by the operating system for which it was packaged.

## 1. Abstract

The Universal Operating Environment (UOE) explores a computing model in which an AI-assisted system understands software, its dependencies, its execution environment, and its own design. Rather than treating “Windows-only,” “macOS-only,” or “Linux-only” as definitive answers, UOE should analyze the actual requirements and investigate compatible ways to meet them.

This proposal goes further than cross-platform binary execution. It asks whether **installed applications are the right primary unit of computing**. An application could instead be one implementation of a capability: alongside a local library, a container, a remote service, a script, a generated component, a VM, or a combination of these.

We propose investigating a **Capability Graph** and a **Living System Knowledge Base** coordinated by an **AI Systems Engineer** under deterministic security and execution controls.

This is a research proposal. It does **not** claim that every program can be executed, that AI can reliably recreate an arbitrary proprietary API, that applications should be abolished, or that today’s operating-system abstractions are obsolete. Those are hypotheses to test—not slogans to implement blindly.

## 2. Why revisit the old assumptions?

Traditional operating systems provide indispensable mechanisms: CPU scheduling, memory protection, device drivers, storage, identity, process isolation, networking, and interfaces that software can depend on. These are not arbitrary details, and reliable computing will continue to need many of them.

Yet several higher-level conventions deserve renewed examination:

| Established convention | Question for UOE |
| --- | --- |
| An application is installed for a specific OS | Can the system discover and satisfy actual runtime requirements instead? |
| The user chooses a particular application | Can the user instead request a capability or outcome, while retaining direct control of chosen applications? |
| Dependencies are assembled by humans or package managers | Can a planner resolve them across runtimes, adapters, VMs, and services? |
| Documentation is separate from running software | Can specifications, code, decisions, tests, and observations form part of an operational system model? |
| Successful deployment is the end of the process | Can verified solutions become reusable execution recipes and knowledge? |
| A machine is the natural boundary of a computing environment | Can local and remote resources be described through the same contracts without concealing locality when it matters? |

The answer to each question may be “sometimes.” The purpose of UOE is to make that “sometimes” measurable, expandable, and useful.

### 2.1 What is not arbitrary

An executable's instruction set, application binary interface (ABI), calling conventions, kernel interfaces, licensing constraints, driver expectations, secure hardware requirements, real-time deadlines, and externally hosted services can be decisive. A compatibility engine cannot wish them away.

UOE should record these constraints as explicit requirements with evidence and uncertainty, then evaluate possible solutions. An honest “not currently feasible because X” is better than a fabricated claim of universal support.

## 3. Proposed conceptual model

A capability-centered system would distinguish at least eight kinds of object:

1. **Intent** — what a person, service, or automation wants to accomplish, including constraints.
2. **Capability** — a versioned, testable contract for a behavior such as image decoding, document editing, network access, or rendering a window.
3. **Artifact** — an existing implementation: binary, source tree, library, application bundle, container, WASM component, script, or service endpoint.
4. **Requirement** — an interface, runtime, privilege, resource, behavioral guarantee, or external dependency an artifact needs.
5. **Provider / adapter** — a way to supply one or more capabilities or bridge interfaces.
6. **Host** — local, virtual, or remote resources with measurable hardware and software properties.
7. **Execution plan / recipe** — a reproducible explanation of which providers and hosts meet requirements, including permissions and failure conditions.
8. **Evidence** — specifications, source references, observed behavior, tests, provenance, failures, and confidence levels backing the above relationships.

These are proposed logical concepts, **not necessarily eight services or databases**.

### 3.1 Capabilities are contracts, not vague labels

“Can edit photos” is a useful human description, but insufficient for automated composition. A capability requires machine-interpretable contracts: operations, input/output types, versions, side effects, error semantics, required privileges, performance constraints, and tests.

A capability must also identify what it *does not* promise. Two image decoders with different color-management behavior, for instance, may not be interchangeable for a given workload.

### 3.2 The Capability Graph

The graph would relate artifacts, capabilities, dependencies, hosts, adapters, validation results, and source evidence. It should support questions such as:

- What does this artifact require, and how do we know?
- Which installed or available providers could satisfy those requirements?
- What translation, emulation, or virtualization steps are necessary?
- Which solution has been verified for this version and environment?
- What rights, resources, security boundaries, and user approvals apply?
- What is missing, uncertain, or impossible on the current host?

The graph **must not treat model-generated claims as facts**. Each edge needs provenance and a verification state: observed, documented, inferred, tested, rejected, or unresolved. Contradictory findings must be preserved and revisable.

## 4. High-level architecture

~~~text
  Human intent / traditional application launch / API / automation
                               |
                       Request interpreter
                               |
                      Artifact inspector
                               |
                 Requirement & capability model
                               |
             +-----------------+-----------------+
             |                                   |
     Capability Graph                   Living Knowledge Base
             |                          source / specs / tests
             +-----------------+-----------------+
                               |
                       Execution planner
                      /        |        \
               Existing     Compose     Investigate missing
               provider     providers    capability (AI-assisted)
                      \        |        /
                       Proposed execution plan
                               |
                  Deterministic policy & consent
                               |
                     Isolated execution controller
                               |
                      Observations and tests
                               |
               Versioned, evidenced solution record
~~~

The AI can assist interpretation, investigation, engineering, and explanation. It **does not become the security authority**. The parser, policy engine, approval process, execution controller, and validation checks must work independently of the model's confidence or instructions.

### 4.1 Two equally valid entry points

**Artifact-first:** The user brings an existing executable. UOE inspects it and finds a feasible execution strategy, ideally retaining the original software and its behavior.

**Capability-first:** The user requests functionality. UOE discovers an existing implementation, composes available capabilities, or proposes building a missing component.

The capability-first path must not silently replace an original application's behavior with a merely similar implementation. Users need to know whether they are running the original artifact, a compatibility-translated artifact, or a separate alternative.

### 4.2 Compatibility is a spectrum

Prefer the least complex valid option that meets contracts and policy:

1. Execute natively on a suitable host.
2. Use a known compatible runtime or adapter.
3. Translate required interfaces or instructions with established implementations.
4. Use an emulator or virtual machine with legally available dependencies.
5. Investigate or build a missing adapter against an available specification.
6. Offer an explicitly identified alternative implementation **only with user agreement**.
7. Report the precise unresolved blocker.

An AI-generated compatibility shim is not considered compatible merely because it compiles or launches. Its behavior must be tested against an independent oracle or meaningful contract.

## 5. AI as a native systems engineer

UOE should offer AI as an interchangeable capability that may run locally, remotely, or through cooperating specialized agents. It should be possible to perform deterministic inspection, planning, and known executions **without an AI connection**.

Proposed responsibilities include:

- **Analyst:** identify requirements, gaps, assumptions, and likely solutions.
- **Engineer:** propose code, adapters, configurations, and tests.
- **Verifier:** design experiments and examine evidence; not self-approve deployment.
- **Knowledge steward:** connect implementations to decisions, incidents, tests, documentation, and provenance.

These are responsibilities, not a requirement for four separate models.

### 5.1 Documentation as operational knowledge and possible training data

Every substantial component should link:

- implementation and versioned interface specifications;
- design rationale, trade-offs, and architectural decisions;
- dependencies and compatibility assumptions;
- tests, results, failures, and known limitations;
- provenance, licenses, maintainers, and security boundaries.

This knowledge can be immediately useful through search, indexing, structured retrieval, and context assembly. **It does not automatically update a model's weights.**

Separately, suitable materials may be curated into evaluation or fine-tuning datasets **only after checking consent, provenance, licenses, privacy, quality, and contamination risks**. Evaluations must use held-out evidence to avoid simply measuring memorization of the project's own test solutions.

### 5.2 The system may improve itself, but not certify itself

UOE may propose changes to its own components. Changes should flow through reproducible builds, independent tests, policy gates, rollback, and review. The system must not be permitted to weaken its own security policy, invent passing test results, or promote unverified hypotheses into trusted knowledge.

## 6. Execution across desktops, servers, and remote resources

The same capability contract should be usable whether a provider runs on a workstation, server, VM, or remote machine. The planner would consider CPU/GPU architecture, I/O and display access, network availability, latency, bandwidth, data residency, privacy, energy/cost constraints, and licensing.

Local-first should be possible, not mandatory. Remote execution must be visible where location or data movement affects privacy, performance, cost, or policy. “One environment” is not a justification for quietly uploading local data.

Initial work may run on Linux, but the architecture should not assume Linux-specific concepts in its public semantic contracts unless the capability actually requires them.

## 7. Safety, correctness, and legal constraints

The following are proposed non-negotiable engineering boundaries:

- **Untrusted means untrusted:** downloaded executables, model output, retrieved documentation, generated code, and external service responses.
- **Static inspection cannot execute the inspected artifact.** Parsers should be resource-limited and fuzzed.
- **Separate understanding from authority:** the AI can recommend; independent mechanisms authorize and execute.
- **Privilege is explicit:** no ambient root access for AI; use typed capabilities, scoped permissions, and audited actions.
- **Isolation is risk-based:** unknown binaries generally require strongly isolated disposable VMs or equivalent protections; containers alone should not be assumed sufficient.
- **No hidden network or data exfiltration:** execution policy describes network, filesystem, devices, secrets, and resource budgets.
- **Reproducibility and rollback:** verified solutions identify exact versions and retain recovery paths.
- **License and rights awareness:** open-source UOE does not grant rights to redistribute proprietary OS frameworks, bypass licensing, or copy protected implementations.
- **Truthful compatibility reporting:** “launches,” “passes a smoke test,” and “matches the expected behavior” are different claims.

The project's AGPL-3.0-or-later licensing governs original covered UOE code; third-party runtimes, binaries, datasets, models, and services may have different licenses and restrictions.

## 8. Research hypotheses (to falsify)

**H1 — Requirements over OS labels:** A structured requirements model can identify viable execution strategies that OS labels alone would miss.

**H2 — Capability reuse:** Verified interface adapters and execution recipes can solve meaningful classes of repeated compatibility problems, not just one-off demonstrations.

**H3 — Living knowledge improves engineering:** Giving an AI access to versioned code/specification/test provenance improves troubleshooting correctness compared with access to source or generic model knowledge alone.

**H4 — Capability-first interaction adds value:** For selected user tasks, satisfying a capability contract can be more portable or resilient than selecting a fixed installed application.

**H5 — Deterministic controls remain compatible with autonomy:** The system can investigate and propose repairs without being given uncontrolled privileges.

Each hypothesis needs a baseline, a failure condition, reproducible evidence, and an explicit result. UOE should publish negative findings.

## 9. First vertical experiment: The Missing Capability

This experiment complements, rather than replaces, [RFC 0001](0001-artifact-execution.md). RFC 0001 supplies the inspector and plan model; this experiment tests whether the knowledge-and-adaptation loop is useful.

### 9.1 Controlled fixture

Create an intentionally small, redistributable Windows PE test application that calls a project-owned, versioned DLL interface. Ship its interface specification and independent reference tests; initially withhold the implementation from the repair agent.

On an isolated Linux test host, make the DLL unavailable so the program fails predictably. The test binary and its behavior must be created and licensed by the project. Do **not** start with third-party proprietary binaries.

### 9.2 Experimental sequence

1. **Observe:** record the initial failure, environment, executable digest, and test version.
2. **Inspect:** generate an artifact manifest and identify the missing interface.
3. **Plan:** select an available runner, such as Wine, and document its prerequisites.
4. **Investigate:** retrieve the interface contract and determine which functionality is absent.
5. **Propose:** let the AI generate a candidate compatible adapter, build configuration, and tests.
6. **Authorize:** require explicit approval to build and execute inside an isolated test VM with bounded resources and network restrictions.
7. **Verify:** independently test required behavior and failure modes, not only process exit status.
8. **Preserve:** store the reviewed adapter, manifest, recipe, provenance, limitations, and test evidence.
9. **Reuse:** on a clean second test host, attempt the same task using the verified record without repeating the original AI investigation.

A second variant should deliberately present an unsupported requirement and verify that the system reports the blocker instead of inventing success.

### 9.3 What constitutes success?

- The original fixture exhibits the expected initial failure.
- The generated manifest correctly identifies the missing dependency.
- The plan identifies a valid runner or explains why none is available.
- A human-authorized proposed adapter satisfies predetermined behavioral tests in isolation.
- The resulting solution can be reproduced on a second clean host.
- Every artifact and conclusion has a traceable source and version.
- Failed attempts and unsupported cases remain visible.

Track planning accuracy, false-confidence rate, behavioral test pass rate, number of human approvals, reproducibility across runs, resource use, and reuse effectiveness. **No single successful demo demonstrates universal compatibility.**

### 9.4 Baselines

Compare against (a) a knowledgeable developer following conventional documentation, and (b) an AI coding agent without the Capability Graph or persistent knowledge. This distinguishes architectural value from the general capability of a modern model to write code.

## 10. Proposed phases

**Phase A — Describe.** Complete the static inspector, evidence model, capability schema, and host description. No execution of inspected artifacts.

**Phase B — Plan.** Implement a deterministic adapter registry and execution planner for selected known runtimes.

**Phase C — Execute safely.** Build user-authorized isolated execution with audit records, policy, and repeatable fixtures.

**Phase D — Adapt and remember.** Run the Missing Capability experiment, integrate AI-assisted diagnosis, store provenance-backed solutions, and test reuse.

**Phase E — Expand.** Study end-user capability discovery, distributed resources, desktop/server workflows, broader formats, and additional host platforms.

Do not make a custom kernel, app store, GUI, or distributed scheduler prerequisites for Phase A.

## 11. Alternatives and trade-offs

**Keep applications as the primary abstraction.** This preserves well-understood UX and packaging. UOE could still add intelligent compatibility planning without making capability-first workflows central. This remains a viable outcome.

**Build another Linux distribution with an AI assistant.** Fast to prototype and easier to operate, but risks inheriting Linux-specific assumptions and treating AI as a shell wrapper. Could be a delivery format, not necessarily the architectural center.

**Use containers, VMs, and existing compatibility projects only.** Maximizes reuse and reliability; may be sufficient for many workloads. UOE must prove additional value beyond selecting among established tools.

**Always generate software on demand.** Attractive in principle but threatens reproducibility, latency, auditability, licensing clarity, and security. Prefer reuse of verified implementations and generation only when justified.

**Replace all traditional OS interfaces.** Discards decades of mature mechanisms and compatibility. Nothing in this RFC requires doing so.

## 12. Open questions for public discussion

1. What is the smallest useful, versioned definition of a capability?
2. When is a capability contract genuinely equivalent to an existing application's behavior?
3. Should the graph describe only verified local knowledge or also uncertain discoverable external providers?
4. How much autonomy can we grant before the security model becomes unacceptable?
5. Can the architecture operate usefully with no AI model, or with a very small local model?
6. How should the system resolve contradictory documentation, stale knowledge, and incompatible versions?
7. What is the appropriate trust and distribution model for community-submitted execution recipes?
8. Which traditional user interfaces, applications, and administrative controls should be preserved unchanged?
9. How do we measure usefulness against a normal Linux workstation plus Wine, VMs, package managers, and an AI coding assistant?
10. At what point would evidence justify calling UOE an operating environment rather than a set of interoperability tools?

## 13. Decision requested

**Do not adopt “applications are obsolete” as doctrine.** Adopt it as a serious hypothesis.

The immediate proposal is to:

- develop a minimal capability/requirement/evidence model alongside RFC 0001;
- define a deterministic, inspectable execution-planning interface;
- conduct the Missing Capability experiment with project-owned fixtures;
- publish quantitative results and failed attempts;
- revisit the architecture after real demonstrations rather than designing an entire OS in advance.

The guiding idea is to preserve the mechanisms that make computers dependable while questioning the conventions that unnecessarily restrict what they can do.

> **UOE should know what software needs, understand what the system can provide, and learn from every verified attempt to bridge the two.**
