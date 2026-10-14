# Universal Operating Environment (UOE)

**Any software. Any computer. One intelligent environment.**

> **Status:** Working v0.2 research prototype on `main`. Static inspection, digest-bound capability planning, and a controlled fixture demonstration are implemented. Universal execution and autonomous management remain goals.

UOE is an open-source effort to develop an AI-native operating environment that understands software requirements, selects or constructs execution strategies, and retains verified knowledge about how its components work.

A program labeled “Windows only” or “macOS only” presents a *compatibility problem to investigate*, not an automatic rejection. Some barriers may remain technically or legally unsolvable; UOE will state those limitations clearly.

## Principles

- **Universal execution as an objective:** identify ELF, PE, Mach-O, WASM and future artifact types; match them to native execution, translation, emulation or virtualization.
- **AI as a native capability:** model-neutral local and remote AI can inspect, propose and test changes using constrained tools.
- **Knowledge as infrastructure:** code, tests, interface contracts, architecture decisions, incident histories and documentation form an auditable, retrievable system model.
- **Solutions accumulate:** verified adapters and repairs can be reused and improved.
- **Human control:** permission gates, sandboxing, deterministic policy, provenance and reproducible tests come before autonomous changes.

## Begin here

- [Vision and charter](VISION.md)
- [Architecture overview](docs/architecture/overview.md)
- [RFC 0001 — Inspection and execution planning](docs/rfcs/0001-artifact-execution.md)
- [RFC 0002 — Capability-centered computing (draft)](docs/rfcs/0002-capability-centered-computing.md) · [Discuss](https://github.com/Ravenmoray/universal-operating-environment/issues/7)
- [Capability Graph model (draft proposal)](docs/rfcs/proposals/minimal-capability-graph.md) · [Research issue #9](https://github.com/Ravenmoray/universal-operating-environment/issues/9)
- [Capability Graph read-only experiment](experiments/capability-graph/README.md) · [Evidence and testing guide](docs/research/evidence-and-testing.md)
- [Working UOE CLI prototype, including v0.2 digest-bound capability planning](docs/research/working-prototype.md) — `inspect`, `plan`, and explicit controlled `demo`
- [Evidence-gated delivery plan from v0.2 to v1.0](docs/roadmap/v1-delivery-plan.md)
- [Experiment 002 — Missing capability: ELF execution, PE compilation, and controlled Wine research](experiments/missing-capability/README.md) · [AI evaluation methodology](docs/research/003-ai-adapter-evaluation.md) · [Follow-up issue #10](https://github.com/Ravenmoray/universal-operating-environment/issues/10)
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md) — humans and AI agents welcome
- [RFC process and proposal template](docs/rfcs/README.md)
- [Open invitation to challenge UOE](https://github.com/Ravenmoray/universal-operating-environment/issues/8)
- [Security](SECURITY.md)
- [Instructions for AI contributors](AGENTS.md)

## Current milestone

The CLI inspects ELF, PE, Mach-O and WASM headers without executing the input,
then proposes runtime and capability-provider candidates. The explicit `demo`
command runs only reviewed project-owned fixtures. Dependencies are currently
supplied through declarations; real binary import extraction is the next feature.

Start with the [working prototype guide](docs/research/working-prototype.md).
The [next delivery sequence](docs/roadmap/v1-delivery-plan.md#next-delivery-sequence)
keeps parser work, execution isolation and AI evaluation in separate testable steps.

Initial development host: Linux for practicality, **not** an architectural requirement.

## License

Original project code and documentation are offered under [GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later), unless a file explicitly states otherwise. Third-party components keep their own licenses. Review dependencies before including or distributing them.

See [Contributing](CONTRIBUTING.md) for participation expectations.
