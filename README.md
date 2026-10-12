# Universal Operating Environment (UOE)

**Any software. Any computer. One intelligent environment.**

> **Status:** Research proposal. Universal execution and autonomous management are goals, not implemented capabilities.

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
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Instructions for AI contributors](AGENTS.md)

## First milestone

Design an inspector that **does not execute** its input. It will output a versioned, structured manifest of format, architecture, dependencies, evidence and unknowns. The next component, a deterministic planner, identifies potential execution backends.

Initial development host: Linux for practicality, **not** an architectural requirement.

## License

Original project code and documentation are offered under [GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later), unless a file explicitly states otherwise. Third-party components keep their own licenses. Review dependencies before including or distributing them.

See [Contributing](CONTRIBUTING.md) for participation expectations.
