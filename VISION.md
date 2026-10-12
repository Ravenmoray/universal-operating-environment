# Vision and Project Charter

## Mission

Build a universal, AI-native computing environment that can understand, execute, adapt, maintain and evolve software across conventional operating-system boundaries.

## Founding proposition

**The computer should adapt to the software and its user, not require the user to adapt to the operating system.**

The system should understand its construction because its source, design decisions, specifications, tests and maintenance history are available as living knowledge. That knowledge can be retrieved during operation and, where licensing and privacy permit, curated into future training datasets.

## Core commitments

1. **Open forever:** project-original code is licensed AGPL-3.0-or-later, with transparent public development.
2. **Cross-platform ambition:** the host kernel is an implementation detail; initial Linux use must not become a permanent design constraint.
3. **Evidence-driven compatibility:** investigate requirements, select known runtimes first, and record what cannot be resolved.
4. **Model independence:** no mandatory proprietary AI service; local and remotely hosted models can be supported.
5. **Deterministic trust boundaries:** an AI may propose, but cannot bypass authorization, validation or isolation.
6. **Reproducibility:** every compatibility claim must have repeatable tests and documented assumptions.
7. **Knowledge continuity:** code, tests, dependencies, decisions, failures and successful solutions remain linked and reviewable.

## Not current promises

A novel kernel; guaranteed execution of all Windows/macOS software; permission to circumvent licensing; production-grade security; fully autonomous privileged AI administration.

## Open research questions

How accurately can binaries be understood without execution? How should missing interfaces be reconstructed safely? How can a system know its own behavior while keeping knowledge accurate? Which findings generalize across applications? What information may lawfully become training data?
