# Security Policy — Early Research

This repository is experimental. Do not use it to execute unknown software on personal or production machines.

- Static inspection must not execute the inspected artifact.
- An AI model's recommendation is not authorization.
- All binaries, retrieved docs, generated code and model outputs are untrusted.
- Execution must require explicit consent and a constrained environment with resource limits and auditable activity.
- Do not build compatibility techniques around credential theft, protection bypass, or license circumvention.
- No unrestricted root shell for AI agents.
- Test security boundaries independently from the reasoning model.

## Reporting

Please do not publish working exploits or sensitive findings in public issues. Maintainers should enable GitHub private vulnerability reporting before any execution engine is released.
