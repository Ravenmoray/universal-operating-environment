# UOE RFC process

**RFC = Request for Comments.** RFCs are public proposals for significant changes to the Universal Operating Environment. They are a mechanism for discussion, not a shortcut to project authority.

UOE invites **humans and authorized AI agents** to identify assumptions, propose new approaches, document experiments, and challenge existing designs.

## Choose the smallest useful channel

| Contribution | Best starting place |
| --- | --- |
| Open-ended question, alternative, or architectural debate | [GitHub Discussions](https://github.com/Ravenmoray/universal-operating-environment/discussions) **once enabled**; until then use a research issue |
| Research question, test idea, or proposed RFC | [RFC proposal issue](https://github.com/Ravenmoray/universal-operating-environment/issues/new/choose) |
| Detailed design or substantial architectural change | Draft RFC through a pull request |
| Specific code change or documentation fix | Pull request, linked to any relevant issue |
| Security vulnerability | Private report; follow [SECURITY.md](../../SECURITY.md), not public discussion |

**A reader of this repository is not automatically authorized to post.** Agents need explicit permission from their operator and a GitHub identity with write or issue/PR privileges. When they cannot post, they should prepare a clear Markdown proposal for a person to submit.

## RFC life cycle

1. **Discover.** Read the [vision](../../VISION.md), [architecture](../architecture/overview.md), existing RFCs, issues and discussions. Avoid duplication.
2. **Frame a question.** Open an RFC proposal issue. State the problem, why it matters, alternatives, evidence, unknowns, and what would falsify the proposal.
3. **Draft.** Copy [TEMPLATE.md](TEMPLATE.md) into `docs/rfcs/proposals/<descriptive-slug>.md` on a branch or fork; submit a pull request referencing the issue. Do not rename an existing RFC.
4. **Review in public.** Invite counterexamples, security and license review, alternative designs, and reproducible experiments. Respond to substantive objections, not just votes.
5. **Record a decision.** Maintainers record an explicit status and rationale. A merged document can remain **Draft** or **Under Review**; merging a PR alone never signals technical acceptance.
6. **Validate and revise.** Tests and observed evidence may overturn previously accepted assumptions. File a new issue or an amendment RFC; preserve historical reasoning and traceability.

### Status vocabulary

- **Draft** — open idea, not a project commitment.
- **Under Review** — enough detail to request focused technical feedback.
- **Accepted** — explicit, recorded maintainer decision; may still need implementation.
- **Rejected** — considered and declined, with reason.
- **Superseded** — replaced by a linked later decision.
- **Withdrawn** — proposer withdrew, with history preserved.

Only maintainers should assign a stable sequential RFC number. New authors should use the `proposals/` folder first. Existing numbered RFCs 0001 and 0002 are **Draft**, not accepted.

## What makes a good proposal?

Describe the **problem before the solution**. Explain the impact on UOE's universal-execution goals; identify dependencies, trust boundaries, portability concerns and possible licensing restrictions; name at least one credible alternative; show what can be measured. An unexpected result or failed experiment can be valuable evidence.

Do not claim that unknown binaries run safely, that generated shims are correct because they compile, or that model-generated explanations are established facts.

## AI contributor expectations

- Read [AGENTS.md](../../AGENTS.md) and [CONTRIBUTING.md](../../CONTRIBUTING.md).
- Obtain permission before creating public issues, comments, PRs, or pushes. Use only credentials granted to your account or configured bot.
- Disclose substantial AI assistance and the accountable submitter if known. Never impersonate contributors, reviewers, or maintainers.
- Use evidence and reproducible tests; disclose uncertainty and distinguish original work from cited sources.
- Avoid automated discussion loops, issue floods, repetitive suggestions, and irrelevant generated material.
- Never autonomously merge an RFC or modify project security/governance on the strength of your own analysis.

## Existing proposals

- [RFC 0001 — Artifact Inspection and Execution Planning](0001-artifact-execution.md) — **Draft**
- [RFC 0002 — Capability-Centered Computing](0002-capability-centered-computing.md) — **Draft**, [discussion issue #7](https://github.com/Ravenmoray/universal-operating-environment/issues/7)
- [Proposal — Minimal Capability Graph](proposals/minimal-capability-graph.md) — **Draft**, [research issue #9](https://github.com/Ravenmoray/universal-operating-environment/issues/9)

- [Proposal — Exact-scope execution authorization](proposals/execution-authorization-contract.md) — **Draft**, data-only v0.5 contract for [issue #15](https://github.com/Ravenmoray/universal-operating-environment/issues/15)

We want a repository that is **easy for autonomous systems to understand** while remaining accountable to human operators and maintainers.
