# Experiment 003 — AI-Assisted Adapter Development

**Status:** Nonblind AI-authored implementation verified; blind autonomous evaluation is future work  
**Date:** 2026-10-12  
**Discussion:** [Issue #10](https://github.com/Ravenmoray/universal-operating-environment/issues/10)

## Research question

Can an AI agent inspect a failed program, infer a missing capability, implement the required interface, and demonstrate independently evaluated behavioral compatibility? Does the Capability Graph reduce incorrect candidate selection, human intervention, or time to solution compared with conventional tooling?

A successful function implementation by an AI is **not yet** proof of autonomous repair. These are distinct milestones.

## Observed preliminary result

An AI-authored C adapter was checked into the repository at [agent_candidate_v0.c](../../experiments/missing-capability/agent_candidate_v0.c). It implements the project's published `uoe_text_normalize_v1` contract. The existing [verify.py](../../experiments/missing-capability/verify.py) harness compiles this candidate and checks its behavior with the original client and a separate Python oracle.

The test run [38323963232](https://github.com/Ravenmoray/universal-operating-environment/actions/runs/38323963232) completed successfully:

- **17 oracle assertions** per build for the candidate, including bounded input lengths, exact buffer capacity, non-ASCII bytes, invalid inputs, and client output.
- Two clean build directories were evaluated on the same CI host.
- The candidate's source and compiled binary hashes are included in the logged report.

**Important provenance:** ChatGPT (GPT-6) authored the candidate with the public repository available. The reference implementation and its tests were not withheld. This was not an independent, blinded, repeated-trial experiment, and there is no claim of AI discovering an unknown proprietary API or autonomously modifying a live operating system.

## Blinded trial proposal

A proper agent evaluation should maintain separately controlled roles:

1. **Benchmark preparer:** create several versioned project-owned interfaces and clients, together with independent *private-to-the-evaluated-agent* behavioral tests and known correct reference implementations.
2. **Agent workspace:** expose only the allowed artifact, public contract and relevant diagnostics. Do not expose reference source or the hidden oracle. Record accessible input hashes, model/provider/version, time and resource budget, prompts and permitted tool calls.
3. **Proposal phase:** agent writes a candidate implementation and a reproducible build plan. No bypass of a deterministic approval gate.
4. **Evaluation phase:** execute only approved, reviewed candidate code in a disposable VM with no secrets, restricted network and resource limits; independently run immutable held-out oracle tests.
5. **Evidence phase:** record build status, behavioral pass rate, attempted repairs, tool use, cost, elapsed time, failures, and any policy violations. Keep the outcome even on failure.
6. **Reuse phase:** present a clean agent or machine with the **verified resulting solution and signed provenance**, then measure whether it can reproduce or apply the fix without rediscovering it.

## Baselines

Use at least two:

- conventional human/dev instructions following the same allowed specification;
- an AI coding agent using the same model/budget but **without** Capability Graph retrieval.

Optionally include a standard package-manager/Wine/VM workflow where the candidate requires it. Without baselines, success can be attributable to the general model or an easy fixture rather than any UOE architecture.

## Measurements

Measure implementation correctness, unexpected behavior, assertion coverage, end-to-end execution, reproducibility across independently provisioned machines, first-try and eventual success rates, cost, human intervention, and false confidence.

Track **failure categories**: incorrect interface inference, missing imports, ABI mismatch, compile failure, improper buffer behavior, incorrect output, environment incompatibility, policy breach, and lack of evidence.

## Integrity controls

- Do not expose the test oracle to the agent being evaluated.
- Run candidate code only in independently controlled, restricted execution facilities, never with GitHub secrets or maintainer credentials.
- Evaluate against a predetermined contract, not a test suite invented only after a particular candidate succeeds.
- Use immutable artifact digests and timestamps. Mark synthetic evidence as synthetic.
- Never call a simple compilation, export presence, or success exit code “proof of compatibility.”
- Open-source benchmarks inevitably become visible to future models; prevent test contamination by rotating or freshly generating withheld tasks and checking access scope.
- License all benchmark fixture code deliberately; follow third-party licensing restrictions.

## Next engineering decisions

The public repository can host **harness source and representative tests**, but cannot be assumed to hide evaluation fixtures from code-review agents that have access to the full public repository. For genuinely blinded evaluation, split agent and evaluator permissions and isolate the evaluator's reference/held-out tests until a trial concludes.

This design is intended to be reviewed publicly and revised before calling any result an autonomous-repair benchmark.
