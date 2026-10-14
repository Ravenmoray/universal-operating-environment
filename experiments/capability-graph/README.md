# Capability Graph v0 — Read-Only Research Prototype

**Experiment only. Not an accepted UOE architecture.** See [draft RFC](../../docs/rfcs/proposals/minimal-capability-graph.md) and [issue #9](https://github.com/Ravenmoray/universal-operating-environment/issues/9).

This deliberately tiny prototype exercises one hypothesis: explicit, evidence-bound claims can prevent a planner from conflating unsupported guesses with test-backed *candidates*.

It does **not** inspect binaries, run arbitrary programs, verify external claims, implement a compatibility layer, or establish that an application will work. The fictional demo evidence is **test data only**, not a real-world attestation.

## Commands (Python 3.10+, no third-party runtime dependencies)

From the repository root:

```sh
PYTHONPATH=experiments/capability-graph python -m uoe_graph validate experiments/capability-graph/fixtures/demo.json
PYTHONPATH=experiments/capability-graph python -m uoe_graph plan experiments/capability-graph/fixtures/demo.json --artifact artifact:demo --host host:linux
PYTHONPATH=experiments/capability-graph python -m unittest discover -s experiments/capability-graph/tests -v
```

The original commands now delegate to the single `uoe.graph` implementation; keep the full repository checkout when using this experiment. Both the experimental and integrated CLI suites exercise that shared implementation. The graph schema remains `0.1.0`, independently of the CLI version.

The validator enforces a minimal contract in Python. A JSON Schema is supplied to document the interchange format; future CI can validate both representations and compare behavior.

**Planning never invokes the program named in the graph.** No automatic downloads, installer execution, networking or privilege escalation.

## Intentionally missing features

Contract semantics, ABI/architecture constraints, true version negotiations, signed attestations, negative scoped findings, provider eligibility policies, sandboxing, executable inspection, production security, and persistent graph indexing.

## Next test

Compare this approach against a plain dependency inventory. If the graph does not measurably improve classification of candidate vs unresolved behavior, simplify it.
