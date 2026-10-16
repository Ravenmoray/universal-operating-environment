# Execution authorization contract experiment

**Draft, data-only v0.5 proposal; not an executor or security boundary.**

Read the [proposal](../../docs/rfcs/proposals/execution-authorization-contract.md)
for the trust assumptions, decision table and unresolved controller gates.
`model.py` accepts already-decoded values and returns only denial or eligibility.
`example.json` is synthetic: its digests and trusted-context flags are placeholders,
not authenticated facts. Nothing here authenticates consent or starts a process.

From the repository root:

```sh
python3 -m unittest discover -s tests -p test_authorization_contract.py -v
```

The existing PR unit-test discovery includes these tests. No CLI, parser, graph,
workflow or demo behavior is changed. Tests do not prove real isolation, atomic
approval consumption, audit durability, revocation or safe artifact execution.
