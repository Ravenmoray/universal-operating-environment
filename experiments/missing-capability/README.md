# Experiment 002 — A real missing capability (native Linux)

**Status:** Controlled engineering fixture. No AI-generated repair or cross-OS compatibility yet.

This experiment moves UOE from a fictional Capability Graph into **actual compiled and executed project-owned software**.

A small Linux ELF client uses `dlopen()` to request a versioned text-transform interface from a shared library. The library is deliberately absent on the first attempt. The harness then compares a provider with the **wrong exported symbol**, a provider with the **right symbol but incorrect behavior**, and a correct reference implementation.

This shows an essential distinction: locating a library, loading it, and getting the intended behavior are **three different claims**.

## Reproduce

Requirements: **Linux**, Python 3.10+, a C compiler such as GCC or Clang, and no network connection. For security, only run this test with the project-owned, reviewed source. No third-party binaries or generated code are run.

From the repository root:

```sh
python3 experiments/missing-capability/verify.py
python3 experiments/missing-capability/verify.py --output /tmp/uoe-missing-capability-report.json
```

The harness compiles the client and providers in temporary directories, checks missing-library and missing-symbol error codes, rejects the incorrect provider with an external Python test oracle, tests the correct provider's C ABI behavior (including invalid inputs and buffer capacity), and recompiles and reruns the entire test in a fresh temporary directory.

It creates a small evidence graph compatible with the [existing static Capability Graph prototype](../capability-graph/README.md), then confirms the plan says `test_backed_candidate`. That graph is generated from the same local test, so it is **neither independently attested evidence nor a claim of general compatibility**.

## Behavioral contract

See [include/uoe_text_v1.h](include/uoe_text_v1.h). The provider exports `uoe_text_normalize_v1`. It prepends `UOE/1:`, uppercases ASCII a-z, and preserves other byte values, with specified error codes and an upper bound for input length.

The Python oracle is intentionally separate from the candidate provider source.

## Evidence hierarchy

| Observation | Valid conclusion | Invalid conclusion |
| --- | --- | --- |
| `dlopen` fails with code 40 | No loadable library was supplied in this test | The interface cannot be implemented |
| Library loads but symbol lookup fails (41) | This provider does not export required API | All similar providers are invalid |
| Wrong provider loads and returns normally | The program can start and call the symbol | The provider is behaviorally correct |
| Correct provider passes contract oracle | This implementation matches listed contract vectors on this host | Arbitrary Windows/macOS software is compatible |
| Second clean build directory passes | Results can be reproduced in a fresh directory | Independent machine replication, secure provenance, or AI repair |

## Test status

The CI workflow is defined at [.github/workflows/missing-capability.yml](../../.github/workflows/missing-capability.yml). The report includes exact compiled binary hashes, a host description, failures, bounded test counts and explicit limitations.

**Important:** The test executes local, project-owned compiled C. It does **not** provide a secure sandbox for running untrusted binaries. A future repair agent must use independent isolation and approval gates before executing generated code.

## Next steps

1. Introduce an AI-generated candidate adapter under the same *independent* oracle. Compare success, mistakes and repair cost with a non-AI baseline.
2. Collect signed attestations and source provenance; the current graph is only internally self-consistent.
3. Reproduce on an independently provisioned Linux host.
4. Port the same contract to a project-owned Windows PE/DLL fixture, then test it on Linux through Wine under proper isolation.
5. Compare the Capability Graph route against ordinary package/dependency resolution. If the graph brings no additional demonstrated value, simplify it.

Review [RFC 0002](../../docs/rfcs/0002-capability-centered-computing.md) and [Capability Graph issue #9](https://github.com/Ravenmoray/universal-operating-environment/issues/9).
