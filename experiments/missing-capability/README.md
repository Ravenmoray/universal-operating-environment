# Experiment 002 — A real missing capability (native Linux)

**Status:** Controlled engineering fixture. A disclosed **nonblind AI-authored candidate** passes the ELF contract oracle. A separate trusted CI workflow now tests project-owned Windows PE execution under Wine; that run must be verified before making runtime claims.

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

## AI-authored candidate: what this establishes

[agent_candidate_v0.c](agent_candidate_v0.c) was drafted by ChatGPT (GPT-6) against the published UOE interface on October 12, 2026. The same reviewed, project-owned `verify.py` oracle evaluates it alongside the original reference and deliberately invalid providers.

This is **not a blind autonomous repair**: the source of the reference implementation and all existing public tests were accessible to the assistant beforehand. The evaluation can establish that the candidate satisfies the current known contract vectors, including buffer capacity, maximum input size, non-ASCII bytes, and a real client call. It cannot show how well an agent handles an unfamiliar undocumented third-party program.

For a meaningful blind evaluation, the agent must have access only to an explicitly scoped public contract and permitted artifacts; the test oracle and reference implementation should be withheld from the agent's accessible workspace and the results assessed independently. Even then, the evaluation needs multiple trials, a non-AI baseline, provenance, and an execution isolation design.

## Same capability, different executable formats

The experiment also includes a **Windows PE32+ x86-64 client** using `LoadLibraryA` / `GetProcAddress`, built from the same interface header as the Linux ELF client. The same provider source can be built into either a Linux `.so` or a Windows `.dll` with an explicit exported symbol.

On a Linux workstation with `gcc-mingw-w64-x86-64` and `binutils-mingw-w64-x86-64` installed:

```sh
python3 experiments/missing-capability/crosscheck_pe.py
```

The [Windows cross-compilation workflow](../../.github/workflows/cross-compile-pe.yml) verifies PE32+ headers, x86-64 architecture, DLL flag and exported symbol. **It does not execute the Windows program**, verify runtime behavior in Wine, or claim compatibility beyond static compilation. A separate [trusted Wine runtime workflow](../../.github/workflows/wine-fixture.yml) now **passes** for these project-owned binaries. The [verified run](https://github.com/Ravenmoray/universal-operating-environment/actions/runs/38324324417) used Wine 9.0 on an ephemeral Linux runner, detected a missing DLL and missing symbol, rejected a behaviorally incorrect provider, and validated three end-to-end inputs through the correct DLL **and** the disclosed, nonblind AI-authored DLL. Wine is a compatibility layer, **not a security sandbox**, and neither the native client nor this fixture exercises arbitrary third-party applications.

## Test status

The CI workflow is defined at [.github/workflows/missing-capability.yml](../../.github/workflows/missing-capability.yml). It runs on trusted pushes and maintainer-initiated manual runs only, **not on untrusted pull requests**, because it compiles and executes C source. The report includes exact compiled binary hashes, a host description, failures, bounded test counts and explicit limitations.

**Important:** The test executes local, project-owned compiled C. It does **not** provide a secure sandbox for running untrusted binaries. A future repair agent must use independent isolation and approval gates before executing generated code.

## Next steps

1. Introduce an AI-generated candidate adapter under the same *independent* oracle. Compare success, mistakes and repair cost with a non-AI baseline.
2. Collect signed attestations and source provenance; the current graph is only internally self-consistent.
3. Reproduce on an independently provisioned Linux host.
4. Repeat the Wine test on another independently provisioned host, then evaluate how secure disposable VMs could constrain untrusted and AI-generated code. This fixture currently runs only reviewed project-owned code on a trusted, ephemeral CI runner.
5. Compare the Capability Graph route against ordinary package/dependency resolution. If the graph brings no additional demonstrated value, simplify it.

Review [RFC 0002](../../docs/rfcs/0002-capability-centered-computing.md) and [Capability Graph issue #9](https://github.com/Ravenmoray/universal-operating-environment/issues/9).
