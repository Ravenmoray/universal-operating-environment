# Architecture Overview (Draft)

```text
 Human / CLI / Desktop / API
             |
     Request and artifact
             |
  +----------v----------+
  | AI analysis/planning|   Model-neutral, optional in deterministic paths
  +----------+----------+
             |
  +----------v----------+
  | Policy/approval gate|   Deterministic enforcement
  +----------+----------+
             |
  +----------v----------+
  | Static inspector    |   Never executes input
  +----------+----------+
             |
  +----------v----------+
  | Execution planner   |   Evidence, constraints, supported backends
  +----+--------+-------+
       |        |
 Native runtime | Compatibility / emulation / VM
       +--------+
             |
       Isolated controller
             |
    Evidence and knowledge store
```

## Proposed interfaces

**Artifact Inspector:** untrusted bytes → format, architecture, dependencies, evidence, unknowns.

**Execution Planner:** manifest + host capabilities + policy + registered adapters → ranked strategies and unmet requirements.

**Runner Adapter:** declares supported formats/interfaces, platform requirements, sandbox expectations, legal prerequisites and invocation method.

**Execution Controller:** checks user authorization, applies isolation and limits, records outcome and supports recovery where feasible.

**Knowledge Store:** records tested facts, provenance, specifications, architectural choices, changes and incidents. It must distinguish verified evidence from model hypotheses.

## Trust model

The model cannot authorize its own execution or bypass deterministic policy. External artifacts and generated code are untrusted. Successful launch does not prove that an application behaves correctly.

## Implementation

Linux is the initial research host, not a permanent dependency. Rust is a candidate for safety-sensitive binary parsing; Python is an option for early AI tools. Interface contracts matter more than choosing a single language.
