# Guidance for AI Contributors

Read README.md, VISION.md, SECURITY.md, relevant architecture documents and RFCs first.

1. Distinguish observed facts, inferences, hypotheses and unsupported assumptions.
2. Never call a platform restriction impossible without exploring its actual requirements; never guarantee compatibility without tests.
3. Do not run unknown artifacts without explicit isolation and authorization.
4. Do not grant yourself permissions, change policy gates, or silently modify privileged components.
5. Record evidence, versions, failed experiments and test outputs.
6. Keep model providers interchangeable and avoid dependencies on confidential training data.
7. Update specs, tests and docs alongside behavioral changes.
8. State honestly what is proposed rather than implemented.
