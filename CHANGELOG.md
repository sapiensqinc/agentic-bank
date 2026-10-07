# Changelog

## [0.0.2] - 2026-10-07

### Security
- Patch AJV to 8.18.0 and update compatible HTTP/tooling dependencies.
- Move the test runtime and coverage provider together from vulnerable Vitest 3 to 4.1.11, retaining all existing test and coverage gates.

### Validation
- Migrate two existing unreachable-guard coverage hints to Vitest 4 syntax, retaining 100% thresholds. Explicitly test that zero or duplicate consumption records are rejected by the schema gate.
- Frozen pnpm installation, types, tests, coverage, web build and deterministic sandbox conformance/evaluation. No model, banking or payment API calls.
