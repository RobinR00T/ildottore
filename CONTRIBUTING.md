# Contributing to Il Dottore

Il Dottore is built **spec-driven** (Zynap methodology). Read `AGENTS.md` and
`docs/00-ai-build-playbook.md` before contributing - the contract is the source of truth.

## The two ways to contribute

### 1. Add a test technique (no core code - the common case)
This is the product's extensibility story (`docs/06`). To add an attack:
1. `dottore new-spec --family <family> --id <ID>` (scaffolds YAML + empty fixtures).
2. Fill `attack`, `expected_secure_behavior`, `evaluators`, and **golden `fixtures`**
   (`vulnerable` → scanner must flag; `hardened` → scanner must pass). Include a
   hallucinated-but-valid negative for PII/secret checks (`docs/11 §4`).
3. `dottore lint specs/` must pass (schema + policy + "fixtures prove detection").
4. Reference the id from a suite. Open a PR.

### 2. Change the engine (code)
1. Work against a unit **contract** in `specs/contracts/`. If none exists, propose one.
2. Follow the guardrails in `AGENTS.md §3` (security-by-default, permissive licenses only,
   zero tech debt, provably correct). A refactor and a feature never share a PR.
3. Every module ships tests satisfying `docs/07`. Coverage ≥ 85% core. `lint-imports` green.
4. Log any human-decision fork in the contract §9. Missing decision → an ADR (`docs/adr/`).

## Commits & PRs
- Conventional Commits; signed (GPG) where possible.
- Each PR updates docs touched + `CHANGELOG.md` + `docs/PROGRESS.md`.
- CI must be green (lint specs → tests → golden gate → coverage → self-scan).

## License
By contributing you agree your contributions are licensed under the **MIT License**. Only
permissive-licensed dependencies (MIT/Apache-2.0/BSD) are accepted.
