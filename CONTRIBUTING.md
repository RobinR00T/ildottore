# Contributing to Il Dottore

Il Dottore is built **spec-driven** (Zynap methodology). Read `AGENTS.md` and
`docs/00-ai-build-playbook.md` before contributing: the contract is the source of truth.

## The two ways to contribute

### 1. Add a test technique (no core code: the common case)
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

## Two rules about oracles, learned the expensive way

A spec's deterministic oracle decides what a customer reads in a report, so two rules are
enforced rather than suggested:

* **A marker may not be satisfied by an echo.** `dottore lint` refuses a `regex_presence`
  pattern that appears anywhere the target can read, and a `regex_absence` pattern taken from
  the request the spec sends, the text in its images included (`ORACLE_MARKER_IS_ECHOABLE`). A
  refusal quotes the request; if that satisfies your oracle, the oracle measures nothing. Key it
  on what only a secure (or only an exploited) target produces. Image text always counts as the
  request: a marker for reproduced untrusted content goes in `attack.carrier` or
  `setup.documents`. The same code refuses a spec scored by the `refusal` evaluator that puts
  one of its compliance tells anywhere in front of the target ("step 1", "step one", "here are
  the steps", "here's how to", the full list in `src/ildottore/shared/refusal_tells.py`): after
  a refusal, that evaluator reads them as instructions, quoted or not.
* **Removing a false positive must not cost a detection.** If you re-key an oracle, add the
  exploited replies it must still catch to `tests/battery/test_detection_not_regressed.py`. A
  false alarm is visible and arguable; a missed exploit is a clean report.

The full list of rules bought with defects is in `docs/00-ai-build-playbook.md` §0b.

## Mapping a spec to OWASP AISVS

AISVS lists controls, not attacks, so the optional `aisvs:` list on a spec claims one thing: a
**failure** of this spec is evidence that those controls are absent or ineffective. Add an ID
only when that sentence is true of your oracle, not when the spec is merely about the same
topic. A passing spec never verifies a control, and nothing you write should say it does
(clause A-28). `dottore lint` refuses an ID that is not in the standard and one that
`src/ildottore/shared/aisvs.py` classifies as out of reach or untested; if you believe the
classification is wrong, change it there, with the argument, and the pinned test with it.

## Commits & PRs
- Conventional Commits; signed (GPG) where possible.
- Each PR updates docs touched + `CHANGELOG.md` + `docs/PROGRESS.md`.
- CI must be green (lint specs → tests → golden gate → coverage → self-scan).

## License
By contributing you agree your contributions are licensed under the **MIT License**. Only
permissive-licensed dependencies (MIT/Apache-2.0/BSD) are accepted.
