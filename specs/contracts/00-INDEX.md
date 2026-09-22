# 00-INDEX: Contract master index & program ledger

Stage-2 (Specify) output. The authoritative unit list, **dependency DAG**, **single-executor
ledger** and **open-decisions rollup** for MVP‑1. The PITV orchestrator (`docs/00 §3-§4`)
schedules from this graph: independent chains parallel, dependents gated, same-file units
serialized. **One owner per unit, no double-edits.**

## Units

| Unit | Owns (src/ildottore/…) | Depends on | Wave |
|------|------------------------|------------|------|
| `u00-shared-models` | `shared/` (models, protocols, enums) |: | W0 |
| `u01-config-scope-policy` | `policy/`, `config.py`, `redactor.py` | u00 | W1 |
| `u02-spec-registry-linter` | `registry/`, `cli/lint.py` | u00 | W1 |
| `u05-prompt-mutator` | `mutators/` | u00 | W1 |
| `u07-scoring` | `scoring/` | u00 | W1 |
| `u03-mock-target-golden-harness` | `adapters/mock.py`, `testing/golden.py` | u00, u01 | W2 |
| `u04-target-adapters` | `adapters/{base,openai,anthropic,rest}.py` | u00, u01 | W2 |
| `u10-evidence-run-store` | `store/` | u00, u01 | W2 |
| `u06-evaluators` | `evaluators/` | u00, u04 | W3 |
| `u09-fingerprint-engine` | `fingerprint/` | u00, u04 | W3 |
| `u08-execution-engine` | `core/` (runner, planner, budgets) | u00,u01,u02,u04,u05,u06,u07 | W4 |
| `u11-reporting` | `reporting/` | u00, u07, u10 | W4 |
| `u13-attack-specs-battery` | `specs/attacks/*`, `specs/suites/*`, fixtures | u02, u03 | W4 |
| `u12-cli` | `cli/` (composition root, commands) | all above | W5 |
| `u14-self-validation-ci` | `tests/`, `.github/workflows/`, `.importlinter` | all above | W5 |

## Dependency DAG (build order)

```
W0: u00
W1: u01  u02  u05  u07                 (need only u00)
W2: u03  u04  u10                       (u04 → unlocks u06,u09; u01 shared → serialize policy edits)
W3: u06  u09                            (need u04)
W4: u08  u11  u13                       (u08 gates on the whole middle tier)
W5: u12  u14                            (integration + validation last)
```

Parallel chains per wave run concurrently; a unit starts only when every dep is DONE.

## Shared interface registry (serialize DECISIONS, not just files)

The stable contracts every unit codes against: changing any is a program-level open decision,
not a unit-local choice:

- `shared.models`: `AttackSpec, Target, Capabilities, TestRun, Attempt, Verdict, Finding,
  Evidence, RiskScore, ModelFingerprint, TestPlan` (must validate vs `schemas/`). **`TestPlan`
  + `ModelFingerprint` are shared wire shapes owned by u00** (ADR-0006). The **plan-builder is
  u08-only** (`core/planner.py`); u09 produces `ModelFingerprint.capability_guess` and feeds it.
- **Schemas are Pydantic-first** (ADR-0006): only `attack-spec.schema.json` is hand-authored;
  `suite`/`pack`/`test-plan` schemas are generated from the models by `u00` (`schema_export.py`).
- `requires` (spec-level) ⊇ `Capabilities` (target flags) + `{system_prompt, seed}`: related
  but distinct vocabularies; capability-gating maps between them.
- `shared.protocols`: `TargetAdapter, Evaluator, Mutator, RiskScorer, EvidenceStore, RunStore,
  Reporter` (`docs/01 §3`).
- Verdict polarity is fixed repo-wide: `pass` = secure, `fail` = exploited (`docs/04`).

## Program ledger: open decisions (rolled up from unit §9)

| OD | Unit | Decision | Owner | Status |
|----|------|----------|-------|--------|
| OD-1 | u04 | logprobs → common `TokenLogprob` | ADR-0005 | **resolved** (ADR-0005) |
| OD-2 | u01 | scope.yaml signing | conductor | **resolved:** SHA-256 checksum now behind pluggable verifier; sigstore later |
| OD-3 | u06 | judge model default + 2nd judge | human | **default:** configured target model @ temp=0, 2nd-judge OFF in MVP-1 (revisit) |
| OD-4 | u10 | evidence at-rest encryption | conductor | **resolved:** plaintext + redaction MVP-1, pluggable cipher seam MVP-2 |
| OD-5 | u08/u09/u12 | adaptive planner default | conductor | **resolved:** OPT-IN (`--adaptive`); `-sV` fingerprints only |
| OD-6 | u07 | confidence threshold confirmed vs needs-review | conductor | **default 0.75**; band on raw float before rounding |
| OD-7 | u03/u13 | fixture location (inline vs sidecar) | conductor | **resolved:** schema supports both, runner resolves inline-first |
| OD-8 | u05 | translate mutator backing + languages | conductor | **default:** static offline phrase-map, `{es,fr,de,zh}` for MVP-1 |
| OD-9 | u09 | statistical-layer embedding source | conductor | **resolved:** response feature-vector NN (no heavy embedder dep) |
| OD-10 | u02 | pack signature enforcement timing | conductor | **resolved:** parse+record manifest now, enforce signatures MVP-2 |
| OD-11 | u13 | ship `DL-PII-ELICIT-001` in MVP-1? | **human** | **default (safe):** present but **disabled by default**, policy-gated (docs/11 DL4/DL5) |
| OD-12 | u11 | `--unsafe-render` in MVP-1? | conductor | **resolved:** present, hard-gated + banner; HTML evidence inline-masked + ref |
| OD-13 | u14 | coverage-scope gate | conductor | **resolved:** per-core-package ≥85%, aggregate reported |
| OD-14 | program | ownership of suite/pack/test-plan schemas | ADR-0006 | **resolved:** Pydantic-first, generated by u00 |
| OD-15 | u01 | redactor entropy threshold | conductor | **resolved:** global interim, reuse u06 `secret_shape` policy when it lands |

## Assurance clauses A-1..A-23 (added 2026-09-22, from the audit series)

Eight adversarial audits over 2026-09-20..22 found defects that a green suite, a clean linter
and four kept import contracts could not see, because every one of them is a claim the code
makes about itself: a probe that says it is benign, a count that says it is the count, a
denominator that says what it is over, an exit code that says what kind of failure it was.

Each finding is written into the owning unit's §7 as a numbered **A-n** clause with the failure
it came from, so the criterion is checkable and the reason it exists is not lost:

| Clause | Unit | The claim it makes checkable |
|---|---|---|
| A-1..A-3 | u09 | benign is a predicate over the carrier, the probe discriminates, declared cost equals real cost |
| A-4..A-6 | u08 | the wall budget measures time, every send passes the rate gate, a halt says why |
| A-7..A-11 | u12 | no-send holds under combination, printed numbers are computed by the working code, operational failure exits 3, a resume is bound to its target, a ceiling binds every request |
| A-12..A-15 | u11 | no denominator over survivors, uncounted values are reported, figures carry their edition, machine formats carry the run state |
| A-16, A-23 | u10 | a store path resolves inside the store root, recognition traffic is stored apart from the attempts |
| A-17 | u02 | every framework field is validated, membership where it drives a denominator |
| A-18..A-20 | u01 | authorization is reachability, schemes are allowlisted, one answer per target |
| A-21..A-22 | u14 | a test asserts the claim against the real collaborator, and is deterministic |

The pattern under most of them, worth stating once: **something counted or omitted what did
not belong to it**, and the count was computed correctly and then dropped exactly where a human
looks. Two of the clauses exist because the fix for an earlier one reintroduced the same shape
one layer down, which is why auditing a fix is scheduled work and not a courtesy.

## Merge gate

After all units DONE: run the full `docs/07` taxonomy + import-linter + self-scan on the
**combined** tree (not per-unit only). Green = MVP‑1 candidate → Stage 6 human finish.
