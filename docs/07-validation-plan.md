# 07 — Validation plan (the broad self-testing phase)

**Requirement:** a *very broad* validation of the scanner's own code and detections. A
security scanner that produces false positives/negatives is worse than none. This plan
validates **the scanner**, not the targets.

## 0. Two things we validate

1. **The scanner code works** (engineering correctness).
2. **The scanner's detections are correct** — it flags truly-vulnerable behavior and passes
   truly-safe behavior (detection accuracy: FP/FN rates).

## 1. Test taxonomy (every layer covered)

| # | Layer | Type | What it proves | Tooling |
|---|---|---|---|---|
| 1 | Models/specs | **Schema validation** | every YAML spec/suite/target/pack validates | JSON Schema + Pydantic |
| 2 | Spec linter | **Static checks** | no id collisions, valid framework maps, `test_only` on flagged families, evaluator types exist | custom + CI |
| 3 | Units | **Unit tests** | each function/class in isolation; coverage gate ≥ 85% core | pytest |
| 4 | Mutator | **Property-based tests** | mutations are deterministic given a seed; preserve intent; round-trip where reversible | Hypothesis |
| 5 | Adapters | **Contract tests + recorded cassettes** | request bytes match provider contract; allowlist enforced; retries/timeouts/rate-limit behave; **no live keys in CI** | pytest + VCR/cassettes |
| 6 | **Golden targets** | **Detection-accuracy tests** | scanner FLAGS the vulnerable fixture and PASSES the hardened fixture, per spec | MockTarget + fixtures |
| 7 | Evaluators | **Labeled precision/recall** | each evaluator's P/R vs a labeled corpus stays above threshold | pytest + labeled data |
| 8 | Judge | **Robustness / injection tests** | a target that injects the judge cannot flip a verdict (→ `inconclusive`/`judge_compromised`) | adversarial fixtures |
| 9 | Determinism | **Replay tests** | same suite+target+seed → same finding set; sampling params recorded | pytest |
| 10 | Scoring | **Property tests** | monotonicity (↑impact ⇒ ↑risk), confidence never changes band, banding boundaries | Hypothesis |
| 11 | Reporting | **Snapshot + schema tests** | JSON matches schema; SARIF validates against SARIF 2.1.0; JUnit valid; HTML renders; secrets masked | snapshot + validators |
| 12 | CLI/API | **E2E tests** | `run --suite … --target mock --fail-on high` exits with correct code + artifacts | subprocess/httpx |
| 13 | Availability specs | **Budget/guardrail tests** | DoS specs never exceed token/request/time caps; scanner can't self-DoS | pytest + fake clock |
| 14 | Boundaries | **Import-linter contract** | package dependency rule (`docs/01 §2`) holds | import-linter |
| 15 | Safety | **Negative tests** | out-of-scope target refused; dangerous payload without `test_only` rejected; sensitive tool never really executes | pytest |
| 16 | Meta / regression | **Golden-run snapshots** | a frozen reference run produces a stable report (diff-reviewed) | snapshot |
| 17 | Self-scan | **Dogfooding** | run the scanner against the scanner's own LLM-using code (the judge) and gate on findings | CI job |
| 18 | Metamorphic | **Metamorphic tests** | semantics-preserving mutation of a payload must not change the verdict; a strictly-stronger attack must not *reduce* detection | pytest |

## 2. The golden-target harness (centerpiece — layer 6)

- `MockTarget(scenario)` returns deterministic canned responses. Scenarios are declared in
  each spec's `fixtures`:
  - `fixtures.vulnerable`: a response that *does* exhibit the insecure behavior → scanner
    **must** produce a `fail` finding.
  - `fixtures.hardened`: a response that refuses/ignores the attack → scanner **must** `pass`.
- CI runs every spec against both fixtures. This is the FP/FN gate: a spec whose fixtures
  don't produce the expected verdicts **cannot be merged** (ties into `docs/06`
  "self-proving specs").
- Aggregate metric published per build: **spec detection accuracy** = (correct verdicts on
  fixtures) / (total fixtures), plus per-family FP and FN rates.

## 3. Detection-accuracy targets (release gates)

| Metric | Gate |
|---|---|
| Golden-fixture verdict accuracy (all specs) | 100% (fixtures are ground truth) |
| Evaluator precision (per evaluator, labeled corpus) | ≥ 0.90 |
| Evaluator recall (per evaluator, labeled corpus) | ≥ 0.85 |
| Judge injection-resistance (adversarial suite) | 0 verdict flips (all → inconclusive/blocked) |
| Determinism replay | 100% stable finding set at fixed seed |
| Core coverage | ≥ 85% |

## 4. Test data & fixtures

- `tests/fixtures/vulnerable/` and `tests/fixtures/hardened/` mirror the attack families.
- `tests/fixtures/labeled/` = evaluator precision/recall corpus (positives, negatives, hard).
- `tests/fixtures/adversarial-judge/` = target outputs that try to prompt-inject the judge.
- `tests/cassettes/` = recorded provider interactions (secrets scrubbed) for adapter contract
  tests. **No real API keys ever committed or used in CI.**

## 5. CI pipeline (ordered gates)

1. `lint specs/` (schema + static). 2. import-boundary contract. 3. unit + property.
4. adapter contract (cassettes). 5. **golden-target detection-accuracy** (hard gate).
6. evaluator P/R gate. 7. judge-robustness gate. 8. determinism replay. 9. reporting/schema
(SARIF/JUnit valid). 10. E2E CLI. 11. self-scan (SARIF) — fail on new high/critical.
12. coverage gate. Nightly: full regression golden-run snapshot + metamorphic suite.

## 6. Manual / exploratory validation (before each MVP sign-off)

- Run the full OWASP suite against 1 real model per provider (staging keys, in-scope) and
  have a human review a sample of findings + evidence for plausibility.
- Model-comparison report reviewed for sanity (do the relative results match expert intuition?).
- Red-team the scanner: deliberately try to make it (a) miss a real issue, (b) fire on a safe
  model, (c) inject its judge. File any success as a spec/evaluator gap.
