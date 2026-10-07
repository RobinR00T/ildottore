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
| OD-2 | u01 | scope.yaml signing | conductor | **checksum built, signing open:** an optional SHA-256 `checksum` sits behind a pluggable verifier and is verified only when present (`load_scope(require_checksum=False)`; no caller passes `True`). It lives in the file it protects, so it detects accidental change, not an editor who recomputes or deletes it: it is not a signature. Real signing (sigstore, or a keyed MAC whose key is not beside the file) remains open (audit D-01, SEC-11). Since 2026-10-05 every run records the scope digest, in the run store (each scope of the run, in order) and in every report (audit D-17) |
| OD-3 | u06 | judge model default + 2nd judge | human | **recorded default:** configured target model @ temp=0, 2nd-judge OFF in MVP-1 (revisit). **Code (audit F-25):** there is no default judge. A live run without `--judge` leaves `semantic_judge` unregistered, so it is `inconclusive: capability_unavailable`; offline, only the `vulnerable` and `hardened` mocks have a scripted scenario judge (`bare` and `comprehending` have none). The judge's first pass is at temperature 0, later self-consistency passes at 0.5. 2nd judge OFF holds |
| OD-4 | u10 | evidence at-rest encryption | conductor | **resolved:** plaintext + redaction MVP-1, pluggable cipher seam MVP-2 |
| OD-5 | u08/u09/u12 | adaptive planner default | conductor | **built; sign-off pending:** adaptive ordering is implied by `-sV` and `-A`; there is no `--adaptive` flag (audit F-6). `cli/run.py` sets `adaptive = fingerprint_first or deep`, so `--deep` also switches adaptive mode on, but with no fingerprint it keeps the declared mutator order. Adaptive only reorders a spec's mutators. (The first resolution, "OPT-IN (`--adaptive`); `-sV` fingerprints only", was never implemented; the user docs describe the code) |
| OD-6 | u07 | confidence threshold confirmed vs needs-review | conductor | **default 0.75**; band on raw float before rounding |
| OD-7 | u03/u13 | fixture location (inline vs sidecar) | conductor | **built inline only; sign-off pending.** The schema's `fixtures` takes `vulnerable` and `hardened` with `additionalProperties: false` and no path field; `testing/golden.py` calls sidecar resolution a future seam (audit F-25). "Schema supports both" was not true |
| OD-8 | u05 | translate mutator backing + languages | conductor | **default:** static offline phrase-map, `{es,fr,de,zh}` for MVP-1 |
| OD-9 | u09 | statistical-layer embedding source | conductor | **resolved:** response feature-vector NN (no heavy embedder dep) |
| OD-10 | u02 | pack signature enforcement timing | conductor | **resolved:** parse+record manifest now, enforce signatures MVP-2 |
| OD-11 | u13 | ship `DL-PII-ELICIT-001` in MVP-1? | **human** | **default (safe):** present but **disabled by default**, policy-gated (docs/11 DL4/DL5). From the CLI it cannot be enabled at all: no option loads a policy pack or sets the run's PII key (whether to add one is open) |
| OD-12 | u11 | `--unsafe-render` in MVP-1? | conductor | **decided:** present, hard-gated + banner; HTML evidence inline-masked + ref. **Built:** only the internal half. `config.SafetyFlags.unsafe_render` and the HTML template's switch (banner, unescaped reasoning) exist, off by default; no CLI flag sets them (`dottore run --unsafe-render` answers "No such option"), and no reporter reads `test_only` (audit F-25) |
| OD-13 | u14 | coverage-scope gate | conductor | **decided:** per-core-package ≥85%, aggregate reported. **Built:** an aggregate gate only (`--cov-fail-under=85` in `Makefile`, `ci.yml`, `audit.yml`); no per-package threshold is enforced (audit F-25) |
| OD-14 | program | ownership of suite/pack/test-plan schemas | ADR-0006 | **resolved:** Pydantic-first, generated by u00 |
| OD-15 | u01 | redactor entropy threshold | conductor | **resolved:** global interim, reuse u06 `secret_shape` policy when it lands. **Status:** `secret_shape` has landed with per-key-type entropy thresholds; the redactor still uses its own global one (`redactor.py`), so the "reuse" half is pending (audit F-25) |
| OD-16 | u06 | should an evaluator ABSTAIN on a reply that answers nothing? | conductor | **open, ADR-0007 proposes B (2026-09-23):** a text oracle scores an irrelevant reply in whichever direction its polarity points, so a canned non-answer comes back `fail` from `DOS-TOKEN-AMP-001` and `pass` from `MCP-TOOLPOISON-001`. Pinned by `tests/cli/test_scenario_mode.py`; the docstrings that claimed otherwise are corrected. A relevance precondition would fix it and is a design change, not a spec edit |
| OD-17 | u09/u08 | `baseline_resistance`: wire it, or drop it from the wire shape | conductor | **open, ADR-0008 proposes B-after-live-or-C (2026-09-23):** dead at BOTH ends. No fingerprint layer writes `guardrails["baseline_resistance"]` (`docs/10` says so) and nothing in `src/` reads `PlanSelection.baseline_resistance`, yet the field sits in the u00 shape and in two contracts as if it flowed. Honest options: populate it from a live run (it needs live data to mean anything, see `docs/16`) or remove it in the next contract revision. Not a unilateral call: it is a contracted shape |
| OD-18 | u08/u04 | a spec's `setup` (documents, mock tools, memory seed) never reaches a live target | conductor | **decided 2026-10-06 by the owner: C, A first (ADR-0009); A built for `type: model` targets (2026-10-06), B for deployed applications (2026-10-07): `seeded_setup` declares the seeded specs, a tool-name map and granted tools; an undeclared spec is `inconclusive: setup_not_seeded` with no send.** Before: ADR-0009 proposed C: B first, then A (2026-10-03): `_build_request` sends prompt, system prompt, sampling and media only (as built, checked 2026-10-04: multi-turn specs also send their turns as messages, the multi-identity sweep sends the identity, and `setup.system_prompt` is the system prompt; the rest of `setup` (documents, mock tools, memory seed) still never goes out); 32 of 75 specs depend on setup, 26 of them go out on a fully capable target, and `tool_call` flags a real target's own tools as unauthorized. B = operator declares seeded setup plus a tool-name map, unseeded specs `inconclusive`; A = deliver setup in-band with a tool loop. Before the live validation |
| OD-19 | u06/u08 | `evaluator_logic: weighted` is declared by 33 specs and implemented in no run path | conductor | **open, ADR-0010 proposes B (2026-10-03):** the runner never reads the field (a deterministic fail decides), the lint fixture engine treats it as `all_pass` (any failing evaluator decides, as for every `evaluator_logic` value there), and the vote in `evaluators/combine.py` is called by neither. B = document the runner's rule as the semantics and rename the value; A (implement the vote) would let a judge PASS outvote a leaked canary. **Amended the same day:** a judge-only fail is confirmed and gates CI today (precisely, checked 2026-10-04: when the judge says fail on every attempt of one mutation variant, with at least 2 attempts per variant, or on every attempt of the spec below that, and mean confidence at or above the threshold); the ADR now recommends it be needs-review |
| OD-23 | u09/u12 | an environment failure on one `-sV` probe stops the whole run | human | **open, built reversibly (2026-10-07, A-35):** one reply over 4 MiB or undecodable stopped `run -sV` / `-A` with exit 3 before any attack (1 request), while without `-sV` it failed one attempt. Built (A): a reply that comes back refused (env, `retryable = False`, by the attack phase's own predicate) fails that probe; its layer gives no evidence from it; the fingerprint is built from the rest; stderr and the fingerprint line say so; the run goes on. A probe that gets no answer at all (5xx, 429, timeout, refused connection, after the retries) still stops the pass with its cause, as before. Alternatives: isolate every env failure as the attack phase does (built first, withdrawn: a target that never replies cost 25.5 minutes of probing against 92 s, and `dottore fingerprint` exited 0 on a closed port; it would need a breaker and the probe pass bound by `--timeout`/`--budget-wall`), stop the pass on any of them as before (B), or drop the fingerprint and run in declared order (C). A 200 that is not JSON still stops the pass (OD-21) |

## Assurance clauses A-1..A-30 (added 2026-09-22, from the audit series)

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
| A-24 | u12 | a resume is bound to its campaign: battery, target, route, sample size and money |
| A-7..A-11 | u12 | no-send holds under combination, printed numbers are computed by the working code, operational failure exits 3, a resume is bound to its target, a ceiling binds every request |
| A-26 | u11 | a gap says which kind it is (roadmap, out of reach, or by design), with the reason |
| A-12..A-15 | u11 | no denominator over survivors, uncounted values are reported, figures carry their edition, machine formats carry the run state |
| A-25 | u09 | the ordering -sV produces is measured in CI, not just executed |
| A-35 | u09 | a probe whose reply comes back refused (an environment failure a retry would repeat, by the attack phase's own predicate) costs that probe, not the pass: no evidence from it, never read as an empty reply, no refusal gets past the constant-target check and a pass with a refused attributing reply is never called constant, it never names more than the same probes answered with an empty reply (12,276 passes measured; against a full pass it can still break a tie), every other probe still sent, the failure recorded by class and said on stderr; a probe that gets no answer still stops the pass |
| A-16, A-23 | u10 | a store path resolves inside the store root, recognition traffic is stored apart from the attempts |
| A-27 | u02 | an oracle may not be satisfied by an echo of what the spec itself sent |
| A-28 | u02 | a control framework (AISVS) is mapped by falsification, and a mapping cannot contradict its own classification |
| A-17 | u02 | every framework field is validated, membership where it drives a denominator |
| A-18..A-20 | u01 | authorization is reachability, schemes are allowlisted, one answer per target |
| A-29..A-30 | u01 | a gate keys on what a spec cannot opt out of; the allowlist authorizes the path the client sends, on its port, refuses separator encodings, and a fleet's judge comes only from the fleet file |
| A-21..A-22 | u14 | a test asserts the claim against the real collaborator, and is deterministic |

The pattern under most of them, worth stating once: **something counted or omitted what did
not belong to it**, and the count was computed correctly and then dropped exactly where a human
looks. Two of the clauses exist because the fix for an earlier one reintroduced the same shape
one layer down, which is why auditing a fix is scheduled work and not a courtesy.

## Merge gate

After all units DONE: run the full `docs/07` taxonomy + import-linter + self-scan on the
**combined** tree (not per-unit only). Green = MVP‑1 candidate → Stage 6 human finish.
