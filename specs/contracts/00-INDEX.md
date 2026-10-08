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
| OD-22 | u02/u12 | a spec regex that does not compile: refuse the run, or skip only that spec; and its lint code | human | **open, built reversibly (2026-10-07, A-33):** the run is refused before anything is sent, as for a spec file that fails to load (F-10), and lint reports `EVALUATOR_MISCONFIGURED`. Alternatives: skip that spec as `inconclusive` with nothing sent and no coverage credit (like `setup_not_seeded`), and a code of its own (`INVALID_PATTERN`) |
| OD-30 | u01 | flow nesting under the depth limit still costs per token | human | **decided 2026-10-08 by the owner: A, to be built on its own branch** (opened 2026-10-07): PyYAML's pure-Python scanner walks one possible key per open flow level on every token, so a document nested close to the limit is accepted at a few times the cost of a flat one (A-52 refuses only what passes it). A: a lower limit for flow nesting only (the repository's 130 YAML files nest at most 2 flow levels, 6 of any style); B: libyaml's scanner, whose composer is C, so the per-node checks of `safe_yaml` would move to its events; C: leave it: each walk is bounded at about 100 keys, about three passes over them per token |
| OD-33 | u01/u12 | fleet ids that differ only by case: refuse everywhere, or only where the file system folds case | conductor | **decided 2026-10-07 by the conductor, confirmed by the owner the same evening, built (A-56):** refused on every file system. `dottore fleet` writes one `target-<id>.yaml` per target, and on a case-insensitive file system `Prod` and `prod` were one file: the second overwrote the first, the command exited 0, and the printed `dottore run` refused an id the fleet declared once. Everywhere is portable and the simplest rule (`run` compares report paths case-folded everywhere); the cost is that a fleet with `Prod` and `prod` is refused on Linux too, and so is a judge spelled as a target only up to case, which worked. The alternative not taken: probe the `--out` file system |

## Assurance clauses (added 2026-09-22, from the audit series)

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
| A-45 | u12 | a target file's `capabilities` or `sampling_defaults` refusal names the file, the field and the reason on one line, never the value |
| A-7..A-11 | u12 | no-send holds under combination, printed numbers are computed by the working code, operational failure exits 3, a resume is bound to its target, a ceiling binds every request |
| A-42 | u12 | a run parses each target file once, so the target it authorizes is the one it sends to |
| A-46 | u12 | a resumed run records what its -sV probe pass sent however the pass ends (an error, Ctrl-C, SIGTERM, a stop after it), each probe once |
| A-26 | u11 | a gap says which kind it is (roadmap, out of reach, or by design), with the reason |
| A-12..A-15 | u11 | no denominator over survivors, uncounted values are reported, figures carry their edition, machine formats carry the run state |
| A-25 | u09 | the ordering -sV produces is measured in CI, not just executed |
| A-16, A-23 | u10 | a store path resolves inside the store root, recognition traffic is stored apart from the attempts |
| A-27 | u02 | an oracle may not be satisfied by an echo of what the spec itself sent |
| A-28 | u02 | a control framework (AISVS) is mapped by falsification, and a mapping cannot contradict its own classification |
| A-33 | u02 | a regex a spec writes compiles, through one function lint, a run and the evaluators share: one that does not is a lint finding and a run refuses its spec before sending, never a crash (the nesting limit still moves a few levels with the caller's stack) |
| A-17 | u02 | every framework field is validated, membership where it drives a denominator |
| A-40 | u02 (and u12, u09) | a number too long to write out is reported with its file where it enters (a spec, at any depth and in any YAML collection; a labels key; a report; a target file's `type`, `mock_scenario` and `seeded_setup` keys), never printed |
| A-44 | u02 | a spec's keys are strings: one that is not (an int, a bare `on`, a date) is a SCHEMA finding at its path, not a lint traceback |
| A-18..A-20 | u01 | authorization is reachability, schemes are allowlisted, one answer per target |
| A-52 | u01 | a list or a map written past the depth limit is refused where it starts, before the scanner pays for what follows |
| A-29..A-30 | u01 | a gate keys on what a spec cannot opt out of; the allowlist authorizes the path the client sends, on its port, refuses separator encodings, and a fleet's judge comes only from the fleet file |
| A-41 | u01 | a YAML value that costs far more to build than it weighs (a number past 1,000 characters, past 1,000 keys that are numbers) is refused before it is built |
| A-56 | u01 | no two of a fleet's ids differ only by case, on every file system, so no generated target file overwrites another; each refusal locates its entries |
| A-21..A-22 | u14 | a test asserts the claim against the real collaborator, and is deterministic |

The pattern under most of them, worth stating once: **something counted or omitted what did
not belong to it**, and the count was computed correctly and then dropped exactly where a human
looks. Two of the clauses exist because the fix for an earlier one reintroduced the same shape
one layer down, which is why auditing a fix is scheduled work and not a courtesy.

## Merge gate

After all units DONE: run the full `docs/07` taxonomy + import-linter + self-scan on the
**combined** tree (not per-unit only). Green = MVP‑1 candidate → Stage 6 human finish.
