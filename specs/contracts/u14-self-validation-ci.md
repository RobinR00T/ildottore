# u14-self-validation-ci.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/00` +
`docs/01` + `docs/07` (18-layer taxonomy) + `specs/contracts/00-INDEX.md` before implementing.
**Last unit** (W5) — depends on every unit above; wires the test taxonomy + CI merge gate.

## §1 Scope & ownership
- **OWNS:** `tests/` (scaffolding, `conftest.py`, shared fixtures, taxonomy layout, fixture
  dirs), `.github/workflows/` (`ci.yml`, `audit.yml`, `dependabot.yml`), `.importlinter`,
  `pyproject.toml` `[tool.pytest.ini_options]` + `[tool.coverage.*]` sections.
- **MUST NOT touch:** any `src/ildottore/**` production code, `schemas/`, `docs/`,
  another unit's owned files, or spec YAML under `specs/attacks|suites`. This unit wires and
  gates existing behavior; it never adds product features to fix a red gate — it reports.

## §2 Intended behavior
Provide the executable harness that proves the whole build. (1) Lay out `tests/` so every one
of the 18 taxonomy layers (`docs/07 §1`) has a home and each unit's own tests slot in without
collision. (2) Author `.importlinter` encoding the dependency rule (`docs/01 §2`). (3) Define
the **ordered CI pipeline** (`docs/07 §5`, 12 gates) that fails closed on any layer, plus a
nightly regression/metamorphic run and a proactive `audit.yml`. (4) Ship shared fixtures/
conftest (MockTarget wiring, fixture-dir discovery, fake clock, cassette player) that per-unit
tests reuse. It owns *scaffolding + wiring + gates*, not the per-layer test bodies that belong
to each unit's contract (evaluators own their P/R tests, mutator owns property tests, etc.).

## §3 Dependencies & interface contracts
- Depends on **all units** (W0–W4 + u12). Consumes only public surfaces: `shared.models`,
  `shared.protocols`, the `dottore` CLI entry (u12), MockTarget + golden harness (u03),
  cassettes (u04), reporters (u11). Codes against the **shared interface registry**
  (`00-INDEX §"Shared interface registry"`, `docs/01 §3`) — never a unit's internals.
- Verdict polarity fixed repo-wide: `pass` = secure, `fail` = exploited (`docs/04`).
- `.importlinter` is the machine form of `docs/01 §2`: `shared` importable by all; `core`
  imports interfaces only; `adapters` import nothing in-repo but `shared`; `evaluators` import
  `shared` (+ adapter *interface* for judge); composition only in `cli`/`api`.

## §4 Known constraints — KEEP / DECIDE
- KEEP: **no live API keys in CI** — adapters exercised only via `tests/cassettes/`
  (`docs/07 §4`); a CI guard fails if any test opens a real socket to a provider host.
- KEEP: gates are **ordered and fail-closed** — a later gate never runs green over an earlier
  red; golden-fixture accuracy (layer 6) and self-scan (layer 17) are hard merge blockers.
- KEEP: env-vs-product discipline (`AGENTS.md §2`) — infra flake ⇒ retry/skip, real defect ⇒
  FAIL; never mark a product defect `xfail`.
- KEEP: this unit adds no `src/` code; a red gate is escalated, not patched here.
- DECIDE: coverage measured **per-package core ≥ 85%** vs a single global number (propose
  per-core-package, aggregate reported).

## §5 Implementation plan (each step its own commit, green before next)
1. `pyproject.toml` pytest + coverage config; `tests/` tree with one dir per taxonomy layer
   and the fixture dirs (`vulnerable/`, `hardened/`, `labeled/`, `adversarial-judge/`,
   `cassettes/`); root `conftest.py` (MockTarget factory, fixture-dir loaders, fake clock).
2. `.importlinter` contract + a `tests/test_import_contract.py` smoke that asserts it runs.
3. `ci.yml` with the 12 ordered gates as discrete jobs/steps (`docs/07 §5`), fail-closed,
   no-live-socket guard, artifact upload (SARIF/JUnit/coverage).
4. Nightly workflow: full regression golden-run snapshot + metamorphic suite (layers 16, 18).
5. `audit.yml` (proactive validator, weekly cron) + `dependabot.yml` (permissive-only ecosystem
   scan, grouped, non-empty `ignore`/allow to satisfy schema).

## §6 Data/wire shapes
- `.importlinter`: TOML/INI `[importlinter]` root + layered/independence contracts naming
  `ildottore.shared|core|adapters|evaluators|cli|reporting|store|policy|…`.
- CI publishes per build: **spec detection accuracy** = correct-verdicts/total-fixtures, plus
  per-family FP/FN, coverage %, evaluator P/R table, judge-flip count — as JUnit + a JSON
  summary artifact. SARIF from self-scan validates against **SARIF 2.1.0**; JUnit valid XML.
- No new persisted domain models; consumes `TestRun`/`Finding` shapes only through reporters.

## §7 Acceptance criteria (machine-checkable, exact commands + gates)
- `pytest -q` green; **core coverage ≥ 85%** (`docs/07 §3`): `pytest --cov=src/ildottore
  --cov-report=term-missing --cov-fail-under=85`.
- `lint-imports` green (exit 0) against `.importlinter`; `tests/test_import_contract.py` passes.
- `ruff check . && ruff format --check . && mypy src` clean.
- `dottore lint specs/` exits 0 (layers 1–2).
- **Golden-fixture accuracy = 100%** (layer 6, hard gate): every spec flags `fixtures.vulnerable`
  (`fail`) and passes `fixtures.hardened` (`pass`); a mismatch fails CI.
- Evaluator **precision ≥ 0.90 / recall ≥ 0.85** on `tests/fixtures/labeled/` (layer 7).
- Judge robustness: **0 verdict flips** on `tests/fixtures/adversarial-judge/` (layer 8).
- Determinism replay: **100% stable finding set** at fixed seed (layer 9).
- Reporting: SARIF validates vs 2.1.0, JUnit valid, secrets masked (layer 11).
- E2E: `dottore run --suite … --target mock --fail-on high` exits with the correct code +
  writes expected artifacts (layer 12).
- Self-scan (layer 17): **no new high/critical** in our own LLM-using code, or CI fails.
- CI job order matches `docs/07 §5` (1→12) and fails closed; no-live-socket guard active.

## §8 Out of scope / forbidden
- MUST NOT add or modify `src/ildottore/**`, `schemas/`, `docs/`, or spec YAML to make a gate
  pass — escalate the red gate to its owning unit.
- MUST NOT authbypass the no-live-key rule (no real provider calls in CI); no secrets in
  workflows or fixtures.
- MUST NOT relax a threshold (coverage, P/R, accuracy) to go green — thresholds are `docs/07`.
- MUST NOT own per-layer test *content* that another unit's contract assigns (only scaffolding,
  wiring, shared fixtures, gates).
- Not its call: coverage-scope decision if contested (see §9) · any threshold change (program).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- Coverage scope: per-core-package ≥ 85% vs single global gate (propose per-package, aggregate
  reported).
- Whether `audit.yml` "workflow permissions read/write" is auto-set or left operator-pending
  (propose operator-pending, documented in workflow header).
- Nightly regression golden-run baseline location + diff-review owner (propose `tests/golden-run/`,
  conductor reviews the snapshot diff).
