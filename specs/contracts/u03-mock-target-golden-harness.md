# u03-mock-target-golden-harness.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/07 §2`
+ `docs/01` + `shared/` before implementing. **This unit is THE safety net**: it decides whether
every attack spec's fixtures actually prove what they claim (the FP/FN gate, `docs/07 §3`).

## §1 Scope & ownership
- **OWNS:** `src/ildottore/adapters/mock.py` (deterministic offline `MockTarget`),
  `src/ildottore/testing/golden.py` (the golden runner + accuracy aggregator).
- **MUST NOT touch:** `shared/`, `policy/`, `config.py`, `redactor.py`, other adapters
  (`base/openai/anthropic/rest.py` — u04), `evaluators/`, `core/`, `scoring/`, any spec YAML
  or `tests/fixtures/**` (fixtures are authored by u13/spec-owners; this unit consumes them).

## §2 Intended behavior
`MockTarget(scenario)` is a deterministic, **offline, no-network** `TargetAdapter`: given an
attack spec's `fixtures.{vulnerable,hardened}` block it returns the declared canned
`ModelResponse` (text, optional tool-calls, optional logprobs) with **zero I/O and no clock/RNG**
— identical bytes on every call. The golden runner (`golden.py`) drives, for each spec:
scanner-against-`vulnerable` **must** yield `fail` (exploited), scanner-against-`hardened`
**must** yield `pass` (secure). Any spec whose fixtures don't produce the expected verdicts is a
**merge-blocking** failure. Runner publishes **spec detection accuracy** = correct-verdicts /
total-fixtures + per-family FP/FN rates (`docs/07 §2`). Full spec: `docs/07 §2`, flow `docs/01 §4`.

## §3 Dependencies & interface contracts
- **u00** — implements `shared.protocols.TargetAdapter` (`id: str`, `async send(ModelRequest) ->
  ModelResponse`, `capabilities() -> Capabilities`). Consumes `shared.models.{ModelRequest,
  ModelResponse, Capabilities, AttackSpec, Verdict}`. Polarity fixed repo-wide: `pass`=secure,
  `fail`=exploited (`00-INDEX`, `docs/04`).
- **u01** — golden runner honors the Policy Engine: MockTarget is declared in-scope; runner uses
  `policy` to confirm `test_only`-flagged fixtures only run when the pack enables them.
- MockTarget declares `Capabilities` from the fixture (tools/rag/logprobs/multi_identity) so a
  spec needing an absent capability yields `inconclusive: capability_unavailable`, not a fake pass.
- Runner invokes the **real** evaluator pipeline (u06) + combine when composed by u12; in this
  unit's own tests the evaluator is injected via the `Evaluator` protocol (no concrete import).

## §4 Known constraints — KEEP / DECIDE
- **KEEP:** MockTarget is pure — no `httpx`, no sockets, no `time`, no `random`, no filesystem
  writes. Determinism is the whole point; a network import in `mock.py` fails CI.
- **KEEP:** a fixture selects response by scenario key only; MockTarget does **not** interpret the
  attack (no matching logic) — it replays exactly what the fixture author declared.
- **KEEP:** golden accuracy gate is **100%** on fixtures (fixtures are ground truth, `docs/07 §3`);
  runner exits non-zero on any mismatch and emits a per-spec/per-family diff.
- **KEEP:** multi-response fixtures (N-run repro) replay a declared **sequence**, cycling
  deterministically by attempt index — no drift.
- **DECIDE:** fixture-carrying location — inline in the spec YAML `fixtures:` block vs sidecar
  files under `tests/fixtures/{vulnerable,hardened}/` (`docs/07 §4`). Propose: schema allows both,
  runner resolves inline-first (§9).

## §5 Implementation plan (each step its own commit, green before next)
1. `adapters/mock.py`: `MockTarget(scenario, fixture)` implementing `TargetAdapter`; `send()`
   returns canned `ModelResponse`; `capabilities()` from fixture; sequence-cycling for N runs.
2. `testing/golden.py`: `load_fixtures(spec)`, `run_spec(spec, scenario, evaluator) -> Verdict`,
   assertion helpers `assert_flags_vulnerable` / `assert_passes_hardened`.
3. `golden.py`: `run_all(specs) -> GoldenReport` aggregator (accuracy + per-family FP/FN),
   non-zero exit + human-readable diff on mismatch.
4. Policy integration: skip/allow `test_only` fixtures per pack (u01); record skip reason.
5. Self-tests: property test that MockTarget is byte-identical across repeated `send()`.

## §6 Data/wire shapes
- `fixtures.vulnerable` / `fixtures.hardened`: `{response: str | list[str], tool_calls?: [...],
  logprobs?: [...], capabilities?: {...}, test_only?: bool}` (validated vs
  `schemas/attack-spec.schema.json`).
- `GoldenReport = {total: int, correct: int, accuracy: float, by_family: {family: {fp: int,
  fn: int, n: int}}, mismatches: [{spec_id, scenario, expected, got}]}`.
- MockTarget emits `ModelResponse` unchanged from `shared.models`; logprobs populated only when
  the fixture declares them (so `logprob_membership` specs are exercisable offline).

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/adapters/test_mock.py tests/testing/test_golden.py -q` green;
  coverage ≥ 90% for `adapters/mock.py` + `testing/golden.py`.
- **Determinism (hard):** property test (Hypothesis) — 100 repeated `send()` on the same fixture
  return byte-identical `ModelResponse` (`docs/07 §1 row 9`).
- **No-network (hard):** test asserts `mock.py` imports nothing from `{httpx, socket, requests,
  urllib, time, random}` (AST/import check) and a socket-guard fixture proves `send()` opens no
  connection.
- **Golden gate self-test:** synthetic vulnerable+hardened fixtures + a stub evaluator prove the
  runner returns accuracy `1.0` on matches and **exits non-zero** with a populated `mismatches`
  list on an injected wrong verdict (`docs/07 §3` = 100% gate).
- **Capability honesty:** a fixture lacking a required capability yields
  `inconclusive: capability_unavailable`, never `pass`.
- `ruff check`, `ruff format --check`, `mypy src/ildottore/adapters/mock.py
  src/ildottore/testing/golden.py` clean; `lint-imports` green (adapters import shared only).

## §8 Out of scope / forbidden
- MUST NOT perform any network I/O, read a clock, or use RNG in `mock.py` (offline determinism).
- MUST NOT import or call real provider adapters/SDKs (u04) or evaluators/scoring concretes
  (inject via protocol only).
- MUST NOT author, mutate, or "fix" attack specs or fixtures — it only consumes and judges them.
- MUST NOT implement mutation (u05), scoring/banding (u07), evidence/run persistence (u10), or
  reporting (u11).
- Not its call: fixture-storage-location decision (§9) · which families ship fixtures (u13).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-u03-a** fixture location: inline in spec YAML vs sidecar `tests/fixtures/**` — propose
  schema supports both, runner resolves inline-first; flag as ADR if it constrains u13.
- Whether per-family FP/FN thresholds are informational or also merge-gating in MVP‑1 (propose:
  overall 100% accuracy gates; per-family rates informational until u13 battery exists).
