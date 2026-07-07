# unit-06-evaluators.md

Exemplar contract (the bar for all units). 9-section anatomy per `docs/00 §2`. Read
`AGENTS.md` + `docs/04` + `docs/11` + `shared/` before implementing.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/evaluators/` — `base.py`, `regex.py`, `exact.py`, `refusal.py`,
  `secret_leakage.py`, `tool_call.py`, `semantic_judge.py`, `pii_detector.py`,
  `secret_shape.py`, `authz_leak.py`, `registry.py`, `combine.py`.
- **MUST NOT touch:** `shared/`, `adapters/`, `core/`, `scoring/`, any spec YAML.

## §2 Intended behavior
Turn a target response (+ traces + context) into a `Verdict{status, confidence, reasoning,
matched}`, `status ∈ {pass, fail, inconclusive}`, polarity fixed: `pass` = secure, `fail` =
exploited. Deterministic evaluators are cheap pre-filters; `semantic_judge` is the arbiter for
semantics only. Combine per spec `evaluator_logic` (`all_pass`|`any_fail`|`weighted`); any
required `inconclusive` ⇒ aggregate `inconclusive` (never coerced). Full spec: `docs/04`.

## §3 Dependencies & interface contracts
- Implements `shared.protocols.Evaluator` (`type: str`, `async evaluate(ctx)->Verdict`).
- `semantic_judge` calls an LLM **only via `shared.protocols.TargetAdapter`** (u04) — no direct
  provider SDKs. Consumes `shared.models.{Verdict, EvalContext, Attempt}`.
- Registers each evaluator under its `type` string used in `schemas/attack-spec.schema.json`.

## §4 Known constraints — KEEP / DECIDE
- KEEP: deterministic evaluators emit confidence `1.0` (or `0.0`⇒`inconclusive` on ambiguity).
- KEEP: data-leak FP discipline — format-valid hit without corroboration (canary/corpus/
  cross-identity) ⇒ `needs-review`, never confirmed (`docs/11 §4`).
- DECIDE (OD-3): default judge model + whether a 2nd judge runs for self-consistency.

## §5 Implementation plan (each step its own commit, green before next)
1. `base.py` + `registry.py` (protocol, entry-point discovery per `docs/06`).
2. Deterministic set: regex_absence/presence, exact_match, refusal, secret_leakage, tool_call.
3. `pii_detector` (Luhn, IBAN mod-97, locale IDs, entropy) + `secret_shape` + `authz_leak`.
4. `semantic_judge` with hardening (`docs/04 §4`): data delimiters, structured JSON output,
   injection tripwire, self-consistency, `temperature=0`.
5. `combine.py` (evaluator_logic).

## §6 Data/wire shapes
`Verdict = {status: "pass"|"fail"|"inconclusive", confidence: float[0,1], reasoning: str,
matched: list[str], evaluator_type: str}`. Judge raw+parsed output persisted to evidence
(masked). PII/secret hits stored **typed + masked/hashed only** (`docs/11 §5`).

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/evaluators -q` green; coverage ≥ 90% for this package.
- **Labeled P/R gate** (`docs/07 §3`): each evaluator precision ≥ 0.90, recall ≥ 0.85 on
  `tests/fixtures/labeled/` — including hallucinated-but-valid negatives for pii/secret.
- **Judge robustness:** `tests/fixtures/adversarial-judge/` → 0 verdict flips (all →
  `inconclusive`/`judge_compromised`).
- Determinism: judge at `temperature=0` + fixed seed ⇒ stable verdict on replay.
- `ruff check`, `mypy src/ildottore/evaluators` clean; `lint-imports` green.

## §8 Out of scope / forbidden
- MUST NOT call provider SDKs directly (only via `TargetAdapter`).
- MUST NOT persist raw secrets/PII anywhere (redactor only).
- MUST NOT implement scoring/banding (that's u07) or fetch/execute tools (mocks only).
- Not its call: judge model hosting decision (OD-3) · scoring formula (u07).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-3** default judge model (own-hosted vs API) + second-judge self-consistency on/off.
- Whether `secret_shape` entropy threshold is global or per-key-type (propose per-type).
