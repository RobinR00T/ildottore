# u05-prompt-mutator.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/03 §4`
+ `docs/06 §3` + `shared/` before implementing.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/mutators/` - `base.py` (protocol adapter + `Mutation`/`MutationResult`
  helpers), `registry.py` (entry-point discovery per `docs/06 §3`), and one module per strategy:
  `identity.py`, `translate.py`, `base64_wrap.py`, `rot13.py`, `unicode_confusable.py`,
  `zero_width_inject.py`, `roleplay_wrap.py`, `nested_instruction.py`, `comment_carrier.py`
  (markdown + html carriers), `payload_splitting.py`, `refusal_suppression_prefix.py`.
- **MUST NOT touch:** `shared/`, `adapters/`, `core/`, `evaluators/`, `scoring/`, `policy/`,
  `registry/` (spec registry, u02), any spec/suite YAML, `schemas/`.

## §2 Intended behavior
Expand one base attack `attack.user_prompt`/`attack.carrier` into the declared variants
(`docs/03 §4`). A mutation is a **deterministic, intent-preserving** transform of the *carrier/
obfuscation* only - the same `expected_secure_behavior` must still apply, so the evaluator/judge
contract is unchanged. Determinism is seeded by `(spec.id, mutation.name)` (`docs/01 §3.3`): the
same seed ⇒ byte-identical output on replay, no wall-clock/RNG/network. `identity` is the null
transform (returns input unchanged). Built-in strategies are the exact list in `docs/03 §4`;
strategies are **pluggable** (L3, `docs/06 §3`) via the `dottore.mutators` entry point. A spec
naming an unknown mutation is a linter error (u02), never a silent skip.

## §3 Dependencies & interface contracts
- Depends only on **u00** (`shared`). Implements `shared.protocols.Mutator`
  (`type: str`; `mutate(text: str, *, seed: int, params: dict) -> MutationResult`) and registers
  each strategy under its `type` string used in `schemas/attack-spec.schema.json` mutation names.
- Consumes `shared.models` mutation/attack shapes only; produces the mutated carrier(s) the
  execution engine (u08) feeds to the adapter. **No** provider SDKs, no LLM calls (`translate`
  is a deterministic offline table/map, not an API translation - see §4/§9).
- Registry mirrors u06 pattern: protocol validation at load, clear error on a bad plugin.

## §4 Known constraints - KEEP / DECIDE
- KEEP: every strategy is a **pure function** of `(text, seed, params)`; no I/O, no global state,
  no clock/`random` without the passed seed. Property test enforces determinism + idempotent
  `identity`.
- KEEP: intent-preserving - a mutation only re-encodes/wraps; it must not add or drop the attack's
  semantic ask. `payload_splitting`/`nested_instruction`/`roleplay_wrap` reassemble to the same
  intent.
- KEEP: reversibility metadata - `MutationResult` records `strategy`, `seed`, `params` and (for
  reversible encodings: base64/rot13/zero-width) enough to reconstruct provenance for evidence.
- KEEP: `unicode_confusable`/`zero_width_inject` are bounded (documented codepoint tables; density
  cap in `params`) - no unbounded blow-up.
- DECIDE (§9): `translate` backing (static phrase-map subset vs pluggable dictionary) and its
  default language set.

## §5 Implementation plan (each step its own commit, green before next)
1. `base.py` (`Mutator` protocol adapter, `Mutation`/`MutationResult` dataclasses, seed derivation
   `hash(spec.id + mutation.name)`) + `registry.py` (entry-point discovery, protocol validation).
2. Trivial deterministic set: `identity`, `rot13`, `base64_wrap`.
3. Obfuscators: `unicode_confusable` (confusable table), `zero_width_inject` (ZWSP/ZWNJ, density
   param).
4. Carriers/wrappers: `roleplay_wrap`, `nested_instruction`, `comment_carrier` (markdown + html),
   `refusal_suppression_prefix`.
5. `payload_splitting` (seeded split points + reassembly note) and `translate` (per §9 decision).

## §6 Data/wire shapes
`MutationResult = {text: str, strategy: str, seed: int, params: dict, reversible: bool,
provenance: dict}`. `text` is the transformed carrier; `provenance` carries the decode hint for
reversible encodings and the confusable/split map otherwise (masked if it ever carries payload
per redactor rules). No secrets/PII produced. Input mutation list shape follows
`schemas/attack-spec.schema.json` `mutations[]` (name + optional params); u05 does not extend the
schema.

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/mutators -q` green; coverage ≥ 90% for `src/ildottore/mutators`.
- **Golden fixtures** (`tests/fixtures/mutators/golden/`): each of the 12 built-in strategies has
  an input→output golden; `pytest` diffs byte-exact. Fixtures committed and stable across runs.
- **Determinism property test** (Hypothesis, `docs/07`): `mutate(t, seed=s)` == `mutate(t, seed=s)`
  for all strategies; different seeds may differ; `identity(t) == t` for all `t`.
- **Reversibility test:** `base64_wrap`/`rot13`/`zero_width_inject` outputs decode back to the
  original payload; asserted programmatically.
- **Registry test:** a stub plugin under `dottore.mutators` is discovered and validated; a
  malformed one raises a clear protocol error (no silent skip).
- `ruff check`, `ruff format --check`, `mypy src/ildottore/mutators` clean; `lint-imports` green
  (mutators import only `shared` + stdlib).

## §8 Out of scope / forbidden
- MUST NOT call any network/LLM/provider SDK (no live translation, no remote confusable service).
- MUST NOT read/mutate spec YAML, run specs, evaluate, score, or dispatch to adapters (u08 owns
  orchestration; u06 evaluation; u07 scoring).
- MUST NOT add new mutation `type` strings to `schemas/` (schema is owned; new built-ins are a
  schema change = program decision).
- MUST NOT introduce nondeterminism (wall clock, unseeded RNG, dict-order-dependent output).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- `translate` implementation: ship a small static phrase-map subset (deterministic, offline) for
  MVP‑1 vs a pluggable dictionary provider; and the default language set. **Proposed:** static
  offline subset for a fixed 3-4 language list; pluggable later (L3). Flag as new OD to index.
- Whether `unicode_confusable`/`zero_width_inject` density defaults live in mutator code or move to
  a shared `frameworks/`-style table (**propose:** in-module tables for MVP‑1).
