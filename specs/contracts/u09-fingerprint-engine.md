# u09-fingerprint-engine.md

> **RECONCILIATION (ADR-0006: authoritative).** This unit produces **`ModelFingerprint` only**
> and feeds it to the u08 planner. **Remove `fingerprint/planner.py` and any TestPlan-building
> from scope**: u08 owns `build_plan`. `ModelFingerprint` is defined in `shared.models` (u00);
> its guess field is `capability_guess` (distinct from the `Capabilities` enum). Statistical
> layer uses a response feature-vector nearest-neighbor (no heavy/ambiguous-license embedder
> dep): OD-9.

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/10` +
`docs/06` (pluggable data packs) + `docs/07` (validation) + `shared/` before implementing.
**HARD unit**: 6 signal layers, probabilistic verdict, honesty about contradictions.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/fingerprint/`: `engine.py` (orchestrator), `layers/` (`metadata.py`,
  `capability.py`, `behavioral.py`, `tokenizer.py`, `guardrail.py`, `statistical.py`, `base.py`),
  `signatures.py` (signature-pack loader), `probes.py` (seeded benign probe battery),
  `combine.py` (weighted evidence → confidence), `planner.py` (adaptive `TestPlan` tailoring).
- **Ships:** a versioned signature data-pack under `src/ildottore/fingerprint/signatures/`
  (`*.yaml` + self-test corpus): a data pack, not code (`docs/06`); new models = update pack.
- **MUST NOT touch:** `shared/`, `adapters/`, `core/`, `evaluators/`, `scoring/`, spec YAML.

## §2 Intended behavior
Two first-class roles (`docs/10`): (1) **standalone recognition**: probe an unknown endpoint
with benign signals, return a `ModelFingerprint{family, version, capabilities, guardrails,
evidence, spoofing_flags}` and stop; (2) **adaptive first pass**: feed that fingerprint to
`planner` to emit a reviewable `TestPlan` (specs kept/dropped + why, family-effective mutator
weights, baseline resistance). Six signal layers run independently, each emitting weighted
`Evidence`; `combine` fuses them into per-field guesses + confidence. Self-report is a **weak**
signal: any layer contradicting the statistical layer surfaces a `spoofing_flag`, never
suppressed. Every run is **reproducible** (fixed seeded probe battery). Benign probes only -
no jailbreak payloads, scope-allowlist-gated.

## §3 Dependencies & interface contracts
- Consumes `shared.protocols.TargetAdapter` (u04) via injected instance: **no provider SDKs
  directly**; reads `adapter.capabilities()` + sends `ModelRequest`, reads `ModelResponse`
  (envelope, headers, logprobs when present).
- Produces `shared.models.ModelFingerprint` (interface registry, `docs/01 §3`); consumes
  `shared.models.{Capabilities, Evidence, ModelRequest, ModelResponse}`.
- Layers implement a local `FingerprintLayer` protocol (`base.py`: `layer: str`,
  `async probe(adapter, ctx) -> list[Evidence]`); registered by name for pluggable extension.
- `planner` consumes `AttackSpec`/suite metadata to filter/weight: read-only, emits `TestPlan`.

## §4 Known constraints: KEEP / DECIDE
- KEEP: probabilistic output: every field carries `confidence ∈ [0,1]` + evidence; never
  asserted as ground truth. Empty/contradictory signals ⇒ low confidence, not a fabricated guess.
- KEEP: benign-only probes; scope-allowlist enforced at adapter layer; standalone is the safe
  default first step on an unknown endpoint.
- KEEP: signature DB is a versioned data pack with a self-test corpus; loader validates pack
  version + schema; a pack update must not silently break the loader.
- KEEP: seeded probe battery (seed = `(target_id, probe.name)`) ⇒ deterministic replay.
- DECIDE (OD-5): adaptive planner default ON with `-sV` or opt-in (`--no-adaptive` always
  disables). DECIDE (OD-9): statistical layer embedding source: bundled small embedder vs
  response-feature vector (propose feature-vector + nearest-neighbor to avoid a heavy dep).

## §5 Implementation plan (each step its own commit, green before next)
1. `base.py` (FingerprintLayer protocol) + `probes.py` (seeded benign battery) + `signatures.py`
   (pack loader + version/schema validation + self-test corpus loader).
2. `layers/metadata.py` + `layers/capability.py`: passive envelope/header/error parsing +
   `adapter.capabilities()` reflection. No model call needed for metadata beyond one benign send.
3. `layers/behavioral.py` + `layers/tokenizer.py`: seeded self-id/cutoff/idiom probes; glitch-
   token family tells.
4. `layers/guardrail.py`: benign boundary nudges → input/output filter + refusal-style +
   moderation-latency signature.
5. `layers/statistical.py`: fixed query battery → feature vector → nearest-neighbor vs pack.
6. `combine.py`: weighted evidence fusion → per-field guess/confidence + `spoofing_flags`.
7. `engine.py` (orchestrate layers, assemble `ModelFingerprint`) + `planner.py` (`TestPlan`).

## §6 Data/wire shapes
`ModelFingerprint = {target_id, family:{guess,confidence}, version:{guess,confidence,cutoff_hint},
capabilities:{tools,json_mode,vision,streaming,seed,max_context_tokens}, guardrails:{input_filter,
output_filter,refusal_style,moderation_latency_ms}, evidence:list[{layer,signal,weight}],
spoofing_flags:list[str], recommended_plan_ref}` (exact shape in `docs/10 §2`). `Evidence` per
`shared.models`. Signature pack entry: `{family, version, signals:{layer→matcher}, weights}`.
`TestPlan = {plan_ref, target_id, selected:list[{spec_id, reason}], skipped:list[{spec_id,
reason}], mutator_weights, baseline_resistance}`: nothing silently dropped (`docs/07`).

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/fingerprint -q` green; coverage ≥ 90% for `src/ildottore/fingerprint/`.
- **Detection gate** (`docs/10 §6`, `docs/07 §3`) against the labeled self-test corpus:
  family **precision ≥ 0.90, recall ≥ 0.85**; version **top-1 ≥ 0.70, top-3 ≥ 0.90**. A
  signature-pack update that regresses either fails CI (locked baseline in test).
- **Spoofing honesty:** `tests/fixtures/fingerprint/spoofed/` (self-report conflicts with
  statistical layer) ⇒ correct `spoofing_flags` set + family confidence not inflated by the
  self-report; **0 cases** where a spoofed self-id silently wins.
- **Determinism:** same target + seed ⇒ byte-identical `ModelFingerprint` on replay (golden
  fixture in `tests/fixtures/fingerprint/golden/`).
- **Adaptive planner:** given a fixed fingerprint, `TestPlan` selected/skipped sets match the
  golden plan; every skip carries a reason (assert no un-reasoned drops).
- **Safety-negative:** all probes classified benign; an out-of-scope target ⇒ adapter refusal
  propagated (no probe sent). `ruff check`, `mypy src/ildottore/fingerprint`, `lint-imports` clean.

## §8 Out of scope / forbidden
- MUST NOT call provider SDKs directly (only via `TargetAdapter`); MUST NOT send any jailbreak /
  `test_only` payload: benign probes only.
- MUST NOT implement scoring/banding (u07), evaluators (u06), the run loop (u08), or persist
  evidence itself (u10 stores; this unit only produces `Evidence` objects).
- MUST NOT hardcode model identity from self-report; MUST NOT bypass the scope allowlist.
- Not its call: adaptive-default decision (OD-5) · embedding-source decision (OD-9).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-5** (shared w/ u08): adaptive planner default ON with `-sV` vs opt-in. Owner: human.
- **OD-9** (new): statistical-layer embedding source: bundled embedder vs response
  feature-vector nearest-neighbor. Propose: feature-vector (no heavy/ambiguous-license dep,
  `AGENTS.md §3`). Owner: human / ADR.
- Whether the signature pack ships in-repo for MVP-1 or as a separately-versioned artifact
  (propose in-repo `signatures/` for MVP-1, extract later). Owner: human.
