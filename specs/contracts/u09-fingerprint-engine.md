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

**A-1 Benign is a predicate, not a category (added 2026-09-22 after A-1 shipped broken).**
"All probes classified benign" was satisfied by inspection and violated in fact: the carrier
layer probed every registered mutator, so recognition sent a refusal-suppression preamble, a
fabricated no-restrictions prior turn, a claimed-compromise framing and the published GCG
universal suffix, the last byte-identical to the string `JB-REFUSAL-SUPPRESS-001` ships behind
`test_only: true` **and** a policy gate. The payload was benign; the carrier was the attack.
The criterion is therefore mechanical:
- a probe carrier MUST NOT leave the probe sentence as a **substring** of its output (a carrier
  that does has *added* instruction text, and that added text is the technique);
- the test asserts the classification over the **real** mutator registry, and separately
  asserts on the bytes that would go on the wire that no probe contains a known attack tell
  (`tests/fingerprint/test_carrier_layer.py`).

**A-2 A probe that drives the plan MUST discriminate, and be shown to.** The measurement is
scored against simulated oracles built from the real mutators: an ideal decoder scores every
probed carrier, and a **pure echo**, a **refusal** and a **refusal that quotes the prompt** all
score zero. (The first version scored 13 of 18 for all three, and guaranteed a zero on the two
carriers that rewrite the marker's own characters, so the signal ordering the battery was
mostly noise.)

**A-3 Declared cost equals real cost.** Every layer declares `probe_count`, and a test asserts
the sum **equals the number of `adapter.send` calls a pass makes**. "One probe per layer" was a
guess, wrong for three of six, and it was published to operators as the price of `-sV`.

**A-25 The ordering `-sV` exists to produce is measured in CI, not just executed (added
2026-09-22).** Every offline scenario answered with one fixed string whatever arrived, so no
carrier was ever comprehended, the hint came back empty, and the ordering (the part that
decides what a customer's endpoint is sent first) was asserted nowhere: CI ran the layer and
checked that it ran. `mock_scenario: comprehending` is an offline target that decodes what it
is sent (zero-width, rot13, base64) and follows the instruction when it survives, so the layer
produces a real split and the plan comes out in a different order, through the real layer, the
real mutators and the real planner. It is a **simulated decoder, not a model**: it proves the
chain, not how any given model behaves, and the docs say so where the claim is made. It also may not buy the measurement with a **verdict**: whatever the plain
`bare` mock decides, the decoding one decides identically, spec by spec over the shipped
battery. (The first version of this clause said "every spec stays inconclusive", which is false
and always was: three specs decide against any fixed-string offline target because their
oracles read only the response text. The test asserted it over one spec the test itself built,
so it could not find that out. Both are fixed: the property is differential now, and measured
against `specs/`.) What this file checks is the **ordering**; the scoring discriminators
(the echo tell, the zero-width strip, marker invariance) are pinned by
`tests/fingerprint/test_carrier_layer.py`, each one individually since 2026-09-22, because an
audit removed all three at once and the suite stayed green. Checked by
`tests/fingerprint/test_carrier_measured_offline.py` and `tests/fingerprint/test_carrier_layer.py`.

## §8 Out of scope / forbidden
- MUST NOT call provider SDKs directly (only via `TargetAdapter`); MUST NOT send any jailbreak /
  `test_only` payload: benign probes only. **This binds the carrier as well as the payload**
  (see §7 A-1): a probe wrapped in an adversarial framing is an adversarial probe, whatever the
  sentence inside it says.
- MUST NOT probe with a mutator whose behaviour it could not classify (an unclassifiable
  transform is not sent).
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
