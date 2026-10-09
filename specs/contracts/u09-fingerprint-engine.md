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
suppressed. Every run is **reproducible** offline (fixed seeded probe battery); live, as far as
the target is deterministic at temperature 0, which every probe pins (`PROBE_SAMPLING`, with a
512-token reply cap) and the OpenAI and Anthropic adapters send (a REST template and a WebSocket
target have no sampling field: their probes go out at the deployment's own). Benign probes
only - no jailbreak payloads, scope-allowlist-gated.

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
- KEEP: seeded probe battery (seed = `(target_id, probe.name)`) ⇒ deterministic replay. The
  seed rides in request metadata and is not sent; on the wire every probe is temperature 0 with
  a capped reply (as built 2026-10-07: three layers had sent no temperature at all) wherever the
  adapter sends sampling (OpenAI, Anthropic; not a REST template nor a WebSocket target, whose
  wire shape has no field for it, pre-merge audit of PR #87).
- DECIDE (OD-5): adaptive planner default ON with `-sV` or opt-in (`--no-adaptive` always
  disables). Resolved as built: `-sV` (and `-A`) imply adaptive ordering; there is no
  `--no-adaptive` flag (`00-INDEX.md` OD-5). DECIDE (OD-9): statistical layer embedding source: bundled small embedder vs
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
`shared.models`. (As built, 2026-10-04: the key is `capability_guess`, copied from the target's
declared capabilities, not probed: `{tools, json_mode (= tools), vision (= multimodal),
streaming, seed, rag, memory, logprobs}` plus `effective_mutators` when the carrier layer
recovered any; no `max_context_tokens`. `family` and a non-null `version` are `{guess,
confidence, cutoff_hint}`; `recommended_plan_ref` is always null. `spoofing_flags` can hold
`self_report_conflicts_with_statistical` and `non_discriminating_target`: the second is set when
every attributing (non-carrier) probe got the same reply text, at least three answered; text
evidence then does not attribute, only metadata evidence matching a `model=` field names the
family, a version is kept only when one clearly leads (a tie gives none), and otherwise the
family is `unknown`. Since 2026-10-05: any tie between families gives `unknown` and any tie
between versions gives no version; the statistical layer emits nothing when its probes got
repeated replies; capability-layer evidence carries weight 0 and never counts; a family named by
the metadata layer alone, and its version, are capped at the pack's metadata weight; an entry's
`model=` fragments are alternatives; the metadata signatures are `model=` names only; a live
probe adapter reports the target file's capabilities, and the adapters redact the `model` echo
without the entropy rule. See `docs/10 §2`, "Attribution rules".) Signature pack entry:
`{family, version, signals:{layer→matcher}, weights}`.
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
  fixture in `tests/fixtures/fingerprint/golden/`). Live, only as far as the target is
  deterministic at temperature 0: the first local pass gave byte-identical output with 9 of its
  17 probes at temperature 1, and again with all 17 at 0 (`docs/16` §1), which is one model,
  not a guarantee.
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

**A-35 A probe whose reply comes back refused costs that probe, not the pass (added
2026-10-07, OD-23).** With `run -sV` or `-A`, one reply the adapters refuse as an environment
failure a retry would repeat (`ResponseTooLarge`, a reply over 4 MiB; `ResponseUndecodable`, an
encoding they do not decode) stopped the run with exit 3 after one request, before any attack,
while without `-sV` the same reply failed one attempt and every spec ran (pre-commit audit of
`fix/target-deep-json`). `dottore fingerprint` exited 3 the same way. The layers called
`adapter.send` with nothing between one probe and the pass. The criterion:
- the engine classifies a send's error with the predicate the attack phase uses for an attempt
  (`core.execute.default_is_env_error`, injected by `cli.wiring.build_fingerprint_engine`, since
  u09 may not import `core`) and the `retryable = False` marker the attack phase reads; such a
  refused reply (over 4 MiB, undecodable, or nested past 100 levels: `ResponseTooDeep`) becomes
  `ProbeFailed` for that probe, and anything else goes through and stops
  the pass: a probe that gets **no answer at all** (a 5xx, a 429, a timeout, a refused
  connection, after the meter's retries), a product error, a refusal by the scope, the request
  ceiling, every `BaseException`. The first version isolated every environment failure, and
  its pre-commit audit measured a target that never replies at 25.5 minutes of probing (17
  probes, three 30 s timeouts each; `--budget-wall` and `--timeout` do not bound the probe pass)
  before an attack that failed the same way (38 minutes for a 2-spec `run -sV`, against 92 s),
  and `dottore fingerprint` exiting 0 on a closed port;
- a failed probe gives no evidence and is never read as an empty reply: the guardrails stay
  unknown (`{}`, not "no filter"), a carrier is left out of the comprehension map (unmeasured,
  not 0.0), the statistical layer gives nothing when one of its three is missing (explicitly: a
  pack's centroid only has to be non-empty), and every other layer's evidence is identical to
  that of a pass with no failure;
- refusals cannot get past the constant-target check, and it is never claimed once an
  attributing reply is refused: when refused replies leave fewer than three attributing
  replies, or the ones left are all alike, the text layers' evidence is not counted and
  `non_discriminating_target` is not set (a constant target with 8 of 10 replies refused was
  named meta-llama at 0.41 by the pre-commit audit; refusing a target's varied replies got it
  flagged constant by the pre-merge audit). A refused carrier does not count, since the check
  never reads the carriers (counting it dropped the flag from a constant target; delta audit);
- a partial pass never names more than the same probes answered with an empty reply: measured
  over 12,276 passes (every subset of the 10 attributing sends of the 12 corpus targets), it is
  identical when no statistical probe is refused, and otherwise `unknown` or the same family
  with lower confidence (2,344 of 10,752 differ, none the other way); pinned on every single and
  paired refusal and every pass with two replies or fewer left. Against a full pass, losing a
  tell can still break a tie the full pass leaves unknown or drop a self-report and with it its
  spoofing flag, as a bland reply would, and the confidence is renormalized over what remains,
  not discounted; `probes_failed` and the fingerprint line mark the pass partial;
- every other probe of the built-in layers is still sent, once (A-3 holds with failures: sends
  equal the declared count); a layer that lets the failure through stops its own remaining
  probes;
- the failures are recorded as `layer/probe: ErrorClass`, never the error's text (it can quote
  the reply), in an `engine` evidence entry `probe_errors=[...]` with the flag `probes_failed`;
  `run -sV` says so on stderr (never silenced by `-q`) and on the fingerprint line, `dottore
  fingerprint` on stderr, and exits 3 when every probe was refused (an empty fingerprint is not
  a result).
Checked by `tests/fingerprint/test_probe_failures.py` (each of the 17 probes refused in turn,
against a pass with evidence in every layer) and `tests/cli/test_probe_env_error.py` (a local
stub through the real CLI). Out of this clause: a 200 that is not JSON (`AdapterProductError`)
still stops the pass, as it stops the campaign; that is OD-21.

**A-36 (owned by u08) covers the guardrail layer's latency too (2026-10-07).**
`moderation_latency_ms` is the target's own figure, so it is read through
`shared.amounts.is_amount` (a finite, non-negative number a float can hold): a 400-digit
integer, an infinity, a NaN or a negative figure is `null`. The 400-digit one made `float()`
raise and `fingerprint` and `run -sV` exit 1; the others were recorded as latencies.
`tests/fingerprint/test_latency_figure.py`.

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
  Resolved as built: `-sV`/`-A` imply adaptive ordering, no flag (`00-INDEX.md`).
- **OD-9** (new): statistical-layer embedding source: bundled embedder vs response
  feature-vector nearest-neighbor. Propose: feature-vector (no heavy/ambiguous-license dep,
  `AGENTS.md §3`). Owner: human / ADR.
- Whether the signature pack ships in-repo for MVP-1 or as a separately-versioned artifact
  (propose in-repo `signatures/` for MVP-1, extract later). Owner: human.
- **OD-23** (shared w/ u12, 2026-10-07): an environment failure on one `-sV` probe. **A**: a reply
  that comes back refused (`retryable = False`) fails that probe and the run goes on, with the
  fingerprint built from the rest, while a probe that gets no answer at all still stops the pass
  with its cause, as before (built, reversibly, §7 A-35). **A-all**: every environment failure
  fails only its probe, as the attack phase treats an attempt; built first and withdrawn, because
  a target that never replies then cost 25.5 minutes of probing (38 for a 2-spec run, the same
  exit 3 at the end) against 92 s, and `dottore fingerprint` exited 0 on a closed port; it would
  need a breaker (stop once the first few probes all get no answer) and the probe pass bound by
  `--timeout` and `--budget-wall`. **B**: stop the pass on any of them, as before (a refused reply
  handled worse than a 503 the meter retries). **C**: drop the whole fingerprint and run the
  attack in declared order. Owner: human.
