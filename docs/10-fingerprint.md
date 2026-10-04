# 10: Model fingerprinting engine (`-sV` / standalone recon)

Two roles for fingerprinting: both first-class:

1. **Standalone recognition** (`dottore fingerprint <target>`, or `run -sn` for the
   authorization-and-capability half without probes): identify
   *what model, which version, which guardrails and capabilities* sit behind an endpoint, and
   stop. Nothing else is attacked. This is the nmap `-sV` / banner-grab analogue and a useful
   product on its own (asset discovery of AI endpoints).
2. **Adaptive first pass** (`-sV`, or `-A`, before a scan): the fingerprint is recorded,
   printed, and **used to order each spec's mutators**, best carrier first.

   What drives that ordering is a measurement of *this* target, not a table of priors. The
   **carrier layer** (`fingerprint/layers/carrier.py`) sends one benign, policy-neutral
   instruction through every registered mutator and checks whether the target still follows
   it; `core/planner._order_family_effective` then runs the carriers it recovered before the
   ones it did not. A transformation whose instruction the model cannot recover cannot carry
   an attack either, so it belongs at the back of the queue.

   **Be precise about what that is and is not.** It measures *carrier comprehension*. It does
   **not** measure guardrail evasion, which would require sending something a guardrail should
   block, and this engine sends benign probes only (contract §8). So the ordering is a
   measured proxy for carrier viability against this target, never a claim about what will
   defeat its filters.

   The alternative was a hand-written "mutators known to work against family X" table. We
   have no empirical basis for one, and shipping it would attach a confidence to a fiction.

   The other hook, the planner function `core/planner._baseline_resistance`, is **dead at both
   ends**: it reads a per-category expectation from `guardrails["baseline_resistance"]`, a key no
   fingerprint layer writes, so it always returns `None`; and the
   `PlanSelection.baseline_resistance` field it fills has no reader anywhere in `src/` (OD-17).
   No layer writes the key because benign probes
   cannot measure per-category resistance, so nothing emits it and no result is scored
   relative to an expectation. Tracked in `docs/12`. That one really is inert, and saying so
   is cheaper than a number nobody can defend.

   **Only obscuring carriers are probed, and that is a safety boundary.** A carrier that
   leaves the instruction readable and wraps it in new text (a refusal-suppression preamble, a
   fabricated prior turn, a GCG suffix) is attack technique, and recognition sends benign
   probes only (contract §8). The split is computed, not listed: a mutator whose output still
   contains the original sentence has *added* instructions around it. On the shipped set that
   is 7 carriers probed of 18, and every carrier the repo documents as an attack is on the
   other side.

   **Cost:** one request per probed carrier, so a fingerprint pass is ~17 requests rather than
   the 10 it was. The resolved plan prints the figure (`fingerprint: +N probe(s) per target`),
   `--estimate` prices it, an explicit `--budget-requests` binds it, the probes are paced by
   the same `--rate` ceiling as attack traffic, and `--dry-run` / `--estimate` / `-sn` send
   none of them.

   **One limit worth knowing before you rely on it.** What CI measures is a *simulated*
   decoder: `mock_scenario: comprehending` is an offline target that strips zero-width
   padding and decodes rot13 and base64, so the layer produces a real split and the plan
   really is reordered by it, end to end and with no endpoint. That proves the chain, not
   how any given model behaves. The bare/fixture scenarios still answer with a fixed string,
   so `-sV` orders nothing against those, and the claim "this carrier works on that model"
   only ever comes from a live run.

   **The probes are evidence.** Each one is stored under `<run-id>/probes/` through the same
   redacted, content-addressed path as an attack attempt, and `dottore replay` lists them
   under their own heading, so a scan can answer "what did `-sV` send my endpoint" request by
   request. They are kept out of `attempts/` deliberately: a probe is not an attack attempt,
   and counting it as one would move the reproducibility denominator and the attempt count.

Grounded in prior art (LLMmap-style statistical fingerprinting; OpenAI `system_fingerprint`;
glitch-token behavior). Fingerprinting is **probabilistic**: always reported with a
confidence and the evidence, never as ground truth (providers can spoof; models hallucinate
their own identity).

## 1. Signal layers (combined into one verdict)

| Layer | Technique | Signals |
|---|---|---|
| **Passive / metadata** (no attack) | inspect response envelope & errors | `model` echo, OpenAI `system_fingerprint`, `finish_reason`/`stop_reason` vocab, role names (`assistant` vs `model`), tool-call schema shape, token-usage field names, HTTP headers, error JSON format, rate-limit header style |
| **Capability probes** | benign feature checks | tools/function-calling present? JSON/structured-output mode? vision? streaming? max context? `seed` support? |
| **Behavioral / active** | small fixed benign probe set (seeded) | self-identification prompt, knowledge-cutoff questions, refusal-style phrasing, markdown/formatting idioms, system-prompt echo style, known family "tells" |
| **Tokenizer / glitch** | probe known glitch tokens per family | e.g. GPT-family BPE artifacts vs Claude vs Llama tokenization behavior → distinguishes families |
| **Guardrail** | benign boundary nudges | pre/post moderation present? canned refusal strings? latency signature of a filter layer? input vs output filtering? |
| **Statistical (LLMmap-style)** | fixed query battery → embed responses → nearest-neighbor vs signature DB | robust family/version classification when self-report is unreliable |

The table is the design. As built, seven layers run and a pass sends 17 requests on the shipped
mutator set (each layer declares its `probe_count`, and the plan prints the sum): metadata 1,
**capability 0** (it reads the capabilities the target file declares and asks the target
nothing; its evidence is listed with weight 0 and never counts toward a family), behavioral 4,
tokenizer 1, guardrail 1, statistical 3 and carrier 7 (one per probed carrier). The metadata
layer still flattens the whole envelope, but the shipped pack matches only the `model` name in
it (see the attribution rules in §2). The statistical layer embeds nothing: it compares a
deterministic feature vector of the replies' structure with the signature pack's centroids
(OD-9). The CLI builds the seventh, carrier, layer; `FingerprintEngine()` on its own has six.

## 2. Output: `ModelFingerprint`

The block below is what `dottore fingerprint <target.yaml> --scope <scope.yaml> --offline`
printed on 2026-10-05 for an offline target with `mock_scenario: comprehending` and
`capabilities: {tools: false}` (keys and values as emitted). What each key holds:

- `family`: `{guess, confidence, cutoff_hint}`; `guess` is `unknown` with confidence 0.0 when no
  evidence attributes a family.
- `version`: `null`, or `{guess, confidence, cutoff_hint}`, the cutoff hint coming from the
  signature pack.
- `capability_guess`: **copied from the capabilities the target file declares, not probed.**
  The capability layer sends nothing (`probe_count = 0`); it reads `adapter.capabilities()`.
  `json_mode` mirrors the declared `tools` flag and `vision` mirrors `multimodal`; there is no
  context-size field. When the carrier layer recovered at least one carrier, the key
  `effective_mutators` lists them best-first: it is the one key the planner reads.
- `guardrails`: the profile the guardrail layer emits (`input_filter`, `output_filter`,
  `refusal_style`, `moderation_latency_ms`).
- `evidence`: `{layer, signal, weight}` per layer hit. The carrier-comprehension scores travel as
  the `carrier` entry.
- `spoofing_flags`: see below.
- `recommended_plan_ref`: always `null`; the u08 planner owns plan building (ADR-0006).

```json
{
  "target_id": "mock-comp",
  "family": {"guess": "unknown", "confidence": 0.0, "cutoff_hint": null},
  "version": null,
  "capability_guess": {"tools": false, "json_mode": false, "vision": false, "streaming": false,
                       "seed": false, "rag": false, "memory": false, "logprobs": false,
                       "effective_mutators": ["base64_wrap", "rot13", "translate",
                                              "zero_width_inject"]},
  "guardrails": {"input_filter": false, "moderation_latency_ms": null,
                 "output_filter": false, "refusal_style": "unknown"},
  "evidence": [
    {"layer": "capability", "signal": "family=meta-llama|capability tells ['tools=false']", "weight": 0.0},
    {"layer": "capability", "signal": "family=meta-llama|capability tells ['tools=false']", "weight": 0.0},
    {"layer": "guardrail", "signal": "guardrail_profile={\"input_filter\": false, \"moderation_latency_ms\": null, \"output_filter\": false, \"refusal_style\": \"unknown\"}", "weight": 0.0},
    {"layer": "carrier", "signal": "carrier_comprehension={\"base64_wrap\": 1.0, \"leetspeak\": 0.0, \"payload_splitting\": 0.0, \"rot13\": 1.0, \"translate\": 1.0, \"unicode_confusable\": 0.0, \"zero_width_inject\": 1.0}", "weight": 0.0}
  ],
  "spoofing_flags": ["non_discriminating_target"],
  "recommended_plan_ref": null
}
```

Note that the capability evidence above names `meta-llama` with weight 0: declared capabilities
are listed, never counted (see the attribution rules below). The family is `unknown` because the
target answered every attributing probe alike (the `non_discriminating_target` flag) and its
envelope has no `model` field. The statistical layer sent its three probes and emitted nothing,
because they got the same reply.

**Spoofing flags.** Two are emitted:

- `self_report_conflicts_with_statistical`: a self-report names a family the statistical layer
  disagrees with; the self-report is then left out of the family tally.
- `non_discriminating_target`: the target gave the **same reply text to every attributing
  probe**, with at least three probes answered. The carrier layer's probes are left out of the
  check, because a target may answer carriers differently (that is what comprehension measures)
  and every other probe alike. A constant reply carries no signal from the model, so the text
  layers' evidence is discarded for attribution: only metadata evidence that matched a `model=`
  field in the response envelope may name the family, and the version is kept only when one
  version clearly leads (a tie gives no version). With no such evidence the family is
  `unknown`. The evidence list still shows every layer's hits, and `run -sV` adds "[the target
  answered every attributing probe alike: no text signal]" to its fingerprint line. Every
  offline scenario trips it (`bare`, `vulnerable`, `hardened`, and `comprehending`, which gives
  every non-carrier probe the same "I do not understand" reply); before the flag, a constant mock
  was named `meta-llama` at 0.67 and a refuse-all target `llama-3-8b` with a 2023-03 cutoff.

**Attribution rules** (each one closes a case where a target was named without a signal, found
by the audit of the fingerprint that followed the full audit of 2026-10-03, and by the
pre-commit audit of its fix; figures measured on 2026-10-05 against the code before the fix):

- **A tie names nothing.** Two families with the same evidence mass give `unknown`; two versions
  of the guessed family with the same mass give `version: null`. A tie used to be broken by
  name, and every family-wide signal adds the same mass to each version of the family, so the
  alphabet picked `llama-3-8b` (with its 2023-03 cutoff), `gpt-4-turbo` or `claude-opus`.
- **The statistical layer ignores a canned responder.** If its three probes, which ask for
  different things, get fewer than three different reply texts, it emits no evidence: short,
  plain canned replies sat close to one centroid and named that family (a stub alternating two
  answers drew 0.41 of `meta-llama` evidence for each of two versions and was named `meta-llama`,
  version `llama-3-8b`, at 0.65, and still at 0.58 when its envelope said `gpt-4o`).
- **Declared capabilities never count.** The capability layer reads what the target file
  declares about the deployment, not anything the model did, so its evidence is listed with
  weight 0 (the pack has no capability weight). Counted, a target that gave no other evidence and
  declared no tools was `meta-llama` at 0.29, and the repo's own gpt-4o example (`tools: false`,
  `streaming: true`, the whole meta-llama profile) tied a real `model=gpt-4o` envelope into
  `unknown`.
- **An envelope-only attribution is capped at the metadata weight.** When only the metadata
  layer names the family (always the case for a `non_discriminating_target`), its share of the
  mass is 1 by construction: a constant target whose envelope said `gpt-4o` was named at 0.52 on
  that one field. The family's confidence, and the version's, are now at most the pack's
  metadata weight for that family (0.4 in the shipped pack).
- **Only the `model` name counts from the envelope.** Every OpenAI-compatible server sends
  `finish_reason=stop`, and the bare key `system_fingerprint` matched whatever value a
  compatible server put there (or none): a Qwen model behind a server sending
  `system_fingerprint: fp_ollama` was `openai-gpt`, version `gpt-4-turbo`, at 0.42. Claude's
  `stop_reason` and `role=assistant` fragments could never match, because the Anthropic adapter
  reports the stop reason as `finish_reason` and keeps only `id` and `model`, so a real Claude
  envelope was worth a third of the others. The pack's metadata signals are now `model=` names only.
  `model=meta-llama` is listed beside `model=llama`, so a vLLM name such as
  `meta-llama/Meta-Llama-3-8B-Instruct` is recognised, and an entry's `model=` fragments are
  alternatives that fill one slot (an envelope carries one model name; counted as two, they
  held meta-llama at half its weight). The live adapters redact a string `model` echo without
  the entropy rule (patterns and known credentials still apply), in memory only: mixed-case
  names like that one were masked as high-entropy before the metadata layer could read them.
  What is stored (evidence, run store, reports) still gets the full redactor, so a stored model
  name of that shape is masked.
- **A live probe reports the target file's capabilities.** `dottore fingerprint` and `run -sV`
  on a live target wrap the adapter so `capability_guess` and the capability layer read the
  `capabilities` the target file declares, not the adapter's defaults (OpenAI: `tools`,
  `streaming`, `seed` and `logprobs` all true, so `tools: false` in the file reported
  `tools: true`).

**Known limits (left open).** The statistical centroids are coarse: short, distinct replies land
near the `meta-llama` centroid, which can outvote a real `model=` name (a gpt-4o or a Claude
answering in short sentences, with its model name in the envelope, was `meta-llama` at 0.39 on
2026-10-05, through the real OpenAI adapter on a mock transport). By design
the statistical layer outranks what a target says about itself, so whether a `model=` name
should win over it is the owner's call. The envelope cap is a cliff: one more weak hit from
another layer (a generic refusal phrase several families share) lifts a family named by its
envelope above 0.4. A capability weight in a custom pack is ignored.

Within a family, the shipped pack's versions share every signal except the behavioral
fragments, so a version is named only from what the model says about itself (for example
"sonnet" in its self-description), the weakest and most easily spoofed channel; otherwise the
version is `null`.

- Every fingerprint run is **reproducible** (fixed seeded probe battery, evidence stored like
  any attempt: `docs/07`).
- **Signature DB** is a versioned data pack, not code: it ships in-repo under
  `src/ildottore/fingerprint/signatures/`, validated by `fingerprint/signatures.py` on load, so
  new models = update the signature pack, not the engine. Ships with a self-test corpus.

## 3. Adaptive test-plan tailoring (the first-pass role)

What the planner does today, with and without a fingerprint:

1. **Filters by capability**, from the capabilities the **target file declares**, not from the
   fingerprint, and with or without `-sV`: no `tools` ⇒ the specs that require tools are
   skipped as `inconclusive: capability_unavailable` (never a pass), and likewise for `rag`,
   `memory`, `logprobs`, `multi_identity` and the rest.
2. **Orders each spec's mutators by carrier comprehension** (built, see the introduction above
   §1): the carriers the target recovered move to the front, in the spec's declared order; the
   rest follow, in declared order. It selects no spec and drops no variant.
3. **Does not set baseline expectations.** The design was to record the family's known
   resistance and score a result relative to it. That half is the dead `_baseline_resistance`
   hook described above §1: nothing writes the guardrails key it reads, and nothing reads the
   plan field it fills (OD-17, ADR-0008). The same
   goes for the original idea of weighting variants "historically effective against the
   detected family", which the introduction rejects for lack of an empirical basis.
4. **Emits an explicit, reviewable `TestPlan`** (which specs, why, which were skipped and why).
   Nothing is silently dropped: skipped tests are logged (per `docs/07` "no silent caps").

Tailoring is OFF unless a fingerprint exists: only `-sV` (or `-A`, which implies it) produces
one. `--deep` alone switches the planner to adaptive mode, but with no fingerprint there is
nothing to order by, so the declared order is kept. Without `-sV`/`-A` the full selected suite
runs untailored (there is no `--no-adaptive` flag on the CLI; the pass-through is the default,
and `core.planner.build_plan(adaptive=False)` is what implements it when `--deep` is absent
too), which is what apples-to-apples benchmarking across models needs.

## 4. CLI surface

```bash
dottore fingerprint target.yaml --scope scope.yaml       # standalone recognition, no attacks
dottore run -sn -t target.yaml --scope scope.yaml        # discovery only: sends NOTHING
dottore run -sV --suite owasp:llm -t target.yaml ...     # fingerprint → tailored scan
dottore run --suite owasp:llm ...                        # no -sV ⇒ no tailoring (parity)
```

## 5. Safety

- Fingerprinting uses only **benign** probes (no jailbreak payloads); still gated by the scope
  allowlist. It is the safest mode and the right default first step on an unknown endpoint.
- Behavioral self-identification is treated as a *weak* signal; contradictions with the
  statistical layer are surfaced as `spoofing_flags`, never hidden.

## 6. Validation (ties to `docs/07`)

- Signature DB ships a labeled corpus; CI measures **family precision/recall** and
  **version top-1/top-3 accuracy**, gated so a signature-pack update can't regress recognition.
- Determinism: same target + seed ⇒ same fingerprint verdict.
