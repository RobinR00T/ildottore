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

   The other hook, `_baseline_resistance` (a per-category expectation read from
   `guardrails["baseline_resistance"]`), is **dead at both ends**: unwritten by the engine, and
   the `PlanSelection.baseline_resistance` it fills has no reader anywhere in `src/` (OD-17).
   Unwritten because: benign probes
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

## 2. Output: `ModelFingerprint`

The shape below is what `dottore fingerprint <target.yaml> --scope <scope.yaml>` prints (keys
as emitted; the values are illustrative). Capabilities are a guess from probes, under
`capability_guess`, and carry no context-size field. The carrier-comprehension scores travel as
an evidence entry (`layer: carrier`).

```json
{
  "target_id": "unknown-endpoint-1",
  "family": {"guess": "anthropic-claude", "confidence": 0.93},
  "version": {"guess": "claude-opus-4.x", "confidence": 0.71, "cutoff_hint": "…"},
  "capability_guess": {"tools": true, "json_mode": true, "vision": false, "streaming": true,
                       "seed": false, "rag": false, "memory": false, "logprobs": false},
  "guardrails": {"input_filter": true, "output_filter": true,
                 "refusal_style": "polite-explain", "moderation_latency_ms": 140},
  "evidence": [{"layer": "metadata", "signal": "system_fingerprint=fp_…", "weight": 0.4},
               {"layer": "behavioral", "signal": "self-id: 'I am Claude'", "weight": 0.2},
               {"layer": "statistical", "signal": "nn-dist 0.08 vs claude-opus sig", "weight": 0.4}],
  "spoofing_flags": ["self_report_conflicts_with_statistical"],   // honesty about contradictions
  "recommended_plan_ref": "plan_2026_07_07_001"
}
```

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
   hook described above §1: nothing writes it and nothing reads it (OD-17, ADR-0008). The same
   goes for the original idea of weighting variants "historically effective against the
   detected family", which the introduction rejects for lack of an empirical basis.
4. **Emits an explicit, reviewable `TestPlan`** (which specs, why, which were skipped and why).
   Nothing is silently dropped: skipped tests are logged (per `docs/07` "no silent caps").

Tailoring is OFF unless a fingerprint exists: only `-sV` (or `-A`, which implies it) produces
one. `--deep` alone switches the planner to adaptive mode, but with no fingerprint there is
nothing to order by, so the declared order is kept. Without `-sV`/`-A` the full selected suite
runs untailored (there is no `--no-adaptive` flag on the CLI; the pass-through is the default,
and `core.planner.build_plan(adaptive=False)` is what implements it), which is what
apples-to-apples benchmarking across models needs.

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
