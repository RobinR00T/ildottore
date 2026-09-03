# 10 - Model fingerprinting engine (`-sV` / standalone recon)

Two roles for fingerprinting - both first-class:

1. **Standalone recognition** (`dottore fingerprint <target>` or `dottore -sV -sn`): identify
   *what model, which version, which guardrails and capabilities* sit behind an endpoint, and
   stop. Nothing else is attacked. This is the nmap `-sV` / banner-grab analogue and a useful
   product on its own (asset discovery of AI endpoints).
2. **Adaptive first pass** (`-sV` before a scan): the fingerprint drives **test-plan
   tailoring** - pick the relevant specs, tune mutators to what's known-effective against that
   family, skip inapplicable tests, and set the expected baseline resistance.

Grounded in prior art (LLMmap-style statistical fingerprinting; OpenAI `system_fingerprint`;
glitch-token behavior). Fingerprinting is **probabilistic** - always reported with a
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

## 2. Output - `ModelFingerprint`

```json
{
  "target_id": "unknown-endpoint-1",
  "family": {"guess": "anthropic-claude", "confidence": 0.93},
  "version": {"guess": "claude-opus-4.x", "confidence": 0.71, "cutoff_hint": "…"},
  "capabilities": {"tools": true, "json_mode": true, "vision": false,
                   "streaming": true, "seed": false, "max_context_tokens": 200000},
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
  any attempt - `docs/07`).
- **Signature DB** is a versioned, pluggable data pack (`frameworks/`-style, `docs/06`): new
  models = update the signature pack, not the code. Ships with a self-test corpus.

## 3. Adaptive test-plan tailoring (the first-pass role)

Given a `ModelFingerprint`, the planner:

1. **Filters by capability** - no `tools` ⇒ drop `agent_tool_abuse`; no `rag` ⇒ drop RAG specs
   (or mark `inconclusive: capability_unavailable`).
2. **Selects family-effective specs/mutators** - e.g. weight encoding/roleplay variants that
   are historically effective against the detected family; skip variants known to be no-ops.
3. **Sets baseline expectations** - records the family's known resistance so a result is scored
   *relative to expectation* (a jailbreak that works on a normally-hardened family is more
   notable).
4. **Emits an explicit, reviewable `TestPlan`** (which specs, why, which were skipped and why).
   Nothing is silently dropped - skipped tests are logged (per `docs/07` "no silent caps").

`--no-adaptive` disables tailoring and runs the full selected suite regardless (for
apples-to-apples benchmarking across models).

## 4. CLI surface

```bash
dottore fingerprint <target> --scope scope.yaml          # standalone recognition, no attacks
dottore -sV -sn -t target.yaml --scope scope.yaml        # same, nmap-style flags
dottore -sV --suite owasp:llm -t target.yaml ...         # fingerprint → tailored scan
dottore --suite owasp:llm --no-adaptive ...              # skip tailoring (benchmark parity)
dottore fingerprint <target> -oJ fp.json                 # machine output
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
