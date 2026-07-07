# 12 — Gaps & backlog (prioritized coverage roadmap)

Honest gap analysis of Il Dottore's LLM-security coverage, prioritized. This is the living
"what's missing" list. **Legend:** P0 = needed for a credible LLM security scanner ·
P1 = strong differentiator / real attack surface · P2 = later.
**Status:** ✅ specced & scheduled · 🟡 partially specced · ⬜ not yet.

## P0 — in scope for MVP‑1 (capabilities are hard to retrofit later)

| Gap | Status | Where | Target |
|-----|--------|-------|--------|
| **Data-leak / memorization family** (leak-by-asking: RAG enum, cross-tenant, memory, divergence, prefix-completion, verbatim, membership, canary) | ✅ | `docs/11` | MVP‑1 (layer A + divergence + cross-tenant); MVP‑2 (membership) |
| **PII / secret-shape evaluators with FP control** (Luhn, IBAN mod-97, key prefixes, entropy; hallucination ≠ leak) | ✅ | `docs/04`, `docs/11 §4` | MVP‑1 |
| **Logprobs capture in adapters** (membership inference, confidence side-channels) | ✅ | `docs/00` (stack + Phase D), `docs/01 §3` | capture MVP‑1 · membership MVP‑2 |
| **Multi-identity / cross-tenant harness** (authz_leak evaluator, ≥2 identities in scope) | ✅ | `docs/00` (Phase A), `docs/01 §6`, `docs/11 §3` | MVP‑1 |
| **Multimodal** (image/audio/document injection; visual/typographic PI) | ✅ (own phase) | `docs/00` (Phase G) | MVP‑3 (highest cost, highest differentiator) |

## P1 — MVP‑2

| Gap | Status | Note |
|-----|--------|------|
| **Adversarial-suffix / transfer attacks** (GCG-style, black-box transferable jailbreaks) | ⬜ | state-of-the-art automated jailbreak; today only hand-authored variants |
| **Guardrail / moderation-layer evasion** as its own target | 🟡 | fingerprint detects the filter (`docs/10`); need specs that attack the filter, in+out |
| **Embedding / vector-store attacks (LLM08)** (embedding inversion, neighbor retrieval, cross-tenant index leak) | 🟡 | placeholder in `docs/08 §4`; needs a vector-store target type |
| **Defined multilingual battery** (low-resource-language jailbreaks) | 🟡 | `translate:<lang>` mutator exists; need a systematic measured battery |
| **Baseline diff / drift across versions** ("did this model get worse?") | ⬜ | `replay` exists; need baseline compare + regression report for CI |
| **Coverage metric** (report % of OWASP/ATLAS actually exercised) | ⬜ | prevents "passed the scan" from misleading |
| **Function-calling / structured-output attacks** (JSON-schema poisoning, arg smuggling) | 🟡 | partially under tool-abuse; deepen |
| **Finding dedupe across mutations** (1 vuln × N variants → 1 finding w/ variants) | ⬜ | signal/noise; a variant explosion looks like N bugs |
| **Agentic-extortion / JadePuffer-class susceptibility** (`docs/13`) | ✅ specced (2 specs + suite) | full `agentic-extortion` pack (7 specs) + `kill_chain_progression` L3 evaluator = build under u13/u06; policy-gated OFF |

## P2 — later

| Gap | Note |
|-----|------|
| Streaming pre-moderation leakage | partial output before the output filter fires |
| Timing / token-probability side-channels | infra-dependent |
| Pre-run cost estimate (`--dry-run $`) | budget planning |
| Human-in-the-loop feedback loop | calibrate judge + labels from operator triage |
| Bias / toxicity / fairness pack | adjacent to security; NIST wants it — ship as optional pack, not core |

## Standing note

Il Dottore is currently **100% design/spec** — nothing is validated by execution yet. The
single biggest "gap" until Phase A–F land is that it is unbuilt. The methodology
(repro + evidence + risk mapping, judge hardening, self-validation, extensibility) is the
strength; coverage breadth (above) and building it are the work.
