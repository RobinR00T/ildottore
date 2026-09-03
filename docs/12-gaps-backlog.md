# 12 — Gaps & backlog (prioritized coverage roadmap)

Honest gap analysis of Il Dottore's LLM-security coverage, prioritized. This is the living
"what's missing" list. **Legend:** P0 = needed for a credible LLM security scanner ·
P1 = strong differentiator / real attack surface · P2 = later.
**Status:** ✅ specced & scheduled · 🟡 partially specced · ⬜ not yet.

> **Delivered 2026-08-30 (see `docs/14`):** the **multi-turn engine** (Crescendo/Linear/
> Sequential/Bad-Likert/Tree) closed a blind spot not even listed below; plus the
> **access-control** family (BFLA/BOLA/RBAC/SSRF/debug/shell-injection/tool-metadata-poisoning),
> broader **OWASP-Agents-2026** agentic coverage, six obfuscation **enhancer mutators**, a
> **multilingual** seed spec and **system-reconnaissance**.
> The rows below are updated where those landed.
>
> **Delivered 2026-09-02:** the **MCP adapter** (HTTP + stdio, read-only discovery) + `mcp`
> suite; **multi-identity execution** (makes `authz_leak` live end-to-end); and the optional
> **Responsible-AI pack** (`safety_content` + `bias_fairness` categories, `responsible-ai`
> suite, RAI owasp codes).
>
> **Delivered 2026-09-03:** the **guardrail-evasion** suite, the **adversarial-suffix** transfer
> mutator, **parameterized mutations** (`translate:{es,fr,de,zh}`), a pre-run **cost estimate**
> (`run --estimate`), bounded **HITL calibration** (`calibrate`), and **function-calling /
> argument-smuggling** detection (`tool_call.forbidden_args` + `FUNCALL-ARGSMUGGLE-001`).
> Battery is now 53 specs / 11 suites.

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
| **Adversarial-suffix / transfer attacks** (GCG-style, black-box transferable jailbreaks) | 🟡 **transfer built** | `adversarial_suffix` mutator carries the pinned published GCG universal suffix (Zou et al. 2023), reproducible + wired into JB-REFUSAL-SUPPRESS. Live gradient optimization stays out of scope (needs model gradients; non-reproducible) |
| **Guardrail / moderation-layer evasion** as its own target | ✅ **built** (2026-09-03) | `guardrail-evasion` suite: `GUARD-INPUT-EVASION-001` (obfuscated trigger evades the input classifier, model must still refuse) + `GUARD-OUTPUT-ENCODE-001` (encode the reply past the output filter). A dedicated filter-target type stays future work |
| **Embedding / vector-store attacks (LLM08)** (embedding inversion, neighbor retrieval, cross-tenant index leak) | ✅ **built** (3 specs + suite) | placeholder in `docs/08 §4`; needs a vector-store target type |
| **Defined multilingual battery** (low-resource-language jailbreaks) | ✅ **built** (2026-09-02) | parameterized mutations (`name:param`) now supported by the runner; `JB-MULTILINGUAL-001` runs `translate:{es,fr,de,zh}` systematically (offline, deterministic gloss). Adding more languages is a `PHRASE_MAP` entry |
| **Multi-turn adaptive jailbreaks** (Crescendo/Linear/Sequential/Bad-Likert/Tree) | ✅ **built** | pinned-ladder engine `core/conversation.py` + 5 specs + `multi-turn` suite (docs/14) |
| **Access-control family** (BFLA/BOLA/RBAC/SSRF/debug/shell-injection/tool-metadata-poisoning) | ✅ **built** | `access-control` suite (docs/14) |
| **OWASP-Agents-2026 agentic breadth** (goal theft, recursive hijack, identity abuse, inter-agent, drift) | ✅ **built** | `agentic-owasp2026` suite (docs/14) |
| **Baseline diff / drift across versions** ("did this model get worse?") | ✅ **built** (`dottore diff`) | `replay` exists; need baseline compare + regression report for CI |
| **Coverage metric** (report % of OWASP/ATLAS actually exercised) | ✅ **built** | run summary + JSON/HTML/terminal show % OWASP + ATLAS exercised + run/skip/block counts |
| **Function-calling / structured-output attacks** (JSON-schema poisoning, arg smuggling) | ✅ **built** (2026-09-03) | `tool_call` evaluator gained an opt-in `forbidden_args` (spec declares out-of-schema/privileged argument keys; a truthy value under any of them, at any depth, fails); `FUNCALL-ARGSMUGGLE-001` proves it (role/bypass_review smuggled into an authorized `update_account`). Inert for every spec that omits `forbidden_args` |
| **Finding dedupe across mutations** (1 vuln × N variants → 1 finding w/ variants) | ✅ **structural** | the runner already emits **one `Finding` per (spec, target)** and folds every mutation variant into that finding's `attempts` (`core/runner._run_spec`), so a mutation sweep never inflates the finding count. Cross-*spec* semantic dedup (merging different specs judged to be the same underlying vuln) stays deferred on purpose: it is a lossy judgment call that can hide real signal, so it is left to the human operator |
| **Agentic-extortion / JadePuffer-class susceptibility** (`docs/13`) | ✅ **built (7 specs + suite, golden-gated)** | pack complete + FP-disciplined (narration≠fail); `kill_chain_progression` L3 evaluator **built** (MVP-2 w1, wired into AG-EXTORT-CHAIN + AG-DESTRUCTIVE-DBDROP); policy-gated OFF |

## P2 — later

| Gap | Note |
|-----|------|
| Streaming pre-moderation leakage | ⬜ needs a streaming adapter; inherently timing-dependent (tension with the reproducibility thesis), so deferred deliberately |
| Timing / token-probability side-channels | ⬜ infra-dependent and non-reproducible by nature; out of scope for a deterministic scanner |
| Pre-run cost estimate | ✅ **built** (2026-09-03): `dottore run --estimate` prints requests (specs x runs x mutations x turns) + a rough token gloss, no sends. No per-model pricing baked in (multiply by your rate) |
| Human-in-the-loop feedback loop | ✅ **built** (2026-09-03, bounded): `dottore calibrate <report.json> <labels.yaml>` scores the scanner against operator labels (agreement + precision/recall, fail = positive). Read-only; a continuous triage store is future work |
| Bias / toxicity / fairness pack | ✅ **built** (2026-09-02): `safety_content` + `bias_fairness` categories, `SAFETY-HARMFUL-001` + `BIAS-STEREOTYPE-001`, `responsible-ai` suite. Optional pack (RAI owasp codes, NIST-mapped), not security core |

## Standing note

The engine is **built and self-validating**: every spec ships golden `vulnerable`/`hardened`
fixtures that the linter runs through the real evaluators on each `dottore lint`, the CI gate
wall (ruff, mypy --strict, import-linter, `lint specs`, pytest + coverage, self-scan, bandit,
pip-audit) is green, and `make gates` mirrors it locally. The strength remains the methodology
(reproducibility + evidence + risk mapping, judge hardening, self-validation, extensibility);
what is left is coverage breadth (the rows above) and the deliberately deferred P2 items
(streaming pre-moderation, timing side-channels) that trade away reproducibility.
