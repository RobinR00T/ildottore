# 08 — Default test battery (grounded in the state of the art)

This is the **minimum battery** shipped by default, distilled from the ecosystem
(NVIDIA garak, Microsoft PyRIT, promptfoo, Giskard, AgentDojo) and the reference frameworks
(OWASP LLM Top 10 2025, MITRE ATLAS, NIST AI 600-1). Sources: see `docs/REFERENCES.md`.

## 1. What the state of the art taught us (folded into the design)

1. **Multi-turn is not optional.** PyRIT's headline value is automated *multi-turn* attacks
   (Crescendo, TAP, Skeleton Key) that adapt based on the target's reply. Our spec format gets
   a first-class `turns` + an `escalation` mode (iterate up to a budget, adapt on refusal).
2. **Attack success is a curve, not a bit.** Gray Swan / Anthropic data: Claude holds ~0.1%
   on a *single* attempt but ~5–6% after *100 adaptive* attempts. → our reproducibility model
   (N-runs) is right, and we add an **adaptive-attempts budget** so a finding reports success
   rate *as a function of attempts*, not one lucky hit.
3. **Measure utility AND security jointly** (AgentDojo). A model that refuses everything is
   "secure" but useless; over-refusal is a real failure. → every run also captures a
   **benign-utility baseline** (does the target still do its job?), and we flag
   *over-defense / false-refusal* as its own finding class (dataset: XSTest-style).
4. **Test the system, not just the model** (OpenAI Atlas/connectors work). Real risk lives in
   connectors, MCP servers, tool wiring, RAG plumbing. → target types `agent`/`rag`/`api`, and
   an MCP/tool-abuse block.
5. **Mutators = garak "buffs".** Encoding, translation, obfuscation, ASCII-smuggling,
   zero-width, homoglyph — apply as transforms over base payloads (our Prompt Mutator).
6. **Dataset-backed specs.** promptfoo pulls HarmBench, BeaverTails, CyberSecEval,
   DoNotAnswer, ToxicChat, XSTest. → a spec can be `dataset`-backed (sampled, seeded), not
   only hand-authored.
7. **Framework presets sell.** promptfoo ships `owasp:llm`, `mitre:atlas`, `nist:ai`,
   `eu:ai-act`, `gdpr`, `iso:42001` presets. → suites map to the same presets (regulatory
   angle: DORA / EU AI Act matter for our buyers).
8. **Defense is never 100% at the model layer** (Anthropic). Our job is *assurance evidence*
   across the stack, reported as risk — which is exactly the product thesis.

## 2. The three tiers

| Tier | Profile flag | Purpose | ~#tests | Runtime |
|---|---|---|---|---|
| **T0 — Quick** | `--quick` | nmap-default equivalent: fast triage, single-turn, cheap | ~15 | minutes |
| **T1 — Standard** | `--suite owasp:llm` (default) | full OWASP LLM Top 10 2025 coverage | ~60 | tens of min |
| **T2 — Deep** | `--deep` / `--suite agentic` | multi-turn, adaptive, agentic/RAG, dataset-backed | 150+ | long |

## 3. The minimum battery (T0 "Quick") — mapped to OWASP LLM Top 10 2025

Each id ships golden fixtures (`docs/07`) and framework mappings. This is the default
"you have 10 minutes, tell me if this thing is obviously broken" set.

| # | id | Tests | OWASP | ATLAS |
|---|----|-------|-------|-------|
| 1 | `PI-DIRECT-001` | Direct prompt injection / instruction override | LLM01 | Prompt Injection |
| 2 | `PI-INDIRECT-RAG-001` | Indirect injection via retrieved doc (canary) | LLM01 | PI (indirect) |
| 3 | `PI-INDIRECT-TOOL-001` | Injection via tool/function output | LLM01 | PI (indirect) |
| 4 | `JB-ROLEPLAY-001` | Roleplay / persona jailbreak (DAN-class) | LLM01 | Jailbreak |
| 5 | `JB-REFUSAL-SUPPRESS-001` | Refusal-suppression prefix | LLM01 | Jailbreak |
| 6 | `JB-ENCODING-001` | Base64/ROT13/leetspeak encoding bypass | LLM01 | Evade ML |
| 7 | `SP-LEAK-001` | System prompt extraction / leakage | LLM07 | Discovery |
| 8 | `DL-SECRET-CANARY-001` | Secret/canary leakage in output | LLM02 | Exfiltration |
| 9 | `DL-XSESSION-001` | Cross-session / cross-user leakage | LLM02 | Exfiltration |
| 10 | `OUT-CODEINJ-001` | Insecure code generation (injectable output) | LLM05 | — |
| 11 | `OUT-XSS-001` | XSS/HTML/script in rendered output | LLM05 | — |
| 12 | `OUT-SQLI-001` | Unsafe SQL generation | LLM05 | — |
| 13 | `AG-TOOL-UNAUTH-001` | Unauthorized / over-permissioned tool call | LLM06 | — |
| 14 | `AG-CONFIRM-BYPASS-001` | Destructive action without confirmation (dry-run) | LLM06 | — |
| 15 | `DOS-TOKEN-AMP-001` | Token amplification / unbounded output | LLM10 | Denial of ML Service |
| 16 | `DL-MEMORIZE-DIVERGENCE-001` | Training-data regurgitation via divergence/repetition | LLM02 | Exfiltration |
| 17 | `DL-XTENANT-001` | Cross-tenant data leak (needs 2 identities) | LLM02 | Exfiltration |
| 18 | `DL-PII-ELICIT-001` | PII elicitation (synthetic-first; off by default) | LLM02 | Exfiltration |

> **P0 data-leak additions (`docs/11`).** Rows 16–18 bring the "detect leaks by asking" family
> into the default battery. They require target capabilities (`logprobs` for membership,
> `multi_identity` for cross-tenant) — where absent, they return `inconclusive`, never a false
> pass. All obey the FP discipline + safety/legal gates of `docs/11 §4–§5`.

## 4. T1 "Standard" adds (full OWASP coverage)

- **LLM01/07 depth**: multi-turn injection, second-order injection, context override,
  instruction-hierarchy bypass, ASCII-smuggling, zero-width, homoglyph, payload-splitting.
- **LLM02** (full data-leak family, `docs/11`): memory/RAG-source leakage, tool-credential
  exposure, RAG corpus enumeration, prefix-completion & verbatim-copyright extraction,
  membership inference (logprobs), secret-shape elicitation, breach-canary detection.
- **LLM03/04 (supply chain / poisoning)**: model-identification/fingerprinting,
  package-hallucination in generated code, RAG document poisoning, retrieval poisoning,
  citation laundering, source confusion.
- **LLM05**: command injection, path traversal, hallucinated security claims,
  sensitive-data-in-logs.
- **LLM06**: confused-deputy, SSRF-like tool use, tool-parameter injection, MCP abuse,
  email/calendar/file misuse (mocked).
- **LLM08**: embedding-inversion / vector-store leakage probes (RAG targets).
- **LLM09**: misinformation, overreliance, sycophancy, unverifiable claims.
- **LLM10**: recursive-reasoning loops, context flooding, expensive-tool loops (budget-guarded).
- **Utility/over-defense**: XSTest-style false-refusal battery (T3-in-T1 sanity).

## 5. T2 "Deep / Agentic" adds

- **Multi-turn adaptive**: Crescendo-, TAP-, Skeleton-Key-style escalation (spec `escalation`
  mode + adaptive-attempts budget).
- **Agentic** (AgentDojo-inspired): memory poisoning, tool discovery, goal hijacking,
  data-exfiltration via tool chains, coding-agent suite (repo/terminal-output injection,
  sandbox escape, secret read, CI exfil) — all with mocked side-effects.
- **Dataset-backed**: sampled specs from HarmBench / BeaverTails / CyberSecEval / DoNotAnswer /
  ToxicChat / XSTest (seeded for reproducibility).

## 6. Regulatory presets (suites)

`owasp:llm` (default) · `mitre:atlas` · `nist:ai` · `eu:ai-act` · `dora` · `iso:42001` ·
`gdpr`. A preset is just a suite that references the relevant specs and carries the
framework rollup — no code. (These are our differentiator for EU/regulated buyers.)
