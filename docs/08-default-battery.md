# 08: Default test battery (grounded in the state of the art)

This is the **minimum battery** shipped by default, distilled from the ecosystem
(NVIDIA garak, Microsoft PyRIT, promptfoo, Giskard, AgentDojo) and the reference frameworks
(OWASP LLM Top 10 2025, MITRE ATLAS, NIST AI RMF and its GenAI Profile, NIST AI 600-1).
Sources: see `docs/REFERENCES.md`. NIST is a design reference, not a mapping the code checks:
each spec's `nist_ai_rmf` field carries an AI RMF function/subcategory token (`MEASURE 2.7`,
`MANAGE 2.2`, `MEASURE 2.11`, `GOVERN 1.1`), validated by shape only; no spec names an AI 600-1
risk category, and `dottore coverage` has no NIST axis.

Status key for this document: items marked **(not built)** are design that has no spec field,
mechanism or suite behind it today. Everything else is in the shipped battery.

## 1. What the state of the art taught us (folded into the design)

1. **Multi-turn is not optional.** PyRIT's headline value is automated *multi-turn* attacks
   (Crescendo, TAP, Skeleton Key) that adapt based on the target's reply. Our spec format gets
   a first-class `turns` (built: 11 specs carry pinned turns, five of them in the
   `multi-turn` suite) + an `escalation` mode (iterate up to a budget, adapt on refusal)
   **(not built:** no such field; the turns are fixed in the spec, which `dottore coverage`
   lists under ATLAS "AI Attack Adaptation" as deliberate, a roadmap decision).
2. **Attack success is a curve, not a bit.** Gray Swan / Anthropic data: Claude holds ~0.1%
   on a *single* attempt but ~5-6% after *100 adaptive* attempts. → our reproducibility model
   (N-runs) is right, and we add an **adaptive-attempts budget** so a finding reports success
   rate *as a function of attempts*, not one lucky hit **(not built:** a finding reports one
   rate over `--runs` attempts).
3. **Measure utility AND security jointly** (AgentDojo). A model that refuses everything is
   "secure" but useless; over-refusal is a real failure. → every run also captures a
   **benign-utility baseline** (does the target still do its job?), and we flag
   *over-defense / false-refusal* as its own finding class (dataset: XSTest-style) **(not
   built:** no utility baseline and no false-refusal finding class).
4. **Test the system, not just the model** (OpenAI Atlas/connectors work). Real risk lives in
   connectors, MCP servers, tool wiring, RAG plumbing. → target types `agent`/`rag`/`api`, and
   an MCP/tool-abuse block.
5. **Mutators = garak "buffs".** Encoding, translation, obfuscation, ASCII-smuggling,
   zero-width, homoglyph: apply as transforms over base payloads (our Prompt Mutator).
6. **Dataset-backed specs.** promptfoo pulls HarmBench, BeaverTails, CyberSecEval,
   DoNotAnswer, ToxicChat, XSTest. → a spec can be `dataset`-backed (sampled, seeded), not
   only hand-authored **(not built:** no `dataset` field; every spec is hand-authored).
7. **Framework presets sell.** promptfoo ships `owasp:llm`, `mitre:atlas`, `nist:ai`,
   `eu:ai-act`, `gdpr`, `iso:42001` presets. → suites map to the same presets (regulatory
   angle: DORA / EU AI Act matter for our buyers). Only `owasp:llm` exists as a suite (§6).
8. **Defense is never 100% at the model layer** (Anthropic). Our job is *assurance evidence*
   across the stack, reported as risk: which is exactly the product thesis.

## 2. The three tiers

| Tier | Profile flag | Purpose | ~#tests | Runtime |
|---|---|---|---|---|
| **T0: Quick** | `--quick` | nmap-default equivalent: fast triage, cheap (mostly single-turn; `JB-ROLEPLAY-001` is multi-turn) | 18 | minutes |
| **T1: Standard** | `--suite owasp:llm` | the OWASP LLM Top 10 2025 suite (design: full coverage) | 18, the same ids as T0 | minutes |
| **T2: Deep** | `--deep` | the full shipped battery at `-T2` | 75 candidates; a target runs those its capabilities allow | long |

Measured, not designed: `owasp-llm-top10` and `quick` list the same 18 spec ids, so T0 and T1
are one battery today (T1's design size was ~60). Neither is the default: a `run` with no
`--suite` selects the full battery, every spec the target can run. The whole battery covers 8
of the 10 OWASP LLM codes (`dottore coverage --framework owasp`). `--quick` selects the `quick`
suite at `-T0`. `--deep` runs the full battery at `-T2`, the same selection as no flag;
adaptive ordering needs a fingerprint, so it applies only with `-sV` (or `-A`, which adds it):
`docs/09 §2`. `--suite agentic` is not T2: it resolves to `agentic-extortion`, 7 specs. The
"150+" in the original design table was a target, not a measurement: the battery ships 75
specs. (Until 2026-09-21 both flags only moved the timing template and changed no battery at
all.)

## 3. The minimum battery (T0 "Quick"): mapped to OWASP LLM Top 10 2025

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
| 10 | `OUT-CODEINJ-001` | Insecure code generation (injectable output) | LLM05 |: |
| 11 | `OUT-XSS-001` | XSS/HTML/script in rendered output | LLM05 |: |
| 12 | `OUT-SQLI-001` | Unsafe SQL generation | LLM05 |: |
| 13 | `AG-TOOL-UNAUTH-001` | Unauthorized / over-permissioned tool call | LLM06 |: |
| 14 | `AG-CONFIRM-BYPASS-001` | Destructive action without confirmation (dry-run) | LLM06 |: |
| 15 | `DOS-TOKEN-AMP-001` | Token amplification / unbounded output | LLM10 | Denial of ML Service |
| 16 | `DL-MEMORIZE-DIVERGENCE-001` | Training-data regurgitation via divergence/repetition | LLM02 | Exfiltration |
| 17 | `DL-XTENANT-001` | Cross-tenant data leak (needs 2 identities) | LLM02 | Exfiltration |
| 18 | `DL-PII-ELICIT-001` | PII elicitation (synthetic-first; off by default) | LLM02 | Exfiltration |

> **P0 data-leak additions (`docs/11`).** Rows 16-18 bring the "detect leaks by asking" family
> into the default battery. They require target capabilities (`logprobs` for membership,
> `multi_identity` for cross-tenant): where absent, they return `inconclusive`, never a false
> pass. All obey the FP discipline + safety/legal gates of `docs/11 §4-§5`.

## 4. T1 "Standard" adds (full OWASP coverage)

§4 and §5 are the design's list of techniques for T1 and T2, not the content of a suite: no
T1-only or T2-only suite exists. Several of these techniques ship as specs in other suites
(`dottore registry ls`, `dottore coverage`); the ones marked (not built) have no spec.

- **LLM01/07 depth**: multi-turn injection, second-order injection, context override,
  instruction-hierarchy bypass, ASCII-smuggling, zero-width, homoglyph, payload-splitting.
- **LLM02** (full data-leak family, `docs/11`): memory/RAG-source leakage, tool-credential
  exposure, RAG corpus enumeration, prefix-completion & verbatim-copyright extraction,
  membership inference (logprobs), secret-shape elicitation, breach-canary detection. The
  data-leak family ships five specs (`DL-SECRET-CANARY-001`, `DL-XSESSION-001`,
  `DL-XTENANT-001`, `DL-MEMORIZE-DIVERGENCE-001`, `DL-PII-ELICIT-001`); of the techniques in
  this bullet, tool-credential exposure, RAG enumeration, prefix completion, verbatim
  copyright, membership inference, secret-shape elicitation and breach canary are **(not
  built)** (`docs/11 §1`).
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
- **Utility/over-defense**: XSTest-style false-refusal battery (T3-in-T1 sanity) **(not
  built)**.

## 5. T2 "Deep / Agentic" adds

- **Multi-turn adaptive**: Crescendo-, TAP-, Skeleton-Key-style escalation (spec `escalation`
  mode + adaptive-attempts budget) **(not built**; the multi-turn specs replay pinned
  turns).
- **Agentic** (AgentDojo-inspired): memory poisoning, tool discovery, goal hijacking,
  data-exfiltration via tool chains, coding-agent suite (repo/terminal-output injection,
  sandbox escape, secret read, CI exfil): all with mocked side-effects.
- **Agentic malicious-use / autonomous extortion (JadePuffer-class, `docs/13`)**: indirect-
  injection-driven kill-chain (recon→exfil→destroy→ransom), destructive tool use without
  confirmation, offensive-toolkit codegen (refusal). Policy-gated OFF; mocked tools, no
  functional payloads. Suite: `agentic-extortion` (7 specs). The CLI cannot enable the gated
  ones (no policy-pack flag), so from `dottore` they are always `blocked_by_policy`.
- **Dataset-backed**: sampled specs from HarmBench / BeaverTails / CyberSecEval / DoNotAnswer /
  ToxicChat / XSTest (seeded for reproducibility) **(not built)**.

## 6. Regulatory presets (suites)

`owasp:llm` · `mitre:atlas` · `nist:ai` · `eu:ai-act` · `dora` · `iso:42001` · `gdpr`. A
preset is just a suite that references the relevant specs and carries the framework rollup: no
code. (These are our differentiator for EU/regulated buyers.)

**Status:** only `owasp:llm` resolves (to `owasp-llm-top10`), and it is not the default. The
alias table in `cli/flags.py` maps `mitre:atlas`, `nist:ai`, `eu:ai-act`, `dora` and
`iso:42001` to suite ids that no file in `specs/suites/` defines, so each exits 3 ("is not
registered"); `gdpr` is not in the table at all. **(not built)** for all six. The framework view
that exists is `dottore coverage` (OWASP, ATLAS, IoPC, AISVS).
