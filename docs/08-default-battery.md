# 08: Default test battery (grounded in the state of the art)

This is the **minimum battery** shipped by default, distilled from the ecosystem
(NVIDIA garak, Microsoft PyRIT, promptfoo, Giskard, AgentDojo) and the reference frameworks
(OWASP LLM Top 10 2025, MITRE ATLAS, NIST AI RMF and its GenAI Profile, NIST AI 600-1).
Sources: see `docs/REFERENCES.md`. NIST is a design reference, not a mapping the code checks:
each spec's `nist_ai_rmf` field carries an AI RMF function/subcategory token (`MEASURE 2.7`,
`MANAGE 2.2`, `MEASURE 2.11`, `GOVERN 1.1`), validated by shape only; no spec names an AI 600-1
risk category, and `dottore coverage` has no NIST axis.

Status key for this document: items marked **(not built)** are design that has no spec field,
mechanism or suite behind it today. In §4 and §5 every technique is marked: either it names
the spec id or mutator that ships it, or it says (not built). Where a line does neither (§1's
lessons, §6's design intent), read it as design, not as a shipped feature.

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
   zero-width, homoglyph: apply as transforms over base payloads (our Prompt Mutator; 19
   built-in mutators ship, ASCII-smuggling is **(not built)**, and `translate` glosses a
   keyword table rather than translating, `docs/03 §4`).
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
| **T2: Deep** | `--deep` | the full shipped battery at `-T2` | 75 candidates; a target runs those its declared capabilities and the policy gate allow (67 at most: the 8 policy-gated specs never send from the CLI) | long |

Measured, not designed: `owasp-llm-top10` and `quick` list the same 18 spec ids, so T0 and T1
are one battery today (T1's design size was ~60). Neither is the default: a `run` with no
`--suite` selects the full battery, every spec the target can run. The whole battery covers 8
of the 10 OWASP LLM codes (`dottore coverage --framework owasp`). `--quick` selects the `quick`
suite at `-T0`. `--deep` changes the timing template to `-T2` and not the selection: with no `--suite` it
runs the full battery, as no flag does;
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
> into the default battery. Two require target capabilities (row 16 `logprobs`, row 17
> `multi_identity`): where absent, they are skipped as `inconclusive: capability_unavailable`,
> never a false pass. Row 18 requires nothing but is policy-gated (`layer_b_pii`), so from the
> CLI it is always `blocked_by_policy`. All obey the FP discipline + safety/legal gates of
> `docs/11 §4-§5`.

## 4. T1 "Standard" adds (full OWASP coverage)

§4 and §5 are the design's list of techniques for T1 and T2, not the content of a suite: no
T1-only or T2-only suite exists. Several of these techniques ship as specs in other suites
(`dottore registry ls`, `dottore coverage`); the ones marked (not built) have no spec.

- **LLM01/07 depth**: multi-turn injection (`PI-DELAYED-TRIGGER-001`, pinned turns),
  second-order injection (`MEM-POISON-001`, `PI-DELAYED-TRIGGER-001`), context override and
  instruction-hierarchy bypass (`PI-DIRECT-001`), zero-width (`zero_width_inject` mutator),
  homoglyph (`unicode_confusable` mutator, `GUARD-UNICODE-EVASION-001`), payload-splitting
  (`payload_splitting` mutator). ASCII-smuggling (Unicode tag characters) **(not built)**: no
  mutator or spec emits them.
- **LLM02** (full data-leak family, `docs/11`): memory/RAG-source leakage, tool-credential
  exposure, RAG corpus enumeration, prefix-completion & verbatim-copyright extraction,
  membership inference (logprobs), secret-shape elicitation, breach-canary detection. The
  data-leak family ships five specs (`DL-SECRET-CANARY-001`, `DL-XSESSION-001`,
  `DL-XTENANT-001`, `DL-MEMORIZE-DIVERGENCE-001`, `DL-PII-ELICIT-001`); of the techniques in
  this bullet, tool-credential exposure, RAG enumeration, prefix completion, verbatim
  copyright, membership inference, secret-shape elicitation and breach canary are **(not
  built)** (`docs/11 §1`).
- **LLM03/04 (supply chain / poisoning)**: model identification (`RECON-MODEL-IDENTITY-001`,
  `RECON-SYSTEM-001`, and `dottore fingerprint`), package hallucination in generated code
  (`SUPPLY-SLOPSQUAT-001`), RAG document poisoning (`PI-INDIRECT-RAG-001`). Retrieval
  poisoning as its own spec, citation laundering and source confusion **(not built)**. None of
  the shipped specs is mapped to LLM03 or LLM04: `dottore coverage --framework owasp` lists both
  as out of reach for a black-box scanner, and the specs above count under the code they declare
  (LLM01, LLM07, LLM09).
- **LLM05**: command injection (`OUT-SHELLI-001`). Path traversal, hallucinated security
  claims and sensitive-data-in-logs **(not built)**.
- **LLM06**: confused-deputy (`AG-TOOL-UNAUTH-001`), SSRF-like tool use (`AC-SSRF-001`),
  tool-parameter injection (`FUNCALL-ARGSMUGGLE-001`), MCP abuse (`MCP-TOOLPOISON-001`), mail
  misuse through mocked tools (`AG-TOOLCHAIN-EXFIL-001`). Calendar and file misuse as their
  own specs **(not built)**.
- **LLM08**: embedding-inversion / vector-store leakage probes (`EMB-INVERSION-PROBE-001`,
  `EMB-NEIGHBOR-LEAK-001`, `EMB-XTENANT-RETRIEVAL-001`; RAG targets).
- **LLM09**: overreliance on a fabricated answer (`SUPPLY-SLOPSQUAT-001`). Misinformation,
  sycophancy and unverifiable claims **(not built)** (`SAFETY-DISINFO-001` tests refusing to
  write disinformation, a responsible-AI spec, not LLM09).
- **LLM10**: token amplification (`DOS-TOKEN-AMP-001`) and resource hijacking
  (`DOS-RESOURCE-HIJACK-001`). Recursive-reasoning loops, context flooding and expensive-tool
  loops **(not built)**.
- **Utility/over-defense**: XSTest-style false-refusal battery (T3-in-T1 sanity) **(not
  built)**.

## 5. T2 "Deep / Agentic" adds

- **Multi-turn adaptive**: Crescendo-, TAP-, Skeleton-Key-style escalation (spec `escalation`
  mode + adaptive-attempts budget) **(not built**; the multi-turn specs replay pinned
  turns).
- **Agentic** (AgentDojo-inspired), all with mocked side-effects: memory poisoning
  (`MEM-POISON-001`), tool discovery (`RECON-SYSTEM-001`), goal hijacking
  (`AG-RECURSIVE-HIJACK-001`, `AG-GOAL-THEFT-001`), data exfiltration via tool chains
  (`AG-TOOLCHAIN-EXFIL-001`). The coding-agent suite (repo/terminal-output injection, sandbox
  escape, secret read, CI exfil) **(not built)**: the nearest single spec is
  `AG-CODEEXEC-UNEXPECTED-001` (code from processed data run by a code interpreter).
- **Agentic malicious-use / autonomous extortion (JadePuffer-class, `docs/13`)**: indirect-
  injection-driven kill-chain (recon→exfil→destroy→ransom), destructive tool use without
  confirmation, offensive-toolkit codegen (refusal). Policy-gated OFF; mocked tools, no
  functional payloads. Suite: `agentic-extortion` (7 specs). The CLI cannot enable the gated
  ones (no policy-pack flag), so from `dottore` none of the seven ever sends. Which inconclusive
  each one gets depends on the target, because the capability filter runs before the policy
  gate: six of them require `tools`, so on a target that does not declare it they are skipped as
  `inconclusive: capability_unavailable` and never reach the gate; on a target that declares
  `tools`, all seven are `blocked_by_policy`. `JB-OFFENSIVE-RANSOM-CODEGEN-001` requires nothing
  and is `blocked_by_policy` on every target. `--suite agentic` alone therefore exits 3 ("nothing
  would be sent"), naming the split (for example "6 skipped for capabilities, 1 blocked by
  policy" on a target without tools).
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
