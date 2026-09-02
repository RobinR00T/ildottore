# 14, DeepTeam gap analysis (coverage map, no code dependency)

Spec-by-spec map of **DeepTeam** (`github.com/confident-ai/deepteam`, Apache-2.0) against Il
Dottore's current battery, to drive our native roadmap. **Decision (2026-08-30):** DeepTeam is
used as a **coverage reference only**. We do **not** take it as a dependency, and we do **not**
adopt its runtime model (see "What we deliberately do NOT adopt"). Where we later port a
concrete prompt or payload idea, we attribute it (Apache-2.0 requires attribution).

> **Build status (2026-08-30), P0 + P1 + most of P2 shipped natively.** Delivered in this
> pass (all gates green: ruff, mypy, import-linter, `dottore lint`, full pytest, offline E2E):
> - **P0 multi-turn engine**, `core/conversation.py` (pinned attacker ladders threaded as
>   `messages`, final-turn scored, transcript persisted); wired into `core/runner.py` behind
>   `_is_multi_turn`; 5 specs (`JB-CRESCENDO/LINEAR/SEQUENTIAL/LIKERT/TREE`) + `multi-turn`
>   suite. Reproducibility preserved: attacker turns are pinned, never LLM-generated.
> - **P1 access-control pack**, `AC-BFLA/BOLA/RBAC/SSRF/DEBUG`, `OUT-SHELLI`,
>   `AG-TOOLMETA-POISON` + `access-control` suite.
> - **P1 agentic breadth**, `AG-GOAL-THEFT/RECURSIVE-HIJACK/IDENTITY-ABUSE/INTERAGENT-
>   COMPROMISE/AUTONOMY-DRIFT` + `agentic-owasp2026` suite (drift is multi-turn).
> - **P1/P2 enhancers**, 6 new mutators (`leetspeak`, `adversarial_poetry`, `math_problem`,
>   `gray_box`, `linguistic_confusion`, `context_poisoning`), wired into the jailbreak specs'
>   `mutations`; `JB-MULTILINGUAL` (translate); `RECON-SYSTEM` (P2). Battery: 47 specs, 8 suites.
> - **Deferred by design:** true adaptive Tree-of-attacks search (shipped as a pinned breadth
>   ladder instead); a fully systematic per-language multilingual battery (needs mutation
>   parameters, one `translate` spec seeds it); the Responsible-AI / Safety / Business content
>   packs (bias/toxicity/…), they don't fit the security `category` enum and `docs/12` scopes
>   them as optional non-core.

**Legend:** ✅ covered · 🟡 partial (touched by an adjacent spec, not a first-class family) ·
❌ not covered.
**Priority:** P0 = credibility gap, build next · P1 = strong differentiator · P2 = later / optional.

---

## Why DeepTeam is a map and not a base

DeepTeam and Il Dottore are architecturally opposite on the one axis that defines Il Dottore:

| Axis | DeepTeam | Il Dottore |
|------|----------|-----------|
| Attack source | Attacker-LLM **generates** inputs dynamically at runtime (DeepEval) | **Declarative** YAML specs, hand-authored |
| Reproducibility | Statistical, regenerated each run | Pinned (`seed`, `temperature: 0.0`), replayable |
| Arbiter | LLM-as-judge (DeepEval) | Deterministic arbiter first (canary/regex/shape), `semantic_judge` as one weighted input |
| Thesis | Breadth of coverage | Reproducibility + evidence + operational-risk mapping |
| Dependency | Built on DeepEval | Own thin adapters (ADR-0002) |

So DeepTeam's value to us is its **taxonomy** (what to test) and its **prompt craft** (how an
attack reads), not its engine. Adopting the engine would dilute exactly what differentiates
Il Dottore. The families below are ranked by security value, not by how easy DeepTeam makes them.

---

## The headline gap: multi-turn adaptive attacks (P0)

Il Dottore is **100% single-turn** today: every spec is one `user_prompt` (+ single-turn
mutations), one exchange. DeepTeam's real strength is **iterative, adaptive multi-turn**
jailbreaking, and it is **not even listed in `docs/12`**, so this is a blind spot, not a
deferred item. This is the single most valuable thing to add, and it is the only gap that
needs an **engine change** (conversation state in the spec schema + runner), which is why it
is P0 and must be gated.

| DeepTeam multi-turn attack | Il Dottore | Priority |
|-----|--------|------|
| CrescendoJailbreaking (gradual escalation across turns) | ❌ | **P0** |
| LinearJailbreaking (persistent refinement) | ❌ | **P0** |
| TreeJailbreaking (branching search over attack paths) | ❌ | P1 |
| SequentialBreak (staged decomposition of a harmful ask) | ❌ | P1 |
| Bad Likert Judge (elicit-via-rating-scale) | ❌ | P1 |

**Build note:** the reproducibility thesis survives multi-turn only if the *attacker turns are
themselves pinned* (a scripted or seed-fixed ladder), not free-form LLM generation. That is the
design constraint for the multi-turn schema extension.

---

## Vulnerability coverage map

### Data Privacy
| DeepTeam type | Il Dottore | Priority | Action |
|-----|--------|------|------|
| PII Leakage (direct / API-DB access / session leak) | ✅ DL-PII-ELICIT, DL-XSESSION |, | covered |
| Prompt Leakage (secrets / instructions / permissions) | ✅ SP-LEAK, DL-SECRET-CANARY |, | covered |

### Security (largest net-new family)
| DeepTeam type | Il Dottore | Priority | Action |
|-----|--------|------|------|
| SQL Injection (app executes model output) | ✅ OUT-SQLI |, | covered |
| Shell Injection | 🟡 OUT-CODEINJ (output-handling, not tool-shell) | P1 | new spec: model output → shell exec |
| Unexpected Code Execution | 🟡 OUT-CODEINJ | P1 | fold into the shell/codeexec pack |
| BFLA (function-level authz bypass) | ❌ | **P1** | access-control pack |
| BOLA (object-level / cross-customer) | 🟡 DL-XTENANT (data-plane only) | **P1** | authz on tool/API object access |
| RBAC (role / privilege bypass) | 🟡 AG-CONFIRM-BYPASS, AG-TOOL-UNAUTH | **P1** | first-class role-escalation spec |
| SSRF (internal access / port scan via tool) | ❌ | **P1** | access-control pack |
| Debug Access (hidden/debug commands) | ❌ | P1 | access-control pack |
| Tool Metadata Poisoning | 🟡 PI-INDIRECT-TOOL | P1 | deepen tool-schema poisoning |
| Cross-Context Retrieval | 🟡 EMB-XTENANT-RETRIEVAL, DL-XTENANT | P2 | overlap, low delta |
| System Reconnaissance | ❌ | P2 | recon-via-prompt spec |

### Agentic (Il Dottore already strong; DeepTeam is broader on OWASP-Agents-2026)
| DeepTeam type | Il Dottore | Priority | Action |
|-----|--------|------|------|
| Excessive Agency | ✅ AG-AUTONOMY-SELFCORRECT, AG-TOOL-UNAUTH |, | covered (LLM06) |
| Indirect Instruction | ✅ PI-INDIRECT-RAG, PI-INDIRECT-TOOL |, | covered |
| Exploit Tool Agent | ✅ AG-CRED-SWEEP, AG-EXFIL-EGRESS, AG-DESTRUCTIVE-DBDROP |, | covered |
| External System Abuse | 🟡 AG-EXFIL-EGRESS, AG-PERSIST-BEACON | P2 | partial |
| Tool Orchestration Abuse | 🟡 AG-TOOL-UNAUTH | P1 | multi-tool sequence abuse |
| Autonomous Agent Drift | 🟡 AG-AUTONOMY-SELFCORRECT | P1 | drift-over-time spec |
| Goal Theft | ❌ | P1 | objective-extraction spec |
| Robustness (input overreliance / prompt hijacking) | 🟡 | P1 | dedicated robustness spec |
| Recursive Hijacking (self-modifying goal chains) | ❌ | **P1** | novel, high-value |
| Agent Identity & Trust Abuse | ❌ | **P1** | agent-impersonation spec |
| Inter-Agent Communication Compromise | ❌ | **P1** | multi-agent message spoofing (aligns with orchestrator threat model) |

### Responsible AI / Safety / Business (adjacent to security; optional packs per `docs/12` P2)
| DeepTeam type | Il Dottore | Priority | Action |
|-----|--------|------|------|
| Bias (race / gender / political) | ❌ | P2 | optional responsible-AI pack |
| Toxicity (profanity / insults / threats) | ❌ | P2 | optional responsible-AI pack |
| Illegal Activity | 🟡 JB-* refusal probes | P2 | systematic harmful-content battery |
| Graphic Content | ❌ | P2 | safety battery |
| Personal Safety (bullying / self-harm) | ❌ | P2 | safety battery |
| Misinformation (unsupported claims / factual error) | ❌ | P2 | maps to LLM09 overreliance |
| Intellectual Property | ❌ | P2 | low security value |
| Competition (competitor mention / discredit) | ❌ | P2 | low security value |

---

## Attack-technique (enhancement) coverage map

| DeepTeam single-turn attack | Il Dottore | Priority | Action |
|-----|--------|------|------|
| PromptInjection | ✅ PI-DIRECT |, | covered |
| SystemOverride | ✅ PI-DIRECT |, | covered |
| Roleplay | ✅ JB-ROLEPLAY |, | covered |
| Base64 / ROT-13 | ✅ JB-ENCODING (`base64_wrap`, `rot13` wired) |, | covered |
| Leetspeak | 🟡 named in JB-ENCODING but no `leetspeak` mutation wired | P2 | add the mutator |
| InputBypass | 🟡 JB-REFUSAL-SUPPRESS | P2 | fold into refusal-suppression mutator |
| ContextPoisoning | 🟡 PI-INDIRECT-RAG | P1 | dedicated context-poisoning mutator |
| PermissionEscalation | 🟡 (→ RBAC pack) | P1 | pairs with access-control pack |
| Multilingual | 🟡 `translate:` mutator, no battery | P1 | systematic measured battery (also `docs/12`) |
| AdversarialPoetry | ❌ | P1 | cheap, effective, novel mutator |
| MathProblem | ❌ | P2 | encoding-style mutator |
| GrayBox | ❌ | P2 | partial-knowledge mutator |
| LinguisticConfusion | ❌ | P2 | mutator |

Multi-turn attacks: see the P0 table above.

---

## What we deliberately do NOT adopt

- **Dynamic LLM attack synthesis.** Breaks pinned reproducibility, our core thesis. Multi-turn
  ladders must be scripted/seed-fixed, not free-form generated.
- **DeepEval LLM-as-judge as the arbiter.** We keep deterministic arbiters first; a judge is
  one weighted input, never the sole verdict.
- **Runtime Guardrails** (DeepTeam ships 7: Toxicity, PromptInjection, Privacy, Illegal,
  Hallucination, Topical, Cybersecurity). That is a runtime-protection product, out of scanner
  scope. The in-scope adjacent item is **attacking** a guardrail (guardrail-evasion specs),
  already tracked as 🟡 in `docs/12`.

---

## Recommended native roadmap (what to build, in order)

- **P0, Multi-turn engine.** Extend the spec schema + runner with pinned conversation state,
  then ship **Crescendo** and **Linear** as the first two multi-turn families. Gated behind the
  same policy discipline as the offensive packs. This is the only item that needs an engine
  change; everything below is pure spec authoring on the current engine.
- **P1, Access-control pack.** BFLA, BOLA, RBAC, SSRF, Debug Access, Shell/code-exec,
  Tool Metadata Poisoning. Largest net-new *security* surface, fits the single-turn engine.
- **P1, Agentic breadth.** Recursive Hijacking, Agent Identity & Trust Abuse, Inter-Agent
  Communication Compromise, Goal Theft, Autonomous Drift. Aligns with the orchestrator threat
  model.
- **P1, Enhancements.** AdversarialPoetry mutator + systematic Multilingual battery +
  ContextPoisoning mutator.
- **P2, Optional packs.** Responsible-AI (bias/toxicity), Safety battery
  (illegal/graphic/personal-safety), Business (misinfo/IP/competition), remaining single-turn
  enhancements (MathProblem, GrayBox, LinguisticConfusion), System Reconnaissance.

**Net:** DeepTeam confirms Il Dottore's core (PI, jailbreak, data-leak, embeddings, agentic
extortion) is competitive, and exposes three real holes to close natively: **multi-turn (P0)**,
**access-control (P1)**, and **broader OWASP-Agents-2026 agentic coverage (P1)**.

---

## Attribution

DeepTeam by Confident AI, Apache-2.0 (`github.com/confident-ai/deepteam`). Used here as a
taxonomy and prompt-craft reference. Any concrete payload or prompt ported from DeepTeam into a
native spec must carry an attribution note in that spec's `references:` block.
