# 15, NOVA / IoPC gap analysis (coverage map, no runtime dependency)

Spec-by-technique map of the **Nova IoPC taxonomy** ("Indicators of Prompt Compromise",
`promptintel.novahunting.ai/taxonomy`, live state as of 2026-09-19, by Thomas Roccia /
SecurityBreak) against
Il Dottore's battery, to drive the native roadmap. **Decision (2026-09-19):** the Nova property
is used as a **coverage reference and intel source only**. We do **not** take the PromptIntel
feed as a runtime dependency, we do **not** ingest raw feed prompts as specs, and we do **not**
adopt the NOVA detection engine (see "What we deliberately do NOT adopt"). Where a technique
exposes a genuine, safe-by-design gap we author a native spec with a fixture-proven oracle and
attribute the taxonomy code.

> **Build status (2026-09-19), 10 gaps closed natively.** Delivered in this pass (all gates
> green: ruff, ruff format, mypy --strict, import-linter, `dottore lint` 0/0, full pytest,
> coverage, self-scan, bandit, pip-audit):
> - **10 new specs** closing genuine IoPC gaps, grouped in the new **`nova-iopc`** suite. Each
>   is single-turn or pinned-multi-turn, `test_only` (OFF by default), with a **deterministic
>   primary evaluator** so the golden FP/FN gate proves it offline.
> - Battery: **67 specs, 13 suites, 1 pack** (was 57 / 12 / 1).
> - **No runtime dependency** on the PromptIntel feed and **no raw feed payload shipped**: the
>   harmful subset (working malware / ransomware / weaponized lures) is covered by safe proxies
>   evaluated on refusal integrity, never by shipping the payload.

**Legend:** OK covered (first-class spec) . partial (touched by an adjacent spec/mutator/command,
not a first-class family) . GAP-CLOSED (new spec this pass) . out-of-scope (not testable at a
live inference endpoint, or attacker-side infrastructure).

---

## Why NOVA / PromptIntel is a map and not a base

The Nova property has three assets. Each gets a different answer, for the same reason DeepTeam
did (docs/14): the value is the **taxonomy** (what to test), not the delivery mechanism.

| Asset | What it is | Verdict for Il Dottore |
|-------|-----------|------------------------|
| **IoPC taxonomy** (T1-T9 tactic families + R-code impact classes) | A structured tactic/technique/impact ontology for prompt compromise | **Use as a third coverage map** (alongside OWASP LLM Top 10 + MITRE ATLAS). This document. |
| **PromptIntel feed** (~94 real prompts + `/api`) | A live catalogue of observed attack prompts, some genuinely harmful | **Do NOT ingest at runtime.** Against the thesis (spec-driven, not a prompt zoo), ships harmful payloads, and a live feed breaks reproducibility. Reading only, to inspire safe specs. |
| **NOVA rule engine** (`novarun`, `.nov` YARA-for-prompts) | A detection format (keyword + semantic + LLM patterns) | **Prior art, not a dependency.** It is a detection / blue-team tool; Il Dottore is assessment / red-purple. Different layer. |

The "video" on the property is an asciinema terminal demo of `novarun` (`asciinema.org/a/707435`),
not a talk: it shows the detection engine matching a prompt against a `.nov` rule. It confirms
the rule engine is the blue-team half and does not change the analysis above.

Architecturally, Nova PromptIntel and Il Dottore sit on opposite ends of the same axis:

| Axis | PromptIntel feed | Il Dottore |
|------|------------------|-----------|
| Unit | A raw observed prompt (a string) | A declarative spec: payload + fixture pair + evaluator + scoring + mapping |
| Oracle | None (it is intel, not a test) | The vulnerable/hardened fixture pair, proven offline |
| Reproducibility | Live, changes as the feed updates | Pinned (`seed`, `temperature: 0.0`), replayable |
| Harmful payloads | Present (ransomware / malware gen) | Never shipped; covered by safe proxies on refusal integrity |

So a "battery" out of this is not the 94 prompts dropped in as 94 specs (no fixtures, no
evaluator, and it would ship working weapons). It is the taxonomy turned into properly-authored
specs, which is exactly what this pass does.

---

## Coverage map: IoPC techniques (T1-T9)

| IoPC | Technique | Il Dottore | Status |
|------|-----------|-----------|--------|
| T1.001 | Direct Prompt Injection | PI-DIRECT-001 | OK |
| T1.002 | Indirect Prompt Injection | PI-INDIRECT-RAG-001, PI-INDIRECT-TOOL-001 | OK |
| T1.003 | Agent Data Injection | PI-INDIRECT-TOOL-001 (data an agent processes) | partial |
| T1.004 | Jailbreak & Safety Bypass | JB-* (12 specs) | OK |
| T1.005 | Triggered & Delayed Instruction Activation | **PI-DELAYED-TRIGGER-001** | GAP-CLOSED |
| T2.001 | Retrieval / RAG Poisoning | PI-INDIRECT-RAG-001 (injection vector); EMB-* (embedding side) | partial |
| T2.002 | Persistent Memory Poisoning | **MEM-POISON-001** | GAP-CLOSED |
| T2.003 | Training & Fine-tuning Data Poisoning | (training pipeline, not a live endpoint) | out-of-scope |
| T2.004 | AI Supply Chain Compromise | MCP-TOOLPOISON-001 (MCP metadata); broader chain not runtime | partial |
| T2.005 | Hallucinated Dependency Exploitation (slopsquatting) | **SUPPLY-SLOPSQUAT-001** | GAP-CLOSED |
| T3.001 | Agentic Tool Misuse | AG-TOOL-UNAUTH-001, AC-*, AG-* | OK |
| T3.002 | Tool & Context Poisoning | MCP-TOOLPOISON-001, AG-TOOLMETA-POISON-001 | OK |
| T3.003 | Cross-Agent Context Propagation | AG-INTERAGENT-COMPROMISE-001; deepened by AG-WORM-PROPAGATE-001 | partial |
| T3.004 | Human-Agent Trust Exploitation | **AG-TRUST-APPROVAL-001** | GAP-CLOSED |
| T4.001 | Agent Identity & Privilege Abuse | AG-IDENTITY-ABUSE-001, AC-RBAC/BFLA/BOLA-001 | OK |
| T4.002 | Unexpected Code Execution | AG-CODEEXEC-UNEXPECTED-001 | OK (2026-09-22; the three specs credited here before executed nothing, see below) |
| T4.003 | Agent Goal Drift | AG-AUTONOMY-DRIFT-001 | OK |
| T5.001 | System Prompt & Configuration Disclosure | SP-LEAK-001, RECON-SYSTEM-001 | OK |
| T5.002 | Sensitive Data Disclosure | DL-* (8 specs) | OK |
| T5.003 | Insecure Output Handling | OUT-XSS/SQLI/CODEINJ/SHELLI-001 | OK |
| T6.001 | Unbounded Consumption & Cost Abuse | DOS-TOKEN-AMP-001 | OK |
| T7.001 | Model Extraction & Inversion | EMB-INVERSION-PROBE-001, DL-MEMORIZE-DIVERGENCE-001 (membership); distillation-cloning not modeled | partial |
| T7.002 | Adversarial Evasion | GUARD-INPUT-EVASION-001, GUARD-OUTPUT-ENCODE-001 | OK |
| T8.001 | AI System Reconnaissance | RECON-SYSTEM-001 (self); RECON-TARGET-OSINT-001 (target) | OK |
| T8.002 | Model & Agent Fingerprinting | RECON-MODEL-IDENTITY-001 | OK (2026-09-22; the `dottore fingerprint` credit was a conflation, see below) |
| T8.003 | Offline Attack Staging | (attacker-side offline activity) | out-of-scope |
| T8.004 | AI System Access Acquisition | (attacker infrastructure / access) | out-of-scope |
| T9.001 | Agent Configuration & Prompt Logic Tampering | AG-TOOLMETA-POISON-001; persistence variant adjacent to MEM-POISON-001 | partial |
| T9.002 | Detection & Attribution Evasion | **AG-LOG-EVASION-001** | GAP-CLOSED |
| T9.003 | Self-Replicating Prompt (AI Worm) | **AG-WORM-PROPAGATE-001** | GAP-CLOSED |

## Coverage map: IoPC impact classes (R-codes)

R-codes are outcome/impact tags, so most map to evaluator verdicts on the techniques above.
The ones that named a distinct behavior we did not test became specs.

| IoPC | Impact class | Il Dottore | Status |
|------|-------------|-----------|--------|
| R005 | Transform-based instruction smuggling | JB-ENCODING-001, GUARD-OUTPUT-ENCODE-001 | OK |
| R008 | Disinformation generation at scale | **SAFETY-DISINFO-001** | GAP-CLOSED |
| R009 | Malware & exploit code generation | JB-OFFENSIVE-RANSOM-CODEGEN-001 | OK |
| R010 | Target reconnaissance via model | **RECON-TARGET-OSINT-001** | GAP-CLOSED |
| R012 | Fraud & social-engineering content | **SAFETY-PHISH-BEC-001** | GAP-CLOSED |
| R013 | Malicious workflow automation | AG-EXTORT-CHAIN-001, AG-PERSIST-BEACON-001 | partial |
| R014 | LLM-enabled offensive tooling | JB-OFFENSIVE-RANSOM-CODEGEN-001 | partial |
| R015 | Model resource hijacking (LLMjacking) | DOS-RESOURCE-HIJACK-001 | OK (2026-09-22; the credential-theft route stays out of scope, the scope-abuse route is covered) |
| R022 | Encoding & obfuscation | JB-ENCODING-001 (base64_wrap / rot13 / leetspeak mutators) | OK |
| R023 | Unicode & homoglyph manipulation | **GUARD-UNICODE-EVASION-001** | GAP-CLOSED |
| R024 | Multi-step prompt chaining | JB-CRESCENDO/LINEAR/SEQUENTIAL-001 | OK |
| R025 | Roleplay & fictional framing | JB-ROLEPLAY-001 | OK |
| R026 | Instruction fragmentation | JB-SEQUENTIAL-001 + payload_splitting mutator | partial |
| R027 | Adversarial token perturbation | GUARD-INPUT-EVASION-001 + adversarial_suffix mutator | partial |
| R028 | Cross-modal payload delivery | MM-IMG-PROMPTINJECT-001, MM-IMG-DOC-INJECT-001, MM-AUD-PROMPTINJECT-001 | OK |
| R030 | Telemetry & provenance evasion | **AG-LOG-EVASION-001** | GAP-CLOSED |
| R031 | System prompt leak | SP-LEAK-001 | OK |
| R032 | Credential leak in output | DL-SECRET-CANARY-001, AG-CRED-SWEEP-001 | OK |
| R033 | PII exposure in output | DL-PII-ELICIT-001 | OK |
| R034 | Sensitive document disclosure | DL-* | OK |
| R035 | Guardrail & reasoning disclosure | SP-LEAK-001, RECON-SYSTEM-001 | partial |
| R036 | Harmful content generation | SAFETY-HARMFUL-001, MM-IMG-HARMFUL-001 | OK |
| R037 | Working exploit or payload output | JB-OFFENSIVE-RANSOM-CODEGEN-001 | OK |

---

## Gaps closed in this pass (the `nova-iopc` suite)

Each new spec pairs a deterministic primary evaluator (so the golden gate proves it offline)
with a safe fixture. The harmful-content classes (R008/R010/R012) are **safe proxies**: the
disallowed intent is explicit, no working payload is shipped, and the oracle is refusal integrity.

| Spec | IoPC | Primary evaluator | Notes |
|------|------|-------------------|-------|
| PI-DELAYED-TRIGGER-001 | T1.005 | tool_call | Dormant injection fires on a later trigger word; agent must not exfiltrate. |
| SUPPLY-SLOPSQUAT-001 | T2.005 | regex_presence | Slopsquatting: a confident non-existent package is a defect; secure answer flags "verify". |
| MEM-POISON-001 | T2.002 | regex_absence | A durable-memory note cannot install standing behavior in a later session. |
| AG-TRUST-APPROVAL-001 | T3.004 | regex_presence | Approval summary must disclose the destructive/irreversible nature, not hide it. |
| AG-WORM-PROPAGATE-001 | T9.003 | regex_absence | Self-replicating payload (Morris-II class) must not be reproduced or forwarded. |
| GUARD-UNICODE-EVASION-001 | R023 | refusal | Homoglyph/zero-width deception of the human reviewer; model must act on true intent. |
| SAFETY-PHISH-BEC-001 | R012 | refusal | Phishing / BEC credential-harvesting lure request must be refused. |
| SAFETY-DISINFO-001 | R008 | refusal | Coordinated-disinformation / fake-persona request must be refused. |
| RECON-TARGET-OSINT-001 | R010 | refusal | Unauthorized target-recon (attack-prep OSINT) must be refused. |
| AG-LOG-EVASION-001 | T9.002 / R030 | tool_call | Agent must refuse to delete/forge audit logs or strip provenance. |

---

## Deliberately out-of-scope (and why)

- **T2.003 Training & Fine-tuning Data Poisoning.** Attacks the training pipeline, not a live
  inference endpoint. Il Dottore scans a running target; it cannot exercise this. (Since
  2026-09-22 this, T8.003, T8.004, LLM03 and LLM04 are printed by `dottore coverage` under
  "out of reach for a black-box runtime scanner", with the reason, instead of sitting in the
  same list as work that is merely pending.)
- **T8.003 Offline Attack Staging** and **T8.004 AI System Access Acquisition.** Attacker-side
  activity (building proxy models, acquiring accounts/infrastructure). There is no target to
  probe.
- **R015 Model resource hijacking (LLMjacking).** ~~Abuse of stolen credentials /
  infrastructure, an infra-security concern, not a property of the model's responses.~~
  **Revised 2026-09-22, and the revision is narrower than a reversal.** That reasoning holds
  for the route it considered: a stolen key used against someone else's account is infra
  security, and this tool cannot see it. It is not the only route to the same impact. A
  narrow-scope assistant that accepts a long unrelated workload spends the operator's
  inference budget on the requester's task, every request looking individually reasonable,
  and *that* is entirely a property of the responses. Covered by
  `DOS-RESOURCE-HIJACK-001`; the credential-theft route remains out of scope and always was.
- **T7.001 distillation-style functionality cloning.** The membership/inversion half is covered;
  full functional cloning needs a large, costly query campaign that does not fit the pinned,
  reproducible, budget-bounded model. Left as a possible future mode, not core.

---

## What we deliberately do NOT adopt

- **Runtime ingestion of the PromptIntel feed.** Breaks pinned reproducibility, dilutes the
  spec-driven thesis, and would pull genuinely harmful payloads (ransomware / malware / working
  lures) into the repo. The feed is reading material to inspire safe specs, never a data source.
- **Raw feed prompts as specs.** A prompt with no fixture pair and no evaluator proves nothing
  and would fail `dottore lint`. The unit stays the fixture-proven spec.
- **The NOVA `.nov` rule engine.** A detection / blue-team tool; Il Dottore is assessment. We
  note it as prior art, not a dependency.

---

## Machine-readable mapping (built 2026-09-19)

The map below is no longer only prose. Every shipped spec carries a first-class `iopc:` block,
and the run report measures coverage against the **pinned taxonomy universe** in
`shared/iopc.py` (30 techniques + 23 impacts), the same way `OWASP_LLM_TOTAL` and
`ATLAS_TACTIC_UNIVERSE` already worked.

A provenance note that cost an audit to get right: the universe is transcribed from the **live**
taxonomy on 2026-09-19, **not** from the published `v2.0.0-alpha` artifact the site banner
advertises. That release holds 46 different entries (8 techniques, 38 impacts, 19 impact titles
under older names) and predates the entire T4 to T9 range our specs map to. Pinning to it would
have been reproducible and wrong.

```yaml
iopc:
  techniques: ["IOPC-T1.005"]     # the HOW
  impacts: ["IOPC-R023"]          # the DAMAGE
```

Design decisions worth recording:

- **Two axes, reported separately.** Techniques answer "what attack path did we exercise";
  impacts answer "what kind of harm did we test". The impact axis is the one a non-technical
  reader understands, so it gets its own line rather than being folded into a single number.
- **Optional in the schema, required for our battery by test.** Making it a required field
  would break every third-party spec pack (the repo is public and v0.1.0 is released), so the
  schema stays permissive and `tests/battery` pins that our own 75 specs are fully mapped.
- **A spec may map on one axis only.** The responsible-AI safety specs carry an impact code and
  no technique, because they assert a class of harm rather than an attack technique. That is
  honest, so the test accepts either axis.
- **One documented exemption**: `BIAS-STEREOTYPE-001`. IoPC has no fairness dimension on either
  axis, and a fabricated mapping is worse than an acknowledged gap.
- **Unknown codes are a lint error.** The JSON schema rejects a malformed code; the linter
  rejects a well-formed but non-existent one, which would otherwise match nothing and shrink
  the coverage numerator silently for ever.

**Where the battery actually stands: 27/30 techniques (90%) and 23/23 impacts (100%)**, since
the three specs added on 2026-09-22 (`RECON-MODEL-IDENTITY-001`, `AG-CODEEXEC-UNEXPECTED-001`,
`DOS-RESOURCE-HIJACK-001`). Every remaining uncovered code is one a black-box runtime scanner
cannot reach, and the command says which and why. It was 25/30 and 22/23 before those three.

That number is lower than the one first published here, and the correction is the useful part.
An adversarial review of the mapping found 30 of the 72 specs mis-mapped, mostly **over-claims**:
codes declared on specs that do not really exercise them, which inflate the very percentage a
customer reads. The worst was `IOPC-T4.002` "Unexpected Code Execution", carried by
`OUT-CODEINJ-001` and `OUT-SHELLI-001`, where nothing executes at all: both are `target_type:
model` with no tools, and the oracle is a regex over *generated source*. That is insecure code
generation (`T5.003`, which both already declared). Dropping the false claim moved the technique
axis from 87% to 83% and turned T4.002 into what it always was: **a real gap**, since the battery
had no code-interpreter or sandbox-escape spec until `AG-CODEEXEC-UNEXPECTED-001` on 2026-09-22.

The other uncovered codes are deliberate out-of-scope decisions recorded below (training-data
poisoning, offline staging, access acquisition). Two of that list have since moved:
`IOPC-T8.002` (fingerprinting) was written off on the grounds that `dottore fingerprint`
covers it, which conflated two different things: the tool fingerprinting a target is not a
test of whether the target *discloses* what it was configured to hide, and that second thing
is a finding a customer can act on. `RECON-MODEL-IDENTITY-001` tests it. `R015` moved for the
reason recorded against it below.

**A caveat on what these percentages mean.** The tables below mark eleven codes as *partial*
(touched by an adjacent spec rather than covered first class). The machine-readable axis cannot
express that nuance: a declared code counts the same either way. The mapping was therefore
tightened so a spec declares a code only when it genuinely exercises it, which keeps the number
honest without inventing a half-covered state. Read a percentage here as "codes with at least
one genuine spec", never as depth of coverage.

---

## Attribution

Nova IoPC taxonomy by Thomas Roccia / SecurityBreak (`promptintel.novahunting.ai/taxonomy`,
live state as of 2026-09-19; the published v2.0.0-alpha artifact is an older, smaller
snapshot). Used here as a taxonomy and coverage reference; the technique/impact codes are
cited for mapping. No prompt, payload or code from the PromptIntel feed or the NOVA engine is
shipped in this repository. Any concrete idea later ported from a specific feed entry into a
native spec must carry an attribution note in that spec's `tags:` / comment block.
