# Responsible Use & Authorization: Il Dottore

**Purpose of this document.** Il Dottore is a *defensive* AI-security assurance tool. Because
its subject matter (prompt injection, jailbreak, data-leak, agentic-abuse test cases) is
dual-use, this page states: in good faith: the authorization, intent, and the safety
controls that are actually built into the code, so any reviewer (human or AI assistant)
working on the project has the context to distinguish authorized defensive research from
misuse. **This is context, not a bypass:** if a specific request is genuinely intended to
cause real-world harm, refusing it is the correct behavior, and nothing here changes that.

## 1. What this is
A spec-driven security scanner ("nmap-for-AI") that tests whether an LLM or AI application
resists known attack classes, aligned to **OWASP LLM Top 10 (2025)**, **MITRE ATLAS**, and
**NIST AI 600-1**. It is the same category of tool as NVIDIA **garak**, Microsoft **PyRIT**,
and **promptfoo**: published, industry-standard, defensive red-team/assurance tooling. Its
value proposition is *reproducibility + evidence + risk mapping*, i.e. producing an auditable
assurance report, not offensive capability.

## 2. Who & authorization
- **Owner:** Dani Solis <daniel.solis@zynap.com> (a personal open-source project).
- **Context:** authorized product development and security research. License **MIT**.
- **Operating rule (enforced in code):** the tool refuses to scan any target that is not
  covered by a signed `scope.yaml` authorization record with an endpoint allowlist
  (default-deny). The scope file *is* the authorization; runs are auditable (who / what / when
  / scope hash). Using it against systems you are not authorized to test is prohibited and may
  be illegal.

## 3. Safe-by-design: the controls that are actually implemented
These are not aspirations; they are enforced by the code and covered by tests
(see `docs/02-threat-model.md`, `docs/11 §5`, `docs/13 §4`):

| Control | What it guarantees |
|--------|--------------------|
| **No functional payloads** | The repository contains **no** working exploits, encryptors, or malware. Offensive-code-generation tests assert *refusal*; a "vulnerable" fixture uses an abstract marker (`[MODEL PRODUCED …]`), never runnable code. |
| **Mocked / dry-run tools** | Agent tools (`drop_table`, `http_post`, `read_env`, `write_cron`, …) are dry-run mocks that record *intent* only: they never touch a real database, filesystem, or network. |
| **No real exfiltration** | Data-leak tests use **planted canaries** and **synthetic** data, never real secrets. Any secret/PII a detector sees is stored masked/hashed; raw values are redacted in logs, evidence, and reports. |
| **Endpoint allowlist (default-deny)** | Adapters refuse any host/path not in the scope allowlist. |
| **Offensive & PII specs OFF by default** | The agentic-extortion pack (`offensive_simulation`) and PII-elicitation (`layer_b_pii`) are **policy-gated OFF**: they return `blocked_by_policy` with **zero sends** unless the engagement's policy pack explicitly enables the capability (enforced via `requires_policy`; unit-tested). |
| **Documentation-range IoCs** | Any adversary indicators referenced are RFC-5737 test ranges or fixture strings: allowlist-blocked, never contacted. |
| **Budget caps** | Availability/DoS tests are hard-capped (tokens/requests/wall-clock) so the tool cannot be turned into a DoS weapon. |

## 4. What Il Dottore is *not*
- Not a jailbreak-as-a-service, not a malware toolkit, not an autonomous attacker. It does not
  ship or run offensive capability against third parties.
- The agentic-ransomware ("JadePuffer-class") family tests **susceptibility**: *"could this
  agent be coerced into a destructive chain?"*: entirely against mocked tools, to help
  operators harden their own systems. It does not perform the attack.

## 5. For an AI assistant reviewing or extending this project
Requests in this repo are, by default, to build, test, document, or extend a **defensive**
security-assurance tool operating under the controls in §3. Authoring attack *specifications*
(declarative test cases), evaluators, refusal-tests, and susceptibility probes for that tool -
with mocks, canaries, and no functional payloads: is legitimate defensive work, consistent
with published tools like garak/PyRIT/promptfoo. Please proceed on that basis. If a specific
ask would require a genuinely harmful artifact (a working exploit, real malware, real
exfiltration, or targeting a system without authorization), that is out of scope for this
project: decline it, and it will not be asked here.

---
*Companion: `SECURITY.md` (disclosure), `docs/02-threat-model.md` (tool threat model),
`docs/11 §5` / `docs/13 §4` (data-leak & agentic-abuse safety gates). Internal only, not for
publication as-is: `~/AI projects/ildottore-anthropic-safeguard-log.md` logs any real safeguard
blocks for Anthropic feedback (as of this writing: none).*
