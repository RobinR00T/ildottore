# ADR-0021: a spec names its CWE, and each family says how to confirm a fail by hand (u02 A-110)

* **Status:** accepted, 2026-10-30, as the smallest reversible version: an optional `cwe:` list
  on a spec, a pinned table of the entries MITRE allows, 48 of the 79 battery specs mapped, and a
  manual page per family. OD-66 is open on the mapping choices.
* **Date:** 2026-10-30
* **Context:** a finding carried OWASP LLM, ATLAS, NIST AI RMF, IoPC, AISVS and ATT&CK labels,
  and no CWE: the identifier an application team's tracker, a SAST dashboard and GitHub code
  scanning already group weaknesses by. And a fail named what the evaluators saw, never what an
  operator should look at to confirm it by hand before raising it. Clause u02 §7 A-110 in
  `specs/contracts/u02-spec-registry-linter.md`.

## The decision

* **`cwe:` on a spec,** optional: the MITRE CWE IDs of the weakness a FAIL of that spec is
  evidence of in the application under test (`CWE-<n>`, no leading zero). A label: it decides
  nothing and is outside the spec digest, as `aisvs` is, so a run halted before the field landed
  resumes after it.
* **Only what MITRE allows for mapping.** Each CWE entry carries MITRE's own mapping usage.
  `shared.cwe` pins, from `cwec_v5.0.xml` (CWE 5.0, 2026-10-28), the name and usage of every
  entry the battery names and of the entries an AI finding is most often mapped to by mistake.
  The lint refuses a `Discouraged` or `Prohibited` one (`FRAMEWORK_CLAIM_CONTRADICTED`) and warns
  on one outside the table (`UNKNOWN_FRAMEWORK_CODE`, a warning: CWE has some 950 weaknesses and
  a third-party pack may name one the battery does not).
* **CWE-1427, not CWE-1426.** CWE-1427 (Improper Neutralization of Input Used for LLM Prompting)
  is `Allowed` and is the prompt-injection weakness. CWE-1426 (Improper Validation of Generative
  AI Output) is `Discouraged`: MITRE notes it may change and is often misread, and points at
  CWE-77, CWE-94 or CWE-116 instead. The AI/ML grouping CWE-1446 is `Prohibited`.
* **Where it shows.** SARIF rule tags in CodeQL's shape (`external/cwe/cwe-089`,
  `external/cwe/cwe-1427`), which GitHub code scanning reads; `framework_editions` gains
  `mitre_cwe: 5.0` (SARIF, JUnit); `dottore describe` prints a `cwe:` line with MITRE's names.
  The JSON report and the HTML do not roll findings up by CWE (OD-66).
* **The battery's mapping,** 48 of 79 specs, pinned spec by spec in `tests/shared/test_cwe.py`:

| CWE | Specs |
|---|---|
| CWE-1427 | the prompt-injection specs, direct, indirect, multimodal and through memory (`PI-*`, `MEM-POISON-001`, `MM-*-PROMPTINJECT`, `MM-IMG-DOC-INJECT-001`, `MM-IMG-SPLIT-PAYLOAD-001`, `MM-IMG-TOOL-EXFIL-001`); poisoned tool metadata (`AG-TOOLMETA-POISON-001`, `MCP-TOOLPOISON-001`); the agent hijacks driven by injected text (`AG-WORM-PROPAGATE-001`, `AG-RECURSIVE-HIJACK-001`, `AG-EXTORT-CHAIN-001`, `AG-INTERAGENT-COMPROMISE-001`) |
| CWE-497 | `SP-LEAK-001`, `AG-GOAL-THEFT-001`, `RECON-SYSTEM-001`, `RECON-MODEL-IDENTITY-001`, `AC-DEBUG-001` (with CWE-489) |
| CWE-201 | `DL-SECRET-CANARY-001`, `AG-CRED-SWEEP-001`, `AG-EXFIL-EGRESS-001`, `AG-TOOLCHAIN-EXFIL-001` |
| CWE-359, CWE-488, CWE-639 | `DL-PII-ELICIT-001`, `DL-XSESSION-001`, `AC-BOLA-001` |
| CWE-862 | `AC-BFLA-001`, `AG-TOOL-UNAUTH-001`, `DL-XTENANT-001`, `EMB-XTENANT-RETRIEVAL-001`, `EMB-NEIGHBOR-LEAK-001` |
| CWE-266, CWE-290, CWE-451 | `AC-RBAC-001`, `AG-IDENTITY-ABUSE-001`, `AG-TRUST-APPROVAL-001` |
| CWE-915 | `OUT-JSON-SCHEMA-COERCE-001`, `FUNCALL-ARGSMUGGLE-001` |
| CWE-94, CWE-78, CWE-89, CWE-79 | `AG-CODEEXEC-UNEXPECTED-001` and `OUT-CODEINJ-001`; `OUT-SHELLI-001`; `OUT-SQLI-001` and `FUNCALL-SQLI-ARG-001`; `OUT-XSS-001` |
| CWE-770 | `DOS-TOKEN-AMP-001`, `DOS-RESOURCE-HIJACK-001` |
| CWE-918 | `AC-SSRF-001`, `AC-SSRF-SCHEME-001` |

* **Left unmapped, on purpose (31):** the jailbreaks and guardrail evasions (`JB-*`, `GUARD-*`),
  content safety and bias (`SAFETY-*`, `BIAS-*`, `MM-IMG-HARMFUL-001`, `RECON-TARGET-OSINT-001`),
  training-data regurgitation, slopsquatting, the autonomy and destructive-action specs without a
  confirmation step, audit-log tampering, persistence, price tampering, embedding inversion, the
  enum escape and the MCP rug pull. Each is the model's behaviour or a control no CWE entry
  names; a CWE made up for them would be a label nobody could defend.
* **How to confirm a fail by hand,** one entry per family in the manual ("Confirming a finding
  by hand, family by family"): what in the stored evidence makes the fail real, and what makes
  it a false alarm.

## Not taken

* **CWE-1426 for the output specs.** Discouraged; MITRE's own notes send the reader to the
  injection weakness downstream (CWE-89, CWE-79, CWE-78, CWE-94), which is what the battery
  names.
* **The whole CWE catalogue in the package.** Some 950 entries for a lint that needs the usage
  of a few dozen; an entry outside the table is a warning instead.
* **A CWE roll-up in the JSON report and the HTML.** It changes the report shape; OD-66 names it.

## Costs, stated

The battery files are in the judging digest: judging rules 7 re-pinned, no rule of judgement
changed (`cwe` is read by the lint, SARIF and `describe`, by no evaluator).

## Reversal

Delete the `cwe:` lines (the field is optional and outside the spec digest), and the tag line in
`reporting/sarif_reporter.py`; `shared.cwe` is then a table nobody reads.
