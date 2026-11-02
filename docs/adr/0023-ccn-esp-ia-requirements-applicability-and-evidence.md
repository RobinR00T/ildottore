# ADR-0023: CCN-STIC-2011 (ESP-IA): the requirements a fail is evidence against, what applies to a target, and the evidence draft (u02 A-116, u12 A-117, A-118)

* **Status:** accepted, 2026-11-02, as the smallest reversible version: an optional `esp_ia:` list
  on a spec, an optional `esp_ia: answers:` block on a target file, a coverage view and a replay
  option, all read-only. OD-70 and OD-71 are open.
* **Date:** 2026-11-02
* **Context:** Spain's National Cryptologic Centre published CCN-STIC-2011, *Metodología de
  Evaluación de Seguridad de Productos, Inteligencia Artificial* (ESP-IA), version 1.0, October
  2026. A vendor describes the product's architecture and answers 21 yes or no characterization
  questions (`C01` to `C21`, and `C16a` when `C16` is yes); 24 cumulative rules (`R01` to `R22`,
  `RP01`, `RP02`) turn the answers into nine threats and two policies, and those into 27
  Functional Security Requirements (`RFS-...`). An accredited laboratory then verifies each
  applicable requirement, PASS or FAIL, against the CCN's own test guides, and adds at least three
  person-days of penetration testing with the OWASP AI Testing Guide as the minimum reference. The
  report it writes follows the guide's Annex B. A finding carried OWASP LLM, ATLAS, NIST AI RMF,
  IoPC, AISVS, ATT&CK and CWE labels, and nothing a Spanish evaluation reads. Clauses u02 §7 A-116
  in `specs/contracts/u02-spec-registry-linter.md`, u12 §7 A-117 and A-118 in
  `specs/contracts/u12-cli.md`.

## The decision

* **Codes only.** The CCN forbids reproducing the guide, in part or in whole, without its written
  authorization. `shared.esp_ia` keeps the identifiers (questions, rules, threats, requirements,
  and which codes each rule joins), transcribed on 2026-11-02 from Tables 1 to 4 of version 1.0.
  The text of a question or a requirement is not in the repository; every reason next to a code is
  this project's own wording.
* **Falsification only, as AISVS.** A requirement is a property the product must provide, and a
  black box never sees the mechanism that provides it. A spec's `esp_ia:` list means "a FAIL of
  this spec is evidence that these requirements are not met". A PASS means the probes did not
  falsify them, never that they are met: only the laboratory writes PASS (*PASA*). No output of
  this tool writes it, and a test pins that.
* **`esp_ia:` on a spec** (u02 A-116), optional, `RFS-<XXX>-0<n>`, outside the spec digest as
  `aisvs` and `cwe` are. The lint refuses a code the guide does not contain
  (`UNKNOWN_FRAMEWORK_CODE`) and a claim on one classified out of reach or deliberately untested
  (`FRAMEWORK_CLAIM_CONTRADICTED`), through the helper the AISVS check now shares.
  `dottore coverage --framework esp_ia` counts them; `framework_editions` gains `ccn_esp_ia: 1.0`
  (SARIF, JUnit); `dottore describe` prints an `esp_ia:` line with the threat or policy of each.
* **The battery's mapping,** 64 of 79 specs, 19 of the 27 requirements, pinned requirement by
  requirement in `tests/shared/test_esp_ia.py`:

| Requirement | Specs (summary) |
|---|---|
| RFS-INJ-01 | direct injection and every jailbreak (`PI-DIRECT-001`, `JB-*`), the guardrail evasions, `AG-IDENTITY-ABUSE-001` |
| RFS-EVA-01 | the two input-guardrail evasions (`GUARD-INPUT-EVASION-001`, `GUARD-UNICODE-EVASION-001`) |
| RFS-INJ-02 | indirect injection through documents, tools, images, audio and memory, and the agent hijacks driven by injected text |
| RFS-POI-01 | `MEM-POISON-001`, `AG-RECURSIVE-HIJACK-001` |
| RFS-INV-01, RFS-MEM-01 | `DL-MEMORIZE-DIVERGENCE-001` |
| RFS-DIS-01 to 05 | system prompt and goal theft, reconnaissance, planted canaries, PII, the debug route, embedding leaks; cross-tenant and cross-session leaks; egress and exfiltration through tools |
| RFS-AGE-01 to 05 | autonomy, persistence, unauthorized and smuggled tool calls, SSRF, RBAC, BFLA, BOLA |
| RFS-OVS-01 | the three specs at the human checkpoint (`AG-CONFIRM-BYPASS-001`, `AG-DESTRUCTIVE-DBDROP-001`, `AG-TRUST-APPROVAL-001`) |
| RFS-TRA-03 | `AG-LOG-EVASION-001` |
| RFS-EXH-01 | `DOS-TOKEN-AMP-001`, `DOS-RESOURCE-HIJACK-001` |

* **Left out of the denominator's numerator, each with its reason:** six requirements are out of
  reach for a black box (`RFS-POI-02` to `04`, the training and supply-chain controls;
  `RFS-OVS-02`, an operator's ability to stop an action; `RFS-TRA-01` and `02`, what the product
  records), one is deliberately untested (`RFS-EXH-02`: degradation once exhausted, which the
  safety charter forbids reaching), and one is roadmap (`RFS-EXT-01`, model extraction). All
  eight stay in the denominator: 19 of 27.
* **Unmapped specs, on purpose (15):** content safety and bias (`SAFETY-*`, `BIAS-*`,
  `MM-IMG-HARMFUL-001`, `RECON-TARGET-OSINT-001`), for which ESP-IA has no threat; the insecure
  generated code specs (`OUT-*`), whose weakness lives in what the code does; `SUPPLY-SLOPSQUAT-001`;
  and the two MCP catalogue specs, which test a server's advertised catalogue and not the AI
  functionality reading it.
* **The vendor's answers on a target file** (u12 A-117): `esp_ia: answers:`, every question
  answered `yes` or `no` (YAML booleans; text such as `SÍ` is refused), `C16a` exactly when `C16`
  is yes, outside the target digest. A refusal never names a key the operator wrote.
* **`dottore coverage --framework esp_ia --target FILE`** applies the matrix: the rules met, the
  threats and policies, the requirements that apply, and for each one the specs that would run
  against that target and the ones that would not, with the reason the plan of `dottore run`
  would give (a capability the target does not declare, a scene it does not hold, a system
  prompt its adapter does not send). An offline mock holds its scene, as the plan reads it.
* **The conditions between elements.** The guide attaches to every rule but `RP02` a condition
  between declared architecture elements ("the interface of C01 reaches the model of C02"). One
  target file declares no elements, so the matrix reads each condition as met whenever the answers
  are, and every view says so.
* **`dottore replay RUN_ID --esp-ia FILE.md [--target FILE]`** (u12 A-118) writes a Markdown draft
  numbered as Annex B is: the run and its digests (section 1), the applicable requirements and
  threats when the target's answers are given (2.4, 2.5), results by requirement (4, Table 3's
  shape: **FAIL evidence**, not falsified, inconclusive, no test in this run, out of reach,
  deliberately not tested; never PASS), one test case per mapped spec (7, Table 5's shape, the
  fields a run cannot know left for the laboratory), and sections 8 and 9 left to the laboratory.
  The target file must be the one the run scanned (its digest, with the run's mock route); a spec
  changed since the run counts for no requirement. Read-only: it never overwrites a file and sends
  nothing.

## Not taken

* **Writing PASS or *PASA*.** The verdict needs the CCN's test guides, which this tool does not
  apply, and a pentest it does not run.
* **The guide's text in the package, or a Spanish draft.** The first is forbidden; the second is
  OD-71.
* **Asking the vendor for the architecture elements** (`I-`, `M-`, `D-`, `S-`) and checking each
  rule's condition: a target file is one endpoint, not an architecture. The draft leaves the
  elements to the laboratory.
* **A model-extraction spec for `RFS-EXT-01`.** Roadmap: the probes a fair extraction test needs
  are many and the safety budget is small (OD-70).

## Costs, stated

The battery files are in the judging digest: judging rules 7 re-pinned, no rule of judgement
changed (`esp_ia` is read by the lint, coverage, `describe` and the draft, by no evaluator).
`_classified_claims` in `registry/linter.py` now carries the AISVS check's two refusals for both
frameworks; its messages are unchanged.

## Reversal

Delete the `esp_ia:` lines of the battery and the target examples (both fields are optional and
outside their digests), the `--target` option of `coverage` and the `--esp-ia` option of
`replay`; `shared.esp_ia` and `cli/esp_ia.py` are then modules nobody reads.
