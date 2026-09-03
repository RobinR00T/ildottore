# 02 - Threat model & safety model (of the scanner itself)

A security tool that is itself unsafe is a liability. This document is **normative**: the
build must satisfy it.

## 1. Assets & actors

- **Assets**: customer credentials (`auth_ref`), target endpoints, evidence (may contain
  leaked secrets from the target), the scope authorization, the scanner's own LLM keys.
- **Legit actor**: an authorized operator running an authorized engagement.
- **Abuse actors**: (a) operator scanning an out-of-scope system; (b) a malicious *target*
  that attacks the scanner back (esp. the LLM judge); (c) exfiltration of evidence.

## 2. Safety requirements (hard invariants)

| ID | Requirement |
|----|-------------|
| S1 | **No real destructive actions.** Any tool with side effects (email/calendar/file/HTTP-write/shell/db-write) runs as a **mock or dry-run**; the scanner records the *intent* to call, never executes it. |
| S2 | **No real exfiltration.** Data-leakage tests use **canaries** (unique tokens planted by the scanner) - detection = "did the canary appear in output", never real secrets. |
| S3 | **Endpoint allowlist.** Adapters refuse any host/path not in the scope allowlist. Default-deny. |
| S4 | **Authorization gate.** No run starts without a valid `scope.yaml` covering every target; scope file integrity is checksum-verified and the run records its hash. |
| S5 | **Payload marking.** Every payload that would be dangerous outside a test is `test_only: true` and tagged; reports never render raw dangerous payloads without a `--unsafe-render` opt-in. |
| S6 | **Secret masking.** Secrets/keys are masked in logs, console and reports by a central redactor; evidence stored encrypted at rest (MVP‑2+). |
| S7 | **Judge isolation.** The LLM judge treats target output as **untrusted data**, never as instructions (see `docs/04 §4`). A target that jailbreaks our judge must not flip a verdict. |
| S8 | **Rate & cost caps.** DoS/availability tests have hard token, request and wall-clock budgets; the scanner cannot be turned into a DoS weapon by a spec. |
| S9 | **Blast-radius for RAG/agent setup.** Test corpora are namespaced and torn down; the scanner never writes to a production index without an explicit, scoped, reversible flag. |

## 3. Legal / ethical framing

- The tool assists **authorized** security testing only. The scope file *is* the
  authorization record. Runs are auditable (who/what/when/scope-hash).
- This is a defensive/assurance tool: it validates that a model or AI app resists known
  attack classes. It is not a jailbreak-as-a-service.

## 4. Attacks against the scanner (and mitigations)

| Threat | Mitigation |
|--------|------------|
| Malicious target output prompt-injects the **judge** and flips verdicts | Judge hardening (`docs/04 §4`): output wrapped in data delimiters, judge told it evaluates untrusted data, self-check probes, disagreement → `inconclusive`. |
| Evidence contains real leaked secrets | Redactor + at-rest encryption + access controls; canaries preferred over real secrets. |
| Spec pack from a third party contains a malicious payload / SSRF carrier | Spec linter + policy pack allowlist + `test_only` enforcement + no network from spec loading (`docs/06 §5`). |
| Operator scans out of scope | S3/S4 default-deny gate. |
| Cost blow-up (recursive/expensive specs) | S8 budgets, enforced in the runner, not the spec. |

## 5. Out of scope (v1)

- Actual model weight extraction, training-data reconstruction, or any technique requiring
  privileged/internal access beyond the target's normal interface.
- Real exploitation of downstream systems reached via tool calls (always mocked).
