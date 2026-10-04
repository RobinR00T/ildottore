# 02: Threat model & safety model (of the scanner itself)

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
| S2 | **No real exfiltration.** Data-leakage tests use **canaries** (unique tokens planted by the scanner): detection = "did the canary appear in output", never real secrets. |
| S3 | **Endpoint allowlist.** Adapters refuse any host/path not in the scope allowlist. Default-deny. |
| S4 | **Authorization gate.** No run starts without a valid `scope.yaml` covering every target; scope file integrity is checksum-verified and the run records its hash. (Status: the first half holds. The integrity half does not yet: the scope's SHA-256 `checksum` is optional, verified only when present, and lives in the file it protects, so an editor can recompute or delete it. It is a checksum, not a signature; real signing is open decision OD-2. No run records the scope hash: `policy.scope_hash()` has no caller, and neither the run store nor any report carries it.) |
| S5 | **Payload marking.** Every payload that would be dangerous outside a test is `test_only: true` and tagged; reports never render raw dangerous payloads without a `--unsafe-render` opt-in. (Status: the marking holds, the rendering half does not. The mark is enforced from the spec's category, by `dottore lint` (`MISSING_TEST_ONLY`) and at run time, where an unmarked spec in a flagged family is `blocked_by_policy` (A-29). The opt-in is not built: there is no `--unsafe-render` flag. The HTML reporter has an internal `unsafe_render` switch, off by default and set by nothing, that adds a banner and decides whether finding reasoning is HTML-escaped; autoescape stays on and the HTML report does not show prompts. No reporter reads `test_only`, and the JSON report carries each attempt's request, prompt included: it passes through the redactor, which masks secret, PII and high-entropy shapes and nothing else, so the attack text of a `test_only` spec is readable in the JSON report.) |
| S6 | **Secret masking.** Secrets/keys are masked in logs, console and reports by a central redactor; evidence stored encrypted at rest (MVP‑2+). (Status: masking holds; encryption at rest is not built. An error the CLI prints passes through the redactor too (`cli/app._masked`): URL passwords are masked first; a 64-hex value stays readable only as an evidence file name (`<sha256>.json`) or as a digest the tool computed and the error carries (on a scope checksum mismatch the digest of the body, while the `checksum:` value the operator typed is not quoted at all; on a tamper refusal the hash the artifact's content has now), unless it overlaps a registered credential; every other 64-hex value goes to the redactor. An error names an `auth_ref` only when it is a reference containing `://`; a literal pasted in its place prints as "a literal value (not shown)", because the redactor recognised a raw key only by its entropy. A scope validation error names fields and reasons, never the input value.) |
| S7 | **Judge isolation.** The LLM judge treats target output as **untrusted data**, never as instructions (see `docs/04 §4`). A target that jailbreaks our judge must not flip a verdict. |
| S8 | **Rate & cost caps.** Hard token, request, attempt and wall-clock budgets (`core/budgets.py`), sized from the resolved plan so a ceiling never truncates a scan in silence, **plus** an enforced request-rate ceiling (`core/pacing.py`, `--rate` / `-T`): one shared gate for the whole campaign, so concurrency cannot multiply it, and retries count against it. The scanner cannot be turned into a DoS weapon by a spec. (The rate half of this row was aspirational until 2026-09-21: `--rate` was parsed and dropped, so `--rate 0.0001` finished eighteen specs in 0.67s. Pacing is not applied to an offline mock run, where nothing leaves the process, and the resolved plan states that explicitly. The `--judge` model and the multi-identity sweep sent outside both halves until 2026-10-03; they now pass the same gate and debit the same ceilings, retries happen in one layer so each one counts, and `--rate` must be greater than 0.) |
| S9 | **Blast-radius for RAG/agent setup.** Test corpora are namespaced and torn down; the scanner never writes to a production index without an explicit, scoped, reversible flag. |

## 3. Legal / ethical framing

- The tool assists **authorized** security testing only. The scope file *is* the
  authorization record. Runs are meant to be auditable (who/what/when/scope-hash). Today a run
  records the *what* (spec digests, target digest, judge digest, run count, planning mode) and
  not the rest: no operator, no scope hash, and `started_at` / `finished_at` are empty in the
  run store and in the JSON report.
- This is a defensive/assurance tool: it validates that a model or AI app resists known
  attack classes. It is not a jailbreak-as-a-service.

## 4. Attacks against the scanner (and mitigations)

| Threat | Mitigation |
|--------|------------|
| Malicious target output prompt-injects the **judge** and flips verdicts | Judge hardening (`docs/04 §4`): output wrapped in data delimiters, judge told it evaluates untrusted data, self-check probes, disagreement → `inconclusive`. (Status: the judge evaluator returns `inconclusive` on a disagreement between its two passes, but with no reason, and the runner drops a reasonless judge abstention: the attempt is decided by the deterministic evaluators alone, a `pass` when they all pass, and is `inconclusive` only when the judge is the spec's sole evaluator. Whether a disagreement should keep the attempt `inconclusive`, as this row says, is an open question for the owner, `docs/04 §2`. A judge that emits the tripwire, or reports an injection while saying `secure`, is `judge_compromised` and is kept.) |
| Evidence contains real leaked secrets | Redactor + at-rest encryption + access controls; canaries preferred over real secrets. (Encryption at rest is MVP-2+ and not built, see S6.) |
| Spec pack from a third party contains a malicious payload / SSRF carrier | Spec linter + policy pack allowlist + `test_only` enforcement + no network from spec loading (`docs/06 §5`). |
| Operator scans out of scope | S3/S4 default-deny gate. |
| Cost blow-up (recursive/expensive specs) | S8 budgets, enforced in the runner, not the spec. |

## 5. Out of scope (v1)

- Actual model weight extraction, training-data reconstruction, or any technique requiring
  privileged/internal access beyond the target's normal interface.
- Real exploitation of downstream systems reached via tool calls (always mocked).
