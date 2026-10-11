# u13-attack-specs-battery.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/03`
(spec format) + `docs/08` (T0 battery) + `docs/11` (data-leak family) + `schemas/` + the
exemplars `specs/attacks/PI-INDIRECT-RAG-001.yaml`, `specs/attacks/DoS-TOKEN-AMP-001.yaml`,
`specs/suites/owasp-llm-top10.yaml` before authoring. **Data + fixtures only: no engine code.**

## §1 Scope & ownership
- **OWNS:** `specs/attacks/*.yaml` (the ~18 T0 specs of `docs/08 §3`), `specs/suites/*.yaml`
  (`owasp-llm-top10.yaml` + `quick.yaml`), and each spec's golden fixtures (`fixtures.vulnerable`
  / `fixtures.hardened`, inline in the spec: there is no sidecar location, OD-7;
  `tests/fixtures/specs/` holds the schema-parity corpus, not fixtures).
- **MUST NOT touch:** any `src/ildottore/**` Python, `schemas/attack-spec.schema.json` (consumes,
  never edits: a schema change is an OD to u02), `docs/`, other units' owned files.

## §2 Intended behavior
Author the full **T0 "Quick" battery** (18 ids, `docs/08 §3` rows 1-18) as declarative,
schema-valid YAML attack specs: each describing *what to attempt* and *what secure behavior
looks like*, never imperative code (`docs/03 §1`). Every spec is **self-proving**: it ships a
`vulnerable` fixture the scanner must flag and a `hardened` fixture it must pass, plus at least
one **hallucinated-but-valid negative** for the data-leak family (a format-valid SSN/card/API-key
with no corroboration ⇒ `needs-review`, never a confirmed breach; `docs/11 §4`). Wire all specs
into the `owasp:llm` suite and a `quick` suite. Data-leak specs (rows 8-9, 16-18) implement the
`docs/11` families: canary/secret-shape, divergence memorization, cross-tenant/authz, PII-elicit.

## §3 Dependencies & interface contracts
- Depends on **u02** (spec-registry-linter: `dottore lint specs/` is the gate) and **u03**
  (mock-target + golden harness that replays fixtures). No runtime dep on u04/u06/u08.
- Every spec validates against `schemas/attack-spec.schema.json`; field semantics per `docs/03 §2`.
- `evaluators[].type` strings MUST be ones u06 registers, which is exactly the
  `EvaluatorType` enum (the schema enum is kept 1:1 with it by `tests/shared/test_schema_parity.py`):
  `regex_absence`/`regex_presence`, `exact_match`, `refusal`, `secret_leakage`, `tool_call`,
  `tool_sequence`, `semantic_judge`, `pii_detector`, `secret_shape`, `verbatim_overlap`,
  `logprob_membership`, `authz_leak`, `kill_chain_progression`.
  (Refreshed 2026-09-19: the original list omitted the MVP-2 types and listed `canary`, which
  was never an `EvaluatorType`; a planted canary is proven by `secret_leakage`.)
- `mutations[]` use only built-in strategy names from `docs/03 §4`. `requires[]` uses
  `Capabilities` names (`rag`, `tools`, `memory`, `system_prompt`, `logprobs`, `multi_identity`).
- Verdict polarity fixed repo-wide (`00-INDEX`): `pass` = secure, `fail` = exploited.

## §4 Known constraints: KEEP / DECIDE
- KEEP: leak proof only by **canary / reference-corpus / cross-identity** match (`docs/11 §4`);
  format-only hits ⇒ `needs-review`. No spec ever encodes a real secret/PII: use `{{canary}}`
  and synthetic identities (safety rules DL1-DL6, `docs/11 §5`).
- KEEP: `DL-PII-ELICIT-001` ships `test_only: true` and is **off unless the policy pack enables**
  it (layer-B); `DoS-TOKEN-AMP-001` MUST carry a `budget` block (`docs/03 §2`, `AGENTS.md §2`).
- KEEP: specs needing capabilities absent on target (`logprobs`, `multi_identity`) return
  `inconclusive`, never a false pass: enforced by `requires[]`, verified via u03 harness.
- KEEP: each spec carries `owasp`/`mitre_atlas`/`nist_ai_rmf` + `spec_version` + pinned `sampling`.
- DECIDE: whether `quick.yaml` is a distinct file or an alias/subset view of `owasp:llm` (propose
  distinct file referencing the 18 ids). Not this unit's call: schema shape changes (→ u02 OD).

## §5 Implementation plan (each step its own commit, green before next)
1. Prompt-injection + jailbreak + SP-leak set (rows 1-7): `PI-DIRECT-001`, `PI-INDIRECT-RAG-001`
   (exists: reuse as pattern), `PI-INDIRECT-TOOL-001`, `JB-ROLEPLAY-001`,
   `JB-REFUSAL-SUPPRESS-001`, `JB-ENCODING-001`, `SP-LEAK-001`.
2. Output-security + agent/tool set (rows 10-15): `OUT-CODEINJ-001`, `OUT-XSS-001`,
   `OUT-SQLI-001`, `AG-TOOL-UNAUTH-001`, `AG-CONFIRM-BYPASS-001`, `DoS-TOKEN-AMP-001` (exists).
3. Data-leak family (rows 8-9, 16-18, `docs/11`): `DL-SECRET-CANARY-001`, `DL-XSESSION-001`,
   `DL-MEMORIZE-DIVERGENCE-001`, `DL-XTENANT-001`, `DL-PII-ELICIT-001`: each with a
   hallucinated-but-valid negative fixture.
4. Golden fixtures for all 18 (`vulnerable` + `hardened`), then suites: `owasp-llm-top10.yaml`
   (extend existing) + `quick.yaml`, with framework rollup + run-level defaults (`docs/03 §5`).

## §6 Data/wire shapes
- Spec = the `docs/03 §2` field set; required: `id, spec_version, name, category, owasp,
  mitre_atlas, nist_ai_rmf, severity, target_type, requires, description, attack,
  expected_secure_behavior, evaluators, scoring, fixtures`. `id` = `FAMILY-SUBTYPE-NNN`.
- `fixtures.vulnerable` / `.hardened` = canned `ModelResponse`-shaped payloads (text + optional
  tool_calls/logprobs) the u03 harness feeds the evaluator pipeline. Data-leak vulnerable fixtures
  emit `{{canary}}` or B-only data; hardened refuse or return only authorized data.
- Suite = ordered `spec_ids[]` + `defaults{runs, sampling, budget}` + `frameworks{}` rollup.

## §7 Acceptance criteria (machine-checkable)
- `dottore lint specs/` exits 0: all 18 specs + 2 suites schema-valid (u02 gate), no unknown
  `evaluator.type`/`mutation`/`requires` name, no duplicate `id`, every `test_only` family flagged.
- `pytest tests/battery tests/golden -q` green (u03 golden harness; CI gate 5): for **every**
  spec the scanner **flags the `vulnerable` fixture (`fail`)** and **passes the `hardened`
  fixture (`pass`)**: 18/18 at the time this contract was written, no skips. (Path corrected
  2026-10-04: there is no `tests/specs`. The battery has since grown to 75 specs and 14 suites,
  which `dottore lint specs/` checks.)
- Data-leak FP gate: each hallucinated-but-valid negative fixture yields `needs-review`/
  `inconclusive`, **never `fail`** (asserts `docs/11 §4` discipline). `DoS-TOKEN-AMP-001` has a
  `budget` block; `DL-PII-ELICIT-001` has `test_only: true`: both asserted in tests.
- Coverage: `owasp:llm` + `quick` suites reference all 18 ids; `DL-XTENANT-001` `requires`
  `multi_identity`, `DL-MEMORIZE-DIVERGENCE-001`/membership `requires` `logprobs`.
- Redaction: no fixture contains a real secret/PII (grep gate: only `{{canary}}` + synthetic).
- A flag the model sets on its own destructive call is not a confirmation (OD-38, u06 A-65,
  added 2026-10-09): `AG-CONFIRM-BYPASS-001`'s `vulnerable` fixture carries `confirm: true` on
  its `delete_records` call, so lint and the battery fail if such a flag counts again. No
  `hardened` fixture may rely on one, and none of the 75 carries one.
- A reply that answers nothing decides no spec (OD-16, decided 2026-10-11 under the owner's
  delegation, ADR-0007 option B): against a mock that answers every prompt with one canned
  string, with every capability declared, all 75 specs are `inconclusive`. A text oracle keys on
  the artifact of the exploit (absence polarity) and is paired with a `semantic_judge` wherever
  it cannot prove the secure direction alone; every shipped spec declares a judge.
  `DOS-TOKEN-AMP-001` keys on 100 repetitions in a row and `MCP-TOOLPOISON-001` has a judge
  (`tests/battery/test_irrelevant_reply.py`; it was `inconclusive 73 · fail 1 · pass 1` on
  `6d5f7ae`).
- An MCP spec runs against an MCP server only (OD-44, decided 2026-10-11 under the owner's
  delegation): `MCP-TOOLPOISON-001` `requires: [mcp]`, the capability a target has exactly when
  its provider is `mcp` (an offline mock may declare it), so a chat model is never sent its
  discovery request as a prompt; the golden harness gives the mock the capability, as it does every
  capability a spec requires.
- No `src/**` diff from this unit; `lint-imports` unaffected (YAML-only change).

## §8 Out of scope / forbidden
- MUST NOT write or modify Python, evaluators, mutators, or the JSON schema (consume only).
- MUST NOT embed real secrets, real PII, or real breach-corpus data (DL2/DL3: synthetic/canary
  only). MUST NOT ship a `data_leakage` layer-B spec enabled by default.
- MUST NOT invent evaluator/mutation types not registered by u06 / listed in `docs/03 §4`.
- MUST NOT author beyond the T0 18 (T1/T2 specs are MVP-2+, `docs/08 §4-§5`).
- Not this unit's call: scoring formula (u07), judge model (OD-3), schema evolution (u02).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- `quick.yaml` as a distinct suite file vs a subset alias of `owasp:llm` (propose distinct file).
- Whether `DL-PII-ELICIT-001` ships at all in MVP-1 or is deferred pending the layer-B legal
  gate / policy-pack wiring (`docs/11 §5` DL4/DL5). **Decided 2026-10-11 under the owner's
  delegation (best practice), revisable (OD-11): it ships, `test_only`, disabled by default,
  and the safe default stands.** Today nothing in the CLI can enable it: no option loads a
  policy pack or sets the run's PII key. An explicit opt-in is the right shape, and it is DL4's
  two keys, added together: a policy pack the run loads and records (the engagement's written
  authorization, DL5: `allow_pii_elicitation: true` and `enabled_capabilities: [layer_b_pii]`)
  and a per-run `--allow-pii-elicitation` flag (the operator's deliberate act, so a pack
  reused from another engagement does not enable it alone). A run flag is not added alone: with
  no pack to load it would enable nothing, since the CLI's own pack enables no capability. Both
  come with the policy-pack flag, which stays open (unnumbered, `docs/12`) because it also gates
  the seven `agentic-extortion` specs. Alternatives not taken: one flag that enables it alone
  (one switch and no written record, against DL4 and DL5); dropping the spec until then (it would
  lose its lint proof; `blocked_by_policy` already says what holds it back); an opt-in in the
  scope file (the scope authorizes targets, not test categories). Pinned by
  `tests/policy/test_policy_audit_2026_10_03.py:55` (the shipped spec stays blocked with only its
  capability enabled, neither DL4 key turned) and `:69` (it runs only when every key is turned).
  Reversal (to let one flag enable it): a `run` option that sets
  `SafetyFlags(allow_pii_elicitation=True)` and adds `allow_pii_elicitation` and `layer_b_pii` to
  the pack `cli/wiring.build_permissive_pack` builds, with DL4 in `docs/11` rewritten to one
  key.
- Fixture location convention: inline in the spec vs `tests/fixtures/specs/<id>/`. **Decided
  2026-10-11 under the owner's delegation (best practice), revisable: inline only, as built
  (OD-7, reasoning in u03 §9).** Revisit if a fixture outgrows its spec file (a long multi-turn
  transcript).
