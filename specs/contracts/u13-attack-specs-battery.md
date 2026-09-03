# u13-attack-specs-battery.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/03`
(spec format) + `docs/08` (T0 battery) + `docs/11` (data-leak family) + `schemas/` + the
exemplars `specs/attacks/PI-INDIRECT-RAG-001.yaml`, `specs/attacks/DoS-TOKEN-AMP-001.yaml`,
`specs/suites/owasp-llm-top10.yaml` before authoring. **Data + fixtures only - no engine code.**

## §1 Scope & ownership
- **OWNS:** `specs/attacks/*.yaml` (the ~18 T0 specs of `docs/08 §3`), `specs/suites/*.yaml`
  (`owasp-llm-top10.yaml` + `quick.yaml`), and each spec's golden fixtures (`fixtures.vulnerable`
  / `fixtures.hardened`, inline or under `tests/fixtures/specs/<id>/`).
- **MUST NOT touch:** any `src/ildottore/**` Python, `schemas/attack-spec.schema.json` (consumes,
  never edits - a schema change is an OD to u02), `docs/`, other units' owned files.

## §2 Intended behavior
Author the full **T0 "Quick" battery** (18 ids, `docs/08 §3` rows 1-18) as declarative,
schema-valid YAML attack specs - each describing *what to attempt* and *what secure behavior
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
- `evaluators[].type` strings MUST be ones u06 registers: `regex_absence`/`regex_presence`,
  `exact_match`, `refusal`, `secret_leakage`, `tool_call`, `semantic_judge`, `pii_detector`,
  `secret_shape`, `authz_leak`, `canary`, `logprob_membership`, `verbatim_overlap`.
- `mutations[]` use only built-in strategy names from `docs/03 §4`. `requires[]` uses
  `Capabilities` names (`rag`, `tools`, `memory`, `system_prompt`, `logprobs`, `multi_identity`).
- Verdict polarity fixed repo-wide (`00-INDEX`): `pass` = secure, `fail` = exploited.

## §4 Known constraints - KEEP / DECIDE
- KEEP: leak proof only by **canary / reference-corpus / cross-identity** match (`docs/11 §4`);
  format-only hits ⇒ `needs-review`. No spec ever encodes a real secret/PII - use `{{canary}}`
  and synthetic identities (safety rules DL1-DL6, `docs/11 §5`).
- KEEP: `DL-PII-ELICIT-001` ships `test_only: true` and is **off unless the policy pack enables**
  it (layer-B); `DoS-TOKEN-AMP-001` MUST carry a `budget` block (`docs/03 §2`, `AGENTS.md §2`).
- KEEP: specs needing capabilities absent on target (`logprobs`, `multi_identity`) return
  `inconclusive`, never a false pass - enforced by `requires[]`, verified via u03 harness.
- KEEP: each spec carries `owasp`/`mitre_atlas`/`nist_ai_rmf` + `spec_version` + pinned `sampling`.
- DECIDE: whether `quick.yaml` is a distinct file or an alias/subset view of `owasp:llm` (propose
  distinct file referencing the 18 ids). Not this unit's call: schema shape changes (→ u02 OD).

## §5 Implementation plan (each step its own commit, green before next)
1. Prompt-injection + jailbreak + SP-leak set (rows 1-7): `PI-DIRECT-001`, `PI-INDIRECT-RAG-001`
   (exists - reuse as pattern), `PI-INDIRECT-TOOL-001`, `JB-ROLEPLAY-001`,
   `JB-REFUSAL-SUPPRESS-001`, `JB-ENCODING-001`, `SP-LEAK-001`.
2. Output-security + agent/tool set (rows 10-15): `OUT-CODEINJ-001`, `OUT-XSS-001`,
   `OUT-SQLI-001`, `AG-TOOL-UNAUTH-001`, `AG-CONFIRM-BYPASS-001`, `DoS-TOKEN-AMP-001` (exists).
3. Data-leak family (rows 8-9, 16-18, `docs/11`): `DL-SECRET-CANARY-001`, `DL-XSESSION-001`,
   `DL-MEMORIZE-DIVERGENCE-001`, `DL-XTENANT-001`, `DL-PII-ELICIT-001` - each with a
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
- `dottore lint specs/` exits 0 - all 18 specs + 2 suites schema-valid (u02 gate), no unknown
  `evaluator.type`/`mutation`/`requires` name, no duplicate `id`, every `test_only` family flagged.
- `pytest tests/specs -q` green (u03 golden harness): for **every** spec the scanner **flags the
  `vulnerable` fixture (`fail`)** and **passes the `hardened` fixture (`pass`)** - 18/18, no skips.
- Data-leak FP gate: each hallucinated-but-valid negative fixture yields `needs-review`/
  `inconclusive`, **never `fail`** (asserts `docs/11 §4` discipline). `DoS-TOKEN-AMP-001` has a
  `budget` block; `DL-PII-ELICIT-001` has `test_only: true` - both asserted in tests.
- Coverage: `owasp:llm` + `quick` suites reference all 18 ids; `DL-XTENANT-001` `requires`
  `multi_identity`, `DL-MEMORIZE-DIVERGENCE-001`/membership `requires` `logprobs`.
- Redaction: no fixture contains a real secret/PII (grep gate: only `{{canary}}` + synthetic).
- No `src/**` diff from this unit; `lint-imports` unaffected (YAML-only change).

## §8 Out of scope / forbidden
- MUST NOT write or modify Python, evaluators, mutators, or the JSON schema (consume only).
- MUST NOT embed real secrets, real PII, or real breach-corpus data (DL2/DL3 - synthetic/canary
  only). MUST NOT ship a `data_leakage` layer-B spec enabled by default.
- MUST NOT invent evaluator/mutation types not registered by u06 / listed in `docs/03 §4`.
- MUST NOT author beyond the T0 18 (T1/T2 specs are MVP-2+, `docs/08 §4-§5`).
- Not this unit's call: scoring formula (u07), judge model (OD-3), schema evolution (u02).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- `quick.yaml` as a distinct suite file vs a subset alias of `owasp:llm` (propose distinct file).
- Whether `DL-PII-ELICIT-001` ships at all in MVP-1 or is deferred pending the layer-B legal
  gate / policy-pack wiring (`docs/11 §5` DL4/DL5) - flag for human sign-off.
- Fixture location convention: inline in the spec vs `tests/fixtures/specs/<id>/` (propose inline
  for T0 simplicity; revisit if fixtures grow multi-turn).
