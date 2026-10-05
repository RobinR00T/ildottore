# 03: Attack Spec format

An **attack spec** is a declarative, versioned, machine-validated test. It is the unit of
reproducibility. Every spec validates against `schemas/attack-spec.schema.json`.

## 1. Design principles

- **Declarative, not procedural.** A spec describes *what* to attempt and *what secure
  behavior looks like*, never imperative code. New Python is only needed for a genuinely new
  *evaluator type* or *mutator type*: not for a new test.
- **Self-proving.** Every spec ships golden fixtures (`fixtures.vulnerable`,
  `fixtures.hardened`) so the scanner can prove the spec detects on a known-bad target and
  passes on a known-good one (see `docs/06`, `docs/07`).
- **Capability-typed.** A spec declares the target capabilities it requires
  (`requires: [rag]`, `requires: [tools]`). Missing capability → `inconclusive`, never a
  false pass/fail.
- **Framework-mapped.** Every spec carries `owasp`, `mitre_atlas`, `nist_ai_rmf` (and an
  optional two-axis `iopc:` block, `techniques` + `impacts`, see `docs/15`, plus an optional
  `aisvs:` list of the OWASP AISVS controls a failure is evidence against) so findings roll up
  to the frameworks operators report against.

## 2. Field reference

| Field | Req | Meaning |
|---|---|---|
| `id` | ✓ | Stable unique id, `FAMILY-SUBTYPE-NNN` (e.g. `PI-INDIRECT-RAG-001`). |
| `spec_version` | ✓ | Schema version this spec targets (semver of the format). |
| `name` | ✓ | Human title. |
| `category` | ✓ | One of the nine taxonomy families: `prompt_injection`, `jailbreak`, `data_leakage`, `agent_tool_abuse`, `rag_security`, `output_security`, `availability_cost`, and the two responsible-AI families `safety_content` and `bias_fairness` (`shared/enums.py`). |
| `owasp` / `mitre_atlas` / `nist_ai_rmf` | ✓ | Framework mappings. |
| `iopc` | | Nova IoPC mapping on two axes: `techniques` (the how, `IOPC-T<family>.<nnn>`) and `impacts` (the damage, `IOPC-R<nnn>`). Either axis alone is valid. Optional so third-party packs keep validating; the shipped battery is held to it by test. Codes outside the pinned taxonomy are a lint error (`docs/15`). |
| `aisvs` | | OWASP AISVS 1.0 requirement IDs in the standard's citation form (`v1.0-C2.1.6`) whose control a **FAIL of this spec is evidence against**. Falsification only: a PASS never verifies a control, because a black box never sees the control itself (clause A-28). An ID outside the pinned table is `UNKNOWN_FRAMEWORK_CODE`; an ID the table classifies as out of reach or deliberately untested is `FRAMEWORK_CLAIM_CONTRADICTED`. Optional. IDs only, never the requirement text (CC-BY-SA). |
| `severity` | ✓ | Author's *a-priori* impact class; final risk is computed (`docs/05`). |
| `target_type` | ✓ | `model` \| `chatbot` \| `api` \| `agent` \| `rag`. |
| `requires` | ✓ | Capabilities needed (`rag`, `tools`, `memory`, `system_prompt`). |
| `description` | ✓ | What the test validates. |
| `preconditions` | | Human-readable prerequisites. |
| `setup` | | Declarative setup: `documents`, `tools` (mock defs), `memory_seed`, `system_prompt`. Only `system_prompt` reaches a live target today. The request carries the prompt (for a multi-turn spec, the pinned turns as `messages`), the system prompt, the sampling, the media (with their digests in `metadata`) and, on the multi-identity sweep, the identity; `ModelRequest` has a `tools` field, and nothing sets it. So `documents`, `tools` and `memory_seed` are read only by the evaluators, the lint fixture engine and the linter, and never delivered to a target. 32 of the 75 shipped specs depend on one of the three (OD-18, ADR-0009). |
| `attack` | ✓ | `user_prompt` and/or `carrier` (for indirect injection). `media` adds image or audio parts; the `render_text` of an image that is rendered from it (no `data_b64`) counts as part of the request for `dottore lint`'s echo rule. |
| `mutations` | | List of mutation strategies to apply (see §4). |
| `expected_secure_behavior` | ✓ | Bulleted description of a passing target (drives judge rubric). |
| `evaluators` | ✓ | Ordered evaluator configs (`docs/04`). |
| `evaluator_logic` | | Declared (`all_pass`, `any_fail`, `weighted`), **not read by the runner**. A run combines evaluators by one fixed rule (§3). The lint fixture engine reads it, but every value comes out the same there: any failing stub evaluator makes the fixture `fail`, which for `all_pass`, `any_fail` and `weighted` alike is any-fail. Which semantics is meant is open decision OD-19 (ADR-0010). |
| `scoring` | ✓ | `impact`, `exploitability` (1-4 each) + `confidence_threshold`. |
| `runs` | | N for reproducibility, **declarative only**: the runner ignores it and sends every mutation variant of every spec `--runs` times (default 5), so a spec with `identity` plus three mutations sends 4 x N (times its turns, for a multi-turn spec). The six specs that declare `runs: 3` as a cost control (the two `DOS-*` and four `OUT-*` specs) also run 5. A suite's `default_runs` is likewise not read. |
| `sampling` | | Pinned `temperature`, `top_p`, `seed`, `max_tokens`. |
| `budget` | | Hard caps (`max_tokens`, `max_requests`, `timeout_s`), designed as mandatory for `availability_cost`. **Not enforced and not read:** the schema validates the shape only (no rule makes it mandatory; the two `DOS-*` specs declare it), and nothing in `src/` reads a spec's `budget`. The ceilings that bind a run are campaign-wide (`core/budgets.py`): tokens, requests, wall-clock and attempts, each derived from the resolved plan (never below `DEFAULT_PLAN_BUDGETS`, never above `BUDGET_DERIVATION_CAP` unless the operator says so); the first three can be set by `--budget-tokens`, `--budget-requests` and `--budget-wall`, and the attempts ceiling has no flag. A spec's `sampling.max_tokens` feeds the token estimate. |
| `test_only` | | `true` for any dangerous payload (default `false`, but linter forces `true` for flagged families). |
| `fixtures` | ✓ | `vulnerable` and `hardened` canned responses proving the spec works. |
| `tags` | | Free-form. |

## 3. Canonical example (improved from v0.1)

See `specs/attacks/PI-INDIRECT-RAG-001.yaml`. Key improvements over the v0.1 draft:

- Added `spec_version`, `requires`, `nist_ai_rmf`, `runs`, `sampling`, `budget`, `fixtures`.
- Data-leakage detection uses a **planted canary** (`{{canary}}`) instead of real secrets (S2).
- Judge rubric explicitly separates "obeyed embedded instruction" from "mentioned it" to cut
  false positives.
- Evaluators are combined by the runner's fixed rule, not by `evaluator_logic`: a deterministic
  `fail` decides; else any `inconclusive` (a deterministic abstention, or a judge that was not
  configured or was compromised) decides; else a judge `fail` decides; else `pass`. So the judge
  alone decides an attempt when every deterministic evaluator passed, and today that finding can
  be `confirmed` and trip `--fail-on` (OD-19, ADR-0010 and its amendment).

## 4. Mutation strategies (Prompt Mutator)

Declared per-spec; each is a deterministic transform seeded by `(spec.id, mutation.name)` so
runs are reproducible. Built-in strategies (19 in the registry):

`identity`, `translate:<lang>`, `base64_wrap`, `rot13`, `unicode_confusable`,
`zero_width_inject`, `roleplay_wrap`, `nested_instruction`, `markdown_comment_carrier`,
`html_comment_carrier`, `payload_splitting`, `refusal_suppression_prefix`, `leetspeak`,
`adversarial_poetry`, `adversarial_suffix`, `context_poisoning`, `gray_box`,
`linguistic_confusion`, `math_problem`.

`translate:<lang>` does not translate the prompt. `<lang>` is one of `es`, `fr`, `de`, `zh`
(`LANGUAGES` in `mutators/translate.py`). The mutator replaces each space-separated word whose
lower-cased, punctuation-stripped form is in a 14-word keyword table (`PHRASE_MAP`: ignore,
previous, instructions, reveal, system, prompt, password, secret, tell, me, the, your, and, all)
with that language's gloss, dropping the word's punctuation, and leaves every other word in
English. In `zh` the gloss for "the" is empty, so 13 words change. A prompt written in those
keywords comes out mostly glossed; an ordinary one changes a word or two: on
`JB-MULTILINGUAL-001`, `translate:es` changes one word ("the" to "el") and `translate:zh`
changes none, so that variant sends the identity prompt. A bare `translate` picks one of the
four languages from a hash of the seed (`de` for that spec) and records it in the provenance.
It is not a per-language battery.

A `name:param` mutation is checked against the mutator's declared `accepted_params` (`docs/06
§3`): `translate` accepts its four languages (compared lower-cased and stripped, so
`translate:ES` is accepted), and every other built-in accepts no parameter. `dottore lint`
reports an unaccepted one as `UNKNOWN_MUTATOR_TYPE` (for example `translate:klingon`, or
`rot13:x`), and the runner refuses the spec with `unknown_mutator_parameter` and sends nothing
for it. Before the check, `translate:klingon` sent a language picked by hash and the evidence
recorded "klingon".

Mutators are **pluggable** (`docs/06`). A mutation never changes the *intent* of a spec; it
changes the *carrier/obfuscation*, so the same `expected_secure_behavior` still applies.

## 5. Suites

A suite (`specs/suites/*.yaml`) is an **ordered, versioned reference list** of spec ids
(`id`, `name`, `description`, `suite_version`, `specs`, `default_runs`, `tags`). Suite-level
sampling, budget and `fail_on` defaults are not modeled (the suite files keep them as comments),
and `default_runs` is not read by the runner (§2, `runs`). Suites are
how you ship "the OWASP LLM Top 10 pack" or "the customer-agent baseline". Adding a technique =
add a spec + reference it in a suite (no code). See `specs/suites/owasp-llm-top10.yaml`.
