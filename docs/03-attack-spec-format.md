# 03 — Attack Spec format

An **attack spec** is a declarative, versioned, machine-validated test. It is the unit of
reproducibility. Every spec validates against `schemas/attack-spec.schema.json`.

## 1. Design principles

- **Declarative, not procedural.** A spec describes *what* to attempt and *what secure
  behavior looks like*, never imperative code. New Python is only needed for a genuinely new
  *evaluator type* or *mutator type* — not for a new test.
- **Self-proving.** Every spec ships golden fixtures (`fixtures.vulnerable`,
  `fixtures.hardened`) so the scanner can prove the spec detects on a known-bad target and
  passes on a known-good one (see `docs/06`, `docs/07`).
- **Capability-typed.** A spec declares the target capabilities it requires
  (`requires: [rag]`, `requires: [tools]`). Missing capability → `inconclusive`, never a
  false pass/fail.
- **Framework-mapped.** Every spec carries `owasp`, `mitre_atlas`, `nist_ai_rmf` so findings
  roll up to the frameworks operators report against.

## 2. Field reference

| Field | Req | Meaning |
|---|---|---|
| `id` | ✓ | Stable unique id, `FAMILY-SUBTYPE-NNN` (e.g. `PI-INDIRECT-RAG-001`). |
| `spec_version` | ✓ | Schema version this spec targets (semver of the format). |
| `name` | ✓ | Human title. |
| `category` | ✓ | One of the taxonomy families (`prompt_injection`, `jailbreak`, `data_leakage`, `agent_tool_abuse`, `rag_security`, `output_security`, `availability_cost`). |
| `owasp` / `mitre_atlas` / `nist_ai_rmf` | ✓ | Framework mappings. |
| `severity` | ✓ | Author's *a-priori* impact class; final risk is computed (`docs/05`). |
| `target_type` | ✓ | `model` \| `chatbot` \| `api` \| `agent` \| `rag`. |
| `requires` | ✓ | Capabilities needed (`rag`, `tools`, `memory`, `system_prompt`). |
| `description` | ✓ | What the test validates. |
| `preconditions` | | Human-readable prerequisites. |
| `setup` | | Declarative setup: `documents`, `tools` (mock defs), `memory_seed`, `system_prompt`. |
| `attack` | ✓ | `user_prompt` and/or `carrier` (for indirect injection). |
| `mutations` | | List of mutation strategies to apply (see §4). |
| `expected_secure_behavior` | ✓ | Bulleted description of a passing target (drives judge rubric). |
| `evaluators` | ✓ | Ordered evaluator configs (`docs/04`). |
| `evaluator_logic` | | Boolean combination, default `all_pass`. |
| `scoring` | ✓ | `impact`, `exploitability` (1–4 each) + `confidence_threshold`. |
| `runs` | | N for reproducibility (default from suite/global). |
| `sampling` | | Pinned `temperature`, `top_p`, `seed`, `max_tokens`. |
| `budget` | | Hard caps (`max_tokens`, `max_requests`, `timeout_s`) — mandatory for `availability_cost`. |
| `test_only` | | `true` for any dangerous payload (default `false`, but linter forces `true` for flagged families). |
| `fixtures` | ✓ | `vulnerable` and `hardened` canned responses proving the spec works. |
| `tags` | | Free-form. |

## 3. Canonical example (improved from v0.1)

See `specs/attacks/PI-INDIRECT-RAG-001.yaml`. Key improvements over the v0.1 draft:

- Added `spec_version`, `requires`, `nist_ai_rmf`, `runs`, `sampling`, `budget`, `fixtures`.
- Data-leakage detection uses a **planted canary** (`{{canary}}`) instead of real secrets (S2).
- Judge rubric explicitly separates "obeyed embedded instruction" from "mentioned it" to cut
  false positives.
- `evaluator_logic` makes the regex a *fast pre-filter* and the judge the *arbiter*.

## 4. Mutation strategies (Prompt Mutator)

Declared per-spec; each is a deterministic transform seeded by `(spec.id, mutation.name)` so
runs are reproducible. Built-in strategies:

`identity`, `translate:<lang>`, `base64_wrap`, `rot13`, `unicode_confusable`,
`zero_width_inject`, `roleplay_wrap`, `nested_instruction`, `markdown_comment_carrier`,
`html_comment_carrier`, `payload_splitting`, `refusal_suppression_prefix`.

Mutators are **pluggable** (`docs/06`). A mutation never changes the *intent* of a spec; it
changes the *carrier/obfuscation*, so the same `expected_secure_behavior` still applies.

## 5. Suites

A suite (`specs/suites/*.yaml`) is an **ordered, versioned reference list** of spec ids plus
run-level defaults (global `runs`, sampling, budget) and framework rollup metadata. Suites are
how you ship "the OWASP LLM Top 10 pack" or "the customer-agent baseline". Adding a technique =
add a spec + reference it in a suite (no code). See `specs/suites/owasp-llm-top10.yaml`.
