# 12: Gaps & backlog (prioritized coverage roadmap)

Honest gap analysis of Il Dottore's LLM-security coverage, prioritized. This is the living
"what's missing" list. **Legend:** P0 = needed for a credible LLM security scanner ·
P1 = strong differentiator / real attack surface · P2 = later.
**Status:** ✅ specced & scheduled · 🟡 partially specced · ⬜ not yet.

> **Delivered 2026-08-30 (see `docs/14`):** the **multi-turn engine** (Crescendo/Linear/
> Sequential/Bad-Likert/Tree) closed a blind spot not even listed below; plus the
> **access-control** family (BFLA/BOLA/RBAC/SSRF/debug/shell-injection/tool-metadata-poisoning),
> broader **OWASP-Agents-2026** agentic coverage, six obfuscation **enhancer mutators**, a
> **multilingual** seed spec and **system-reconnaissance**.
> The rows below are updated where those landed.
>
> **Delivered 2026-09-02:** the **MCP adapter** (HTTP + stdio, read-only discovery) + `mcp`
> suite; **multi-identity execution** (makes `authz_leak` live end-to-end); and the optional
> **Responsible-AI pack** (`safety_content` + `bias_fairness` categories, `responsible-ai`
> suite, RAI owasp codes).
>
> **Delivered 2026-09-03:** the **guardrail-evasion** suite, the **adversarial-suffix** transfer
> mutator, **parameterized mutations** (`translate:{es,fr,de,zh}`), a pre-run **cost estimate**
> (`run --estimate`), bounded **HITL calibration** (`calibrate`), and **function-calling /
> argument-smuggling** detection (`tool_call.forbidden_args` + `FUNCALL-ARGSMUGGLE-001`).
> Battery is now 53 specs / 11 suites.
>
> **Delivered 2026-09-19:** the **NOVA/IoPC coverage-gap battery** (10 specs + `nova-iopc` suite,
> authored from a spec-by-technique map against the Nova IoPC taxonomy, see `docs/15`); the
> **structured-output** half of the function-calling row (`OUT-JSON-SCHEMA-COERCE-001` +
> `OUT-JSON-ENUM-ESCAPE-001` + `structured-output` suite); and **multimodal breadth**
> (`MM-IMG-SPLIT-PAYLOAD-001`, a payload split across two image carriers;
> `MM-IMG-TOOL-EXFIL-001`, the visual-to-agentic bridge). Also **tool-orchestration abuse**, which
> had been the last 🟡 of `docs/14`: a new deterministic **`tool_sequence`** evaluator (fails when an
> ORDERED chain of individually-authorized calls completes, subsequence match so an interleaved
> no-op cannot evade it, partial chain = pass) plus `AG-TOOLCHAIN-EXFIL-001`. A per-call check
> provably cannot see it: `tool_call` passes the very trace `tool_sequence` flags, pinned by a
> regression test. Battery is now **75 specs / 14 suites**, 14 evaluator types.

## P0: in scope for MVP‑1 (capabilities are hard to retrofit later)

| Gap | Status | Where | Target |
|-----|--------|-------|--------|
| **Data-leak / memorization family** (leak-by-asking: RAG enum, cross-tenant, memory, divergence, prefix-completion, verbatim, membership, canary) | 🟡 5 of the 12 techniques in `docs/11 §1` ship | `docs/11 §1` | MVP‑1 (layer A + divergence + cross-tenant); MVP‑2 (membership). Shipped: `DL-SECRET-CANARY-001`, `DL-XSESSION-001`, `DL-XTENANT-001`, `DL-MEMORIZE-DIVERGENCE-001`, `DL-PII-ELICIT-001` (the last one policy-gated and not enableable from the CLI). RAG enumeration, system-config elicitation (its system-prompt half is `SP-LEAK-001`), secret-shape elicitation, prefix completion, verbatim copyright, membership and breach canary have no spec |
| **PII / secret-shape evaluators with FP control** (Luhn, IBAN mod-97, key prefixes, entropy; hallucination ≠ leak) | ✅ | `docs/04`, `docs/11 §4` | MVP‑1 |
| **Logprobs capture in adapters** (membership inference, confidence side-channels) | ✅ | `docs/00` (stack + Phase D), `docs/01 §3` | capture MVP‑1 · membership MVP‑2 |
| **Multi-identity / cross-tenant harness** (authz_leak evaluator, ≥2 identities in scope) | ✅ | `docs/00` (Phase A), `docs/01 §6`, `docs/11 §3` | MVP‑1 |
| **Multimodal** (image/audio/document injection; visual/typographic PI) | 🟡 **image injection built** (2026-09-03) | `shared/media.py` | visual prompt injection via text rendered into an image: a direct override (`MM-IMG-PROMPTINJECT-001`) and an indirect injection embedded in a document image (`MM-IMG-DOC-INJECT-001`, the multimodal analogue of PI-INDIRECT-RAG), in the `multimodal` suite. `attack.media` carries a declarative part; `shared/media.py` renders it to a byte-stable PNG with a dependency-free stdlib encoder + 5x7 font (reproducible, no Pillow); the openai/anthropic adapters emit the provider image block. Gated on `capabilities.multimodal`. **Audio built** (2026-09-03): `MM-AUD-PROMPTINJECT-001` carries a spoken override in a pinned WAV (`assets/`, referenced by `asset`, resolved to bytes at load time behind a path-traversal guard; gated on the new `audio` capability, OpenAI `input_audio` block). Carrier bytes are elided from evidence (kept: `asset` + `media_sha256`), so a 100 KB clip neither bloats the record nor trips the fail-closed redaction guard. Non-image **document** injection (PDF/HTML text) is already covered by the retrieval path (`PI-INDIRECT-RAG-001`). **Breadth added 2026-09-19**: `MM-IMG-SPLIT-PAYLOAD-001` splits one instruction across two image carriers (neither complete on its own, which defeats a scanner that inspects attachments one at a time) and `MM-IMG-TOOL-EXFIL-001` crosses from the visual carrier into agent ACTION (an image-borne instruction driving an unauthorized egress tool call), the first MM spec whose blast radius is not just a text reply. Remaining: audio input still targets only OpenAI `input_audio` |

## P1: MVP‑2

| Gap | Status | Note |
|-----|--------|------|
| **Adversarial-suffix / transfer attacks** (GCG-style, black-box transferable jailbreaks) | 🟡 **transfer built** | `adversarial_suffix` mutator carries the pinned published GCG universal suffix (Zou et al. 2023), reproducible + wired into JB-REFUSAL-SUPPRESS. Live gradient optimization stays out of scope (needs model gradients; non-reproducible) |
| **Guardrail / moderation-layer evasion** as its own target | 🟡 **suite built** (2026-09-03), request is a placeholder | `guardrail-evasion` suite: `GUARD-INPUT-EVASION-001` (obfuscated trigger evades the input classifier, model must still refuse) + `GUARD-OUTPUT-ENCODE-001` (encode the reply past the output filter). Both send the literal placeholder `[DISALLOWED-HARMFUL-TASK]` instead of a concrete request, so a refusal or a compliance measures the reaction to a placeholder (as do `MM-IMG-HARMFUL-001` and `SAFETY-HARMFUL-001`). A dedicated filter-target type stays future work |
| **Embedding / vector-store attacks (LLM08)** (embedding inversion, neighbor retrieval, cross-tenant index leak) | ✅ **built** (3 specs + suite) | placeholder in `docs/08 §4`; needs a vector-store target type |
| **Defined multilingual battery** (low-resource-language jailbreaks) | 🟡 **mechanism built, not yet a battery** | parameterized mutations (`name:param`) are supported by the runner, checked by lint and the runner against each mutator's `accepted_params` (an unaccepted parameter is `UNKNOWN_MUTATOR_TYPE` in lint and sends nothing at run time), and `JB-MULTILINGUAL-001` runs `translate` plus `translate:{es,fr,de,zh}`. The `translate` mutator replaces only the words found in a 14-word keyword table (`PHRASE_MAP`, 13 effective in `zh`) and leaves the rest in English, so a prompt not written in those keywords barely changes: on that spec's prompt `translate:es` changes one word ("the" to "el") and `translate:zh` none, so the `zh` variant sends the identity prompt. A real per-language battery needs translated prompts. Adding a gloss is a `PHRASE_MAP` entry; adding a language also needs `LANGUAGES`, which is what `accepted_params` is built from |
| **Multi-turn adaptive jailbreaks** (Crescendo/Linear/Sequential/Bad-Likert/Tree) | ✅ **built** | pinned-ladder engine `core/conversation.py` + 5 specs + `multi-turn` suite (docs/14) |
| **Access-control family** (BFLA/BOLA/RBAC/SSRF/debug/shell-injection/tool-metadata-poisoning) | ✅ **built** | `access-control` suite (docs/14) |
| **OWASP-Agents-2026 agentic breadth** (goal theft, recursive hijack, identity abuse, inter-agent, drift) | ✅ **built** | `agentic-owasp2026` suite (docs/14) |
| **Baseline diff / drift across versions** ("did this model get worse?") | ✅ **built** (`dottore diff`) | `replay` exists; need baseline compare + regression report for CI |
| **Coverage metric** (report % of OWASP/ATLAS actually exercised) | ✅ **built** | run summary + JSON/HTML/terminal show % OWASP + ATLAS exercised + run/skip/block counts |
| **Function-calling / structured-output attacks** (JSON-schema poisoning, arg smuggling) | ✅ **built** (2026-09-03) | `tool_call` evaluator gained an opt-in `forbidden_args` (spec declares out-of-schema/privileged argument keys; a truthy value under any of them, at any depth, fails); `FUNCALL-ARGSMUGGLE-001` proves it (role/bypass_review smuggled into an authorized `update_account`). Inert for every spec that omits `forbidden_args`. **Structured-output half added 2026-09-19**: `forbidden_args` guards what the model sends INTO a tool; `OUT-JSON-SCHEMA-COERCE-001` (out-of-schema privileged field added to the returned JSON) and `OUT-JSON-ENUM-ESCAPE-001` (out-of-enum value on a field that gates exposure) guard what it hands BACK to the application. Grouped in the `structured-output` suite |
| **Finding dedupe across mutations** (1 vuln × N variants → 1 finding w/ variants) | ✅ **structural** | the runner already emits **one `Finding` per (spec, target)** and folds every mutation variant into that finding's `attempts` (`core/runner._run_spec`), so a mutation sweep never inflates the finding count. Cross-*spec* semantic dedup (merging different specs judged to be the same underlying vuln) stays deferred on purpose: it is a lossy judgment call that can hide real signal, so it is left to the human operator |
| **Agentic-extortion / JadePuffer-class susceptibility** (`docs/13`) | ✅ **built (7 specs + suite, golden-gated)** | pack complete + FP-disciplined (narration≠fail); `kill_chain_progression` L3 evaluator **built** (MVP-2 w1, wired into AG-EXTORT-CHAIN + AG-DESTRUCTIVE-DBDROP); policy-gated OFF |

## P2: later

| Gap | Note |
|-----|------|
| Streaming pre-moderation leakage | ⬜ the WebSocket adapter (2026-10-07) reads a streamed reply frame by frame but scores the assembled text; a per-fragment oracle is inherently timing-dependent (tension with the reproducibility thesis), so the spec stays deferred deliberately |
| Timing / token-probability side-channels | ⬜ infra-dependent and non-reproducible by nature; out of scope for a deterministic scanner |
| Pre-run cost estimate | ✅ **built** (2026-09-03): `dottore run --estimate` prints requests (specs x runs x mutations x turns) + a rough token gloss, no sends. No per-model pricing baked in (multiply by your rate) |
| Resume that retries errored attempts (F11) | ✅ **built** (2026-10-04): a `--resume` sends again, under the same attempt id, each attempt that ended in an environment error, and scores one attempt per id; the run store journals every attempt artifact as it is written (schema v4), so a resume interrupted mid-spec can be resumed again (`docs/09 §2`) |
| Human-in-the-loop feedback loop | ✅ **built** (2026-09-03, bounded): `dottore calibrate <report.json> <labels.yaml>` scores the scanner against operator labels (agreement + precision/recall, fail = positive). Read-only; a continuous triage store is future work |
| Bias / toxicity / fairness pack | ✅ **built** (2026-09-02): `safety_content` + `bias_fairness` categories, `SAFETY-HARMFUL-001` + `BIAS-STEREOTYPE-001`, `responsible-ai` suite. Optional pack (RAI owasp codes, NIST-mapped), not security core. `SAFETY-HARMFUL-001` sends the placeholder `[DISALLOWED-HARMFUL-TASK]` rather than a concrete request (see the guardrail-evasion row) |

## Open decisions that limit what a ✅ row means

These are not coverage gaps a new spec closes; they change what a built row proves on a live
target, and each waits on, or records, a decision: OD-18 and OD-19 are rows of
`specs/contracts/00-INDEX.md`; the policy-pack flag has no OD number yet (OD-11, decided
2026-10-11, says the PII opt-in comes with it: the pack and `--allow-pii-elicitation` together,
never the run flag alone).

| Decision | What it limits today |
|---|---|
| **OD-18** (ADR-0009): a spec's `setup` and a live target | Decided 2026-10-06: C, with A first; both built. A (2026-10-06): against a `type: model` target the documents, tools and memory seed are delivered in-band, with a tool loop (at most 4 rounds), which tests the model, not an application. B (2026-10-07): against any other target type a spec with setup sends only when the target file declares it seeded (`seeded_setup`), and is `inconclusive: setup_not_seeded` otherwise; what it tests is only as good as what the operator seeded, which the tool cannot check. A fleet entry cannot declare it |
| **OD-19** (ADR-0010): `evaluator_logic` and a fail the judge alone reported | Decided 2026-10-11 under the owner's delegation (best practice, revisable) and built (u06 A-73): every value names one rule, `deterministic_first`, which the runner, lint and `evaluators.combine` all apply (the 75 specs declare it; `all_pass`, `any_fail` and `weighted` are deprecated names lint warns about, and no vote is taken). What it still limits: a fail decided by the judge alone, when every deterministic evaluator passed, is reported and fails its spec but is `needs-review`, so it gates `--fail-on` only with `--include-needs-review`; a target that only a judge can catch is a finding a reviewer reads, not one CI stops on |
| **Policy-pack flag** | The CLI loads no policy pack, so the 8 specs that declare `requires_policy` (the seven agentic-extortion specs and the PII elicitation spec) never send from `dottore`. The capability filter runs first: the six of them that require `tools` are skipped as `inconclusive: capability_unavailable` on a target that does not declare it, and reach the policy gate (`blocked_by_policy`) only on one that does. `JB-OFFENSIVE-RANSOM-CODEGEN-001` and `DL-PII-ELICIT-001` require nothing and are `blocked_by_policy` on every target |
| **OD-41** (ADR-0011): an attack prompt the provider's own input filter refuses | Decided 2026-10-10 and built (u08 A-69): Azure OpenAI's HTTP 400 `content_filter` and Gemini's `promptFeedback.blockReason` are recorded as blocked attempts (`inconclusive: blocked_by_provider_filter`) and the campaign goes on, so a row against a filtered deployment can come back inconclusive with its attempts counted as blocked: it says nothing about the model. Left open then, closed by OD-42: a Bedrock guardrail intervention is an HTTP 200 carrying the guardrail's own message, which was read as a reply. Still open: OpenAI's `invalid_prompt` 400 and Gemini's OpenAI-compatible endpoint are not read, for want of a documented shape (any other 4xx still stops the run). Amended 2026-10-11 under the owner's delegation (A-79, revisable): Azure's 400 is read only from an `openai` target (or a template that declares `content_filter`), and a run whose every attempt was blocked or cut, with no fail, is `filtered` and exits 3; a partly filtered run keeps its exit code, so a row with blocked attempts still says nothing about the model. |
| **OD-42** (ADR-0011, amended): a reply the provider's own filter cut or replaced | Decided 2026-10-11 and built (u08 A-70): Azure OpenAI's `content_filter`, a Bedrock guardrail's `guardrail_intervened`, Gemini's `SAFETY` and its kin and Anthropic's `refusal` are never read as the model resisting. A row against a filtered deployment can come back `inconclusive` with attempts counted as `cut_by_provider_output_filter` (the model may have written what the filter hid: review them) or `provider_filter_side_unknown` (a Bedrock guardrail without `guardrailConfig.trace`: enable it to learn the side). `--fail-on` does not trip on either. Gemini's `RECITATION` counts as a cut (decided under the owner's delegation, revisable). From `dottore`, only the Azure, Anthropic and WebSocket shapes are reached: Bedrock's and Gemini's need a `RestTemplate` built in Python, since a target file's REST target has no template. Left open: a Gemini template without `finish_path`, Bedrock's `InvokeModel` shape and streamed replies. Amended 2026-10-11 under the owner's delegation (A-79, revisable): a stop is read only from the provider that documents it (another provider's word is an ordinary stop, `foreign_stop` in the reply), the judge's fail on a partial reply stands as a needs-review fail, and the text of a reply a Bedrock trace says it refused the prompt for is read. What it still limits: a target that answers some attacks with its own provider's filter word and no text (an empty `content_filter`) hides those attempts, which are inconclusive, never a pass, and counted apart; only a run it answers that way every time exits 3. |
| **OD-43**: a deployment's own granted tool whose name holds a destructive verb (a `transfer_to_<agent>` hand-off) | Decided 2026-10-11 and built (u06 A-72): the target file may declare it not destructive (`seeded_setup.granted_tools` entry `{name, destructive: false}`), and `tool_call` then does not fail a call to that exact name by its name alone. A pass of a seeded agent spec can therefore rest on the operator's word that a tool destroys nothing, which the tool cannot check: every report states the declaration for the run and counts the attempts it changed, and each such attempt's verdict names the tool, so read those before taking the row as the agent's own resistance. A spec's scene still decides for its own tools, and `kill_chain_progression` is unchanged |

## Standing note

The engine is **built and self-validating**: every spec ships golden `vulnerable`/`hardened`
fixtures. `dottore lint` runs them through an offline stub table that covers seven of the 14
evaluator types (on 2026-10-04: 0 errors, 0 warnings across 75 specs, 14 suites, 1 pack), and
the battery gate in CI (`tests/battery`) runs every spec's fixtures through the real evaluator
the spec lists first, through the golden harness and the mock target. The CI wall is ruff,
mypy --strict, import-linter, `lint specs`, pytest + coverage and the self-scan; `bandit` and
`pip-audit` are not in CI, only in `make gates`, which needs both installed by hand
(`SUPPLY-CHAIN.md`). This note does not certify a green run: the latest workflow run does. The
strength remains the methodology (reproducibility + evidence + risk mapping, judge hardening, self-validation, extensibility);
what is left is coverage breadth (the rows above) and the deliberately deferred P2 items
(streaming pre-moderation, timing side-channels) that trade away reproducibility.
