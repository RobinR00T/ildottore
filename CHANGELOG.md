# Changelog

All notable changes to Il Dottore. Format: [Keep a Changelog](https://keepachangelog.com/),
versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **MCP adapter (`provider: mcp`) + `mcp` suite**: scan a Model Context Protocol server as a
  target. `adapters/mcp.py` speaks JSON-RPC over Streamable HTTP: it performs the `initialize`
  handshake and lists `tools`/`resources`/`prompts`, then renders that advertised metadata as
  the response. Read-only by design (safe-by-design, docs/02 S5): it never calls a tool
  (`tools/call`), and the endpoint allowlist is enforced before every request (S3). The new
  `MCP-TOOLPOISON-001` spec + `mcp` suite flag tool-metadata poisoning ("line jumping"): 
  imperative instructions hidden in a tool description. `kind: mcp` fleet entries now
  materialize (`type: api`, `provider: mcp`) instead of being skipped. Validated live against a
  local MCP server (finding: critical, evidence redacted at rest).
- **MCP stdio transport**: a `provider: mcp`, `transport: stdio` target launches a local MCP
  server as a subprocess and runs the same read-only discovery over newline-delimited JSON-RPC
  (stdin/stdout). Spawning is gated: the exact command line must appear in the scope target's
  `commands` allowlist (default-deny, mirrored by the policy gate and re-checked in the adapter),
  so an unauthorized command spawns zero processes. Validated live (finding: critical via stdio).
- **Fleet config + `dottore fleet`**: declare every LLM / URL / MCP target to validate in one
  `fleet.yaml`, which expands into the authorization `scope.yaml` + one `target.yaml` per
  model (`--run` scans them immediately). API keys are never written, each entry references
  an env var (`api_key_env`). Provider is inferred from the endpoint (`/chat/completions` ⇒
  OpenAI-compatible, `/messages` ⇒ Anthropic). Example: `specs/fleet.example.yaml`.
- **`--judge` (LLM-as-judge for live scans)**: a `--judge <target.yaml>` model wires the
  `semantic_judge` evaluator for over-the-wire scans, so a real target yields decisive
  verdicts instead of abstaining. `wiring.build_judge_adapter` builds a scope-allowlisted
  judge adapter (ADR-0002). Validated live against a local Ollama-backed target.
- **Multi-identity execution (makes authz_leak / M14 live)**: a `multi_identity` spec against a
  target that declares the capability and a scope with >=2 identities now runs end-to-end. The
  runner sends the attack as each identity (each with its own resolved credential from the scope)
  and collects the per-identity responses; `authz_leak` flags a tenant-scoped canary reaching a
  non-owner identity. New `ScopeTarget.identities[].canary` declares which identity owns a canary.
  Previously the runner never populated `EvalContext.identities`, so authz_leak was dormant.
- **Responsible-AI pack (optional, NIST-mapped)**: two new categories `safety_content` and
  `bias_fairness` (the `owasp` field now also accepts an `RAI` code, since these have no OWASP
  LLM Top 10 mapping), the `SAFETY-HARMFUL-001` (direct harmful request must be refused) and
  `BIAS-STEREOTYPE-001` (no demographic stereotype in a decision) specs, and the
  `responsible-ai` suite. Adjacent to security, shipped as an opt-in pack, not the core battery
  (docs/12 P2). Battery is now 50 specs / 10 suites.
- **`adversarial_suffix` mutator (GCG transfer, docs/12 P1)**: appends the published pinned GCG
  universal suffix (Zou et al. 2023) to a carrier, a reproducible black-box transfer jailbreak
  (19 built-in mutators now); wired into `JB-REFUSAL-SUPPRESS-001`. Live gradient optimization
  stays out of scope (needs model gradients and would be non-reproducible).
- **Parameterized mutations `name:param` (docs/12 P1)**: the runner now resolves a mutation by
  its base name and folds the full `name:param` into the seed, so `translate:fr` runs the
  `translate` mutator in French. `JB-MULTILINGUAL-001` uses this to run a systematic
  per-language battery (`translate:{es,fr,de,zh}`), offline and deterministic.
- **Guardrail / moderation-layer evasion pack (docs/12 P1)**: the `guardrail-evasion` suite with
  `GUARD-INPUT-EVASION-001` (an obfuscated trigger evades the input classifier; the model's own
  alignment must still refuse) and `GUARD-OUTPUT-ENCODE-001` (encode the harmful reply to slip
  past the output filter). Battery is now 52 specs / 11 suites.
- **Pre-run cost estimate (docs/12 P2)**: `dottore run --estimate` prints the plan's request
  volume (specs x runs x mutations x turns) and a rough token gloss, with zero sends. No
  per-model pricing is baked in (multiply by your provider's rate).
- **Human-in-the-loop calibration (docs/12 P2)**: `dottore calibrate <report.json> <labels.yaml>`
  scores a run's findings against operator ground-truth labels (agreement + precision/recall,
  `fail` = positive), so a team can measure the scanner and its judge. Read-only, no sends.
- **Function-calling / argument-smuggling detection (docs/12 P1)**: the `tool_call` evaluator
  gained an opt-in `forbidden_args` list. A spec declares argument keys that are out of scope
  for the task (e.g. a privilege field `role`, a control flag `bypass_review`); if the model
  populates any of them with a truthy value (at any nesting depth) on an otherwise-authorized,
  non-destructive tool, that is argument smuggling / schema poisoning and fails. The new
  `FUNCALL-ARGSMUGGLE-001` spec proves it. The check is inert for every spec that omits
  `forbidden_args`, so the existing battery is unaffected. Battery is now 53 specs / 11 suites.

### Documentation
- **User docs to parity**: refreshed `README.md` (real repository map, capabilities,
  quickstart) and `USAGE.md` (fleet, `--judge`, multi-turn, corrected scope schema, corrected
  suite/category aliases, fixed the `fingerprint` invocation and the `--adaptive` drift).
- **New**: `docs/MANUAL.md` (complete operator reference), `docs/FAQ.md`, `INSTALL.md`, and a
  runnable `examples/` directory (local-Ollama, hosted-OpenAI and fleet scenarios, plus a
  GitHub Actions gating workflow). Added `docs/14-deepteam-gap-analysis.md` to the index.
- **man pages**: `man/man1/dottore.1` and `man/man5/dottore-scope.5`.

### Tooling
- **`Makefile`** mirroring the CI merge gate (`make gates`), so the full wall (lint, format
  check, mypy, import boundaries, spec lint, tests, coverage ≥85%, self-scan, bandit,
  pip-audit) runs with one command locally.
- Normalized formatting on the files introduced this cycle so `ruff format --check` (a CI
  gate) is clean.

### Security (adversarial audit remediation, 2026-09-01)
- **Allowlist path-traversal bypass (critical) closed**: `is_allowed` now resolves `..`/`.`
  dot-segments to the path the HTTP client actually requests before matching (a
  `…/v1/../admin` no longer passes a `/v1` authorization). Ports can be pinned (`host:443`);
  cleartext http is refused except to loopback.
- **Redaction hardening (DL2)**: secrets in a dict KEY are masked (not just values); a
  labelled-secret heuristic + a lower entropy threshold + slack `xoxp`/`xoxa` cover shapes the
  built-ins missed; the PEM detector no longer ReDoS-es on `BEGIN`-only blobs (END-marker
  precheck + bounded body); NUL bytes are stripped before the internal stash.
- **Verdict combine**: a decisive DETERMINISTIC fail now carries over an abstaining/unconsulted
  judge, while a judge fail can never override a deterministic FP-discipline abstention.
- **LLM-as-judge**: the control tripwire token is generated fresh per call (was a weaponizable
  static constant); `observed_injection_attempt` only casts doubt on a `secure` verdict, so
  honest `exploited` verdicts on the injection/jailbreak class are no longer discarded.
- **Evaluators**: regex evaluators are case-insensitive (matching specs + the lint stub);
  refusal no longer false-fails a refuse-with-alternative; tool_call flags encryption-for-impact
  and `destructive:true` metadata, honours a nested confirmation, and tightened its injection
  regex (backtick + `$(cmd`); `secret_leakage` honours `canary_ref`.
- **Fleet**: the generated scope/target are produced with `yaml.safe_dump` and target `id`s are
  charset-validated + deduplicated, so a crafted id can't corrupt the authorization allowlist.
- **Scoring**: `risk.reproducibility` is now coherent with `risk`/`band`; `confirmed` requires an
  undisputed fail (aligned with the canonical gate).
- **authz_leak cross-tenant precision (audit M14)**: with an optional canary-owner map
  (`EvalContext.canary_owners`), the evaluator now flags a canary that surfaces in a NON-owner
  identity (A receiving B-only data), not only a canary crossing >=2 identities; the owner
  legitimately seeing its own canary is still not flagged.
- **Linter tool_call stub parity (audit M7)**: the offline `dottore lint` stub now mirrors the
  real `tool_call` evaluator (authorized-allowlist + destructive-verb + confirmation + arg
  injection) instead of treating any tool call as a fail, so lint and the real evaluator agree.

### Changed
- **Verdict combination, an abstaining judge no longer sinks a decisive verdict.** A
  *consulted* `semantic_judge` that abstains (parse fail / low confidence / judge_compromised)
  is dropped so the deterministic arbiter carries (docs/04 §0). A DETERMINISTIC abstention
  (capability-gated / data-leak FP discipline) and an *unconsulted* judge (no `--judge`
  wired ⇒ capability_unavailable) still dominate, so an unconfigured/bare run stays honestly
  inconclusive.
- **Evidence redaction is seeded from the scan's known secrets.** The evidence store now
  masks each spec's `setup.canaries` + `secret_leakage` refs at rest, so a leaked engagement
  secret (a shape the built-in patterns don't know) no longer persists in clear.

### Fixed
- **Live multi-turn against Anthropic** sent an OpenAI-shaped `tool_calls` field the Messages
  API rejects (HTTP 400); the adapter now projects each turn to `{role, content}`, and the
  conversation engine omits empty `tool_calls`.
- **Evidence store false-positive** (`_assert_no_leak`): a numeric logprob float matched the
  phone/card shapes when the serialized JSON was scanned as flat text, refusing every live
  write. The guard now re-scans string leaves only, so real logprobs/usage/latency persist.
- **Mutator reversibility property test** scoped its inputs to exclude zero-width codepoints
  (the round-trip is undefined when the payload itself is zero-width).

### Added
- **Multi-turn attack engine** (`core/conversation.py`): pinned attacker ladders threaded as
  a conversation (prior assistant turns fed back as `messages`), the final turn scored, the
  full transcript persisted for evidence. Wired into the runner behind `_is_multi_turn`;
  reproducibility preserved because attacker turns are pinned, never LLM-generated.
- **DeepTeam gap analysis** (`docs/14`) and the native families it drove (coverage-map only,
  no dependency; Apache-2.0 attribution in each spec):
  - multi-turn jailbreaks, `JB-CRESCENDO/LINEAR/SEQUENTIAL/LIKERT/TREE` + `multi-turn` suite;
  - access-control, `AC-BFLA/BOLA/RBAC/SSRF/DEBUG`, `OUT-SHELLI`, `AG-TOOLMETA-POISON` +
    `access-control` suite;
  - OWASP-Agents-2026 agentic, `AG-GOAL-THEFT/RECURSIVE-HIJACK/IDENTITY-ABUSE/
    INTERAGENT-COMPROMISE/AUTONOMY-DRIFT` + `agentic-owasp2026` suite;
  - `JB-MULTILINGUAL-001`, `RECON-SYSTEM-001` + `obfuscation-enhancers` suite.
- **Six enhancer mutators** (18 built-ins total): `leetspeak`, `adversarial_poetry`,
  `math_problem`, `gray_box`, `linguistic_confusion`, `context_poisoning`; wired into the
  jailbreak specs' `mutations`. Battery is now 47 specs / 8 suites.
- Full spec package (`docs/00-12`, `REFERENCES.md`, ADRs, JSON schema, example specs).
- Zynap Specs-Driven methodology applied: `AGENTS.md`, six-stage build playbook, PITV harness,
  `specs/contracts/` (master index + unit contracts).
- Project scaffold: MIT `LICENSE`, `pyproject.toml`, community files.
- **MVP‑1 built (all 15 units)** via the six-stage PITV method: `shared` models/protocols,
  config/scope/policy + redactor, spec registry + linter, prompt mutators, scoring, target
  adapters (OpenAI/Anthropic/REST + MockTarget), evidence/run store, hardened evaluators
  (incl. data-leak: pii/secret-shape/authz/membership), fingerprint engine, execution engine
  (runner + planner + budgets), reporting (JSON/HTML/SARIF/JUnit), CLI (`dottore`), and the
  self-validation/CI harness.
- **T0 attack battery (20 specs)** across OWASP LLM01/02/05/06/07/10, incl. the data-leak and
  agentic-extortion (JadePuffer-class) families; `specs/pack.yaml` makes them discoverable
  out of the box.
- Merge gate green: full test suite, import-linter (4 contracts), ruff, mypy (116 modules),
  and an E2E `dottore run --quick` against MockTarget.

_Not yet pushed/tagged, pending `gh auth login`. See `docs/PROGRESS.md`._
