# AGENTS.md — Il Dottore

> Read this at the **start of every agent session**. It is the model-neutral, portable context
> layer for this repo (Anthropic / Vercel / `agents.md` practice). Any agent — this month's
> model or next month's — reads this + the relevant `docs/` + the unit **contract**, then works.
> This file, the `docs/`, the contracts and the evals are the memory we **own** (rent the
> intelligence, own the context). Also valid as `CLAUDE.md`.

## 0. What this project is

**Il Dottore** (`dottore`) — a spec-driven security scanner for LLMs and AI apps
(prompt injection, jailbreak, data leakage/memorization, tool/agent abuse, RAG poisoning,
excessive agency, insecure output handling, model DoS). Aligned to OWASP LLM Top 10 (2025),
MITRE ATLAS, NIST AI 600-1. **Thesis:** value = reproducibility + evidence + risk mapping,
not "many jailbreak prompts". License **MIT**. See `README.md` and `docs/`.

> **Current state → `docs/PROGRESS.md`** (living ledger; read it first for where the build is,
> open decisions, and the operator to-do). As of 2026-07-07: Specify stage in progress, no
> `src/` code yet, `gh` re-auth pending before any push.

## 1. How we build here — specs-driven, not vibecoding

We follow Zynap's engineering methodology (*Specs-Driven Development with AI*). The mindset:
**think and design first; the AI does the typing.** The contract is the spec; the acceptance
criteria are the harness. Six stages, each handing a concrete artifact to the next:

1. **Understand** → the architecture + threat model (`docs/01`, `docs/02`) at a frozen commit.
2. **Specify** → one **contract per unit** (`specs/contracts/`, 9-section anatomy) + master
   index (`specs/contracts/00-INDEX.md`) with the dependency DAG and single-executor ledger.
3. **Execute** → the **PITV loop** (Plan·Implement·Test·Validate) per contract, dependency-gated,
   iteration ceiling then PARK. Never merge degraded work.
4. **Validate** → this is **net-new**, so the **spec is the oracle**: machine-checkable
   acceptance criteria + golden fixtures (`docs/07`) + design review + human sign-off.
5. **Sweep** → close the deferred items + the KEEP/FIX backlog (itemized, not "polish").
6. **Finish** → senior human tests hard, lists defects, bulk-prompts the fixes (the 70% rule).

Full method: `docs/00-ai-build-playbook.md`.

## 2. Hard rules (the PITV COMMON block — non-negotiable, enforced not requested)

- **Stay in the fence:** write code only inside `src/ildottore/` and `tests/`. Do not touch
  `docs/`, `schemas/`, or another unit's owned files unless your contract says so.
- **Git:** never `commit`/`push`/`branch` from inside a build loop (read-only `status`/`diff`
  ok). The conductor (human/main loop) owns commits — signed (GPG), Conventional Commits.
- **Secrets:** NEVER print or commit secrets/keys. Source from env/vault; pass via env. The
  central **redactor** masks secrets/PII in logs, evidence and reports (`docs/11 §5`).
- **Safety:** no real destructive actions (tools mocked/dry-run); no real exfiltration (use
  planted canaries); endpoint **allowlist** default-deny; dangerous payloads flagged
  `test_only`; DoS/availability specs are budget-capped. `docs/02` is normative.
- **Humans own decisions:** never silently resolve a fork. Log it in the unit's §9 Open
  Decisions and roll it up to the index ledger. If a decision is missing → write an ADR
  (`docs/adr/`), implement the smallest reversible version, flag it in the PR.
- **Env vs product failure:** an environment error (port down, rate limit) ⇒ retry/skip; a real
  product defect ⇒ FAIL. Don't mask defects as flakes.

## 3. Guardrails we brief into every contract (produce code we can ship and defend)

- **Security by default (OWASP):** validate & sanitize inputs, authn/authz on every endpoint,
  least privilege, no secrets in code. AI output is never security-first — always review.
- **No deprecated patterns:** pin current, maintained versions; verify against today's official
  docs. Risk is the *newest* releases, not old stable code — **check, don't ban by age.**
- **Zero tech debt:** no dead code, no copy-paste, real separation of concerns, tests + types.
  A refactor and a feature never land in the same MR.
- **Clean licensing:** permissive only (MIT / Apache-2.0 / BSD). **No copyleft (GPL/AGPL) or
  source-available deps.** Keep an SBOM.
- **Lean & performant:** no N+1 (one SELECT fanning into 40), bounded memory, no needless deps,
  then measure.
- **Provably correct:** machine-checkable acceptance criteria + adversarial tests + human
  sign-off on every fork. "Done" means proven.

## 4. Stack, commands & conventions

- **Python 3.11+** (dev env is 3.14). `src/` layout, single distribution `ildottore`,
  CLI entry `dottore` (ADR-0004). Pydantic v2 · Typer · httpx · Jinja2 · PyYAML · jsonschema.
- **Package boundaries (enforced by import-linter):** `shared` ← everyone; `core` depends on
  *interfaces* only; adapters don't import evaluators; composition happens in `cli`/`api`.
  See `docs/01 §2-§3`.
- **Commands** (once scaffolded):
  - Install: `uv sync` (or `pip install -e ".[dev]"`)
  - Lint/format/type: `ruff check . && ruff format --check . && mypy src`
  - Tests: `pytest -q` · coverage gate ≥ 85% core
  - Spec lint: `dottore lint specs/`
  - Import contract: `lint-imports`
  - Self-scan (dogfood): `dottore fingerprint … ` + run suite against our own judge
- **Tests taxonomy:** `docs/07` (schema, unit, property/Hypothesis, adapter cassettes,
  golden-target detection accuracy, evaluator P/R, judge robustness, determinism replay,
  reporting/SARIF, E2E, boundaries, safety-negative, metamorphic).

## 5. Operating discipline (keeps the method honest at scale)

- **Evaluation-Driven Development:** define "good" first; the golden-fixture + evaluator-P/R
  suites are a *living* eval scored over many cases, tracked for regressions (Huyen/Vercel EDD).
  AI judges aren't deterministic → pair automated grading with human spot-checks.
- **Observability & resume:** trace agent decisions; checkpoint & resume (workflow `runId`) —
  never restart from zero. Update `docs/PROGRESS.md` + `CHANGELOG.md` + memory each stage.
- **Structural guardrails, not prose:** filesystem + network sandbox (egress allowlist);
  a prompt-injection probe on any tool/browser output (the "lethal trifecta"); a
  **stop-&-escalate circuit-breaker** (N denials / budget breach → halt); govern agent *spend*,
  not just safety (budgets).

## 6. Provenance

Methodology: Zynap *Specs-Driven Development with AI* (2026). Grounded in public best practice —
Anthropic (Claude Code best practices, building effective agents, context engineering, eval
statistics, sandboxing), Vercel (eval-driven dev, agent responsibly, AGENTS.md), GitHub spec-kit,
AWS Kiro, OpenAI agents guide, and the critics we built to survive (Cognition, Karpathy,
Willison, Thoughtworks, Osmani). Full list: `docs/REFERENCES.md`.
