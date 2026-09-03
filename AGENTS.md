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

### Robustness anti-patterns (from the ElSereno audit, 2026-08-29 — apply to ANY code we write)

- **Bound every untrusted read.** Never read a request body, stream or file of attacker-
  controlled size without a cap; reject over-limit input, do not truncate and forward it.
- **Gates fail closed.** A classifier, evaluator or policy check that cannot parse its input
  refuses or scores conservatively; it never falls through to "allow" / "clean".
- **Detectors must match the real format, not the spec-book.** A verdict engine that only
  recognises the tidy encoding goes blind to what targets actually send. Test against real
  payloads, not just canonical examples.
- **Paginate on the raw upstream count, not the post-filter count.** Dropping a few unparseable
  rows must not look like end-of-data and truncate the sweep.
- **Shared state across threads/async needs a lock.** "Read it only after the worker finishes"
  is not synchronisation: join or guard it. Never close a queue/channel a producer can still
  write to.
- **No secrets via argv or plain env** (they leak via ps / /proc/<pid> / shell history): take
  them from a 0600 file or stdin.
- **Validate archive member names on extraction** (reject `..`), even for authenticated archives.
- **Verify protocol/format constants against the normative source, not memory**, and skip any
  per-variant prefix before parsing the body.

### Workflow & verification lessons (Il Dottore build, 2026-09-02: hard-won, do not relearn)

- **The session cwd is NOT this repo.** A session can start in an unrelated sandbox path (e.g. a
  `~/Downloads/...` folder); this repo lives at an absolute path under `~/AI projects/`. Shell
  state does not persist between tool calls (cwd resets after each one), so `cd` into the
  absolute repo root in EVERY command, and when reporting state (branch, hashes, "done") name the
  absolute repo path explicitly so the reader never has to guess where the work landed. If in
  doubt, confirm with `pwd` + `git rev-parse --show-toplevel` before asserting anything.
- **Run the WHOLE gate wall, never a subset.** `ruff check` is NOT `ruff format --check`, and
  neither is the coverage gate. A "all green" claim is only true after `make gates` (the
  Makefile mirrors `.github/workflows/ci.yml` one-for-one). Twice a green claim was wrong
  because only `ruff check` had been run.
- **Detect em/en dashes with Python, never a zsh `grep` using a `$'..'` glyph pattern** (in zsh
  that silently matches nothing and reports a false "0 dashes"). House rule: no em dash or en
  dash in ANY produced text (code, comments, docs, commit messages); substitute a colon, comma,
  period or parentheses. Scan the added diff lines, not whole files (pre-existing repo dashes
  are not ours to rewrite).
- **Validate every example/config against the REAL loader, not by eye.** `specs/scope.example.yaml`
  documented a fictional `engagement/allow_targets/endpoint_allowlist/policy` schema that no
  loader accepts; `dottore lint` skips loose example YAMLs, so it went uncaught and leaked into
  the docs. Load examples through `load_scope`/`load_target` (or a test) before trusting them.
- **GPG signing can strand the branch.** `git rebase --exec 'git commit --amend --no-edit -S'
  <base>` can hang on `pinentry` INSIDE the rebase and leave an interrupted rebase that looks
  like the fix/docs commits were lost (HEAD sits on the first commit). Recovery: **`git rebase
  --abort`** (restores the full branch), or reset to the reflog tip. Correct procedure: warm the
  gpg-agent first in the foreground (`echo warm | gpg --local-user <KEY> --clearsign >/dev/null`)
  THEN rebase. The conductor signs; the build loop never runs GPG.
- **zsh does not word-split unquoted vars or `$(...)`** (a multi-file `git restore/add "$LIST"`
  becomes one bad pathspec). Pipe the list through `xargs`, or use a zsh array.
- **Rebuilding logical commits without `git add -p`:** split by file. A shared/entangled file
  (runner, models, wiring) lands in the commit of the feature that introduced it; rebuild via
  `git reset --mixed main` + re-stage groups; then VERIFY the partition (0 overlaps, union ==
  `git diff --name-only main...HEAD`). Additive **optional** fields on the frozen u00 pydantic
  models (Target/EvalContext/ScopeTarget/Identity) are backward-compatible and allowed.
- **A capability the runner never exercises is a latent gap, not a feature.** `authz_leak` was
  dormant for months because the runner never populated `EvalContext.identities`. When an
  evaluator needs cross-attempt or cross-identity context, wire the execution that feeds it (or
  mark it explicitly latent in `docs/12`), do not ship the evaluator alone and call it done.
- **New adapters/transports keep the charter.** MCP discovery is read-only (never `tools/call`);
  stdio spawns only a scope-authorized exact command; both are allowlist-gated. Do not add a
  capability (real tool invocation, arbitrary subprocess) that breaks safe-by-design/§2.

## 4. Stack, commands & conventions

- **Python 3.11+** (dev env is 3.14). `src/` layout, single distribution `ildottore`,
  CLI entry `dottore` (ADR-0004). Pydantic v2 · Typer · httpx · Jinja2 · PyYAML · jsonschema.
- **Package boundaries (enforced by import-linter):** `shared` ← everyone; `core` depends on
  *interfaces* only; adapters don't import evaluators; composition happens in `cli`/`api`.
  See `docs/01 §2-§3`.
- **Commands:**
  - Install: `uv sync` (or `pip install -e ".[dev]"`)
  - **The whole wall (do this before claiming green): `make gates`** (mirrors CI exactly)
    (ruff lint, ruff format check, mypy strict, import-linter, spec lint, tests, coverage ≥85%,
    self-scan, bandit, pip-audit). `make fix` autofixes format+lint. Do not hand-run a subset.
  - Individually: `ruff check . && ruff format --check . && mypy src` · `pytest -q` (coverage
    gate ≥85% core) · `dottore lint specs/` · `lint-imports` · `python -m tests.selfscan.run`
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
