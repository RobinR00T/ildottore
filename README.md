# Il Dottore: AI Model Security Scanner

> **Il Dottore** (command `dottore`, alias `dott`). Named for the *commedia dell'arte*
> archetype of the diagnostician: the tool **examines** an AI endpoint (fingerprint),
> **diagnoses** its vulnerabilities (findings) and issues a reproducible **clinical report**.

Spec-driven security scanner for LLMs and AI applications (prompt injection, jailbreak,
data leakage, tool/agent abuse, RAG poisoning, excessive agency, insecure output handling,
model DoS). Aligned to **OWASP LLM Top 10 (2025)**, **MITRE ATLAS** and **NIST AI 600-1
(GenAI Profile)**.

> **Thesis (design north star).** The value of this product is **not** "many jailbreak
> prompts". It is **reproducibility + evidence + mapping to operational risk**. Every
> architectural decision optimizes for those three. A finding we cannot reproduce, cannot
> back with evidence, or cannot map to a business risk is treated as noise.

## What it does

- **54 declarative attack specs across 12 suites** covering the OWASP LLM Top 10, MITRE
  ATLAS and agentic/OWASP-Agents-2026 abuse. `dottore registry ls` lists them all.
- **Fingerprint** a target's model + guardrails before attacking (`-sV`).
- **Multi-turn** attacks (Crescendo, Linear, Sequential, Bad-Likert, Tree) whose turns are
  pinned in the spec, so a conversation is as reproducible as a single shot.
- **Deterministic-first evaluators** decide the verdict; an optional **LLM-as-judge**
  (`--judge`) is a hardened secondary, never the sole word.
- **Fleet mode**: declare every LLM / URL / MCP endpoint in one `fleet.yaml` and scan the lot.
- **Reports** in JSON, HTML, SARIF and JUnit; **`replay`** re-derives any run from evidence;
  **`diff`** gates a pipeline on regressions vs a baseline.

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/python -m pip install -e ".[dev]"
.venv/bin/dottore run --quick -t target.yaml --scope scope.yaml -oA report
```

New here? Read [`USAGE.md`](USAGE.md) (practical guide) then [`examples/`](examples/)
(copy-pasteable scenarios, from "no server, no key" to a full fleet). Full reference:
[`docs/MANUAL.md`](docs/MANUAL.md). Install options: [`INSTALL.md`](INSTALL.md).

## Repository map

```text
ildottore/
  README.md · USAGE.md · INSTALL.md · CONTRIBUTING.md · SECURITY.md · CHANGELOG.md
  Makefile                         # local task runner mirroring the CI gates
  pyproject.toml                   # package, deps, ruff/mypy/import-linter config
  src/ildottore/
    cli/                           # the `dottore` command (typer): run, fleet, fingerprint, …
    core/                          # runner + multi-turn conversation engine (the orchestrator)
    adapters/                      # thin over-the-wire clients (openai-compatible, anthropic, rest)
    evaluators/                    # verdict engine: deterministic-first + semantic_judge
    mutators/                      # payload transforms / obfuscation enhancers
    policy/                        # scope + endpoint allowlist (default-deny authorization gate)
    registry/                      # loads + indexes the declarative attack specs
    reporting/                     # JSON / HTML / SARIF / JUnit reporters
    scoring/                       # the risk model (impact x exploitability x reproducibility)
    store/                         # content-addressed evidence store + run store (SQLite)
    fingerprint/                   # model + guardrail fingerprinting (-sV)
    redactor.py                    # secret/PII redaction (redact-at-rest)
    shared/                        # models, enums, protocols (the only cross-package surface)
  specs/
    attacks/                       # individual declarative tests (YAML), the heart
    suites/                        # ordered collections of attack specs
    targets/                       # example target files
    scope.example.yaml             # authorization-record template
    fleet.example.yaml             # fleet template (many targets in one file)
    pack.yaml                      # makes specs/ resolve as a lintable pack
  schemas/                         # JSON Schemas that machine-validate every spec
  examples/                        # runnable, copy-pasteable scenarios
  docs/                            # design corpus (see below) + MANUAL, FAQ, adr/
  tests/                           # unit / contract / golden / e2e / self-scan
```

## Documentation

**Users** → [`USAGE.md`](USAGE.md), [`docs/MANUAL.md`](docs/MANUAL.md),
[`docs/FAQ.md`](docs/FAQ.md), [`examples/`](examples/), [`INSTALL.md`](INSTALL.md).

**Design corpus** (read in order to understand or extend the internals):

```text
docs/
  00-ai-build-playbook.md       # HOW this was built with AI
  01-architecture.md            # components, data flow, contracts
  02-threat-model.md            # what THIS tool must not break, the safety model
  03-attack-spec-format.md      # the declarative test format (the heart)
  04-evaluator-spec.md          # verdict engine incl. judge hardening
  05-scoring-model.md           # risk model (why confidence is NOT a multiplier)
  06-extensibility-suites.md    # how new techniques/suites plug in
  07-validation-plan.md         # the self-validation phase (the CI gates)
  08-default-battery.md         # the default test battery
  09-cli-design.md              # the nmap-style CLI
  10-fingerprint.md             # model fingerprinting engine
  11-data-leak-extraction.md    # leak/memorization detection (+ safety/legal)
  12-gaps-backlog.md            # prioritized coverage roadmap
  13-agentic-abuse-extortion.md # agentic-ransomware (JadePuffer-class) susceptibility
  14-deepteam-gap-analysis.md   # coverage map vs the DeepTeam taxonomy
  RESPONSIBLE-USE.md            # authorization + safe-by-design charter
  REFERENCES.md                 # sources (OWASP, garak, PyRIT, promptfoo, vendors)
  adr/                          # architecture decision records
```

## Non-negotiable invariants

- **Safe-by-design**: no real destructive actions, no real exfiltration; sensitive tools run
  as mocks/dry-run; every dangerous payload is flagged `test_only: true`.
- **Authorization-gated**: no target is scanned without an in-scope entry in a signed
  `scope` file + endpoint allowlist (default-deny; plain http only to loopback).
- **Evidence-first**: prompt, full response, sampling params, tool traces, evaluator
  reasoning and diffs are persisted for every attempt, with secrets redacted at rest.
- **Deterministic where possible, statistical where not**: LLMs are non-deterministic;
  reproducibility is measured over N runs with pinned sampling params, not assumed.

## Development

```bash
make            # the full local merge gate (mirrors CI: lint, format, types, tests, coverage)
make test       # the test suite
make fix        # autofix formatting + lint
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Authorized security testing only:
[`docs/RESPONSIBLE-USE.md`](docs/RESPONSIBLE-USE.md).
