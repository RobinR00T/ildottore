# Changelog

All notable changes to Il Dottore. Format: [Keep a Changelog](https://keepachangelog.com/),
versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Full spec package (`docs/00–12`, `REFERENCES.md`, ADRs, JSON schema, example specs).
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

_Not yet pushed/tagged — pending `gh auth login`. See `docs/PROGRESS.md`._
