# ADR-0004 - Python src-layout single distribution (not a JS-style monorepo)

- **Status:** Accepted
- **Date:** 2026-07-07

## Context
The README repo map sketched a JS-style `packages/` + `apps/` monorepo. For a Python tool that
will ship to PyPI and be maintained long-term, that adds packaging friction (multiple
distributions, path plumbing) with no benefit.

## Decision
One distribution `ildottore` in a `src/` layout: `src/ildottore/{shared,core,adapters,
evaluators,scoring,reporting,policy,mutators,registry,fingerprint,store,cli}`. Package
boundaries from `docs/01 §2` are enforced logically via **import-linter** (config in
`pyproject.toml`), not via separate distributions. CLI entry point: `dottore`.

## Consequences
- (+) Standard, installable (`pip install -e .`), PyPI-ready, simple imports.
- (+) Boundaries still enforced (import-linter contract) - the architecture rule survives.
- (−) The README's `packages/apps` sketch is superseded by this layout.
