# ADR-0001 - Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-07-07

## Context
This project is built 100% by AI from specs. Decisions not captured in specs must still be
traceable, reviewable and reversible.

## Decision
Every non-trivial decision not already fixed by `docs/` is recorded as an ADR in
`docs/adr/NNNN-title.md` (`Status: Proposed|Accepted|Superseded`). The AI must write an ADR
whenever a spec is silent, implement the smallest reversible version, and reference the ADR in
the PR. See `docs/00 §0`.

## Consequences
Reviewers can audit every deviation; superseded decisions stay in history.
