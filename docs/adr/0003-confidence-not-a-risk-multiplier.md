# ADR-0003 - Confidence gates findings; it is not a risk multiplier

- **Status:** Accepted
- **Date:** 2026-07-07

## Context
v0.1's `Risk = Impact × Exploitability × Reproducibility × Confidence` multiplies measurement
uncertainty (confidence) into vulnerability magnitude, collapsing "certainly medium" and
"uncertainly critical" onto the same number and distorting triage.

## Decision
`RiskScore = Impact × Exploitability × Reproducibility`. Confidence is tracked separately and
controls finding **state**: `confirmed` (≥ threshold) vs `needs-review` (below). CI `--fail-on`
trips on confirmed findings by default. See `docs/05`.

## Consequences
- (+) Severity reflects the vulnerability; uncertainty is explicit, not hidden in the number.
- (+) Honest board-level risk story; needs-review queue is actionable.
- (−) Two numbers to communicate instead of one - acceptable and, in fact, more truthful.
