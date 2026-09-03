"""Scriptable exit-code policy (contract §4/§6, ``docs/09 §4``).

The exit code is a **pure function** of ``(findings, fail_on, include_needs_review,
error_state)`` - no side effects, table-tested (contract §7). Semantics:

* ``0`` - clean: no gated finding at or above ``--fail-on``.
* ``1`` - findings present but all **below** ``--fail-on``.
* ``2`` - at least one gated finding **at or above** ``--fail-on``.
* ``>2`` - an operational error (bad scope, unknown suite, I/O …).

``--fail-on`` gates **confirmed** findings by default; ``--include-needs-review``
extends the gate to low-confidence (``confirmed=False``) findings too. A finding only
counts toward the gate when its status is ``fail`` (the target was exploited) - a
``pass``/``inconclusive`` never trips CI.
"""

from __future__ import annotations

from enum import IntEnum

from ildottore.shared.enums import ScanBand, Severity, VerdictStatus
from ildottore.shared.models import Finding

__all__ = [
    "BAND_ORDER",
    "ExitCode",
    "exit_code_for",
    "fail_on_band",
    "gated_findings",
]


class ExitCode(IntEnum):
    """The four scriptable outcomes (``docs/09 §4``)."""

    CLEAN = 0
    FINDINGS_BELOW = 1
    FINDINGS_AT_OR_ABOVE = 2
    ERROR = 3


#: Severity/band ordinal - higher is worse. ``info`` sits below ``low``.
BAND_ORDER: dict[str, int] = {
    ScanBand.INFO.value: 0,
    ScanBand.LOW.value: 1,
    ScanBand.MEDIUM.value: 2,
    ScanBand.HIGH.value: 3,
    ScanBand.CRITICAL.value: 4,
}


def fail_on_band(fail_on: str) -> int:
    """Map a ``--fail-on`` token (``low|medium|high|critical``) to a band ordinal.

    Accepts both :class:`Severity` and :class:`ScanBand` spellings (they share
    ``low/medium/high/critical``); an unknown token raises ``ValueError`` so a typo
    surfaces as an operational error rather than silently disabling the gate.
    """

    token = fail_on.strip().lower()
    if token in BAND_ORDER:
        return BAND_ORDER[token]
    # Accept Severity spellings that are not bands (none diverge today, but be explicit).
    if token in {s.value for s in Severity}:
        return BAND_ORDER[token]
    raise ValueError(
        f"invalid --fail-on {fail_on!r}; expected one of: "
        f"{', '.join(k for k in BAND_ORDER if k != ScanBand.INFO.value)}"
    )


def _is_gate_candidate(finding: Finding, *, include_needs_review: bool) -> bool:
    """Whether a finding is eligible to trip the gate.

    Only an **exploited** (``fail``) finding counts. By default only *confirmed*
    findings gate; ``--include-needs-review`` also lets low-confidence ones through.
    """

    if finding.status is not VerdictStatus.FAIL:
        return False
    if finding.confirmed:
        return True
    return include_needs_review


def gated_findings(
    findings: list[Finding],
    *,
    include_needs_review: bool,
) -> list[Finding]:
    """The subset of ``findings`` that are eligible to trip the CI gate."""

    return [f for f in findings if _is_gate_candidate(f, include_needs_review=include_needs_review)]


def exit_code_for(
    findings: list[Finding],
    *,
    fail_on: str,
    include_needs_review: bool = False,
    error: bool = False,
) -> ExitCode:
    """Pure exit-code decision (contract §6 - no side effects).

    ``error`` short-circuits to :attr:`ExitCode.ERROR` (>2) regardless of findings.
    Otherwise: any gated finding at/above ``fail_on`` → ``2``; some gated finding
    present but all below ``fail_on`` → ``1``; nothing gated → ``0``.
    """

    if error:
        return ExitCode.ERROR

    threshold = fail_on_band(fail_on)
    candidates = gated_findings(findings, include_needs_review=include_needs_review)
    if not candidates:
        return ExitCode.CLEAN

    at_or_above = any(BAND_ORDER.get(f.risk.band.value, 0) >= threshold for f in candidates)
    if at_or_above:
        return ExitCode.FINDINGS_AT_OR_ABOVE
    return ExitCode.FINDINGS_BELOW
