"""Central masking pre-pass for every reporter (contract u11 §4 KEEP, §6).

Masking is **mandatory** and applied at a single choke point *before* any format
writer runs, so a newly added format cannot bypass it. Every reporter calls
:func:`mask_run` / :func:`mask_findings` (or the bundled :class:`MaskingContext`)
and serializes only the masked copies — no writer ever sees a raw secret/PII string.

The redactor itself is owned by u01 (``ildottore.redactor``); this module does **not**
re-implement detection. It is injected as a :class:`Redactor` structural protocol so a
caller can supply a salted production instance; the module default is the unsalted
process-wide redactor. Redaction preserves container shape and is idempotent
(``docs/11 §5``), so the pre-pass is safe to run once per render with no double-masking.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ildottore.redactor import Redactor as _DefaultRedactorImpl
from ildottore.shared.models import Finding, TestRun

__all__ = ["MaskingContext", "Redactor", "mask_findings", "mask_run", "mask_text"]


@runtime_checkable
class Redactor(Protocol):
    """The masking seam reporters depend on (satisfied by ``ildottore.redactor.Redactor``).

    ``redact`` walks any value preserving container shape; ``redact_text`` masks a single
    string. Both are pure and idempotent.
    """

    def redact(self, obj: object) -> object: ...

    def redact_text(self, text: str) -> str: ...


def default_redactor() -> Redactor:
    """Return a fresh unsalted default redactor (u01)."""

    return _DefaultRedactorImpl()


def mask_text(text: str, redactor: Redactor) -> str:
    """Mask a single free-text string (e.g. a template value) through the redactor."""

    return redactor.redact_text(text)


def mask_run(run: TestRun, redactor: Redactor) -> TestRun:
    """Return a deep-masked copy of ``run`` (every string field redacted).

    The redactor walks the model dump preserving shape; the masked dict is re-validated
    back into a :class:`TestRun` so downstream writers keep the typed, frozen contract.
    """

    raw = run.model_dump(mode="json")
    masked = redactor.redact(raw)
    return TestRun.model_validate(masked)


def mask_findings(findings: list[Finding], redactor: Redactor) -> list[Finding]:
    """Return deep-masked copies of ``findings`` (order preserved)."""

    out: list[Finding] = []
    for finding in findings:
        masked = redactor.redact(finding.model_dump(mode="json"))
        out.append(Finding.model_validate(masked))
    return out


class MaskingContext:
    """Bundles a run + findings that have already been masked once (single choke point).

    Every reporter constructs this at the top of :meth:`render` and reads only from it, so
    the raw inputs are masked exactly once and no writer can reach around the redactor.
    """

    __slots__ = ("findings", "run")

    def __init__(self, run: TestRun, findings: list[Finding], redactor: Redactor) -> None:
        self.run = mask_run(run, redactor)
        self.findings = mask_findings(findings, redactor)
