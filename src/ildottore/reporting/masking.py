"""Central masking pre-pass for every reporter (contract u11 §4 KEEP, §6).

Masking is **mandatory** and applied at a single choke point *before* any format
writer runs, so a newly added format cannot bypass it. Every reporter calls
:func:`mask_run` / :func:`mask_findings` (or the bundled :class:`MaskingContext`)
and serializes only the masked copies - no writer ever sees a raw secret/PII string.

The redactor itself is owned by u01 (``ildottore.redactor``); this module does **not**
re-implement detection. It is injected as a :class:`Redactor` structural protocol so a
caller can supply a salted production instance; the module default is the unsalted
process-wide redactor. Redaction preserves container shape and is idempotent
(``docs/11 §5``), so the pre-pass is safe to run once per render with no double-masking.
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

from ildottore.redactor import Redactor as _DefaultRedactorImpl
from ildottore.redactor import redact_evidence_ref
from ildottore.shared.models import Finding, TestRun

_SHA256 = re.compile(r"[0-9a-f]{64}")

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
    back into a :class:`TestRun` so downstream writers keep the typed, frozen contract. The
    findings embedded in the run get the same restores as :func:`mask_findings`: the JSON
    report carries both copies, and only the top-level one used to keep its evidence
    references readable (103 of 110 digests stayed masked under ``run.findings``).
    """

    raw = run.model_dump(mode="json")
    masked = redactor.redact(raw)
    if not isinstance(masked, dict):  # pragma: no cover - redact preserves shape
        raise TypeError("redactor changed the shape of a run dump")
    masked["findings"] = [
        _restore_tool_fields(masked_finding, finding, redactor)
        for masked_finding, finding in zip(masked.get("findings") or [], run.findings, strict=True)
    ]
    # The scope digest is the tool's own SHA-256 of the authorization record; the entropy rule
    # cannot tell it from a key, and masked it says nothing. Kept only in the shape it has.
    if run.scope_sha256 is not None and _SHA256.fullmatch(run.scope_sha256):
        masked["scope_sha256"] = run.scope_sha256
    return TestRun.model_validate(masked)


def _restore_tool_fields(masked: object, finding: Finding, redactor: Redactor) -> dict[str, object]:
    """Put back, on a masked finding dump, the fields the tool generated rather than read.

    The spec id is schema-validated (``shared.models._ID_PATTERN``) and authored, never
    target text: masking a custom one (``ACME-SYSPROMPT2-DOS-003``) with the per-process salt
    gave it a different digest in every run, so ``dottore diff`` saw two unrelated specs and
    reported no regression, and the SARIF rule id changed between runs (review of PR #32).
    """

    if not isinstance(masked, dict):  # pragma: no cover - redact preserves shape
        raise TypeError("redactor changed the shape of a finding dump")
    masked["spec_id"] = finding.spec_id
    masked["evidence"] = [
        redact_evidence_ref(redactor, ref.model_dump(mode="json")) for ref in finding.evidence
    ]
    for masked_attempt, attempt in zip(masked.get("attempts") or [], finding.attempts, strict=True):
        masked_attempt["attempt_id"] = attempt.attempt_id
        masked_attempt["spec_id"] = attempt.spec_id
    return masked


def mask_findings(findings: list[Finding], redactor: Redactor) -> list[Finding]:
    """Return deep-masked copies of ``findings`` (order preserved).

    Everything the target or the operator wrote is masked. What the tool itself generated to
    point at its evidence is not: the evidence references (run id, attempt id, path, sha256),
    each attempt's id and the spec id are restored after the pass. Masking them hid nothing,
    since a digest and a path are not secrets, and it cut the report off from its proof: 107
    of 110 evidence hashes in a quick-suite report read ``«REDACTED:high_entropy:...»``, so
    nobody could find, let alone verify, the artifact a finding cited (audit 2026-10-03, R1).
    """

    return [
        Finding.model_validate(
            _restore_tool_fields(
                redactor.redact(finding.model_dump(mode="json")), finding, redactor
            )
        )
        for finding in findings
    ]


class MaskingContext:
    """Bundles a run + findings that have already been masked once (single choke point).

    Every reporter constructs this at the top of :meth:`render` and reads only from it, so
    the raw inputs are masked exactly once and no writer can reach around the redactor.
    """

    __slots__ = ("findings", "run")

    def __init__(self, run: TestRun, findings: list[Finding], redactor: Redactor) -> None:
        self.run = mask_run(run, redactor)
        self.findings = mask_findings(findings, redactor)
