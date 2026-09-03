"""Typed lint errors + the aggregated lint report (contract §6).

``LintError`` is the atomic finding; ``LintReport`` aggregates them with counts and an
``ok`` flag. Both are frozen Pydantic models so a report round-trips to JSON verbatim for
the ``dottore lint --json`` rendering. No behavior beyond derivation of ``ok``/``counts``.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class LintCode(StrEnum):
    """Fixed enum of lint finding codes (contract §6)."""

    SCHEMA = "SCHEMA"
    ID_COLLISION = "ID_COLLISION"
    UNKNOWN_EVALUATOR_TYPE = "UNKNOWN_EVALUATOR_TYPE"
    UNKNOWN_MUTATOR_TYPE = "UNKNOWN_MUTATOR_TYPE"
    MISSING_TEST_ONLY = "MISSING_TEST_ONLY"
    FIXTURE_NO_DETECT = "FIXTURE_NO_DETECT"
    FIXTURE_HARDENED_FAIL = "FIXTURE_HARDENED_FAIL"
    MISSING_FRAMEWORK_MAP = "MISSING_FRAMEWORK_MAP"
    PARSE_ERROR = "PARSE_ERROR"
    UNKNOWN_SPEC_REF = "UNKNOWN_SPEC_REF"
    ASSET_ERROR = "ASSET_ERROR"


class Severity(StrEnum):
    """Lint finding severity — an ``error`` fails the lint, a ``warning`` does not."""

    ERROR = "error"
    WARNING = "warning"


class LintError(BaseModel):
    """One lint finding (contract §6: ``{code, spec_id, path, message, severity}``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: LintCode
    message: str
    severity: Severity = Severity.ERROR
    spec_id: str | None = None
    path: str | None = None


class LintCounts(BaseModel):
    """Object counts surfaced in the report (contract §6)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    specs: int = 0
    suites: int = 0
    packs: int = 0


class LintReport(BaseModel):
    """Aggregated lint result (contract §6).

    ``ok`` is ``True`` iff there are zero ``error``-severity findings; warnings never fail.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    errors: list[LintError] = Field(default_factory=list)
    warnings: list[LintError] = Field(default_factory=list)
    counts: LintCounts = Field(default_factory=LintCounts)

    @property
    def ok(self) -> bool:
        """No error-severity findings."""
        return len(self.errors) == 0

    def model_dump_report(self) -> dict[str, object]:
        """JSON-friendly dict including the derived ``ok`` flag (for ``--json``)."""
        return {
            "errors": [e.model_dump() for e in self.errors],
            "warnings": [w.model_dump() for w in self.warnings],
            "counts": self.counts.model_dump(),
            "ok": self.ok,
        }
