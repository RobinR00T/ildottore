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
    EVALUATOR_MISCONFIGURED = "EVALUATOR_MISCONFIGURED"
    UNKNOWN_FRAMEWORK_CODE = "UNKNOWN_FRAMEWORK_CODE"
    ORACLE_MARKER_IS_ECHOABLE = "ORACLE_MARKER_IS_ECHOABLE"
    #: A spec claims a framework code its own classification calls out of reach for a black box,
    #: or deliberately untested.
    FRAMEWORK_CLAIM_CONTRADICTED = "FRAMEWORK_CLAIM_CONTRADICTED"
    #: An installed mutator plugin could not be loaded. A warning: lint goes on with the
    #: built-ins, and a spec that names the plugin's mutator gets UNKNOWN_MUTATOR_TYPE.
    MUTATOR_PLUGIN_ERROR = "MUTATOR_PLUGIN_ERROR"
    #: A spec writes a deprecated name of the one combination rule (``all_pass``, ``any_fail``,
    #: ``weighted``) or an evaluator ``weight``, which nothing reads (OD-19, u06 A-73). A warning:
    #: the spec loads and runs the rule ``deterministic_first`` names.
    DEPRECATED_COMBINATION = "DEPRECATED_COMBINATION"
    #: A search path that does not exist. ``lint`` exits 3 on it, the I/O code (u12 A-82).
    PATH_NOT_FOUND = "PATH_NOT_FOUND"
    #: A search path that yields no attack spec and no suite file to read: ``lint`` exits 3 on
    #: it, and ``run``, ``registry ls``, ``coverage`` and ``describe`` refuse it (u12 A-82).
    NO_SPECS = "NO_SPECS"
    #: A warning: YAML files in the subdirectories of a directory without a ``pack.yaml``,
    #: which is read as loose specs, its own files only (u12 A-82).
    FILES_NOT_READ = "FILES_NOT_READ"


#: The codes that say a search path gave nothing to read: what ``lint`` exits 3 on and the other
#: commands refuse, rather than a finding about a spec.
PATH_CODES: frozenset[LintCode] = frozenset({LintCode.PATH_NOT_FOUND, LintCode.NO_SPECS})


class Severity(StrEnum):
    """Lint finding severity - an ``error`` fails the lint, a ``warning`` does not."""

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
