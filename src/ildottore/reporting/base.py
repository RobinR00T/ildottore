"""Reporter base + format registry (contract u11 §5 step 1).

Implements the shared :class:`~ildottore.shared.protocols.Reporter` seam: one reporter per
format, each exposing ``format: str`` and ``render(run, findings) -> bytes``, pure and
deterministic (no I/O, no clock, no network - timestamps come from the run; contract §2, §8).

:class:`BaseReporter` centralizes the two cross-cutting concerns every format shares:

* the **mandatory masking pre-pass** - the run + findings are redacted exactly once via
  :class:`~ildottore.reporting.masking.MaskingContext` before ``_render`` sees them, so no
  concrete writer can reach around the redactor (contract §4 KEEP);
* the **framework rollup** - the shared :class:`~ildottore.reporting.summary.RunSummary` is
  built once from the (masked) findings + the injected ``spec_id → AttackSpec`` map.

Concrete reporters implement :meth:`_render(ctx, summary) -> bytes` only. The registry maps a
:class:`~ildottore.shared.enums.ReportFormat` to a reporter factory so u12 can resolve a
writer by name without importing every module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from ildottore.reporting.masking import MaskingContext, Redactor, default_redactor
from ildottore.reporting.summary import RunSummary, build_run_summary
from ildottore.shared.enums import ReportFormat
from ildottore.shared.models import AttackSpec, Finding, TestRun

__all__ = [
    "BaseReporter",
    "get_reporter",
    "list_formats",
    "register_reporter",
]


class BaseReporter(ABC):
    """Shared masking + summary scaffolding for every concrete reporter."""

    #: The format token (matches a :class:`ReportFormat` value) - set by subclasses.
    format: str

    def __init__(
        self,
        *,
        specs: dict[str, AttackSpec] | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self._specs = specs or {}
        self._redactor = redactor if redactor is not None else default_redactor()

    def render(self, run: TestRun, findings: list[Finding]) -> bytes:
        """Mask once, summarize once, then delegate to the format writer (pure)."""

        ctx = MaskingContext(run, findings, self._redactor)
        summary = build_run_summary(ctx.findings, self._specs)
        return self._render(ctx, summary)

    @abstractmethod
    def _render(self, ctx: MaskingContext, summary: RunSummary) -> bytes:
        """Serialize the already-masked run/findings + summary to bytes."""


# --- registry ---------------------------------------------------------------------

ReporterFactory = Callable[..., BaseReporter]

_FACTORIES: dict[str, ReporterFactory] = {}


def register_reporter(fmt: ReportFormat | str, factory: ReporterFactory) -> None:
    """Register a reporter factory for ``fmt`` (duplicate registration is a hard error)."""

    key = fmt.value if isinstance(fmt, ReportFormat) else fmt
    if key in _FACTORIES:
        raise ValueError(f"reporter already registered for format: {key!r}")
    _FACTORIES[key] = factory


def list_formats() -> list[str]:
    """Return the sorted names of all registered report formats."""

    return sorted(_FACTORIES)


def get_reporter(
    fmt: ReportFormat | str,
    *,
    specs: dict[str, AttackSpec] | None = None,
    redactor: Redactor | None = None,
) -> BaseReporter:
    """Instantiate the reporter registered for ``fmt``.

    Passes ``specs`` (framework attribution) and ``redactor`` (masking seam) through to the
    factory. An unknown format is a clear ``KeyError``, never a silent fallback.
    """

    key = fmt.value if isinstance(fmt, ReportFormat) else fmt
    try:
        factory = _FACTORIES[key]
    except KeyError:
        available = ", ".join(sorted(_FACTORIES))
        raise KeyError(f"unknown report format {key!r}; available: {available}") from None
    return factory(specs=specs, redactor=redactor)
