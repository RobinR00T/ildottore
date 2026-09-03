"""Reporting unit (u11) - renders a finished ``TestRun`` + findings to report artifacts.

One :class:`~ildottore.shared.protocols.Reporter` per format (``json``, ``html``, ``sarif``,
``junit``). Each is pure/deterministic given ``(run, findings)`` and masks all secrets/PII via
the central redactor before serialization (single choke point in :mod:`.masking`). Importing
this package registers every built-in reporter, so :func:`get_reporter` can resolve any format.
"""

from __future__ import annotations

from ildottore.reporting.base import (
    BaseReporter,
    get_reporter,
    list_formats,
    register_reporter,
)
from ildottore.reporting.html_reporter import HtmlReporter
from ildottore.reporting.json_reporter import JsonReporter
from ildottore.reporting.junit_reporter import JunitReporter
from ildottore.reporting.masking import MaskingContext, Redactor, default_redactor
from ildottore.reporting.sarif_reporter import SarifReporter
from ildottore.reporting.summary import RunSummary, build_run_summary

__all__ = [
    "BaseReporter",
    "HtmlReporter",
    "JsonReporter",
    "JunitReporter",
    "MaskingContext",
    "Redactor",
    "RunSummary",
    "SarifReporter",
    "build_run_summary",
    "default_redactor",
    "get_reporter",
    "list_formats",
    "register_reporter",
]
