"""Reporter base + registry (contract §5 step 1)."""

from __future__ import annotations

import pytest

from ildottore.reporting import (
    HtmlReporter,
    JsonReporter,
    JunitReporter,
    SarifReporter,
    get_reporter,
    list_formats,
    register_reporter,
)
from ildottore.reporting.base import BaseReporter
from ildottore.shared.enums import ReportFormat
from ildottore.shared.protocols import Reporter
from tests.reporting.conftest import make_finding, make_run


def test_all_formats_registered() -> None:
    assert set(list_formats()) == {"json", "html", "sarif", "junit"}


@pytest.mark.parametrize("fmt", ["json", "html", "sarif", "junit"])
def test_get_reporter_by_str(fmt: str) -> None:
    reporter = get_reporter(fmt)
    assert isinstance(reporter, BaseReporter)
    assert reporter.format == fmt


@pytest.mark.parametrize("fmt", list(ReportFormat))
def test_get_reporter_by_enum(fmt: ReportFormat) -> None:
    reporter = get_reporter(fmt)
    assert reporter.format == fmt.value


def test_concrete_reporters_satisfy_protocol() -> None:
    for reporter in (JsonReporter(), HtmlReporter(), SarifReporter(), JunitReporter()):
        assert isinstance(reporter, Reporter)


def test_unknown_format_raises() -> None:
    with pytest.raises(KeyError, match="unknown report format"):
        get_reporter("pdf")


def test_duplicate_registration_raises() -> None:
    with pytest.raises(ValueError, match="already registered"):
        register_reporter(ReportFormat.JSON, JsonReporter)


def test_render_returns_bytes() -> None:
    run = make_run(findings=[make_finding()])
    for fmt in list_formats():
        out = get_reporter(fmt).render(run, list(run.findings))
        assert isinstance(out, bytes) and out
