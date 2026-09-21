"""`dottore coverage`: what the battery TESTS, computed without running anything."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.cli.coverage import (
    FRAMEWORK_KEYS,
    battery_coverage,
    render_coverage,
    render_coverage_json,
)
from ildottore.reporting.summary import build_battery_coverage
from ildottore.shared.iopc import IOPC_IMPACT_UNIVERSE, IOPC_TECHNIQUE_UNIVERSE

REPO = Path(__file__).resolve().parents[2]
#: The whole specs tree, as the CLI uses: suites live beside attacks, so a registry
#: built from attacks/ alone cannot resolve --suite.
SPECS = REPO / "specs"


def _coverage():
    return battery_coverage([SPECS])


def test_reports_every_axis_over_the_whole_battery() -> None:
    cov = _coverage()
    assert cov.specs == 72
    keys = [a.key for a in cov.axes]
    assert keys == ["owasp", "atlas", "iopc_techniques", "iopc_impacts"]
    for axis in cov.axes:
        assert 0.0 <= axis.pct <= 1.0, axis.label
        assert axis.exercised + len(axis.missing) == axis.total


def test_responsible_ai_codes_never_inflate_the_owasp_axis() -> None:
    """RAI0x is a different framework; counting it read as a perfect 10/10.

    The battery carries 8 OWASP LLM codes plus RAI01 and RAI02. Summed blindly that is ten
    distinct values over a denominator of ten, which reported 100% OWASP coverage while LLM03
    and LLM04 are untested. This pins the filter.
    """

    owasp = next(a for a in _coverage().axes if a.key == "owasp")
    assert owasp.exercised == 8
    assert owasp.total == 10
    assert all(code.startswith("LLM") for code, _ in owasp.covered)
    assert {code for code, _ in owasp.missing} == {"LLM03", "LLM04"}


def test_iopc_axes_use_the_pinned_universe_as_denominator() -> None:
    cov = _coverage()
    tech = next(a for a in cov.axes if a.key == "iopc_techniques")
    impact = next(a for a in cov.axes if a.key == "iopc_impacts")
    assert tech.total == len(IOPC_TECHNIQUE_UNIVERSE)
    assert impact.total == len(IOPC_IMPACT_UNIVERSE)
    # titles, not bare codes: the impact axis is meant to be readable
    assert any(title != code for code, title in tech.covered)


def test_gaps_are_named_not_just_counted() -> None:
    """A percentage with no list of what is missing invites a flattering reading."""

    out = render_coverage(_coverage(), framework="iopc")
    assert "Not covered" in out
    assert "IOPC-T4.002" in out
    assert "Unexpected Code Execution" in out


def test_no_gaps_flag_suppresses_the_listing() -> None:
    out = render_coverage(_coverage(), framework="iopc", show_gaps=False)
    assert "Not covered" not in out
    assert "IoPC techniques" in out


def test_framework_filter_selects_axes() -> None:
    cov = _coverage()
    assert "OWASP" in render_coverage(cov, framework="owasp", show_gaps=False)
    assert "IoPC" not in render_coverage(cov, framework="owasp", show_gaps=False)
    iopc = render_coverage(cov, framework="iopc", show_gaps=False)
    assert "IoPC techniques" in iopc and "IoPC impacts" in iopc
    assert "OWASP" not in iopc
    assert "all" in FRAMEWORK_KEYS


def test_suite_scoping_measures_only_that_suite() -> None:
    whole = battery_coverage([SPECS])
    scoped = battery_coverage([SPECS], suite="nova-iopc")
    assert scoped.specs == 10
    assert scoped.specs < whole.specs
    whole_t = next(a for a in whole.axes if a.key == "iopc_techniques")
    scoped_t = next(a for a in scoped.axes if a.key == "iopc_techniques")
    assert scoped_t.exercised < whole_t.exercised
    assert scoped_t.total == whole_t.total  # same denominator, smaller numerator


def test_unknown_suite_is_refused_not_reported_as_zero_coverage() -> None:
    """A suite that does not exist is a typo, and 0% is a wrong answer to a typo.

    This test used to assert the opposite (``cov.specs == 0`` and every axis at 0%), which
    pinned the defect rather than the behaviour: "this battery covers nothing" and "you named
    a suite I do not have" are different statements, and the first one reads as a measurement.
    The refusal names the registered suites so the fix needs no guessing.
    """

    with pytest.raises(ValueError) as err:
        battery_coverage([SPECS], suite="does-not-exist")
    assert "not registered" in str(err.value)
    assert "quick" in str(err.value)  # the message lists what IS registered


def test_json_output_honours_no_gaps() -> None:
    """``--json --no-gaps`` drops ``missing`` too: one flag, one meaning per output mode."""

    doc = json.loads(render_coverage_json(_coverage(), framework="owasp", show_gaps=False))
    assert "covered" in doc["axes"][0]
    assert "missing" not in doc["axes"][0]


def test_json_output_is_machine_readable_and_complete() -> None:
    doc = json.loads(render_coverage_json(_coverage(), framework="iopc"))
    assert doc["specs"] == 72
    assert [a["key"] for a in doc["axes"]] == ["iopc_techniques", "iopc_impacts"]
    tech = doc["axes"][0]
    assert len(tech["covered"]) == tech["exercised"]
    assert len(tech["covered"]) + len(tech["missing"]) == tech["total"]
    assert {"code", "title"} == set(tech["missing"][0])


def test_empty_spec_set_is_zero_not_a_crash() -> None:
    cov = build_battery_coverage([])
    assert cov.specs == 0
    assert all(a.exercised == 0 and a.pct == 0.0 and a.total > 0 for a in cov.axes)
