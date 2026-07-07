"""Exit-code golden table (contract §7).

The exit code is a pure function of ``(findings, fail_on, include_needs_review,
error_state)``: clean→0, below-threshold→1, at/above→2, operational-error→>2, and
``--include-needs-review`` flips low-confidence (``confirmed=False``) findings into the
gate. No side effects (``docs/09 §4``).
"""

from __future__ import annotations

import pytest

from ildottore.cli.exit_codes import (
    ExitCode,
    exit_code_for,
    fail_on_band,
    gated_findings,
)
from ildottore.shared.enums import ScanBand, VerdictStatus

from .conftest import make_finding


def test_no_findings_is_clean() -> None:
    assert exit_code_for([], fail_on="high") is ExitCode.CLEAN


def test_finding_below_threshold_is_one() -> None:
    findings = [make_finding(band=ScanBand.LOW)]
    assert exit_code_for(findings, fail_on="high") is ExitCode.FINDINGS_BELOW


def test_finding_at_threshold_is_two() -> None:
    findings = [make_finding(band=ScanBand.HIGH)]
    assert exit_code_for(findings, fail_on="high") is ExitCode.FINDINGS_AT_OR_ABOVE


def test_finding_above_threshold_is_two() -> None:
    findings = [make_finding(band=ScanBand.CRITICAL)]
    assert exit_code_for(findings, fail_on="high") is ExitCode.FINDINGS_AT_OR_ABOVE


def test_error_short_circuits_to_gt_two() -> None:
    findings = [make_finding(band=ScanBand.CRITICAL)]
    code = exit_code_for(findings, fail_on="high", error=True)
    assert code is ExitCode.ERROR
    assert int(code) > 2


def test_passing_finding_never_gates() -> None:
    # A `pass` (secure) verdict must never trip CI even at a critical band.
    findings = [make_finding(status=VerdictStatus.PASS, band=ScanBand.CRITICAL)]
    assert exit_code_for(findings, fail_on="low") is ExitCode.CLEAN


def test_inconclusive_finding_never_gates() -> None:
    findings = [make_finding(status=VerdictStatus.INCONCLUSIVE, band=ScanBand.CRITICAL)]
    assert exit_code_for(findings, fail_on="low") is ExitCode.CLEAN


def test_needs_review_excluded_by_default() -> None:
    # A low-confidence (needs-review) finding does not gate unless opted in.
    findings = [make_finding(band=ScanBand.CRITICAL, confirmed=False)]
    assert exit_code_for(findings, fail_on="high") is ExitCode.CLEAN


def test_include_needs_review_flips_low_confidence_into_gate() -> None:
    findings = [make_finding(band=ScanBand.CRITICAL, confirmed=False)]
    code = exit_code_for(findings, fail_on="high", include_needs_review=True)
    assert code is ExitCode.FINDINGS_AT_OR_ABOVE


def test_include_needs_review_below_threshold_is_one() -> None:
    findings = [make_finding(band=ScanBand.LOW, confirmed=False)]
    code = exit_code_for(findings, fail_on="high", include_needs_review=True)
    assert code is ExitCode.FINDINGS_BELOW


def test_mixed_findings_take_the_worst_band() -> None:
    findings = [
        make_finding("A", band=ScanBand.LOW),
        make_finding("B", band=ScanBand.CRITICAL),
    ]
    assert exit_code_for(findings, fail_on="high") is ExitCode.FINDINGS_AT_OR_ABOVE


@pytest.mark.parametrize(
    ("token", "expected"),
    [("low", 1), ("medium", 2), ("high", 3), ("critical", 4)],
)
def test_fail_on_band_mapping(token: str, expected: int) -> None:
    assert fail_on_band(token) == expected


def test_fail_on_band_case_insensitive() -> None:
    assert fail_on_band("HIGH") == fail_on_band("high")


def test_fail_on_band_rejects_typo() -> None:
    with pytest.raises(ValueError, match="invalid --fail-on"):
        fail_on_band("hihg")


def test_gated_findings_filters_pass_and_needs_review() -> None:
    findings = [
        make_finding("A", status=VerdictStatus.FAIL, confirmed=True),
        make_finding("B", status=VerdictStatus.PASS, confirmed=True),
        make_finding("C", status=VerdictStatus.FAIL, confirmed=False),
    ]
    confirmed_only = gated_findings(findings, include_needs_review=False)
    assert {f.spec_id for f in confirmed_only} == {"A"}
    with_review = gated_findings(findings, include_needs_review=True)
    assert {f.spec_id for f in with_review} == {"A", "C"}
