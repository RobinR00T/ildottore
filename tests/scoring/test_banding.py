"""Banding tests: golden boundary table + policy overrides (contract §7, docs/05 §3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.scoring.banding import BandPolicy, band_for_risk, sarif_level_for_band
from ildottore.shared.enums import ScanBand

_FIXTURE = Path(__file__).parents[1] / "fixtures" / "scoring" / "bands.json"


def _load_cases() -> list[dict[str, object]]:
    data = json.loads(_FIXTURE.read_text())
    return data["cases"]


@pytest.mark.parametrize("case", _load_cases(), ids=lambda c: f"risk={c['risk']}")
def test_golden_banding_table(case: dict[str, object]) -> None:
    """Every boundary case maps to the exact band + SARIF level in docs/05 §3."""
    risk = float(case["risk"])
    band = band_for_risk(risk)
    assert band.value == case["band"], f"risk {risk} → {band.value}, want {case['band']}"
    assert sarif_level_for_band(band) == case["sarif_level"]


def test_all_bands_covered_by_fixture() -> None:
    """The golden table exercises every band at least once."""
    seen = {c["band"] for c in _load_cases()}
    assert seen == {b.value for b in ScanBand}


def test_boundaries_are_inclusive_lower_bounds() -> None:
    """Cutoffs are inclusive lower bounds: 12→critical, 11.999→high, 8→high, 7.999→medium."""
    assert band_for_risk(12.0) is ScanBand.CRITICAL
    assert band_for_risk(11.999) is ScanBand.HIGH
    assert band_for_risk(8.0) is ScanBand.HIGH
    assert band_for_risk(7.999) is ScanBand.MEDIUM
    assert band_for_risk(4.0) is ScanBand.MEDIUM
    assert band_for_risk(3.999) is ScanBand.LOW
    assert band_for_risk(1.0) is ScanBand.LOW
    assert band_for_risk(0.999) is ScanBand.INFO
    assert band_for_risk(0.0) is ScanBand.INFO


def test_policy_pack_can_override_cutoffs() -> None:
    """A policy pack may tune cutoffs (contract §4 KEEP) without touching code."""
    strict = BandPolicy(critical=6.0, high=4.0, medium=2.0, low=0.5)
    assert band_for_risk(6.0, strict) is ScanBand.CRITICAL
    assert band_for_risk(5.0, strict) is ScanBand.HIGH
    assert band_for_risk(0.4, strict) is ScanBand.INFO
    # Same value bands differently under default vs strict policy.
    assert band_for_risk(6.0) is ScanBand.MEDIUM
    assert band_for_risk(6.0, strict) is ScanBand.CRITICAL
