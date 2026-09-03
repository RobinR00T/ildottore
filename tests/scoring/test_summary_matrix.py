"""Run-summary + comparison-matrix tests incl. golden fixtures (docs/05 §4-§5, contract §7)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.scoring.matrix import build_comparison_matrix
from ildottore.scoring.summary import build_run_summary, build_test_run_summary
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import Finding, RiskScore

from .conftest import make_risk_score, make_spec

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "scoring"


def _finding(
    spec_id: str,
    target_id: str,
    status: VerdictStatus,
    risk: RiskScore,
    confirmed: bool = True,
) -> Finding:
    return Finding(
        spec_id=spec_id,
        target_id=target_id,
        status=status,
        risk=risk,
        confirmed=confirmed,
    )


def _multi_target_suite() -> tuple[list[Finding], dict[str, object]]:
    """Two specs x two targets - the canonical benchmark scenario."""
    specs = {
        "PI-DEMO-001": make_spec("PI-DEMO-001", owasp="LLM01", tactic="AML.TA0001", nist="MEASURE"),
        "DL-DEMO-002": make_spec("DL-DEMO-002", owasp="LLM02", tactic="AML.TA0002", nist="MANAGE"),
    }
    findings = [
        _finding(
            "PI-DEMO-001",
            "gpt-x",
            VerdictStatus.FAIL,
            make_risk_score(4, 4, 1.0, band="critical", confidence=0.9),
        ),
        _finding(
            "PI-DEMO-001",
            "claude-y",
            VerdictStatus.PASS,
            make_risk_score(4, 4, 0.0, risk=0.0, band="info", confidence=0.95),
        ),
        _finding(
            "DL-DEMO-002",
            "gpt-x",
            VerdictStatus.FAIL,
            make_risk_score(3, 2, 0.5, band="low", confidence=0.6),
        ),
        _finding(
            "DL-DEMO-002",
            "claude-y",
            VerdictStatus.INCONCLUSIVE,
            make_risk_score(3, 2, 0.0, risk=0.0, band="info", confidence=0.4),
        ),
    ]
    return findings, specs


def test_run_summary_counts() -> None:
    findings, specs = _multi_target_suite()
    summary = build_run_summary(findings, specs)
    assert summary.total == 4
    assert summary.by_status == {"fail": 2, "pass": 1, "inconclusive": 1}
    assert summary.by_band == {"critical": 1, "info": 2, "low": 1}
    assert summary.by_category.owasp == {"LLM01": 2, "LLM02": 2}
    assert summary.by_category.atlas == {"AML.TA0001": 2, "AML.TA0002": 2}
    assert summary.by_category.nist == {"MEASURE": 2, "MANAGE": 2}


def test_run_summary_distributions() -> None:
    findings, specs = _multi_target_suite()
    summary = build_run_summary(findings, specs)
    assert summary.repro_dist["count"] == 4.0
    assert summary.repro_dist["max"] == 1.0
    assert summary.repro_dist["min"] == 0.0
    assert summary.conf_dist["mean"] == pytest.approx((0.9 + 0.95 + 0.6 + 0.4) / 4)


def test_run_summary_missing_spec_is_unknown() -> None:
    findings, _ = _multi_target_suite()
    summary = build_run_summary(findings, specs={})  # no spec map
    assert summary.by_category.owasp == {"unknown": 4}


def test_empty_run_summary() -> None:
    summary = build_run_summary([], {})
    assert summary.total == 0
    assert summary.by_status == {}
    assert summary.repro_dist == {"count": 0.0, "min": 0.0, "max": 0.0, "mean": 0.0}


def test_test_run_summary_slim_shape() -> None:
    findings, specs = _multi_target_suite()
    trs = build_test_run_summary(findings, specs)
    assert trs.total == 4
    assert trs.by_status == {"fail": 2, "pass": 1, "inconclusive": 1}
    assert trs.by_category == {"LLM01": 2, "LLM02": 2}  # flattened OWASP


def test_comparison_matrix_cells() -> None:
    findings, specs = _multi_target_suite()
    matrix = build_comparison_matrix(findings, specs)
    assert matrix.spec_ids == ("DL-DEMO-002", "PI-DEMO-001")
    assert matrix.target_ids == ("claude-y", "gpt-x")
    assert matrix.cells[("PI-DEMO-001", "gpt-x")].band == "critical"
    assert matrix.cells[("PI-DEMO-001", "claude-y")].band == "info"
    assert matrix.cells[("DL-DEMO-002", "gpt-x")].repro == pytest.approx(0.5)
    assert len(matrix.cells) == 4


def test_comparison_matrix_category_rollups() -> None:
    findings, specs = _multi_target_suite()
    matrix = build_comparison_matrix(findings, specs)
    assert matrix.category_rollups["LLM01"] == {"critical": 1, "info": 1}
    assert matrix.category_rollups["LLM02"] == {"low": 1, "info": 1}


# --- golden fixtures --------------------------------------------------------


def _to_jsonable_summary() -> dict:
    findings, specs = _multi_target_suite()
    s = build_run_summary(findings, specs)
    return {
        "total": s.total,
        "by_status": s.by_status,
        "by_band": s.by_band,
        "by_category": {
            "owasp": s.by_category.owasp,
            "atlas": s.by_category.atlas,
            "nist": s.by_category.nist,
        },
        "repro_dist": s.repro_dist,
        "conf_dist": s.conf_dist,
    }


def _to_jsonable_matrix() -> dict:
    findings, specs = _multi_target_suite()
    m = build_comparison_matrix(findings, specs)
    return {
        "cells": {
            f"{spec}|{target}": {"band": c.band, "repro": c.repro, "conf": c.conf}
            for (spec, target), c in sorted(m.cells.items())
        },
        "spec_ids": list(m.spec_ids),
        "target_ids": list(m.target_ids),
        "category_rollups": m.category_rollups,
    }


def test_golden_run_summary_matches() -> None:
    golden = json.loads((_FIXTURES / "run-summary.json").read_text())
    assert _to_jsonable_summary() == golden


def test_golden_matrix_matches() -> None:
    golden = json.loads((_FIXTURES / "matrix.json").read_text())
    assert _to_jsonable_matrix() == golden
