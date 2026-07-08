"""Run-summary + model-comparison aggregation (contract §7 summary correctness)."""

from __future__ import annotations

from ildottore.reporting.summary import (
    ATLAS_TACTIC_UNIVERSE,
    OWASP_LLM_TOTAL,
    build_run_summary,
)
from ildottore.shared.enums import ScanBand, VerdictStatus
from tests.reporting.conftest import make_finding, make_spec


def test_hand_labeled_counts() -> None:
    specs = {
        "PI-DEMO-001": make_spec(owasp="LLM01"),
        "DL-DEMO-002": make_spec("DL-DEMO-002", owasp="LLM02", nist="MAP"),
    }
    findings = [
        make_finding(
            "PI-DEMO-001", band=ScanBand.CRITICAL, status=VerdictStatus.FAIL, confirmed=True
        ),
        make_finding(
            "DL-DEMO-002", band=ScanBand.MEDIUM, status=VerdictStatus.PASS, confirmed=False
        ),
    ]
    summary = build_run_summary(findings, specs)

    assert summary.total == 2
    assert summary.by_status == {"fail": 1, "pass": 1}
    assert summary.by_band == {"critical": 1, "medium": 1}
    assert summary.by_framework.owasp == {"LLM01": 1, "LLM02": 1}
    assert summary.by_framework.nist == {"MAP": 1, "MEASURE": 1}
    assert summary.confirmed_count == 1
    assert summary.needs_review_count == 1


def test_missing_spec_counts_as_unknown() -> None:
    findings = [make_finding("PI-DEMO-001")]
    summary = build_run_summary(findings, specs={})
    assert summary.by_framework.owasp == {"unknown": 1}
    assert summary.by_framework.atlas == {"unknown": 1}
    assert summary.by_framework.nist == {"unknown": 1}


def test_no_comparison_for_single_target() -> None:
    findings = [make_finding(target_id="only")]
    summary = build_run_summary(findings, {"PI-DEMO-001": make_spec()})
    assert summary.model_comparison is None


def test_comparison_populated_for_multiple_targets() -> None:
    specs = {"PI-DEMO-001": make_spec()}
    findings = [
        make_finding(target_id="t-a", band=ScanBand.CRITICAL),
        make_finding(target_id="t-b", band=ScanBand.LOW),
    ]
    summary = build_run_summary(findings, specs)
    comp = summary.model_comparison
    assert comp is not None
    assert comp.target_ids == ("t-a", "t-b")
    assert comp.spec_ids == ("PI-DEMO-001",)
    assert len(comp.cells) == 2
    bands = {c.target_id: c.band for c in comp.cells}
    assert bands == {"t-a": "critical", "t-b": "low"}
    assert comp.category_rollups == {"LLM01": {"critical": 1, "low": 1}}


def test_distribution_empty_is_zeroed() -> None:
    summary = build_run_summary([], specs={})
    assert summary.repro_distribution == {"count": 0.0, "min": 0.0, "max": 0.0, "mean": 0.0}
    assert summary.confidence_distribution["count"] == 0.0


def test_distribution_stats() -> None:
    findings = [
        make_finding("PI-DEMO-001"),  # repro 1.0, conf 0.92
    ]
    summary = build_run_summary(findings, {})
    assert summary.repro_distribution["mean"] == 1.0
    assert summary.confidence_distribution["mean"] == 0.92


def test_coverage_six_owasp_categories_is_sixty_percent() -> None:
    """Acceptance (docs/12 P1): a suite touching 6 OWASP categories ⇒ 60%."""

    owasp_ids = ["LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06"]
    specs = {f"S-{i}": make_spec(f"S-{i}", owasp=oid) for i, oid in enumerate(owasp_ids)}
    findings = [make_finding(f"S-{i}") for i in range(len(owasp_ids))]

    cov = build_run_summary(findings, specs).coverage

    assert cov.owasp_exercised == 6
    assert cov.owasp_total == OWASP_LLM_TOTAL == 10
    assert cov.owasp_pct == 0.6
    assert cov.owasp_categories == tuple(owasp_ids)


def test_coverage_atlas_tactics_against_universe() -> None:
    tactics = ["Initial Access", "Discovery", "Exfiltration"]
    specs = {f"A-{i}": make_spec(f"A-{i}", owasp="LLM01", tactic=t) for i, t in enumerate(tactics)}
    findings = [make_finding(f"A-{i}") for i in range(len(tactics))]

    cov = build_run_summary(findings, specs).coverage

    assert cov.atlas_exercised == 3
    assert cov.atlas_total == len(ATLAS_TACTIC_UNIVERSE)
    assert cov.atlas_pct == 3 / len(ATLAS_TACTIC_UNIVERSE)
    assert cov.atlas_tactics == ("Discovery", "Exfiltration", "Initial Access")


def test_coverage_off_universe_tactic_not_counted() -> None:
    """A tactic outside the ATLAS universe is a spec-authoring error, not coverage."""

    specs = {"X-1": make_spec("X-1", tactic="AML.TA0000")}
    cov = build_run_summary([make_finding("X-1")], specs).coverage
    assert cov.atlas_exercised == 0
    assert cov.atlas_pct == 0.0


def test_coverage_unknown_spec_excluded_from_numerator() -> None:
    cov = build_run_summary([make_finding("PI-DEMO-001")], specs={}).coverage
    assert cov.owasp_exercised == 0
    assert cov.atlas_exercised == 0
    # still counted in the disposition rollup
    assert cov.specs_total == 1
    assert cov.specs_run == 1


def test_coverage_distinct_categories_deduplicated() -> None:
    specs = {
        "S-1": make_spec("S-1", owasp="LLM01"),
        "S-2": make_spec("S-2", owasp="LLM01"),
    }
    cov = build_run_summary([make_finding("S-1"), make_finding("S-2")], specs).coverage
    assert cov.owasp_exercised == 1
    assert cov.owasp_categories == ("LLM01",)


def test_coverage_spec_disposition_counts() -> None:
    findings = [
        make_finding("PI-DEMO-001", status=VerdictStatus.FAIL),
        make_finding("PI-DEMO-001", status=VerdictStatus.PASS),
        make_finding("PI-DEMO-001", status=VerdictStatus.INCONCLUSIVE),
    ]
    cov = build_run_summary(findings, {"PI-DEMO-001": make_spec()}).coverage
    assert cov.specs_total == 3
    assert cov.specs_run == 3
    assert cov.specs_pass == 1
    assert cov.specs_fail == 1
    assert cov.specs_inconclusive == 1


def test_coverage_empty_run_is_zeroed() -> None:
    cov = build_run_summary([], specs={}).coverage
    assert cov.owasp_pct == 0.0
    assert cov.atlas_pct == 0.0
    assert cov.specs_total == 0


def test_counts_are_key_sorted() -> None:
    specs = {
        "A-1": make_spec("A-1", owasp="LLM09"),
        "B-2": make_spec("B-2", owasp="LLM01"),
    }
    findings = [make_finding("A-1"), make_finding("B-2")]
    summary = build_run_summary(findings, specs)
    assert list(summary.by_framework.owasp) == ["LLM01", "LLM09"]
