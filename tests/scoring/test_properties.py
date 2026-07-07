"""Property tests: ADR-0003 invariant + monotonicity (contract §7)."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from ildottore.scoring.base import DefaultRiskScorer
from ildottore.scoring.confidence import FindingState
from ildottore.shared.enums import VerdictStatus

from .conftest import make_attempt, make_spec, make_verdict

_impact = st.integers(min_value=1, max_value=4)
_expl = st.integers(min_value=1, max_value=4)
_confidence = st.floats(min_value=0.0, max_value=1.0)
_n_success = st.integers(min_value=0, max_value=8)
_n_fail = st.integers(min_value=0, max_value=8)


def _attempts(n_success: int, n_fail: int) -> list:
    out = [make_attempt(VerdictStatus.FAIL, attempt_id=f"s{i}") for i in range(n_success)]
    out += [make_attempt(VerdictStatus.PASS, attempt_id=f"f{i}") for i in range(n_fail)]
    return out


@given(impact=_impact, expl=_expl, conf_a=_confidence, conf_b=_confidence)
def test_adr0003_confidence_never_changes_risk(
    impact: int, expl: int, conf_a: float, conf_b: float
) -> None:
    """Two findings identical but for confidence have identical risk/band (ADR-0003)."""
    spec = make_spec(impact=impact, exploitability=expl)
    attempts = _attempts(3, 1)
    a = DefaultRiskScorer().score(spec, [make_verdict(confidence=conf_a)], attempts)
    b = DefaultRiskScorer().score(spec, [make_verdict(confidence=conf_b)], attempts)
    assert a.risk == b.risk
    assert a.band == b.band
    assert a.reproducibility == b.reproducibility


@given(impact=_impact, expl=_expl, conf=_confidence)
def test_adr0003_confidence_never_changes_band(impact: int, expl: int, conf: float) -> None:
    """Confidence only ever varies state, never the band (contract §7 property)."""
    spec = make_spec(impact=impact, exploitability=expl, confidence_threshold=0.75)
    attempts = _attempts(2, 0)
    rs = DefaultRiskScorer().score(spec, [make_verdict(confidence=conf)], attempts)
    high_conf = DefaultRiskScorer().score(spec, [make_verdict(confidence=1.0)], attempts)
    # Band identical regardless of confidence...
    assert rs.band == high_conf.band
    # ...but state may differ with confidence.
    state = DefaultRiskScorer().state(spec, [make_verdict(confidence=conf)])
    assert state in (FindingState.CONFIRMED, FindingState.NEEDS_REVIEW)


@given(i_lo=_impact, i_hi=_impact, expl=_expl)
def test_monotonic_in_impact(i_lo: int, i_hi: int, expl: int) -> None:
    """Higher impact ⇒ risk never decreases (all else equal)."""
    lo, hi = sorted((i_lo, i_hi))
    attempts = _attempts(3, 1)
    verdicts = [make_verdict()]
    r_lo = DefaultRiskScorer().score(make_spec(impact=lo, exploitability=expl), verdicts, attempts)
    r_hi = DefaultRiskScorer().score(make_spec(impact=hi, exploitability=expl), verdicts, attempts)
    assert r_hi.risk >= r_lo.risk


@given(e_lo=_expl, e_hi=_expl, impact=_impact)
def test_monotonic_in_exploitability(e_lo: int, e_hi: int, impact: int) -> None:
    """Higher exploitability ⇒ risk never decreases (all else equal)."""
    lo, hi = sorted((e_lo, e_hi))
    attempts = _attempts(3, 1)
    verdicts = [make_verdict()]
    r_lo = DefaultRiskScorer().score(
        make_spec(impact=impact, exploitability=lo), verdicts, attempts
    )
    r_hi = DefaultRiskScorer().score(
        make_spec(impact=impact, exploitability=hi), verdicts, attempts
    )
    assert r_hi.risk >= r_lo.risk


@given(ns_lo=_n_success, extra=_n_success, n_fail=_n_fail, impact=_impact, expl=_expl)
def test_monotonic_in_reproducibility(
    ns_lo: int, extra: int, n_fail: int, impact: int, expl: int
) -> None:
    """More successful attacks (fixed failures) ⇒ risk never decreases."""
    spec = make_spec(impact=impact, exploitability=expl)
    verdicts = [make_verdict()]
    lo = DefaultRiskScorer().score(spec, verdicts, _attempts(ns_lo, n_fail))
    hi = DefaultRiskScorer().score(spec, verdicts, _attempts(ns_lo + extra, n_fail))
    assert hi.risk >= lo.risk


@given(impact=_impact, expl=_expl, ns=_n_success, nf=_n_fail, conf=_confidence)
def test_risk_bounds_invariant(impact: int, expl: int, ns: int, nf: int, conf: float) -> None:
    """risk always in [0,16]; reproducibility/confidence in [0,1] (model + math)."""
    spec = make_spec(impact=impact, exploitability=expl)
    rs = DefaultRiskScorer().score(spec, [make_verdict(confidence=conf)], _attempts(ns, nf))
    assert 0.0 <= rs.risk <= 16.0
    assert 0.0 <= rs.reproducibility <= 1.0
    assert 0.0 <= rs.confidence <= 1.0
