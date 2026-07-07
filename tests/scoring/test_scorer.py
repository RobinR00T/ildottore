"""DefaultRiskScorer + registry tests (docs/05, contract §3/§7)."""

from __future__ import annotations

import pytest

from ildottore.scoring.banding import BandPolicy
from ildottore.scoring.base import DefaultRiskScorer
from ildottore.scoring.confidence import FindingState
from ildottore.scoring.registry import get_scorer, list_scorers, register_scorer
from ildottore.shared.enums import ScanBand, VerdictStatus
from ildottore.shared.models import RiskScore
from ildottore.shared.protocols import RiskScorer

from .conftest import make_attempt, make_spec, make_verdict


def test_scorer_satisfies_protocol() -> None:
    assert isinstance(DefaultRiskScorer(), RiskScorer)


def test_score_full_repro_critical() -> None:
    """impact=4, expl=4, all-fail ⇒ risk 16 ⇒ critical."""
    spec = make_spec(impact=4, exploitability=4)
    attempts = [make_attempt(VerdictStatus.FAIL) for _ in range(3)]
    verdicts = [make_verdict(VerdictStatus.FAIL, 0.9)]
    rs = DefaultRiskScorer().score(spec, verdicts, attempts)
    assert rs.risk == 16.0
    assert rs.band is ScanBand.CRITICAL
    assert rs.reproducibility == 1.0
    assert rs.confidence == pytest.approx(0.9)


def test_not_reproduced_is_info() -> None:
    """0 successes ⇒ risk 0 ⇒ Info (contract §7)."""
    spec = make_spec(impact=4, exploitability=4)
    attempts = [make_attempt(VerdictStatus.PASS) for _ in range(3)]
    rs = DefaultRiskScorer().score(spec, [make_verdict(VerdictStatus.PASS)], attempts)
    assert rs.risk == 0.0
    assert rs.band is ScanBand.INFO


def test_partial_repro_bands_on_raw_float() -> None:
    """impact=4, expl=3, 2/3 repro ⇒ risk 8.0 ⇒ high (OD-6 raw float)."""
    spec = make_spec(impact=4, exploitability=3)
    attempts = [
        make_attempt(VerdictStatus.FAIL),
        make_attempt(VerdictStatus.FAIL),
        make_attempt(VerdictStatus.PASS),
    ]
    rs = DefaultRiskScorer().score(spec, [make_verdict()], attempts)
    assert rs.risk == pytest.approx(8.0)
    assert rs.band is ScanBand.HIGH


def test_score_is_valid_riskscore_model() -> None:
    spec = make_spec()
    rs = DefaultRiskScorer().score(spec, [make_verdict()], [make_attempt()])
    assert isinstance(rs, RiskScore)
    # round-trips through pydantic validation
    RiskScore.model_validate(rs.model_dump())


def test_determinism_byte_identical_replay() -> None:
    """Same inputs ⇒ byte-identical RiskScore JSON (contract §7)."""
    spec = make_spec(impact=3, exploitability=2)
    attempts = [make_attempt(VerdictStatus.FAIL), make_attempt(VerdictStatus.PASS)]
    verdicts = [make_verdict(confidence=0.8)]
    a = DefaultRiskScorer().score(spec, verdicts, attempts)
    b = DefaultRiskScorer().score(spec, verdicts, attempts)
    assert a.model_dump_json() == b.model_dump_json()


def test_state_confirmed_vs_needs_review() -> None:
    spec = make_spec(confidence_threshold=0.75)
    scorer = DefaultRiskScorer()
    assert scorer.state(spec, [make_verdict(confidence=0.9)]) is FindingState.CONFIRMED
    assert scorer.state(spec, [make_verdict(confidence=0.5)]) is FindingState.NEEDS_REVIEW


def test_state_honors_spec_threshold() -> None:
    """A strict spec threshold flips a mid-confidence finding to needs-review."""
    strict = make_spec(confidence_threshold=0.95)
    lax = make_spec(confidence_threshold=0.5)
    scorer = DefaultRiskScorer()
    verdicts = [make_verdict(confidence=0.8)]
    assert scorer.state(strict, verdicts) is FindingState.NEEDS_REVIEW
    assert scorer.state(lax, verdicts) is FindingState.CONFIRMED


def test_custom_band_policy_applied() -> None:
    spec = make_spec(impact=2, exploitability=1)  # raw risk 2.0
    strict = DefaultRiskScorer(band_policy=BandPolicy(critical=2.0, high=1.5, medium=1.0, low=0.5))
    rs = strict.score(spec, [make_verdict()], [make_attempt(VerdictStatus.FAIL)])
    assert rs.risk == 2.0
    assert rs.band is ScanBand.CRITICAL


# --- registry ---------------------------------------------------------------


def test_registry_default_present() -> None:
    assert "default" in list_scorers()
    assert isinstance(get_scorer(), DefaultRiskScorer)
    assert isinstance(get_scorer("default"), RiskScorer)


def test_registry_unknown_raises() -> None:
    with pytest.raises(KeyError, match="unknown scorer"):
        get_scorer("does-not-exist")


def test_registry_duplicate_registration_rejected() -> None:
    with pytest.raises(ValueError, match="already registered"):
        register_scorer("default", DefaultRiskScorer)


def test_registry_register_and_get_custom() -> None:
    class _Custom(DefaultRiskScorer):
        name = "custom-test"

    register_scorer("custom-test", _Custom)
    assert "custom-test" in list_scorers()
    assert isinstance(get_scorer("custom-test"), _Custom)


class _FakeEntryPoint:
    def __init__(self, name: str, loaded: object) -> None:
        self.name = name
        self._loaded = loaded

    def load(self) -> object:
        return self._loaded


def test_registry_loads_valid_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    """A conforming entry point is discovered and registered (docs/06 §3)."""
    from ildottore.scoring import registry

    class _Plugin(DefaultRiskScorer):
        name = "plugin-a"

    monkeypatch.setattr(registry, "_FACTORIES", {"default": DefaultRiskScorer})
    monkeypatch.setattr(registry, "_loaded_plugins", False)
    monkeypatch.setattr(
        registry.metadata,
        "entry_points",
        lambda group: [_FakeEntryPoint("plugin-a", _Plugin)],
    )
    assert "plugin-a" in registry.list_scorers()
    assert isinstance(registry.get_scorer("plugin-a"), _Plugin)


def test_registry_rejects_nonconforming_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    """An entry point that is not a RiskScorer is rejected, never silently skipped."""
    from ildottore.scoring import registry

    class _NotAScorer:
        pass

    monkeypatch.setattr(registry, "_FACTORIES", {"default": DefaultRiskScorer})
    monkeypatch.setattr(registry, "_loaded_plugins", False)
    monkeypatch.setattr(
        registry.metadata,
        "entry_points",
        lambda group: [_FakeEntryPoint("bad", _NotAScorer)],
    )
    with pytest.raises(TypeError, match="does not implement the RiskScorer protocol"):
        registry.list_scorers()


def test_registry_plugin_does_not_override_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plugin whose name collides with a built-in never silently overrides it (docs/06 §2)."""
    from ildottore.scoring import registry

    class _Shadow(DefaultRiskScorer):
        name = "shadow"

    monkeypatch.setattr(registry, "_FACTORIES", {"default": DefaultRiskScorer})
    monkeypatch.setattr(registry, "_loaded_plugins", False)
    monkeypatch.setattr(
        registry.metadata,
        "entry_points",
        lambda group: [_FakeEntryPoint("default", _Shadow)],
    )
    # "default" already registered → the built-in wins, plugin is not swapped in.
    assert isinstance(registry.get_scorer("default"), DefaultRiskScorer)
    assert registry.list_scorers() == ["default"]
