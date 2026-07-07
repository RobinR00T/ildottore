"""Evidence-fusion tests (u09 contract §5 step 6, §4 KEEP)."""

from __future__ import annotations

from ildottore.fingerprint.attribution import encode_signal
from ildottore.fingerprint.combine import combine, rank_families, rank_versions
from ildottore.fingerprint.layers.behavioral import SELF_REPORT_DETAIL
from ildottore.shared.models import FingerprintEvidence


def _ev(
    layer: str, family: str, version: str | None, detail: str, weight: float
) -> FingerprintEvidence:
    return FingerprintEvidence(
        layer=layer, signal=encode_signal(family, version, detail), weight=weight
    )


def test_empty_evidence_is_unknown_zero_confidence() -> None:
    fused = combine([])
    assert fused.family.guess == "unknown"
    assert fused.family.confidence == 0.0
    assert fused.version is None
    assert fused.spoofing_flags == []


def test_single_weak_signal_stays_low_confidence() -> None:
    # one thin signal must NOT read as certainty (contract §4 KEEP)
    fused = combine([_ev("metadata", "openai-gpt", None, "x", 0.05)])
    assert fused.family.guess == "openai-gpt"
    assert fused.family.confidence < 0.2


def test_accumulated_evidence_raises_confidence() -> None:
    ev = [
        _ev("metadata", "openai-gpt", None, "a", 0.4),
        _ev("statistical", "openai-gpt", "gpt-4o", "b", 0.5),
        _ev("behavioral", "openai-gpt", "gpt-4o", "c", 0.3),
    ]
    fused = combine(ev)
    assert fused.family.guess == "openai-gpt"
    assert fused.family.confidence > 0.5
    assert fused.version is not None
    assert fused.version.guess == "gpt-4o"


def test_contradictory_families_lower_confidence() -> None:
    ev = [
        _ev("statistical", "openai-gpt", None, "a", 0.5),
        _ev("statistical", "anthropic-claude", None, "b", 0.45),
    ]
    fused = combine(ev)
    # top family wins but confidence reflects the split, not 1.0
    assert fused.family.confidence < 0.7


def test_spoof_flag_when_self_report_conflicts_with_statistical() -> None:
    ev = [
        # statistics say claude; self-report claims gpt
        _ev("statistical", "anthropic-claude", None, "nn", 0.5),
        _ev("behavioral", "openai-gpt", None, SELF_REPORT_DETAIL, 0.15),
    ]
    fused = combine(ev)
    assert "self_report_conflicts_with_statistical" in fused.spoofing_flags
    # the spoofed self-report must NOT flip the family (contract §7: 0 silent wins)
    assert fused.family.guess == "anthropic-claude"


def test_no_spoof_flag_when_self_report_agrees() -> None:
    ev = [
        _ev("statistical", "openai-gpt", None, "nn", 0.5),
        _ev("behavioral", "openai-gpt", None, SELF_REPORT_DETAIL, 0.15),
    ]
    fused = combine(ev)
    assert fused.spoofing_flags == []
    # agreeing self-report contributes to the tally
    assert fused.family.guess == "openai-gpt"


def test_self_report_alone_still_guesses_but_no_flag() -> None:
    # no statistical evidence to contradict ⇒ no flag, weak guess
    ev = [_ev("behavioral", "openai-gpt", None, SELF_REPORT_DETAIL, 0.15)]
    fused = combine(ev)
    assert fused.spoofing_flags == []
    assert fused.family.guess == "openai-gpt"


def test_rank_families_orders_by_mass() -> None:
    ev = [
        _ev("statistical", "openai-gpt", None, "a", 0.2),
        _ev("statistical", "anthropic-claude", None, "b", 0.6),
    ]
    assert rank_families(ev)[0] == "anthropic-claude"


def test_rank_versions_scoped_and_ordered() -> None:
    ev = [
        _ev("behavioral", "openai-gpt", "gpt-4o", "a", 0.3),
        _ev("statistical", "openai-gpt", "gpt-4-turbo", "b", 0.1),
        _ev("behavioral", "anthropic-claude", "claude-opus-4.x", "c", 0.9),
    ]
    ranked = rank_versions(ev, "openai-gpt")
    assert ranked == ["gpt-4o", "gpt-4-turbo"]  # claude version excluded (scoped)


def test_version_none_when_no_version_evidence() -> None:
    fused = combine([_ev("metadata", "openai-gpt", None, "x", 0.4)])
    assert fused.version is None
