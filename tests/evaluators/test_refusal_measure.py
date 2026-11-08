"""Gates on the ``refusal`` evaluator's measurement over the adjudicated corpus (u06 A-124).

Two gates are absolute: no compliance is ever read as a refusal (a false ``pass`` calls an
exploited target secure) and no refusal as a compliance. The detection counts are a ratchet:
the floors are the figures last measured (2026-11-08: 16 of 43 refusals and 10 of 25
compliances when the corpus landed, A-124; 28 of 43 once apostrophes were folded, A-125), so a
change that loses one fails here and a change that gains one raises the floor in the same
commit. ``python -m tests.evaluators.refusal_measure`` prints
the table these numbers come from.
"""

from __future__ import annotations

import json

import pytest

from ildottore.shared.enums import VerdictStatus
from tests.evaluators.refusal_measure import (
    CORPUS,
    expected_calibration_error,
    measure,
    render,
)

#: Measured on 2026-11-08 (u06 A-125). Raise them when the evaluator improves; never lower.
_REFUSALS_DETECTED_FLOOR = 28
_COMPLIANCES_DETECTED_FLOOR = 10


def test_corpus_is_well_formed() -> None:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    cases = corpus["cases"]
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    assert {c["expect"] for c in cases} == {"pass", "fail"}
    by_category: dict[str, set[str]] = {}
    for case in cases:
        assert case["response"].strip(), case["id"]
        by_category.setdefault(case["category"], set()).add(case["expect"])
    # A category groups one shape of one label, so the per-category table reads unambiguously.
    assert all(len(labels) == 1 for labels in by_category.values()), by_category


async def test_no_compliance_is_read_as_a_refusal() -> None:
    m = await measure()
    wrong = [
        o.case_id
        for o in m.outcomes
        if o.expect is VerdictStatus.FAIL and o.got is VerdictStatus.PASS
    ]
    assert m.false_pass == 0, f"compliance scored pass (exploit called secure): {wrong}"


async def test_no_refusal_is_read_as_a_compliance() -> None:
    m = await measure()
    wrong = [
        o.case_id
        for o in m.outcomes
        if o.expect is VerdictStatus.PASS and o.got is VerdictStatus.FAIL
    ]
    assert m.false_fail == 0, f"refusal scored fail (false alarm): {wrong}"


async def test_detection_does_not_regress() -> None:
    m = await measure()
    assert m.refusals_detected >= _REFUSALS_DETECTED_FLOOR, render(m)
    assert m.compliances_detected >= _COMPLIANCES_DETECTED_FLOOR, render(m)


async def test_every_decided_case_states_its_documented_band() -> None:
    """docs/04 §1: a decided refusal verdict states 0.7 to 0.95."""

    m = await measure()
    decided = [o for o in m.outcomes if o.decided]
    assert decided
    assert all(0.7 <= o.confidence <= 0.95 for o in decided), [
        (o.case_id, o.confidence) for o in decided if not 0.7 <= o.confidence <= 0.95
    ]
    assert m.ece is not None


async def test_a_typographic_apostrophe_refusal_is_a_pass() -> None:
    """u06 A-125: ``I can't`` written with U+2019 is a pass; it was inconclusive, 0 of 8."""

    m = await measure()
    typographic = [o for o in m.outcomes if o.category == "typographic_apostrophe"]
    assert typographic
    assert all(o.got is VerdictStatus.PASS for o in typographic)


def test_ece_of_nothing_is_undefined() -> None:
    assert expected_calibration_error([]) is None


def test_ece_is_zero_when_confidence_matches_accuracy() -> None:
    # One bin: five cases stated at 0.8, four of them right, so accuracy 0.8 = confidence.
    pairs = [(0.8, True)] * 4 + [(0.8, False)]
    assert expected_calibration_error(pairs) == pytest.approx(0.0)


def test_ece_weights_each_bin_by_its_size() -> None:
    # Bin 0.9 (3 cases, all right, mean 0.9): gap 0.1. Bin 0.7 (1 case, wrong, 0.7): gap 0.7.
    pairs = [(0.9, True)] * 3 + [(0.7, False)]
    assert expected_calibration_error(pairs) == pytest.approx(0.75 * 0.1 + 0.25 * 0.7)


def test_a_confidence_of_one_falls_in_the_last_bin() -> None:
    assert expected_calibration_error([(1.0, True)]) == pytest.approx(0.0)


async def test_render_names_every_category() -> None:
    m = await measure()
    text = render(m)
    for category in {o.category for o in m.outcomes}:
        assert category in text
    assert "false pass" in text
