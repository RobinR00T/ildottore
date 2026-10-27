"""The false-positive breaker's rule over ledger records (u08 A-105, OD-61)."""

from __future__ import annotations

from ildottore.shared.enums import VerdictStatus
from ildottore.shared.review_holds import (
    MINIMUM,
    WINDOW,
    LabelRecord,
    ReviewHold,
    review_holds,
)

FAIL, PASS, UNDECIDED = VerdictStatus.FAIL, VerdictStatus.PASS, VerdictStatus.INCONCLUSIVE


def _labelled(spec_id: str, operators: list[VerdictStatus], *, start: int = 0) -> list[LabelRecord]:
    """One labelled scanner fail per operator verdict, each in its own run."""

    return [
        LabelRecord(run_id=f"run-{start + i:04d}", spec_id=spec_id, scanner=FAIL, operator=op)
        for i, op in enumerate(operators)
    ]


def test_fewer_than_the_minimum_hold_nothing() -> None:
    assert review_holds(_labelled("PI-DIRECT-001", [PASS] * (MINIMUM - 1))) == {}
    held = review_holds(_labelled("PI-DIRECT-001", [PASS] * MINIMUM))
    assert held == {"PI-DIRECT-001": ReviewHold(false_alarms=MINIMUM, labelled=MINIMUM)}


def test_the_rate_must_pass_thirty_per_cent() -> None:
    three_of_ten = [PASS] * 3 + [FAIL] * 7
    assert review_holds(_labelled("PI-DIRECT-001", three_of_ten)) == {}
    four_of_ten = [PASS] * 4 + [FAIL] * 6
    assert review_holds(_labelled("PI-DIRECT-001", four_of_ten)) == {
        "PI-DIRECT-001": ReviewHold(false_alarms=4, labelled=10)
    }


def test_only_the_last_window_counts() -> None:
    old = _labelled("PI-DIRECT-001", [PASS] * WINDOW)
    recent = _labelled("PI-DIRECT-001", [FAIL] * WINDOW, start=WINDOW)
    assert review_holds(old + recent) == {}
    assert review_holds(recent + old)["PI-DIRECT-001"] == ReviewHold(WINDOW, WINDOW)


def test_an_undecided_label_on_a_fail_is_a_false_alarm() -> None:
    held = review_holds(_labelled("PI-DIRECT-001", [UNDECIDED] * 2 + [FAIL] * 3))
    assert held["PI-DIRECT-001"] == ReviewHold(false_alarms=2, labelled=5)


def test_records_the_scanner_did_not_fail_are_not_read() -> None:
    passes = [
        LabelRecord(run_id=f"run-{i}", spec_id="PI-DIRECT-001", scanner=PASS, operator=FAIL)
        for i in range(20)
    ]
    assert review_holds(passes + _labelled("PI-DIRECT-001", [PASS] * 2)) == {}


def test_a_label_recorded_again_counts_once_at_its_latest_value() -> None:
    first = _labelled("PI-DIRECT-001", [PASS] * 5)
    corrected = _labelled("PI-DIRECT-001", [FAIL] * 5)
    assert review_holds(first + corrected) == {}
    assert review_holds(corrected + first)["PI-DIRECT-001"] == ReviewHold(5, 5)


def test_specs_are_counted_apart_and_returned_in_order() -> None:
    records = _labelled("PI-DIRECT-001", [FAIL] * 5) + _labelled("JB-ROLEPLAY-001", [PASS] * 5)
    records += _labelled("AA-FIRST-001", [PASS] * 6)
    assert list(review_holds(records)) == ["AA-FIRST-001", "JB-ROLEPLAY-001"]


def test_the_reason_names_both_counts() -> None:
    assert ReviewHold(4, 10).describe() == ("4 of its last 10 labelled fails were false positives")
