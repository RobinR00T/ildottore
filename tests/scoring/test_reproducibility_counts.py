"""The counts behind a reproducibility rate (u07 A-126): the rate's own k and N."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ildottore.scoring.base import DefaultRiskScorer
from ildottore.scoring.risk import reproducibility_counts, reproducibility_from_attempts
from ildottore.shared.enums import IDENTITY_SWEEP, VerdictStatus
from ildottore.shared.models import Attempt, RiskScore

from .conftest import make_attempt, make_risk_score, make_spec, make_verdict


def _variant(status: VerdictStatus, mutation: str, i: int) -> Attempt:
    return make_attempt(status, attempt_id=f"{mutation}-{i}").model_copy(
        update={"mutation": mutation}
    )


def test_no_attempts_no_counts() -> None:
    assert reproducibility_counts([]) is None


def test_pooled_counts() -> None:
    attempts = [make_attempt(VerdictStatus.FAIL)] * 3 + [make_attempt(VerdictStatus.PASS)] * 2
    assert reproducibility_counts(attempts) == (3, 5)


def test_the_counts_are_the_best_variants_when_it_gives_the_rate() -> None:
    attempts = [_variant(VerdictStatus.FAIL, "b64", i) for i in range(2)]
    attempts += [_variant(VerdictStatus.PASS, "identity", i) for i in range(6)]
    assert reproducibility_counts(attempts) == (2, 2)
    assert reproducibility_from_attempts(attempts) == 1.0


def test_at_a_tied_rate_the_most_trials_win() -> None:
    attempts = [_variant(VerdictStatus.FAIL, "b64", i) for i in range(2)]
    attempts += [_variant(VerdictStatus.FAIL, "identity", i) for i in range(4)]
    assert reproducibility_counts(attempts) == (6, 6)


def test_a_variant_below_the_floor_never_gives_the_counts() -> None:
    attempts = [_variant(VerdictStatus.FAIL, "b64", 0)]
    attempts += [_variant(VerdictStatus.PASS, "identity", i) for i in range(3)]
    assert reproducibility_counts(attempts) == (1, 4)


def test_an_identity_sweep_is_not_a_variant() -> None:
    attempts = [_variant(VerdictStatus.FAIL, IDENTITY_SWEEP, i) for i in range(3)]
    attempts += [_variant(VerdictStatus.PASS, "identity", i) for i in range(3)]
    assert reproducibility_counts(attempts) == (3, 6)


@pytest.mark.parametrize(
    "statuses",
    [
        [VerdictStatus.FAIL],
        [VerdictStatus.PASS, VerdictStatus.FAIL, VerdictStatus.PASS],
        [VerdictStatus.FAIL] * 4,
    ],
)
def test_the_counts_always_give_the_rate(statuses: list[VerdictStatus]) -> None:
    attempts = [make_attempt(s, attempt_id=f"a{i}") for i, s in enumerate(statuses)]
    counts = reproducibility_counts(attempts)
    assert counts is not None
    assert counts[0] / counts[1] == reproducibility_from_attempts(attempts)


def test_the_scorer_records_the_counts() -> None:
    attempts = [make_attempt(VerdictStatus.FAIL)] + [make_attempt(VerdictStatus.PASS)] * 4
    rs = DefaultRiskScorer().score(make_spec(), [make_verdict()], attempts)
    assert (rs.successes, rs.trials) == (1, 5)
    assert rs.reproducibility == 0.2


def test_an_uncounted_score_dumps_as_before() -> None:
    dumped = make_risk_score().model_dump()
    assert "successes" not in dumped
    assert "trials" not in dumped


def test_a_counted_score_round_trips() -> None:
    rs = make_risk_score(reproducibility=0.2).model_copy(update={"successes": 1, "trials": 5})
    assert RiskScore.model_validate(rs.model_dump()) == rs


@pytest.mark.parametrize(
    ("reproducibility", "successes", "trials"),
    [(0.2, 1, None), (0.2, None, 5), (1.0, 6, 5), (0.5, 1, 5)],
)
def test_counts_that_do_not_give_the_rate_are_refused(
    reproducibility: float, successes: int | None, trials: int | None
) -> None:
    base = make_risk_score(reproducibility=reproducibility).model_dump()
    with pytest.raises(ValidationError):
        RiskScore.model_validate({**base, "successes": successes, "trials": trials})
