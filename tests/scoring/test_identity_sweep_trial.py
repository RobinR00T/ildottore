"""An identity sweep's trial counts once in the reproducibility (u08 A-87, item 2).

The sweep sends the attack once as each scope identity and compares the replies. On ``fef4963e``
every attempt carried its verdict, so a crossing one reply showed read as 5 of 5. Now it is stored
as one trial (``mutation`` :data:`~ildottore.shared.enums.IDENTITY_SWEEP`): never a variant of its
own, and the rate is never below the pooled rate over every trial. One rule, read by the scorer,
the runner and ``dottore replay``.
"""

from __future__ import annotations

import pytest

from ildottore.scoring.risk import reproducibility_from_attempts
from ildottore.shared.enums import IDENTITY_SWEEP, VerdictStatus
from ildottore.shared.models import Attempt

from .conftest import make_attempt


def _attempts(statuses: list[VerdictStatus], mutation: str = "identity") -> list[Attempt]:
    return [
        make_attempt(status, attempt_id=f"S::{mutation}#{i}").model_copy(
            update={"mutation": mutation}
        )
        for i, status in enumerate(statuses)
    ]


def _sweeps(statuses: list[VerdictStatus]) -> list[Attempt]:
    return _attempts(statuses, IDENTITY_SWEEP)


P, F, U = VerdictStatus.PASS, VerdictStatus.FAIL, VerdictStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    ("attempts", "sweeps", "expected"),
    [
        # The crossing only the sweep showed: the measured share, 1 of the spec's trials.
        ([P] * 5, [F], 1 / 6),
        ([P] * 10, [F], 1 / 11),
        ([P], [F], 1 / 2),  # --runs 1: no variant stands on its own, the pooled rate decides
        # Every reply leaks: 1.0 at any --runs.
        ([F] * 5, [F], 1.0),
        ([F], [F], 1.0),
        # A sweep that showed nothing never lowers the variant that leaks.
        ([F] * 5, [P], 1.0),
        # A halt and a resume: two sweeps, two trials, never a variant of their own.
        ([P] * 5, [F, F], 2 / 7),
        ([P] * 5, [F, P], 1 / 7),
        # An inconclusive sweep is a trial that did not show the exploit.
        ([F, F, P, P, P], [U], 2 / 5),
    ],
)
def test_a_sweep_is_one_trial(
    attempts: list[VerdictStatus], sweeps: list[VerdictStatus], expected: float
) -> None:
    trials = [*_sweeps(sweeps), *_attempts(attempts)]
    assert reproducibility_from_attempts(trials) == pytest.approx(expected)


def test_two_variants_and_a_sweep() -> None:
    """The best variant stands; the sweep lifts the rate only through the pooled floor."""

    trials = [*_attempts([F] * 2 + [P] * 3), *_attempts([P] * 5, "base64_wrap"), *_sweeps([F])]
    assert reproducibility_from_attempts(trials) == pytest.approx(2 / 5)
    only_sweep = [*_attempts([P] * 5), *_attempts([P] * 5, "base64_wrap"), *_sweeps([F])]
    assert reproducibility_from_attempts(only_sweep) == pytest.approx(1 / 11)


def test_without_a_sweep_the_rate_is_as_before() -> None:
    """Every variant of the same size: the best one is at least the pooled rate."""

    trials = [*_attempts([F] * 5), *_attempts([P] * 5, "rot13")]
    assert reproducibility_from_attempts(trials) == 1.0
    single = [*_attempts([F]), *_attempts([P], "rot13"), *_attempts([P], "leetspeak")]
    assert reproducibility_from_attempts(single) == pytest.approx(1 / 3)
