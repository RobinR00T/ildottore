"""A prior's attempts are checked against the plan without building the plan (A-59, u08).

A resume asks, for each spec the halted run had started, whether the stored attempts hold every
planned ``(mutation, run)`` attempt. The runner answered by building the set of
``mutators x --runs`` attempt ids and testing inclusion, so the work grew with ``--runs``, not with
what was stored: a run store whose count was 10^7 took 3.5 s and 1.3 GiB to resume, and one of
``2**53 + 1`` was still growing at 3.7 GB after 4.5 minutes (OD-32, decided by the owner on
2026-10-08: the runner counts what is stored instead, and ``--runs`` keeps its ``2**53`` bound).
The same set was built when the seeding gate stopped a started spec and before the multi-identity
sweep of a resumed spec.
"""

from __future__ import annotations

import contextlib
import importlib
import itertools
import random
import sys
from collections.abc import Iterator

import pytest

import ildottore.core.runner as runner_mod
from ildottore.core.budgets import BudgetLedger
from ildottore.core.reproduce import attempt_id_for
from ildottore.core.runner import CampaignRunner
from ildottore.shared.enums import RequiresCapability, VerdictStatus
from ildottore.shared.models import Attempt, Finding, ModelRequest, ModelResponse

from .conftest import (
    make_policy_engine,
    make_scenario,
    make_spec,
    make_target,
    mock_adapter_factory,
    no_sleep,
)

#: More planned ids than any of these tests needs; a runner building the plan with
#: ``attempt_id_for`` crosses it (one that writes the ids another way is not counted).
_CAP = 10_000


@pytest.fixture
def counted_ids(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count the attempt ids the runner builds, and stop it past :data:`_CAP`.

    On a runner that builds the plan with it, a ``2**53`` plan stops here at once with a clear
    reason, instead of growing until the machine runs out of memory.
    """

    calls = [0]

    def counting(spec_id: str, mutation: str, run_index: int) -> str:
        calls[0] += 1
        if calls[0] > _CAP:
            raise AssertionError(f"the runner built more than {_CAP:,} planned attempt ids")
        return attempt_id_for(spec_id, mutation, run_index)

    # Not raising when the runner imports no id builder at all, which is the point: a runner that
    # imports one again to build the plan is counted, and so is one that reaches it through its
    # module (pre-commit audit of A-59: a revert written that way grew past 1 GB uncounted).
    monkeypatch.setattr(runner_mod, "attempt_id_for", counting, raising=False)
    # The submodule itself: `ildottore.core.reproduce` as an attribute is the function the package
    # exports under that name.
    reproduce_mod = importlib.import_module("ildottore.core.reproduce")
    monkeypatch.setattr(reproduce_mod, "attempt_id_for", counting)
    return calls


def _held(done: set[str], spec_id: str, mutators: list[str], runs: int) -> int:
    from ildottore.core.reproduce import planned_attempts_held

    return planned_attempts_held(done, spec_id, mutators, runs)


def _planned(spec_id: str, mutators: list[str], runs: int) -> set[str]:
    """The plan as the runner used to build it: the reference the count is checked against."""

    return {attempt_id_for(spec_id, m, i) for m in mutators for i in range(runs)}


# A spec id holding `::` or `#` must not confuse the count, nor one as long as another spec's:
# sliced at the wrong offset, `PI-DIRECT-002::identity#0` would pass for `PI-DIRECT-001`'s.
_SPECS = ["PI-DIRECT-001", "PI-DIRECT-002", "A::B-1", "X-1#2"]
_MUTATORS = ["identity", "b64", "a#1", "x::y", "a"]  # nor a mutation name holding them


def test_the_count_is_the_planned_set_intersected_with_what_is_stored() -> None:
    # A seeded sample of test inputs, the same on every run.
    rng = random.Random(59)  # noqa: S311
    for _ in range(3000):
        spec = rng.choice(_SPECS)
        mutators = [rng.choice(_MUTATORS) for _ in range(rng.randint(0, 4))]  # duplicates too
        runs = rng.randint(1, 4)
        universe = sorted(
            {attempt_id_for(s, m, i) for s in _SPECS for m in _MUTATORS for i in range(6)}
            | {f"{spec}::identity#01", f"{spec}::identity#-1", f"{spec}::identity#", spec}
        )
        done = set(rng.sample(universe, rng.randint(0, len(universe))))
        planned = _planned(spec, mutators, runs)

        assert _held(done, spec, mutators, runs) == len(planned & done), (spec, mutators, runs)


@pytest.mark.parametrize(
    "fake",
    [
        "S::identity#01",
        "S::identity#-1",
        "S::identity#",
        "S::identity#1.0",
        "S::identity#" + chr(0x661),
    ],
    ids=["leading-zero", "negative", "empty", "float", "arabic-digit"],
)
def test_an_id_the_runner_never_writes_is_not_counted(fake: str) -> None:
    """Only the exact form of ``attempt_id_for`` counts, so a stored id cannot pass for one."""

    assert _held({fake}, "S", ["identity"], 5) == 0
    assert _held({fake, "S::identity#1"}, "S", ["identity"], 5) == 1


def test_an_index_past_the_plan_is_not_counted() -> None:
    assert _held({"S::identity#4", "S::identity#5"}, "S", ["identity"], 5) == 1


def test_a_plan_whose_last_index_gains_a_digit_counts_every_stored_attempt() -> None:
    """The widest planned index is read from ``runs - 1``; one digit off at 10, 100 or 1,000 would
    leave the last attempt uncounted and a finished prior gated (delta audit of A-59)."""

    for runs in [1, 9, 10, 11, 99, 100, 101, 1000, 1001]:
        done = _planned("S", ["identity"], runs + 1)  # every planned attempt, and one past the plan

        assert _held(done, "S", ["identity"], runs) == runs, runs


def test_a_huge_plan_is_answered_from_what_is_stored(counted_ids: list[int]) -> None:
    held = _held({"S::identity#0", "S::identity#7"}, "S", ["identity", "b64"], 2**53)

    assert held == 2
    assert counted_ids[0] == 0


def _runner(stores, evaluators, mutators, scorer, *, n: int) -> CampaignRunner:
    evidence, runs = stores
    return CampaignRunner(
        policy=make_policy_engine(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=mock_adapter_factory(make_scenario("unused")),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        identity_adapters=lambda _t: [],
        n=n,
        sleep=no_sleep,
        now=lambda: 0.0,
    )


def _prior(spec_id: str, ids: list[str]) -> Finding:
    spec = make_spec(spec_id)
    return Finding(
        spec_id=spec.id,
        target_id="t1",
        status=VerdictStatus.INCONCLUSIVE,
        risk=runner_mod._zero_risk(spec),
        confirmed=False,
        attempts=[
            Attempt(
                attempt_id=attempt_id,
                spec_id=spec.id,
                request=ModelRequest(prompt="p"),
                response=ModelResponse(text="r"),
            )
            for attempt_id in ids
        ],
        evidence=[],
    )


def test_a_gated_prior_of_a_huge_plan_says_what_it_holds(
    stores, evaluators, mutators, scorer, counted_ids: list[int]
) -> None:
    """The seeding gate's message names how many of the plan were sent, and of how many."""

    runner = _runner(stores, evaluators, mutators, scorer, n=2**53)
    spec = make_spec("JB-REFUSAL-001")
    prior = _prior(spec.id, [attempt_id_for(spec.id, "identity", 0)])

    finding = runner._gated_prior(spec, make_target(), prior, ["identity", "b64"], "gap")

    assert finding.status is VerdictStatus.INCONCLUSIVE
    assert "had sent 1 of 18,014,398,509,481,984 attempts" in (finding.reasoning or "")
    assert counted_ids[0] == 0


def test_a_gated_prior_that_holds_its_plan_is_scored_as_before(
    stores, evaluators, mutators, scorer
) -> None:
    runner = _runner(stores, evaluators, mutators, scorer, n=2)
    spec = make_spec("JB-REFUSAL-001")
    ids = [attempt_id_for(spec.id, m, i) for m in ("identity", "b64") for i in range(2)]

    finding = runner._gated_prior(
        spec, make_target(), _prior(spec.id, ids), ["identity", "b64"], "g"
    )

    assert "had sent" not in (finding.reasoning or "")


async def test_the_identity_sweep_of_a_huge_plan_builds_no_plan(
    stores, evaluators, mutators, scorer, counted_ids: list[int]
) -> None:
    runner = _runner(stores, evaluators, mutators, scorer, n=2**53)
    spec = make_spec("JB-REFUSAL-001", requires=[RequiresCapability.MULTI_IDENTITY])
    ledger = BudgetLedger(max_requests=10)

    identities, owners = await runner._gather_identities(
        make_target(),
        spec,
        "prompt",
        "run-1",
        ledger=ledger,
        mutators=["identity"],
        completed={attempt_id_for(spec.id, "identity", 0)},
    )

    assert (identities, owners) == (None, {})
    assert counted_ids[0] == 0


@pytest.mark.parametrize(("runs", "held"), list(itertools.product([1, 2], [0, 1, 2])))
async def test_the_identity_sweep_is_skipped_only_when_every_attempt_is_stored(
    stores, evaluators, mutators, scorer, runs: int, held: int
) -> None:
    """As before: a resumed spec with every attempt stored has nothing left to sweep."""

    calls: list[object] = []
    runner = _runner(stores, evaluators, mutators, scorer, n=runs)
    runner._identity_adapters = lambda target: calls.append(target) or []  # type: ignore[assignment]
    spec = make_spec("JB-REFUSAL-001", requires=[RequiresCapability.MULTI_IDENTITY])
    completed = {attempt_id_for(spec.id, "identity", i) for i in range(held)}

    await runner._gather_identities(
        make_target(),
        spec,
        "prompt",
        "run-1",
        ledger=BudgetLedger(max_requests=10),
        mutators=["identity"],
        completed=completed,
    )

    assert (calls == []) is (held >= runs)


def test_an_id_of_another_spec_of_the_same_length_is_not_counted() -> None:
    """The sweep reads the run-wide set, which holds every spec's ids (pre-commit audit)."""

    assert _held({"PI-DIRECT-002::identity#0"}, "PI-DIRECT-001", ["identity"], 1) == 0


@pytest.mark.parametrize(
    "fake",
    ["S::identity#" + chr(0xB2), "S::identity#" + "1" * 4301],
    ids=["superscript-digit", "past-the-int-digit-limit"],
)
def test_a_stored_id_whose_index_is_no_number_is_ignored_not_fatal(fake: str) -> None:
    """``int()`` raised ``ValueError`` on both, which a corrupt run store could hold."""

    assert _held({fake, "S::identity#1"}, "S", ["identity"], 2**53) == 1


def test_a_stored_index_wider_than_the_plan_is_passed_over_unread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``int()`` of 10,000 stored indexes of 4,300 digits cost 4 s per check (delta audit of A-59).

    An index wider than ``runs - 1`` is not in the plan, so it is not converted at all.
    """

    reproduce_mod = importlib.import_module("ildottore.core.reproduce")
    converted: list[str] = []

    def counting_int(text: str) -> int:
        converted.append(text)
        return int(text)

    monkeypatch.setattr(reproduce_mod, "int", counting_int, raising=False)
    wide = {f"S::identity#{i}" + "1" * 4290 for i in range(10)}

    assert _held(wide | {"S::identity#1", "S::identity#12"}, "S", ["identity"], 5) == 1
    assert all(len(text) <= 1 for text in converted), "a wider index was converted"


@contextlib.contextmanager
def _digit_limit(limit: int) -> Iterator[None]:
    """The interpreter's limit on the digits ``int`` and ``str`` convert, set by the environment
    (``PYTHONINTMAXSTRDIGITS``) and pinned here so a test does not depend on it."""

    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(limit)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(before)


@pytest.fixture
def no_digit_limit() -> Iterator[None]:
    with _digit_limit(0):  # 0 is no limit at all
        yield


def test_a_run_count_too_long_to_write_out_still_counts_what_is_stored() -> None:
    """``str()`` refuses such a count under the digit limit, so the limit is the widest index then:
    a longer one is not counted, and ``attempt_id_for`` could not have written it either."""

    with _digit_limit(4300):
        runs = 10**5000
        stored = {"S::identity#3", "S::identity#" + "1" * 4301}

        assert _held(stored, "S", ["identity"], runs) == 1
        with pytest.raises(ValueError, match="limit"):
            attempt_id_for("S", "identity", int("1" * 4300) * 10 + 1)


@pytest.mark.usefixtures("no_digit_limit")
def test_without_a_digit_limit_every_stored_id_still_counts() -> None:
    assert _held({"S::identity#0", "S::identity#1"}, "S", ["identity"], 2) == 2


async def test_another_specs_attempts_do_not_skip_the_sweep(
    stores, evaluators, mutators, scorer
) -> None:
    calls: list[object] = []
    runner = _runner(stores, evaluators, mutators, scorer, n=1)
    runner._identity_adapters = lambda target: calls.append(target) or []  # type: ignore[assignment]
    spec = make_spec("JB-REFUSAL-001", requires=[RequiresCapability.MULTI_IDENTITY])

    await runner._gather_identities(
        make_target(),
        spec,
        "prompt",
        "run-1",
        ledger=BudgetLedger(max_requests=10),
        mutators=["identity"],
        completed={attempt_id_for("JB-REFUSAL-002", "identity", 0)},
    )

    assert calls, "the sweep was skipped on another spec's stored attempt"


async def test_a_runner_of_no_runs_still_sweeps(stores, evaluators, mutators, scorer) -> None:
    """With nothing planned, nothing of the plan is stored: the sweep runs, as it did."""

    calls: list[object] = []
    runner = _runner(stores, evaluators, mutators, scorer, n=0)
    runner._identity_adapters = lambda target: calls.append(target) or []  # type: ignore[assignment]
    spec = make_spec("JB-REFUSAL-001", requires=[RequiresCapability.MULTI_IDENTITY])

    await runner._gather_identities(
        make_target(),
        spec,
        "prompt",
        "run-1",
        ledger=BudgetLedger(max_requests=10),
        mutators=["identity"],
        completed=set(),
    )

    assert calls


def test_a_negative_run_count_plans_nothing_as_before(stores, evaluators, mutators, scorer) -> None:
    """A library caller may pass ``n=-1``; the plan it built was empty, so held and scored (delta
    audit of A-59: a product of ``-1`` held nothing and gated the prior instead)."""

    runner = _runner(stores, evaluators, mutators, scorer, n=-1)
    spec = make_spec("JB-REFUSAL-001")

    assert runner._holds_plan(set(), spec.id, ["identity"]) is True
    finding = runner._gated_prior(spec, make_target(), _prior(spec.id, []), ["identity"], "g")
    assert "had sent" not in (finding.reasoning or "")


def test_duplicate_mutators_hold_the_plan_once(stores, evaluators, mutators, scorer) -> None:
    """A ``plan_builder`` passed in by a caller may hand a mutation twice; the CLI's never does."""

    runner = _runner(stores, evaluators, mutators, scorer, n=2)
    done = {attempt_id_for("S", "identity", i) for i in range(2)}

    assert runner._holds_plan(done, "S", ["identity", "identity"]) is True
    assert runner._holds_plan(done, "S", ["identity", "b64"]) is False


def test_a_gated_prior_with_duplicate_mutators_is_scored(
    stores, evaluators, mutators, scorer
) -> None:
    runner = _runner(stores, evaluators, mutators, scorer, n=2)
    spec = make_spec("JB-REFUSAL-001")
    ids = [attempt_id_for(spec.id, "identity", i) for i in range(2)]

    finding = runner._gated_prior(
        spec, make_target(), _prior(spec.id, ids), ["identity", "identity"], "g"
    )

    assert "had sent" not in (finding.reasoning or "")
