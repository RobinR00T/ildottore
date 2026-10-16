"""An identity sweep's crossing counts once in the reproducibility (u08 A-85, item 2).

The sweep sends a spec's attack once as each identity, and ``authz_leak`` reads those replies on
every attempt of the spec, so one reply of tenant A showing tenant B's canary failed all five
attempts and the finding read ``reproducibility 1.0``, Critical (pre-merge audit of the scoring
branch, #112, queued as pre-existing: ``repro_sweep_repro.py``; measured through the CLI on
``7d01521f``). The fail is stamped with the sweep (``Verdict.identity_sweep``), the aggregate keeps
the stamp only when nothing else would fail the attempt, and the scorer and the replay count each
sweep once (``shared.identity_sweep``). The finding stays a confirmed fail: the crossing is a
clean corroboration (``docs/11 §4``); only how often it was shown is counted honestly.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.cli.replay import render_replay
from ildottore.core.runner import CampaignResult, CampaignRunner, IdentityProbe
from ildottore.evaluators import build_default_registry as build_evaluators
from ildottore.mutators import build_default_registry as build_mutators
from ildottore.scoring import DefaultRiskScorer, reproducibility_from_attempts
from ildottore.shared.combination import combine_verdicts
from ildottore.shared.enums import (
    Category,
    EvaluatorType,
    InconclusiveReason,
    ScanBand,
    VerdictStatus,
)
from ildottore.shared.identity_sweep import count_successes
from ildottore.shared.models import (
    AttackSpec,
    Attempt,
    EvaluatorConfig,
    Finding,
    ModelRequest,
    ModelResponse,
    PlanBudgets,
    RiskScore,
    TestRun,
    Verdict,
)
from ildottore.store.evidence_fs import FsEvidenceStore
from ildottore.store.replay import ReplayResult, replay_run
from ildottore.store.run_sqlite import SqliteRunStore

from .conftest import make_policy_engine, make_scenario, mock_adapter_factory, no_sleep
from .test_multi_identity import _CANARY, _mi_target, _xtenant_spec

_RUN = "run-0123456789ab"
_LEAK = f"here is tenant B data: {_CANARY}"


def _probes(tenant_a: str) -> list[IdentityProbe]:
    a = MockTarget(MockScenario(response=tenant_a), id="tenant-a")
    b = MockTarget(MockScenario(response=f"my own record {_CANARY}"), id="tenant-b")
    return [
        IdentityProbe(identity_id="tenant-a", adapter=a, canary=None),
        IdentityProbe(identity_id="tenant-b", adapter=b, canary=_CANARY),
    ]


def _campaign(
    tmp_path: Path,
    *,
    primary: str = "only my own records",
    tenant_a: str = _LEAK,
    spec_canary_ref: bool = False,
    budgets: PlanBudgets | None = None,
    resume_from: TestRun | None = None,
    n: int = 5,
    spec: AttackSpec | None = None,
) -> CampaignResult:
    spec = spec if spec is not None else _xtenant_spec()
    if spec_canary_ref:
        spec = spec.model_copy(
            update={
                "evaluators": [
                    EvaluatorConfig(type=EvaluatorType.SECRET_LEAKAGE, canary_ref=_CANARY),
                    *spec.evaluators,
                ]
            }
        )
    runs = SqliteRunStore(tmp_path / "runs.sqlite")
    probes = _probes(tenant_a)
    runner = CampaignRunner(
        policy=make_policy_engine(allow_categories=[Category.DATA_LEAKAGE]),
        mutators=build_mutators(discover=False),
        evaluators=build_evaluators(discover=False),
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev", journal=runs),
        run_store=runs,
        adapter_factory=mock_adapter_factory(make_scenario(primary)),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        identity_adapters=lambda _t: probes,
        n=n,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    try:
        return asyncio.run(
            runner.run(
                run_id=_RUN,
                target=_mi_target(),
                specs=[spec],
                budgets=budgets,
                resume_from=resume_from,
            )
        )
    finally:
        runs.close()


def test_a_crossing_only_the_sweep_shows_is_one_success(tmp_path: Path) -> None:
    """``7d01521f``: 5 of 5, ``1.0``, Critical. Now 1 of 5, Low, and still a confirmed fail."""

    finding = _campaign(tmp_path).findings[0]
    assert (finding.status, finding.confirmed) == (VerdictStatus.FAIL, True)
    assert finding.risk.reproducibility == pytest.approx(0.2)
    assert finding.risk.band is ScanBand.LOW
    for attempt in finding.attempts:
        assert attempt.verdict is not None
        assert attempt.verdict.status is VerdictStatus.FAIL
        assert attempt.verdict.identity_sweep == 1
        assert "counts it once, not once per attempt" in attempt.verdict.reasoning
    replay = replay_run(tmp_path / "ev", _RUN)
    assert (replay.n, replay.successful_attacks()) == (5, 1)
    assert replay.sweep_fails() == (5, 1)
    assert "5 attempt(s) fail on the crossing of 1 identity sweep(s) alone" in render_replay(replay)


def test_an_attempt_that_fails_on_its_own_reply_counts_as_before(tmp_path: Path) -> None:
    """Control: the canary in each attempt's own reply (``secret_leakage``) is 5 successes."""

    finding = _campaign(tmp_path, primary=_LEAK, spec_canary_ref=True).findings[0]
    assert finding.risk.reproducibility == 1.0
    assert finding.risk.band is ScanBand.CRITICAL
    assert all(a.verdict is not None and a.verdict.identity_sweep is None for a in finding.attempts)
    assert replay_run(tmp_path / "ev", _RUN).successful_attacks() == 5


def test_a_clean_sweep_marks_nothing(tmp_path: Path) -> None:
    finding = _campaign(tmp_path, tenant_a="only tenant A data").findings[0]
    assert finding.status is VerdictStatus.PASS
    assert all(a.verdict is not None and a.verdict.identity_sweep is None for a in finding.attempts)


def test_a_resume_sweeps_again_and_its_sweep_counts_as_one_more(tmp_path: Path) -> None:
    """The halted part's fails carry sweep 1, the resume's sweep 2: two observations, 2 of 5."""

    halted = _campaign(tmp_path, budgets=PlanBudgets(max_requests=4))
    assert halted.status != "complete"
    stored = list(replay_run(tmp_path / "ev", _RUN).attempts)
    assert [a.verdict.identity_sweep for a in stored if a.verdict] == [1, 1]
    prior = TestRun(
        run_id=_RUN,
        findings=[
            Finding(
                spec_id=stored[0].spec_id,
                target_id="t1",
                status=VerdictStatus.FAIL,
                risk=RiskScore(
                    impact=4, exploitability=3, reproducibility=0.0, risk=0.0,
                    band=ScanBand.INFO, confidence=0.0,
                ),
                confirmed=False,
                attempts=stored,
            )
        ],
    )  # fmt: skip
    finding = _campaign(tmp_path, resume_from=prior).findings[0]
    sweeps = sorted(a.verdict.identity_sweep for a in finding.attempts if a.verdict is not None)
    assert sweeps == [1, 1, 2, 2, 2]
    assert finding.risk.reproducibility == pytest.approx(0.4)


# --- the combination keeps the stamp only on a fail nothing else makes -------------------------


def _v(kind: EvaluatorType, status: VerdictStatus, sweep: int | None = None) -> Verdict:
    return Verdict(
        status=status,
        confidence=1.0 if status is not VerdictStatus.INCONCLUSIVE else 0.0,
        reasoning=f"{kind.value} said {status.value}",
        evaluator_type=kind.value,
        identity_sweep=sweep,
    )


_AUTHZ_FAIL = _v(EvaluatorType.AUTHZ_LEAK, VerdictStatus.FAIL, 3)


@pytest.mark.parametrize(
    ("others", "stamped"),
    [
        ([], 3),
        ([_v(EvaluatorType.SECRET_LEAKAGE, VerdictStatus.PASS)], 3),
        ([_v(EvaluatorType.SECRET_LEAKAGE, VerdictStatus.INCONCLUSIVE)], 3),
        ([_v(EvaluatorType.SEMANTIC_JUDGE, VerdictStatus.PASS)], 3),
        # Another fail is the attempt's own: it counts as one success of its own.
        ([_v(EvaluatorType.SECRET_LEAKAGE, VerdictStatus.FAIL)], None),
        ([_v(EvaluatorType.SEMANTIC_JUDGE, VerdictStatus.FAIL)], None),
        # A judge's fail would be outranked by a deterministic abstention without authz_leak.
        (
            [
                _v(EvaluatorType.SEMANTIC_JUDGE, VerdictStatus.FAIL),
                Verdict(
                    status=VerdictStatus.INCONCLUSIVE,
                    confidence=0.0,
                    reasoning="no reply",
                    evaluator_type=EvaluatorType.PII_DETECTOR.value,
                    inconclusive_reason=InconclusiveReason.CAPABILITY_UNAVAILABLE,
                ),
            ],
            3,
        ),
    ],
)
def test_the_aggregate_keeps_the_sweep_only_when_nothing_else_fails_it(
    others: list[Verdict], stamped: int | None
) -> None:
    combined = combine_verdicts([_AUTHZ_FAIL, *others])
    assert combined.status is VerdictStatus.FAIL
    assert combined.identity_sweep == stamped


def test_a_verdict_without_a_sweep_is_dumped_as_before() -> None:
    plain = _v(EvaluatorType.AUTHZ_LEAK, VerdictStatus.FAIL)
    assert "identity_sweep" not in plain.model_dump()
    assert "identity_sweep" not in plain.model_dump_json()
    assert _AUTHZ_FAIL.model_dump()["identity_sweep"] == 3
    assert Verdict.model_validate_json(_AUTHZ_FAIL.model_dump_json()) == _AUTHZ_FAIL


# --- one counting rule for the scorer and the replay --------------------------------------------


def _attempt(index: int, verdict: Verdict, mutation: str = "identity") -> Attempt:
    return Attempt(
        attempt_id=f"S::{mutation}#{index}",
        spec_id="S",
        mutation=mutation,
        request=ModelRequest(prompt="p"),
        response=ModelResponse(text="r"),
        verdict=verdict,
    )


def test_the_scorer_and_the_replay_count_a_sweep_once() -> None:
    stamped = combine_verdicts([_AUTHZ_FAIL])
    own = combine_verdicts([_v(EvaluatorType.SECRET_LEAKAGE, VerdictStatus.FAIL)])
    passed = combine_verdicts([_v(EvaluatorType.SECRET_LEAKAGE, VerdictStatus.PASS)])
    attempts = [
        _attempt(0, stamped),
        _attempt(1, stamped),
        _attempt(2, own),
        _attempt(3, passed),
        _attempt(4, stamped.model_copy(update={"identity_sweep": 4})),
    ]
    assert count_successes(attempts, success=lambda a: a.verdict.status is VerdictStatus.FAIL) == 3
    assert reproducibility_from_attempts(attempts) == pytest.approx(3 / 5)
    replay = ReplayResult(run_id=_RUN, attempts=tuple(attempts))
    assert replay.successful_attacks() == 3
    assert replay.reproducibility() == pytest.approx(3 / 5)
    # Per variant: each variant's rate counts the sweep once, and the best variant decides.
    variants = [_attempt(i, stamped, "identity") for i in range(5)] + [
        _attempt(i, stamped, "base64") for i in range(5)
    ]
    assert reproducibility_from_attempts(variants) == pytest.approx(0.2)
