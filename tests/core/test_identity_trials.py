"""The runner's half of u08 A-87: each attempt's own reply read against the owner map, and the
identity sweep recorded as one trial of its spec.

On ``fef4963e`` every attempt carried the sweep's ``authz_leak`` verdict and its own reply was read
by nothing that knew the owner map, so a crossing the sweep showed counted on every attempt (5 of
5, confirmed) and one only the attempts showed scored nothing. Now each attempt's reply is read as
received by the identities the attempts are sent as (``IdentityProbe.sends_attempts``), and the
sweep is stored beside the attempts as one trial (``mutation: identity_sweep``), judged by the
spec's deterministic evaluators and never by the judge, counted once in the reproducibility, in
the status (a fail fails the spec, anything but a pass keeps it from passing) and never in the
confirmation.
"""

from __future__ import annotations

from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.core.runner import (
    CampaignRunner,
    IdentityProbe,
    _dominant_status,
    answered_attempt_ids,
    resume_progress,
)
from ildottore.shared.enums import (
    IDENTITY_SWEEP,
    Category,
    EvaluatorType,
    VerdictStatus,
)
from ildottore.shared.models import (
    Attempt,
    EvalContext,
    EvaluatorConfig,
    Finding,
    ModelRequest,
    ModelResponse,
    RiskScore,
    TestRun,
    Verdict,
)

from .conftest import make_policy_engine, make_scenario, mock_adapter_factory, no_sleep
from .test_multi_identity import _CANARY, _mi_target, _xtenant_spec

_OWN = "CANARY-A-1c4e8b2d90f37a65"


class _Counter:
    """A primary adapter that answers one text and counts its sends."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.sends = 0
        self.id = "primary"

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        return ModelResponse(text=self.text)

    def capabilities(self):  # type: ignore[no-untyped-def]
        from ildottore.shared.models import Capabilities

        return Capabilities(multi_identity=True)


def _runner(probes, primary, *, evaluators, mutators, scorer, stores, n=2):  # type: ignore[no-untyped-def]
    evidence, runs = stores
    return CampaignRunner(
        policy=make_policy_engine(allow_categories=[Category.DATA_LEAKAGE]),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=(
            (lambda _t, _s: primary)
            if not isinstance(primary, str)
            else mock_adapter_factory(make_scenario(primary))
        ),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        identity_adapters=lambda _t: probes,
        n=n,
        sleep=no_sleep,
        now=lambda: 0.0,
    )


def _probes(a_reply: str, *, attempts_as_a: bool = True, a_canary: str | None = None):  # type: ignore[no-untyped-def]
    a = MockTarget(MockScenario(response=a_reply), id="tenant-a")
    b = MockTarget(MockScenario(response=f"my own record {_CANARY}"), id="tenant-b")
    return [
        IdentityProbe(
            identity_id="tenant-a", adapter=a, canary=a_canary, sends_attempts=attempts_as_a
        ),
        IdentityProbe(identity_id="tenant-b", adapter=b, canary=_CANARY),
    ]


def _trial(finding: Finding) -> Attempt:
    (trial,) = [a for a in finding.attempts if a.mutation == IDENTITY_SWEEP]
    return trial


async def test_a_crossing_only_the_attempts_show_is_read_and_confirmed(
    evaluators, mutators, scorer, stores
) -> None:
    """``fef4963e``: the attempts' replies went unread, the clean sweep passed the spec."""

    leak = f"here is tenant B data: {_CANARY}"
    runner = _runner(
        _probes("only my own records"),
        leak,
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
    )
    result = await runner.run(run_id="r1", target=_mi_target(), specs=[_xtenant_spec()])

    (finding,) = result.findings
    assert (finding.status, finding.confirmed) == (VerdictStatus.FAIL, True)
    assert finding.risk.reproducibility == 1.0  # the attempts' variant, 2 of 2
    assert _trial(finding).verdict.status is VerdictStatus.PASS  # type: ignore[union-attr]
    assert "2/3 attempt-verdicts exploited; 1 of the 3 is the identity sweep's" in (
        finding.reasoning or ""
    )


async def test_attempts_sent_as_no_scope_identity_hold_none_of_their_canaries(
    evaluators, mutators, scorer, stores
) -> None:
    """No probe says the attempts are sent as it: tenant A's own canary is foreign to them."""

    runner = _runner(
        _probes("only my own records", attempts_as_a=False, a_canary=_OWN),
        f"your record {_OWN}",
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
    )
    result = await runner.run(run_id="r1", target=_mi_target(), specs=[_xtenant_spec()])

    (finding,) = result.findings
    assert finding.status is VerdictStatus.FAIL
    attempts = [a for a in finding.attempts if a.mutation != IDENTITY_SWEEP]
    assert all(a.verdict.status is VerdictStatus.FAIL for a in attempts)  # type: ignore[union-attr]
    # The trial has no reply of the attempts' identity, and authz_leak alone judged it.
    trial = _trial(finding)
    assert trial.response is None
    assert "no reply of the identity the attempts are sent as" in trial.verdict.reasoning  # type: ignore[union-attr]


async def test_the_identity_s_own_canary_in_its_attempts_passes(
    evaluators, mutators, scorer, stores
) -> None:
    runner = _runner(
        _probes(f"your record {_OWN}", a_canary=_OWN),
        f"your record {_OWN}",
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
    )
    result = await runner.run(run_id="r1", target=_mi_target(), specs=[_xtenant_spec()])
    assert result.findings[0].status is VerdictStatus.PASS


async def test_the_trial_is_stored_with_what_the_sweep_sent_and_heard(
    evaluators, mutators, scorer, stores
) -> None:
    runner = _runner(
        _probes("only my own records"),
        "only my own records",
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
    )
    result = await runner.run(run_id="r1", target=_mi_target(), specs=[_xtenant_spec()])

    (finding,) = result.findings
    trial = _trial(finding)
    assert trial.attempt_id == "DL-XTENANT-TEST::identity_sweep#0"
    assert trial.request.identity == "tenant-a"
    assert (trial.request.metadata or {})[IDENTITY_SWEEP] == {
        "identities": ["tenant-a", "tenant-b"],
        "answered": ["tenant-a", "tenant-b"],
        "attempts_as": ["tenant-a"],
    }
    assert trial.response is not None and trial.response.text == "only my own records"
    assert trial.attempt_id in {ref.attempt_id for ref in finding.evidence}
    assert len(finding.attempts) == 3


class _CountingJudge:
    """A judge that says secure and counts the replies it was asked about."""

    type = EvaluatorType.SEMANTIC_JUDGE.value

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(self, ctx: EvalContext) -> Verdict:
        self.calls += 1
        return Verdict(
            status=VerdictStatus.PASS,
            confidence=0.95,
            reasoning="secure",
            evaluator_type=self.type,
        )


async def test_the_judge_is_not_consulted_on_the_sweep_trial(
    evaluators, mutators, scorer, stores
) -> None:
    """One more judgement per sweep would be traffic no estimate prices."""

    judge = _CountingJudge()
    evaluators.register(judge, replace=True)
    spec = _xtenant_spec().model_copy(
        update={
            "evaluators": [
                EvaluatorConfig(type=EvaluatorType.AUTHZ_LEAK),
                EvaluatorConfig(type=EvaluatorType.SEMANTIC_JUDGE, rubric="leak or not"),
            ]
        }
    )
    runner = _runner(
        _probes("only my own records"),
        "only my own records",
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
    )
    result = await runner.run(run_id="r1", target=_mi_target(), specs=[spec])

    assert judge.calls == 2  # the two attempts, never the trial
    trial = _trial(result.findings[0])
    assert "the judge is not consulted on it" in trial.verdict.reasoning  # type: ignore[union-attr]
    assert result.findings[0].status is VerdictStatus.PASS


async def test_a_spec_asking_for_the_reserved_mutation_sends_nothing(
    evaluators, mutators, scorer, stores
) -> None:
    primary = _Counter("anything")
    spec = _xtenant_spec().model_copy(update={"mutations": [IDENTITY_SWEEP]})
    runner = _runner(
        _probes("x"),
        primary,
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
    )
    result = await runner.run(run_id="r1", target=_mi_target(), specs=[spec])

    (finding,) = result.findings
    assert finding.status is VerdictStatus.INCONCLUSIVE
    assert (finding.reasoning or "").startswith("reserved_mutation: identity_sweep")
    assert primary.sends == 0


async def test_at_one_run_a_passing_attempt_and_a_passing_sweep_pass(
    evaluators, mutators, scorer, stores
) -> None:
    """The sweep's trial is no vote in the majority: 1 of 2 would have been a tie."""

    runner = _runner(
        _probes("only my own records"),
        "only my own records",
        evaluators=evaluators,
        mutators=mutators,
        scorer=scorer,
        stores=stores,
        n=1,
    )
    result = await runner.run(run_id="r1", target=_mi_target(), specs=[_xtenant_spec()])
    assert result.findings[0].status is VerdictStatus.PASS


def _verdict(status: VerdictStatus) -> Verdict:
    return Verdict(status=status, confidence=1.0, reasoning="r", evaluator_type="aggregate")


def test_a_sweep_that_did_not_pass_keeps_the_spec_from_passing() -> None:
    passes = [_verdict(VerdictStatus.PASS)] * 5
    assert _dominant_status(passes) is VerdictStatus.PASS
    assert _dominant_status(passes, sweeps=[_verdict(VerdictStatus.PASS)]) is VerdictStatus.PASS
    blocked = _dominant_status(passes, sweeps=[_verdict(VerdictStatus.INCONCLUSIVE)])
    assert blocked is VerdictStatus.INCONCLUSIVE
    assert _dominant_status(passes, sweeps=[_verdict(VerdictStatus.FAIL)]) is VerdictStatus.FAIL


def _stored(attempt_id: str, mutation: str) -> Attempt:
    return Attempt(
        attempt_id=attempt_id,
        spec_id="S",
        mutation=mutation,
        request=ModelRequest(prompt="p"),
        response=ModelResponse(text="r"),
        verdict=_verdict(VerdictStatus.PASS),
    )


def test_a_resume_keeps_a_sweep_trial_and_never_resends_it_under_its_id() -> None:
    risk = RiskScore(
        impact=1, exploitability=1, reproducibility=0.0, risk=0.0, band="info", confidence=0.0
    )
    finding = Finding(
        spec_id="S",
        target_id="t",
        status=VerdictStatus.INCONCLUSIVE,
        risk=risk,
        confirmed=False,
        attempts=[_stored("S::identity_sweep#0", IDENTITY_SWEEP), _stored("S::identity#0", "x")],
    )
    run = TestRun(run_id="r", findings=[finding])
    assert answered_attempt_ids(run) == {"S::identity#0"}
    assert resume_progress(run) == (2, 0)
