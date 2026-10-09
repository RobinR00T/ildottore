"""A halt keeps every reply the target gave (core side of the resume of a halted batch).

The CLI tests (`tests/cli/test_resume_halted_mid_batch.py`) drive the ceiling shapes end to end;
these pin the pieces: `reproduce` hands back what it had answered when a debit stops it, a reply
whose usage crosses the token ceiling travels with the halt, a product error mid-batch keeps the
attempts before it, a conversation the ceiling stops is not stored while the ones before it are,
and a judged re-send is the attempt scored over an unjudged first answer.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from ildottore.core.budgets import BudgetExhausted, BudgetLedger
from ildottore.core.execute import BudgetExhaustedAfterReply, RetryPolicy, execute_attempt
from ildottore.core.reproduce import reproduce
from ildottore.core.runner import (
    CampaignResult,
    CampaignRunner,
    _one_per_attempt_id,
    answered_attempt_ids,
    unjudged_attempt_ids,
)
from ildottore.evaluators import build_default_registry as build_evaluators
from ildottore.mutators import build_default_registry as build_mutators
from ildottore.scoring import DefaultRiskScorer
from ildottore.shared.enums import EvaluatorType, ScanBand, VerdictStatus
from ildottore.shared.models import (
    AttackSpec,
    Attempt,
    Capabilities,
    EvalContext,
    Finding,
    ModelRequest,
    ModelResponse,
    PlanBudgets,
    RiskScore,
    TestRun,
    Verdict,
)
from ildottore.store import replay_run
from ildottore.store.evidence_fs import FsEvidenceStore
from ildottore.store.replay import ReplayResult
from ildottore.store.run_sqlite import SqliteRunStore
from tests.core.conftest import AllowAllPolicy, make_spec, make_target, no_sleep

RUN = "run-halt0000001"


class _EnvError(Exception):
    is_env_error = True


class Endpoint:
    """Answers every send; ``fail_at`` raises a product error (not an env error) on that send.

    ``usage_at`` reports a usage on one send only (the others report ``usage``), and ``down``
    makes every send an environment error.
    """

    id = "t1"

    def __init__(
        self,
        *,
        usage: dict[str, int] | None = None,
        fail_at: int | None = None,
        usage_at: tuple[int, dict[str, int]] | None = None,
        down: bool = False,
    ) -> None:
        self.sends = 0
        self.usage = usage
        self.fail_at = fail_at
        self.usage_at = usage_at
        self.down = down

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        if self.down:
            raise _EnvError("ConnectError: connection refused")
        if self.fail_at is not None and self.sends == self.fail_at:
            raise RuntimeError("the target returned something no adapter could read")
        usage = self.usage
        if self.usage_at is not None and self.sends == self.usage_at[0]:
            usage = self.usage_at[1]
        return ModelResponse(text="I cannot help with that.", usage=usage)

    def capabilities(self) -> Capabilities:
        return Capabilities()


class _Judge:
    """Stands in for ``semantic_judge``: ``behaviour`` decides what each evaluation does."""

    type = "semantic_judge"

    def __init__(self, behaviour: Callable[[EvalContext], Awaitable[Verdict]]) -> None:
        self.behaviour = behaviour

    async def evaluate(self, ctx: EvalContext) -> Verdict:
        return await self.behaviour(ctx)


class _WithJudge:
    """The default evaluator registry, with ``judge`` registered as ``semantic_judge``."""

    def __init__(self, judge: _Judge) -> None:
        self.inner = build_evaluators(discover=False)
        self.judge = judge

    def has(self, type_name: str) -> bool:
        return type_name == "semantic_judge" or self.inner.has(type_name)

    def get(self, type_name: str) -> object:
        return self.judge if type_name == "semantic_judge" else self.inner.get(type_name)


async def _refused(_ctx: EvalContext) -> Verdict:
    raise BudgetExhausted("max_requests", 4, 5)


def _campaign(
    tmp_path: Path,
    endpoint: Endpoint | dict[str, Endpoint],
    specs: list[AttackSpec],
    *,
    budgets: PlanBudgets | None = None,
    resume_from: TestRun | None = None,
    judge: _Judge | None = None,
    concurrency: int = 1,
    n: int = 2,
) -> CampaignResult:
    """One campaign over ``specs``; ``endpoint`` per spec id when it is a dict."""

    runs = SqliteRunStore(tmp_path / "runs.sqlite")
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=build_mutators(discover=False),
        evaluators=_WithJudge(judge) if judge is not None else build_evaluators(discover=False),  # type: ignore[arg-type]
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev", journal=runs),
        run_store=runs,
        adapter_factory=lambda _t, spec: (  # type: ignore[arg-type,return-value]
            endpoint[spec.id] if isinstance(endpoint, dict) else endpoint
        ),
        n=n,
        concurrency=concurrency,
        retry=RetryPolicy(max_retries=0),
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    try:
        return asyncio.run(
            runner.run(
                run_id=RUN,
                target=make_target(),
                specs=specs,
                budgets=budgets,
                resume_from=resume_from,
            )
        )
    finally:
        runs.close()


def _stored(tmp_path: Path) -> list[Attempt]:
    return list(replay_run(tmp_path / "ev", RUN).attempts)


def _as_prior(tmp_path: Path) -> TestRun:
    """The stored attempts as the resume rebuilds them (one finding per spec)."""

    by_spec: dict[str, list[Attempt]] = {}
    for attempt in _stored(tmp_path):
        by_spec.setdefault(attempt.spec_id, []).append(attempt)
    return TestRun(
        run_id=RUN,
        findings=[_finding(spec_id, attempts) for spec_id, attempts in by_spec.items()],
    )


def _finding(spec_id: str, attempts: list[Attempt]) -> Finding:
    return Finding(
        spec_id=spec_id,
        target_id="t1",
        status=VerdictStatus.INCONCLUSIVE,
        risk=RiskScore(
            impact=1, exploitability=1, reproducibility=0.0, risk=0.0, band=ScanBand.INFO,
            confidence=0.0,
        ),
        confirmed=False,
        attempts=attempts,
    )  # fmt: skip


# --- reproduce / execute_attempt -----------------------------------------------------------


def test_reproduce_hands_back_the_answers_a_refused_debit_would_have_dropped() -> None:
    batch: list = []
    with pytest.raises(BudgetExhausted):
        asyncio.run(
            reproduce(
                Endpoint(),  # type: ignore[arg-type]
                ModelRequest(prompt="hi"),
                spec_id="S",
                mutation="identity",
                sampling=None,
                ledger=BudgetLedger(max_requests=2),
                n=4,
                sleep=no_sleep,
                now=lambda: 0.0,
                into=batch,
            )
        )
    assert [r.attempt.attempt_id for r in batch] == ["S::identity#0", "S::identity#1"]
    assert all(r.attempt.response is not None for r in batch)


def test_a_reply_over_the_token_ceiling_travels_with_the_halt() -> None:
    ledger = BudgetLedger(max_tokens=1000)
    with pytest.raises(BudgetExhaustedAfterReply) as caught:
        asyncio.run(
            execute_attempt(
                Endpoint(usage={"total_tokens": 5000}),  # type: ignore[arg-type]
                ModelRequest(prompt="hi"),
                attempt_id="a1",
                spec_id="S",
                mutation="identity",
                sampling=None,
                ledger=ledger,
                sleep=no_sleep,
                now=lambda: 0.0,
            )
        )
    halt = caught.value
    # Still a BudgetExhausted, so a caller that does not look for the reply halts all the same.
    assert isinstance(halt, BudgetExhausted) and halt.axis == "max_tokens"
    assert halt.result.attempt.response is not None
    assert ledger.spend().tokens == 5000, "the billed tokens are recorded"

    batch: list = []
    with pytest.raises(BudgetExhausted):
        asyncio.run(
            reproduce(
                Endpoint(usage={"total_tokens": 5000}),  # type: ignore[arg-type]
                ModelRequest(prompt="hi"),
                spec_id="S",
                mutation="identity",
                sampling=None,
                ledger=BudgetLedger(max_tokens=1000),
                n=2,
                sleep=no_sleep,
                now=lambda: 0.0,
                into=batch,
            )
        )
    assert [r.attempt.attempt_id for r in batch] == ["S::identity#0"]


# --- the runner ----------------------------------------------------------------------------


def test_a_product_error_mid_batch_keeps_the_attempts_answered_before_it(
    tmp_path: Path,
) -> None:
    spec = make_spec("JB-REFUSAL-001", mutations=["identity"])
    result = _campaign(tmp_path, Endpoint(fail_at=2), [spec])
    assert result.status == "aborted"
    stored = _stored(tmp_path)
    assert [a.attempt_id for a in stored] == ["JB-REFUSAL-001::identity#0"]
    assert stored[0].verdict is not None, "evaluated before the error went on"

    resumed = Endpoint()
    done = _campaign(tmp_path, resumed, [spec], resume_from=_as_prior(tmp_path))
    assert done.status == "complete"
    assert resumed.sends == 1, "the answered attempt is not sent again"


def test_a_conversation_the_ceiling_stops_is_not_stored_the_one_before_it_is(
    tmp_path: Path,
) -> None:
    spec = make_spec("JB-MULTI-001", mutations=["identity"])
    spec = spec.model_copy(update={"attack": spec.attack.model_copy(update={"turns": ["a", "b"]})})
    endpoint = Endpoint()
    # Conversation #0 is two requests; #1 gets its first turn out and is refused the second.
    result = _campaign(tmp_path, endpoint, [spec], budgets=PlanBudgets(max_requests=3))
    assert result.status == "budget_exhausted"
    assert endpoint.sends == 3
    assert [a.attempt_id for a in _stored(tmp_path)] == ["JB-MULTI-001::identity#0"]

    resumed = Endpoint()
    done = _campaign(tmp_path, resumed, [spec], resume_from=_as_prior(tmp_path))
    assert done.status == "complete"
    assert resumed.sends == 2, "conversation #1 is sent again from its first turn"


@pytest.mark.parametrize(
    ("crossing_send", "stored"),
    [
        (2, ["JB-MULTI-001::identity#0"]),
        (1, []),
        # The last reply of the last conversation: the run must still say it halted.
        (4, ["JB-MULTI-001::identity#0", "JB-MULTI-001::identity#1"]),
    ],
)
def test_a_conversation_whose_last_reply_crosses_the_token_ceiling_is_kept(
    tmp_path: Path, crossing_send: int, stored: list[str]
) -> None:
    """Its last reply crossing the ceiling, the conversation is finished and stored; an earlier
    one stops it unfinished, and none of its per-turn replies is stored as an attempt."""

    spec = make_spec("JB-MULTI-001", mutations=["identity"])
    spec = spec.model_copy(update={"attack": spec.attack.model_copy(update={"turns": ["a", "b"]})})
    endpoint = Endpoint(
        usage={"total_tokens": 10}, usage_at=(crossing_send, {"total_tokens": 100_000})
    )
    result = _campaign(tmp_path, endpoint, [spec], budgets=PlanBudgets(max_tokens=50_000))
    assert result.status == "budget_exhausted"
    assert endpoint.sends == crossing_send
    assert sorted(a.attempt_id for a in _stored(tmp_path)) == stored


def test_a_re_send_that_ends_in_an_environment_error_is_the_attempt_scored(
    tmp_path: Path,
) -> None:
    """The unjudged reply outranked the error's inconclusive, so the spec was scored without
    that attempt and a resume published a PASS from the one verdict left."""

    spec = make_spec("JB-REFUSAL-001", mutations=["identity"])
    assert _campaign(tmp_path, Endpoint(), [spec]).status == "complete"
    judged, second = sorted(_stored(tmp_path), key=lambda a: a.attempt_id)
    assert judged.verdict is not None and judged.verdict.status is VerdictStatus.PASS
    prior = TestRun(
        run_id=RUN,
        findings=[_finding(spec.id, [judged, second.model_copy(update={"verdict": None})])],
    )
    down = Endpoint(down=True)
    resumed = _campaign(tmp_path, down, [spec], resume_from=prior)
    assert down.sends == 1, "the unjudged reply is sent again"
    finding = resumed.findings[0]
    assert finding.status is VerdictStatus.INCONCLUSIVE, "not a PASS over a missing verdict"
    scored = {a.attempt_id: a for a in finding.attempts}[second.attempt_id]
    assert scored.response is None and scored.verdict is not None


def test_a_halted_resume_does_not_publish_a_spec_whose_last_reply_was_not_judged(
    tmp_path: Path,
) -> None:
    """Every planned id is on disk, one without a verdict: that spec is not finished."""

    spec = make_spec("JB-REFUSAL-001", mutations=["identity"])
    assert _campaign(tmp_path, Endpoint(), [spec]).status == "complete"
    stored = _stored(tmp_path)
    unjudged = stored[1].model_copy(update={"verdict": None})
    prior = TestRun(run_id=RUN, findings=[_finding(spec.id, [stored[0], unjudged])])
    assert unjudged_attempt_ids(prior) == {unjudged.attempt_id}
    assert answered_attempt_ids(prior) == {stored[0].attempt_id}

    halted = _campaign(
        tmp_path, Endpoint(), [spec], budgets=PlanBudgets(max_requests=0), resume_from=prior
    )
    assert halted.status == "budget_exhausted"
    assert halted.findings == [], "a spec scored without one of its verdicts is not published"


# --- which artifact of an id is the attempt -------------------------------------------------


def _verdict() -> Verdict:
    return Verdict(
        status=VerdictStatus.PASS, confidence=1.0, reasoning="ok", evaluator_type="refusal"
    )


_UNJUDGED = Attempt(
    attempt_id="a1",
    spec_id="S",
    request=ModelRequest(prompt="x"),
    response=ModelResponse(text="unjudged"),
)


@pytest.mark.parametrize("judged_first", [True, False])
@pytest.mark.parametrize("kind", ["answered", "env-error"])
def test_a_re_send_with_a_verdict_is_the_attempt_whichever_was_written_first(
    judged_first: bool, kind: str
) -> None:
    """Answered and judged, or ended in an environment error: either outranks a bare reply."""

    re_send = (
        _UNJUDGED.model_copy(
            update={"response": ModelResponse(text="judged"), "verdict": _verdict()}
        )
        if kind == "answered"
        else _UNJUDGED.model_copy(update={"response": None, "error": "boom", "verdict": _verdict()})
    )
    order = [re_send, _UNJUDGED] if judged_first else [_UNJUDGED, re_send]
    assert _one_per_attempt_id(order) == [re_send]
    replay = ReplayResult(run_id="r", attempts=tuple(order))
    assert list(replay.effective_attempts()) == [re_send]
    assert replay.n == 1


# --- an evaluation the halt stops (the judge, metered on the same ledger) --------------------


class _Says(Endpoint):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        return ModelResponse(text=self.text)


def test_a_deterministic_fail_is_kept_when_the_ceiling_refuses_the_judge(tmp_path: Path) -> None:
    """A deterministic fail decides without the judge (OD-19): it used to go down with the halt,
    and the resume scored the re-send of a reply that had already leaked."""

    spec = make_spec(evaluators=(EvaluatorType.REFUSAL, EvaluatorType.SEMANTIC_JUDGE))
    leaking = _Says("Here you go: step 1, step 2.")  # the refusal check reads it as compliance
    _campaign(tmp_path, leaking, [spec], judge=_Judge(_refused))
    stored = _stored(tmp_path)
    assert len(stored) == 2
    for attempt in stored:
        assert attempt.verdict is not None and attempt.verdict.status is VerdictStatus.FAIL
        # The evidence says the judge was not consulted, not only the run's state.
        assert "semantic_judge not consulted: budget exhausted" in attempt.verdict.reasoning
    prior = _as_prior(tmp_path)
    assert answered_attempt_ids(prior) == {a.attempt_id for a in stored}, "not sent again"


def test_without_a_deterministic_fail_the_refused_judge_halts_and_the_reply_waits(
    tmp_path: Path,
) -> None:
    spec = make_spec(evaluators=(EvaluatorType.REFUSAL, EvaluatorType.SEMANTIC_JUDGE))
    result = _campaign(tmp_path, _Says("I cannot help with that."), [spec], judge=_Judge(_refused))
    assert result.status == "budget_exhausted"
    stored = _stored(tmp_path)
    assert len(stored) == 2 and all(a.verdict is None for a in stored)


def test_an_evaluator_error_after_a_halt_is_named_in_the_reason(tmp_path: Path) -> None:
    """The halt stays the reason; the evaluator's own error used to leave no trace at all."""

    async def broken(_ctx: EvalContext) -> Verdict:
        raise KeyError("rubric")

    spec = make_spec(evaluators=(EvaluatorType.REFUSAL, EvaluatorType.SEMANTIC_JUDGE))
    result = _campaign(
        tmp_path,
        Endpoint(),
        [spec],
        budgets=PlanBudgets(max_requests=3),
        judge=_Judge(broken),
        n=4,
    )
    assert result.status == "budget_exhausted"
    reason = result.status_reason or ""
    assert "max_requests" in reason
    assert reason.count("also raised KeyError") == 1, "once, not once per stored reply"


def test_an_unrenderable_spec_first_does_not_stop_the_next(tmp_path: Path) -> None:
    """A media error is the spec's own inconclusive, not a campaign abort: the early abort
    must not fire on it, or the specs after it are silently skipped (delta audit)."""

    from ildottore.shared.enums import RequiresCapability

    bad = make_spec("MM-BAD-001", requires=[RequiresCapability.MULTIMODAL])
    bad = bad.model_copy(
        update={"attack": bad.attack.model_copy(update={"media": [{"kind": "image"}]})}
    )
    good = make_spec("JB-REFUSAL-002")
    endpoints = {bad.id: Endpoint(), good.id: Endpoint()}
    runs = SqliteRunStore(tmp_path / "runs.sqlite")
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=build_mutators(discover=False),
        evaluators=build_evaluators(discover=False),
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev", journal=runs),
        run_store=runs,
        adapter_factory=lambda _t, spec: endpoints[spec.id],  # type: ignore[arg-type,return-value]
        n=2,
        concurrency=1,
        retry=RetryPolicy(max_retries=0),
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    try:
        result = asyncio.run(
            runner.run(
                run_id=RUN,
                target=make_target(capabilities=Capabilities(multimodal=True)),
                specs=[bad, good],
            )
        )
    finally:
        runs.close()
    assert result.status == "complete"
    assert {f.spec_id for f in result.findings} == {bad.id, good.id}
    assert endpoints[good.id].sends == 2


def test_a_product_error_stops_new_specs_before_its_replies_are_judged(tmp_path: Path) -> None:
    """Judging the stored reply of the failing spec (a slow judge) let a waiting spec start."""

    async def slow(ctx: EvalContext) -> Verdict:
        await asyncio.sleep(0.2)
        return Verdict(
            status=VerdictStatus.PASS,
            confidence=1.0,
            reasoning="ok",
            evaluator_type="semantic_judge",
        )

    failing = make_spec(
        "JB-REFUSAL-001", evaluators=(EvaluatorType.REFUSAL, EvaluatorType.SEMANTIC_JUDGE)
    )
    quick = make_spec("JB-REFUSAL-002")
    waiting = make_spec("JB-REFUSAL-003")
    endpoints = {
        failing.id: Endpoint(fail_at=2),
        quick.id: Endpoint(),
        waiting.id: Endpoint(),
    }
    result = _campaign(
        tmp_path, endpoints, [failing, quick, waiting], judge=_Judge(slow), concurrency=2
    )
    assert result.status == "aborted"
    assert endpoints[waiting.id].sends == 0, "no spec starts after the product error"
    assert [a.attempt_id for a in _stored(tmp_path) if a.spec_id == failing.id] == [
        "JB-REFUSAL-001::identity#0"
    ]


def test_an_evaluator_error_stops_new_specs_before_the_batch_is_done(tmp_path: Path) -> None:
    """The abort is set at the first evaluator error, not once the spec gives up: a slow
    evaluation of the batch's next reply left room for a waiting spec to start (pre-merge
    audit: a mutant without that abort survived)."""

    calls = {"n": 0}

    async def broken_then_slow(_ctx: EvalContext) -> Verdict:
        calls["n"] += 1
        if calls["n"] > 1:
            await asyncio.sleep(0.2)
        raise KeyError("rubric")

    failing = make_spec(
        "JB-REFUSAL-001", evaluators=(EvaluatorType.REFUSAL, EvaluatorType.SEMANTIC_JUDGE)
    )
    # Neither starts once the abort is set: each finds it set when it gets its turn.
    second = make_spec("JB-REFUSAL-002")
    waiting = make_spec("JB-REFUSAL-003")
    endpoints = {failing.id: Endpoint(), second.id: Endpoint(), waiting.id: Endpoint()}
    result = _campaign(
        tmp_path,
        endpoints,
        [failing, second, waiting],
        judge=_Judge(broken_then_slow),
        concurrency=2,
    )
    assert result.status == "aborted"
    assert endpoints[waiting.id].sends == 0, "no spec starts after the evaluator error"
    assert endpoints[second.id].sends == 0
    assert len([a for a in _stored(tmp_path) if a.spec_id == failing.id]) == 2
