"""Multi-turn conversation executor tests (u08 multi-turn, contract §5.5/§7).

Proves the pinned-ladder conversation path: transcript threading, per-turn mutation,
final-turn scoring, deterministic N-run repro, budget accounting, env-error abort and
resume-skip. Offline and deterministic end-to-end (the target is a MockTarget or a tiny
in-test fake).
"""

from __future__ import annotations

import pytest

from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.core.budgets import BudgetLedger
from ildottore.core.conversation import execute_conversation, reproduce_conversation
from ildottore.core.execute import RetryPolicy
from ildottore.core.reproduce import attempt_id_for
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse, Sampling

_TURNS = [
    "Opening turn, benign framing.",
    "Escalation turn, the real ask.",
    "Final turn, extract the result.",
]


async def _no_sleep(_seconds: float) -> None:
    return None


class _FlakyAdapter:
    """A structural TargetAdapter that raises an env error on one specific turn."""

    id = "flaky"

    def __init__(self, fail_on_turn: int) -> None:
        self._fail_on_turn = fail_on_turn

    async def send(self, request: ModelRequest) -> ModelResponse:
        meta = request.metadata or {}
        idx = meta.get("turn_index")
        if idx == self._fail_on_turn:
            raise TimeoutError("simulated environment timeout")
        return ModelResponse(text=f"reply-{idx}")

    def capabilities(self) -> Capabilities:
        return Capabilities()


async def test_conversation_threads_transcript_and_scores_final_turn() -> None:
    target = MockTarget(MockScenario(response=["r0", "r1", "r2"]))
    ledger = BudgetLedger()
    result = await execute_conversation(
        target,
        _TURNS,
        attempt_id="S::identity#0",
        spec_id="S",
        mutation="identity",
        sampling=Sampling(temperature=0.0),
        ledger=ledger,
        now=lambda: 0.0,
    )
    assert result.env_error is False
    assert result.attempt.response is not None
    # The scored response is the FINAL turn's reply.
    assert result.attempt.response.text == "r2"
    # The full transcript is carried: 3 user turns interleaved with 3 assistant replies.
    messages = result.attempt.request.messages
    assert messages is not None
    assert [m["role"] for m in messages] == [
        "user",
        "assistant",
        "user",
        "assistant",
        "user",
        "assistant",
    ]
    assert [m["content"] for m in messages if m["role"] == "user"] == _TURNS
    assert [m["content"] for m in messages if m["role"] == "assistant"] == ["r0", "r1", "r2"]
    # One request debited per turn.
    assert ledger.snapshot().requests == 3


async def test_conversation_applies_mutation_to_every_turn() -> None:
    target = MockTarget(MockScenario(response="ok"))
    result = await execute_conversation(
        target,
        _TURNS,
        attempt_id="S::up#0",
        spec_id="S",
        mutation="up",
        sampling=None,
        ledger=BudgetLedger(),
        mutate_turn=str.upper,
        now=lambda: 0.0,
    )
    messages = result.attempt.request.messages
    assert messages is not None
    user_turns = [m["content"] for m in messages if m["role"] == "user"]
    assert user_turns == [t.upper() for t in _TURNS]


async def test_reproduce_conversation_is_byte_stable_and_debits_budget() -> None:
    scenario = MockScenario(response=["a", "b"])
    r1 = await reproduce_conversation(
        MockTarget(scenario),
        _TURNS,
        spec_id="S",
        mutation="identity",
        sampling=None,
        ledger=BudgetLedger(),
        n=3,
        now=lambda: 0.0,
    )
    ledger2 = BudgetLedger()
    r2 = await reproduce_conversation(
        MockTarget(scenario),
        _TURNS,
        spec_id="S",
        mutation="identity",
        sampling=None,
        ledger=ledger2,
        n=3,
        now=lambda: 0.0,
    )
    assert [r.attempt.model_dump_json() for r in r1] == [r.attempt.model_dump_json() for r in r2]
    # 3 conversations debit 3 attempts; each conversation sends 3 turns ⇒ 9 requests.
    assert ledger2.snapshot().attempts == 3
    assert ledger2.snapshot().requests == 9
    # One aggregate attempt per conversation (not one per turn).
    assert [r.attempt.attempt_id for r in r2] == [
        attempt_id_for("S", "identity", i) for i in range(3)
    ]


async def test_conversation_env_error_aborts_as_inconclusive() -> None:
    result = await execute_conversation(
        _FlakyAdapter(fail_on_turn=1),
        _TURNS,
        attempt_id="S::identity#0",
        spec_id="S",
        mutation="identity",
        sampling=None,
        ledger=BudgetLedger(),
        retry=RetryPolicy(max_retries=0),
        sleep=_no_sleep,
        now=lambda: 0.0,
    )
    assert result.env_error is True
    assert result.attempt.response is None
    assert result.attempt.error is not None
    # The partial transcript up to the failing turn is preserved for evidence.
    messages = result.attempt.request.messages
    assert messages is not None
    assert messages[0]["content"] == _TURNS[0]
    assert messages[1]["content"] == "reply-0"  # turn 0 succeeded before turn 1 failed


async def test_reproduce_conversation_resume_skips_completed() -> None:
    scenario = MockScenario(response="x")
    completed = {attempt_id_for("S", "identity", 0)}
    results = await reproduce_conversation(
        MockTarget(scenario),
        _TURNS,
        spec_id="S",
        mutation="identity",
        sampling=None,
        ledger=BudgetLedger(),
        n=2,
        completed=completed,
        now=lambda: 0.0,
    )
    assert [r.attempt.attempt_id for r in results] == [attempt_id_for("S", "identity", 1)]


async def test_reproduce_conversation_rejects_zero_n() -> None:
    with pytest.raises(ValueError, match="n must be"):
        await reproduce_conversation(
            MockTarget(MockScenario(response="x")),
            _TURNS,
            spec_id="S",
            mutation="identity",
            sampling=None,
            ledger=BudgetLedger(),
            n=0,
        )


class _ChainAdapter:
    """Answers on turn 0 and acts on the later turns, one tool call per turn."""

    id = "chain"

    def __init__(self, calls_by_turn: dict[int, str]) -> None:
        self._calls_by_turn = calls_by_turn

    async def send(self, request: ModelRequest) -> ModelResponse:
        meta = request.metadata or {}
        idx = meta.get("turn_index")
        name = self._calls_by_turn.get(idx if isinstance(idx, int) else -1)
        calls = [{"name": name, "args": {}}] if name else []
        return ModelResponse(text=f"reply-{idx}", tool_calls=calls)

    def capabilities(self) -> Capabilities:
        return Capabilities(tools=True)


async def test_conversation_accumulates_the_tool_trace_across_turns() -> None:
    """The aggregate carries EVERY turn's tool calls, in order, not just the final turn's.

    Scoring only the last reply let an agent answer on one turn and act on the next, which
    made every trace evaluator (tool_call, tool_sequence, kill_chain_progression)
    under-report a chain that demonstrably happened. The text stays the final turn's.
    """

    target = _ChainAdapter({0: "read_customer_record", 2: "send_email"})
    result = await execute_conversation(
        target,
        _TURNS,
        attempt_id="S::identity#0",
        spec_id="S",
        mutation="identity",
        sampling=Sampling(temperature=0.0),
        ledger=BudgetLedger(),
        retry=RetryPolicy(max_retries=0),
        sleep=_no_sleep,
    )
    response = result.attempt.response
    assert response is not None
    assert response.text == "reply-2"  # still the final turn's reply
    assert [c["name"] for c in response.tool_calls] == ["read_customer_record", "send_email"]


async def test_split_chain_across_turns_is_now_caught_by_tool_sequence() -> None:
    """End to end: the split-across-turns evasion the audit found no longer works."""

    from ildottore.evaluators.tool_sequence import ToolSequenceEvaluator
    from ildottore.shared.enums import EvaluatorType, VerdictStatus
    from ildottore.shared.models import EvalContext, EvaluatorConfig
    from tests.evaluators.conftest import make_spec

    target = _ChainAdapter({0: "read_customer_record", 2: "send_email"})
    result = await execute_conversation(
        target,
        _TURNS,
        attempt_id="S::identity#0",
        spec_id="S",
        mutation="identity",
        sampling=Sampling(temperature=0.0),
        ledger=BudgetLedger(),
        retry=RetryPolicy(max_retries=0),
        sleep=_no_sleep,
    )
    response = result.attempt.response
    assert response is not None

    config = EvaluatorConfig(
        type=EvaluatorType.TOOL_SEQUENCE, patterns=["read_customer_record", "send_email"]
    )
    ctx = EvalContext(
        spec=make_spec(evaluator_type=EvaluatorType.TOOL_SEQUENCE),
        request=ModelRequest(prompt="probe"),
        response=response,
        config=config,
    )
    verdict = await ToolSequenceEvaluator().evaluate(ctx)
    assert verdict.status is VerdictStatus.FAIL
    assert "read_customer_record -> send_email" in verdict.reasoning
