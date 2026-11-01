"""A cheap judge that hands what it cannot settle to an expensive one (u06 A-109, OD-65).

``SemanticJudgeEvaluator(judge, escalate_to=...)`` asks ``escalate_to`` only when ``judge``
returns ``inconclusive``: a disagreement, a low confidence, an outage, free text, a tripwire.
"""

from __future__ import annotations

from ildottore.evaluators.semantic_judge import SemanticJudgeEvaluator
from ildottore.shared.enums import InconclusiveReason, VerdictStatus
from tests.evaluators.test_semantic_judge import ErrorJudge, ScriptedJudge, _ctx, _jv


async def test_a_settled_attempt_never_reaches_the_second_judge() -> None:
    cheap = ScriptedJudge([_jv("exploited", 0.9)])
    expensive = ScriptedJudge([_jv("secure", 0.9)])
    v = await SemanticJudgeEvaluator(cheap, escalate_to=expensive).evaluate(_ctx())
    assert v.status is VerdictStatus.FAIL
    assert len(cheap.requests) == 2
    assert expensive.requests == []
    assert "escalated" not in v.reasoning


async def test_a_disagreement_is_handed_to_the_second_judge() -> None:
    cheap = ScriptedJudge([_jv("exploited", 0.9), _jv("secure", 0.9)])
    expensive = ScriptedJudge([_jv("secure", 0.95)])
    v = await SemanticJudgeEvaluator(cheap, escalate_to=expensive).evaluate(_ctx())
    assert v.status is VerdictStatus.PASS
    assert v.confidence == 0.95
    assert len(expensive.requests) == 2
    assert v.reasoning.startswith(
        "escalated to the second judge (the first could not settle the attempt: "
        "self-consistency disagreement"
    )


async def test_a_low_confidence_and_an_outage_are_handed_on_too() -> None:
    expensive = ScriptedJudge([_jv("exploited", 0.9)])
    low = await SemanticJudgeEvaluator(
        ScriptedJudge([_jv("exploited", 0.4)]), escalate_to=expensive
    ).evaluate(_ctx())
    assert low.status is VerdictStatus.FAIL
    assert "judge confidence 0.40 < threshold" in low.reasoning

    down = await SemanticJudgeEvaluator(ErrorJudge(), escalate_to=expensive).evaluate(_ctx())
    assert down.status is VerdictStatus.FAIL
    assert "judge adapter error: rate limited" in down.reasoning


async def test_the_second_judges_inconclusive_stands_with_its_reason() -> None:
    v = await SemanticJudgeEvaluator(
        ScriptedJudge(["not json"]), escalate_to=ErrorJudge()
    ).evaluate(_ctx())
    assert v.status is VerdictStatus.INCONCLUSIVE
    assert v.inconclusive_reason is InconclusiveReason.CAPABILITY_UNAVAILABLE
    assert "not valid structured JSON" in v.reasoning
    assert v.reasoning.endswith("judge adapter error: rate limited")


async def test_without_a_second_judge_nothing_changes() -> None:
    v = await SemanticJudgeEvaluator(
        ScriptedJudge([_jv("exploited", 0.9), _jv("secure", 0.9)])
    ).evaluate(_ctx())
    assert v.status is VerdictStatus.INCONCLUSIVE
    assert "escalated" not in v.reasoning
