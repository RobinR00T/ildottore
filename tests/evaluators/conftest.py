"""Shared fixtures + builders for the u06 evaluator tests.

Provides light factory helpers so each test states only what it exercises (the response text,
tool calls, canaries, config) without re-declaring a full :class:`AttackSpec` every time.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from ildottore.shared.enums import (
    Category,
    EvaluatorType,
    Severity,
    TargetType,
    VerdictStatus,
)
from ildottore.shared.models import (
    Attack,
    AttackSpec,
    EvalContext,
    EvaluatorConfig,
    FixtureCase,
    Fixtures,
    JsonDict,
    MitreAtlas,
    ModelRequest,
    ModelResponse,
    Scoring,
    Setup,
    TokenLogprob,
)


def make_spec(
    *,
    evaluator_type: EvaluatorType = EvaluatorType.REGEX_ABSENCE,
    expected_secure: list[str] | None = None,
    confidence_threshold: float = 0.75,
    canaries: list[str] | None = None,
    setup_tools: list[JsonDict] | None = None,
) -> AttackSpec:
    """Build a minimal schema-valid :class:`AttackSpec` for an evaluation context."""
    setup = None
    if canaries or setup_tools:
        setup = Setup(canaries=canaries, tools=setup_tools)
    return AttackSpec(
        id="TEST-EVAL-001",
        spec_version="1.0",
        name="test evaluator spec",
        category=Category.PROMPT_INJECTION,
        owasp="LLM01",
        mitre_atlas=MitreAtlas(tactic="AML.TA0000"),
        nist_ai_rmf="MEASURE-2.7",
        severity=Severity.HIGH,
        target_type=TargetType.MODEL,
        requires=[],
        description="a test spec",
        setup=setup,
        attack=Attack(user_prompt="do the bad thing"),
        expected_secure_behavior=expected_secure or ["the model refuses"],
        evaluators=[EvaluatorConfig(type=evaluator_type)],
        scoring=Scoring(impact=3, exploitability=3, confidence_threshold=confidence_threshold),
        fixtures=Fixtures(
            vulnerable=FixtureCase(response="leaked", expect_verdict=VerdictStatus.FAIL),
            hardened=FixtureCase(response="refused", expect_verdict=VerdictStatus.PASS),
        ),
    )


def make_ctx(
    *,
    response_text: str = "",
    tool_calls: list[JsonDict] | None = None,
    logprobs: list[TokenLogprob] | None = None,
    config: EvaluatorConfig | None = None,
    canaries: list[str] | None = None,
    identities: dict[str, ModelResponse] | None = None,
    canary_owners: dict[str, str] | None = None,
    expected_secure: list[str] | None = None,
    confidence_threshold: float = 0.75,
    setup_tools: list[JsonDict] | None = None,
) -> EvalContext:
    """Build an :class:`EvalContext` wrapping a single canned response."""
    cfg = config or EvaluatorConfig(type=EvaluatorType.REGEX_ABSENCE)
    spec = make_spec(
        evaluator_type=cfg.type,
        expected_secure=expected_secure,
        confidence_threshold=confidence_threshold,
        canaries=canaries,
        setup_tools=setup_tools,
    )
    return EvalContext(
        spec=spec,
        request=ModelRequest(prompt="do the bad thing"),
        response=ModelResponse(text=response_text, tool_calls=tool_calls or [], logprobs=logprobs),
        config=cfg,
        canaries=canaries or [],
        identities=identities,
        canary_owners=canary_owners or {},
    )


@pytest.fixture
def ctx_factory() -> Callable[..., EvalContext]:
    """Expose :func:`make_ctx` as a fixture for tests that prefer injection."""
    return make_ctx
