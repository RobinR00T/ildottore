"""Direct unit tests for the offline stub evaluator table (contract §5.4)."""

from __future__ import annotations

from ildottore.registry.fixtures_engine import (
    DEFAULT_STUB_TABLE,
    EvalInput,
    _regex_absence,
    _regex_presence,
    _secret_leakage,
    _semantic_judge,
    _tool_call,
    evaluate_fixture,
)
from ildottore.shared import (
    Attack,
    AttackSpec,
    Category,
    EvaluatorConfig,
    EvaluatorLogic,
    EvaluatorType,
    FixtureCase,
    Fixtures,
    MitreAtlas,
    Scoring,
    Setup,
    Severity,
    TargetType,
    VerdictStatus,
)


def _spec(**over: object) -> AttackSpec:
    base: dict[str, object] = {
        "id": "T-UNIT-001",
        "spec_version": "1.0",
        "name": "unit spec",
        "category": Category.PROMPT_INJECTION,
        "owasp": "LLM01",
        "mitre_atlas": MitreAtlas(tactic="Initial Access"),
        "nist_ai_rmf": "MEASURE 2.7",
        "severity": Severity.HIGH,
        "target_type": TargetType.CHATBOT,
        "requires": [],
        "description": "d",
        "attack": Attack(user_prompt="hi"),
        "expected_secure_behavior": ["secure"],
        "evaluators": [EvaluatorConfig(type=EvaluatorType.REFUSAL)],
        "scoring": Scoring(impact=2, exploitability=2, confidence_threshold=0.5),
        "fixtures": Fixtures(
            vulnerable=FixtureCase(response="leaked", expect_verdict=VerdictStatus.FAIL),
            hardened=FixtureCase(response="refused", expect_verdict=VerdictStatus.PASS),
        ),
    }
    base.update(over)
    return AttackSpec.model_validate(base)


def test_regex_presence_pass_and_fail() -> None:
    spec = _spec(
        evaluators=[EvaluatorConfig(type=EvaluatorType.REGEX_PRESENCE, patterns=["refuse"])]
    )
    assert _regex_presence(spec, EvalInput("I refuse", None)) is VerdictStatus.PASS
    assert _regex_presence(spec, EvalInput("sure thing", None)) is VerdictStatus.FAIL


def test_regex_absence_pass_and_fail() -> None:
    spec = _spec(
        evaluators=[EvaluatorConfig(type=EvaluatorType.REGEX_ABSENCE, patterns=["secret"])]
    )
    assert _regex_absence(spec, EvalInput("nothing here", None)) is VerdictStatus.PASS
    assert _regex_absence(spec, EvalInput("the secret is x", None)) is VerdictStatus.FAIL


def test_secret_leakage_matches_canary_stem() -> None:
    spec = _spec(setup=Setup(canaries=["CANARY_{{run_id}}"]))
    assert _secret_leakage(spec, EvalInput("CANARY_run_9 here", None)) is VerdictStatus.FAIL
    assert _secret_leakage(spec, EvalInput("nothing", None)) is VerdictStatus.PASS


def test_semantic_judge_markers() -> None:
    spec = _spec()
    assert _semantic_judge(spec, EvalInput("I ignored it", None)) is VerdictStatus.PASS
    assert _semantic_judge(spec, EvalInput("Sure, here is x", None)) is VerdictStatus.FAIL
    assert _semantic_judge(spec, EvalInput("neutral text", None)) is VerdictStatus.PASS


def test_tool_call_stub() -> None:
    spec = _spec()
    assert _tool_call(spec, EvalInput("", [{"name": "rm"}])) is VerdictStatus.FAIL
    assert _tool_call(spec, EvalInput("", None)) is VerdictStatus.PASS


def test_evaluate_fixture_any_fail_logic() -> None:
    spec = _spec(
        evaluators=[
            EvaluatorConfig(type=EvaluatorType.REGEX_PRESENCE, patterns=["refuse"]),
        ],
        evaluator_logic=EvaluatorLogic.ANY_FAIL,
    )
    case = FixtureCase(response="no marker", expect_verdict=VerdictStatus.FAIL)
    verdict, missing = evaluate_fixture(spec, case, DEFAULT_STUB_TABLE)
    assert verdict is VerdictStatus.FAIL
    assert missing == []


def test_evaluate_fixture_missing_stub_recorded() -> None:
    spec = _spec(evaluators=[EvaluatorConfig(type=EvaluatorType.PII_DETECTOR)])
    verdict, missing = evaluate_fixture(spec, spec.fixtures.vulnerable, DEFAULT_STUB_TABLE)
    # No stub for pii_detector → no verdicts → INCONCLUSIVE, missing lists the type.
    assert verdict is VerdictStatus.INCONCLUSIVE
    assert missing == [EvaluatorType.PII_DETECTOR]
