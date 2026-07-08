"""Tests for u00 shared models, enums, protocols and schema export."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import yaml
from pydantic import ValidationError

from ildottore import __version__
from ildottore.shared import (
    AttackSpec,
    Capabilities,
    EvaluatorType,
    InconclusiveReason,
    ModelFingerprint,
    ModelResponse,
    PlanBudgets,
    PlanSelection,
    PlanSkip,
    RiskScore,
    ScanBand,
    TestPlan,
    TokenLogprob,
    Verdict,
    VerdictStatus,
    export_schemas,
)
from ildottore.shared.models import FingerprintGuess

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CANONICAL_SPEC = REPO_ROOT / "specs" / "attacks" / "PI-INDIRECT-RAG-001.yaml"
SCHEMA_PATH = REPO_ROOT / "schemas" / "attack-spec.schema.json"


def test_version() -> None:
    assert __version__ == "0.0.1"


# --- AttackSpec: load the canonical YAML and validate ------------------------------


def test_canonical_spec_parses() -> None:
    data = yaml.safe_load(CANONICAL_SPEC.read_text())
    spec = AttackSpec.model_validate(data)
    assert spec.id == "PI-INDIRECT-RAG-001"
    assert spec.category.value == "prompt_injection"
    assert spec.target_type.value == "rag"
    assert spec.scoring.impact == 3
    assert spec.scoring.exploitability == 4
    assert spec.fixtures.vulnerable.expect_verdict is VerdictStatus.FAIL
    assert spec.fixtures.hardened.expect_verdict is VerdictStatus.PASS
    # evaluator types round-tripped into the enum
    types = {e.type for e in spec.evaluators}
    assert EvaluatorType.SECRET_LEAKAGE in types
    assert EvaluatorType.SEMANTIC_JUDGE in types


def test_canonical_spec_round_trips_against_json_schema() -> None:
    """Primary §7 criterion, run **verbatim**: the model dump re-validates vs the schema.

    ``AttackSpec.model_validate(y).model_dump(mode="json")`` must satisfy
    ``schemas/attack-spec.schema.json`` (jsonschema) — no ``exclude_none`` at the call site.
    """
    data = yaml.safe_load(CANONICAL_SPEC.read_text())
    schema = json.loads(SCHEMA_PATH.read_text())
    dumped = AttackSpec.model_validate(data).model_dump(mode="json")
    jsonschema.Draft202012Validator(schema).validate(dumped)
    # byte-stable on re-dump
    assert AttackSpec.model_validate(dumped).model_dump(mode="json") == dumped


def test_spec_round_trip_json_stable() -> None:
    data = yaml.safe_load(CANONICAL_SPEC.read_text())
    spec = AttackSpec.model_validate(data)
    dumped = spec.model_dump(mode="json")
    respec = AttackSpec.model_validate(dumped)
    assert respec.model_dump(mode="json") == dumped


def test_extra_forbid_rejects_unknown_field() -> None:
    data = yaml.safe_load(CANONICAL_SPEC.read_text())
    data["totally_unknown_field"] = "boom"
    with pytest.raises(ValidationError):
        AttackSpec.model_validate(data)


def test_bad_id_pattern_rejected() -> None:
    data = yaml.safe_load(CANONICAL_SPEC.read_text())
    data["id"] = "lowercase-bad"
    with pytest.raises(ValidationError):
        AttackSpec.model_validate(data)


# --- enum coverage ------------------------------------------------------------------


def test_verdict_status_coverage() -> None:
    assert {s.value for s in VerdictStatus} == {"pass", "fail", "inconclusive"}


def test_evaluator_type_full_coverage() -> None:
    expected = {
        "regex_absence",
        "regex_presence",
        "exact_match",
        "refusal",
        "secret_leakage",
        "tool_call",
        "semantic_judge",
        "pii_detector",
        "secret_shape",
        "verbatim_overlap",
        "logprob_membership",
        "authz_leak",
        "kill_chain_progression",
    }
    assert {e.value for e in EvaluatorType} == expected
    assert len(expected) == 13


def test_inconclusive_reason_coverage() -> None:
    assert {r.value for r in InconclusiveReason} == {
        "capability_unavailable",
        "blocked_by_policy",
        "judge_compromised",
    }


# --- Verdict + inconclusive_reason semantics ----------------------------------------


def test_verdict_inconclusive_reason() -> None:
    v = Verdict(
        status=VerdictStatus.INCONCLUSIVE,
        confidence=0.0,
        reasoning="capability missing",
        evaluator_type="logprob_membership",
        inconclusive_reason=InconclusiveReason.CAPABILITY_UNAVAILABLE,
    )
    assert v.inconclusive_reason is InconclusiveReason.CAPABILITY_UNAVAILABLE


def test_verdict_reason_only_when_inconclusive() -> None:
    with pytest.raises(ValidationError):
        Verdict(
            status=VerdictStatus.PASS,
            confidence=1.0,
            reasoning="secure",
            evaluator_type="refusal",
            inconclusive_reason=InconclusiveReason.BLOCKED_BY_POLICY,
        )


def test_verdict_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        Verdict(
            status=VerdictStatus.FAIL,
            confidence=1.2,
            reasoning="x",
            evaluator_type="regex_absence",
        )


def test_verdict_inconclusive_without_reason_is_allowed() -> None:
    """An aggregate ``inconclusive`` verdict may omit a reason (permissive branch)."""
    v = Verdict(
        status=VerdictStatus.INCONCLUSIVE,
        confidence=0.0,
        reasoning="aggregate of mixed evaluators",
        evaluator_type="aggregate",
    )
    assert v.inconclusive_reason is None


# --- ADR-0005: logprobs -------------------------------------------------------------


def test_model_response_logprobs_none_dumps_null() -> None:
    resp = ModelResponse(text="hi")
    assert resp.logprobs is None
    assert resp.model_dump(mode="json")["logprobs"] is None


def test_token_logprob_top_shape() -> None:
    tl = TokenLogprob(token="the", logprob=-0.1, top=[("the", -0.1), ("a", -2.3)])
    resp = ModelResponse(text="the cat", logprobs=[tl])
    assert resp.logprobs is not None
    assert resp.logprobs[0].top == [("the", -0.1), ("a", -2.3)]


# --- RiskScore ----------------------------------------------------------------------


def test_risk_score_valid_and_out_of_range() -> None:
    rs = RiskScore(
        impact=3,
        exploitability=4,
        reproducibility=0.8,
        risk=9.6,
        band=ScanBand.HIGH,
        confidence=0.9,
    )
    assert rs.band is ScanBand.HIGH
    with pytest.raises(ValidationError):
        RiskScore(
            impact=5,  # out of 1..4
            exploitability=4,
            reproducibility=0.8,
            risk=9.6,
            band=ScanBand.HIGH,
            confidence=0.9,
        )


# --- TestPlan (ADR-0006 canonical shape) --------------------------------------------


def test_build_test_plan() -> None:
    plan = TestPlan(
        plan_ref="plan_2026_07_07_001",
        target_id="unknown-endpoint-1",
        adaptive=True,
        fingerprint_ref="fp-1",
        selected=[
            PlanSelection(
                spec_id="PI-INDIRECT-RAG-001",
                reason="target has rag capability",
                mutators=["identity", "html_comment_carrier"],
                baseline_resistance=0.7,
            )
        ],
        skipped=[PlanSkip(spec_id="TOOL-ABUSE-001", reason="no tools capability")],
        budgets=PlanBudgets(max_tokens=10000, max_requests=50, max_wall_s=600, max_attempts=25),
    )
    assert plan.adaptive is True
    assert plan.selected[0].mutators == ["identity", "html_comment_carrier"]
    assert plan.skipped[0].reason == "no tools capability"
    assert plan.budgets.max_attempts == 25
    # round-trips through JSON
    assert TestPlan.model_validate(plan.model_dump(mode="json")) == plan


# --- ModelFingerprint (docs/10 §2) --------------------------------------------------


def test_build_model_fingerprint() -> None:
    fp = ModelFingerprint(
        target_id="unknown-endpoint-1",
        family=FingerprintGuess(guess="anthropic-claude", confidence=0.93),
        version=FingerprintGuess(guess="claude-opus-4.x", confidence=0.71),
        capability_guess={"tools": True, "json_mode": True, "max_context_tokens": 200000},
        guardrails={"input_filter": True, "refusal_style": "polite-explain"},
        spoofing_flags=["self_report_conflicts_with_statistical"],
    )
    assert fp.family.guess == "anthropic-claude"
    # capability_guess is a free dict, distinct from the Capabilities enum
    assert fp.capability_guess["max_context_tokens"] == 200000
    assert isinstance(Capabilities(), Capabilities)


# --- schema export (Pydantic-first, ADR-0006) ---------------------------------------


def test_export_schemas_has_test_plan() -> None:
    schemas = export_schemas()
    assert set(schemas) >= {"suite", "pack", "test-plan"}
    tp = schemas["test-plan"]
    assert tp["type"] == "object"
    props = tp["properties"]
    assert isinstance(props, dict)
    assert "plan_ref" in props
    assert "selected" in props


def test_export_schemas_returns_json_schema_dicts() -> None:
    schemas = export_schemas()
    for name, js in schemas.items():
        assert isinstance(js, dict), name
        assert js.get("type") == "object", name
        assert "properties" in js, name


# --- protocol conformance -----------------------------------------------------------


def test_protocol_runtime_checkable() -> None:
    from ildottore.shared import Mutator

    class DummyMutator:
        name = "identity"

        def mutate(self, text: str, seed: str) -> str:
            return text

    assert isinstance(DummyMutator(), Mutator)
