"""Planner tests: capability filter, adaptive tailoring, golden plan (contract §7)."""

from __future__ import annotations

import json
from pathlib import Path

from ildottore.core.planner import DEFAULT_PLAN_BUDGETS, build_plan
from ildottore.shared.enums import Category, RequiresCapability
from ildottore.shared.models import (
    Capabilities,
    FingerprintGuess,
    ModelFingerprint,
    PlanBudgets,
    TestPlan,
)

from .conftest import make_spec

_GOLDEN = Path(__file__).parent.parent / "fixtures" / "plans" / "adaptive-plan.json"


def test_capability_filter_skips_with_explicit_reason() -> None:
    tools_spec = make_spec(
        "AG-TOOL-001", category=Category.AGENT_TOOL_ABUSE, requires=[RequiresCapability.TOOLS]
    )
    plain_spec = make_spec("JB-REFUSAL-001")
    caps = Capabilities(tools=False)  # target has no tools

    plan = build_plan(
        [tools_spec, plain_spec],
        None,
        caps,
        target_id="t1",
        plan_ref="p1",
    )
    assert [s.spec_id for s in plan.selected] == ["JB-REFUSAL-001"]
    assert len(plan.skipped) == 1
    assert plan.skipped[0].spec_id == "AG-TOOL-001"
    assert "capability_unavailable" in plan.skipped[0].reason
    assert "tools" in plan.skipped[0].reason


def test_system_prompt_requirement_is_not_capability_gated() -> None:
    # system_prompt is a setup prerequisite, not a target capability flag.
    spec = make_spec("JB-REFUSAL-001", requires=[RequiresCapability.SYSTEM_PROMPT])
    plan = build_plan([spec], None, Capabilities(), target_id="t1", plan_ref="p1")
    assert [s.spec_id for s in plan.selected] == ["JB-REFUSAL-001"]
    assert plan.skipped == []


def test_identity_mutator_always_present() -> None:
    spec = make_spec(mutations=["rot13", "base64_wrap"])
    plan = build_plan([spec], None, Capabilities(), target_id="t1", plan_ref="p1")
    assert plan.selected[0].mutators[0] == "identity"
    assert set(plan.selected[0].mutators) == {"identity", "rot13", "base64_wrap"}


def test_no_adaptive_pass_through_ignores_fingerprint() -> None:
    spec = make_spec(mutations=["rot13", "base64_wrap"])
    fp = _fingerprint_with_effective(["base64_wrap"])
    plan = build_plan([spec], fp, Capabilities(), target_id="t1", plan_ref="p1", adaptive=False)
    # Non-adaptive: declared order preserved, no fingerprint_ref, no baseline.
    assert plan.adaptive is False
    assert plan.fingerprint_ref is None
    assert plan.selected[0].baseline_resistance is None
    assert plan.selected[0].mutators == ["identity", "rot13", "base64_wrap"]


def test_adaptive_orders_family_effective_mutators() -> None:
    spec = make_spec(mutations=["rot13", "base64_wrap", "translate"])
    fp = _fingerprint_with_effective(["base64_wrap", "translate"])
    plan = build_plan([spec], fp, Capabilities(), target_id="t1", plan_ref="p1", adaptive=True)
    # identity first, then hint order (base64_wrap, translate), then the rest (rot13).
    assert plan.selected[0].mutators == ["identity", "base64_wrap", "translate", "rot13"]
    assert plan.fingerprint_ref == "plan_ref_x"


def test_adaptive_baseline_resistance_from_guardrails() -> None:
    spec = make_spec(category=Category.JAILBREAK)
    fp = ModelFingerprint(
        target_id="t1",
        family=FingerprintGuess(guess="anthropic-claude", confidence=0.9),
        guardrails={"baseline_resistance": {"jailbreak": 0.85}},
    )
    plan = build_plan([spec], fp, Capabilities(), target_id="t1", plan_ref="p1", adaptive=True)
    assert plan.selected[0].baseline_resistance == 0.85


def test_adaptive_without_effective_hint_preserves_order() -> None:
    spec = make_spec(mutations=["rot13", "base64_wrap"])
    # Fingerprint with NO effective_mutators hint → declared order preserved.
    fp = ModelFingerprint(
        target_id="t1",
        family=FingerprintGuess(guess="x", confidence=0.5),
    )
    plan = build_plan([spec], fp, Capabilities(), target_id="t1", plan_ref="p1", adaptive=True)
    assert plan.selected[0].mutators == ["identity", "rot13", "base64_wrap"]


def test_adaptive_baseline_absent_when_guardrails_not_a_map() -> None:
    spec = make_spec(category=Category.JAILBREAK)
    fp = ModelFingerprint(
        target_id="t1",
        family=FingerprintGuess(guess="x", confidence=0.5),
        guardrails={"baseline_resistance": "not-a-dict"},
    )
    plan = build_plan([spec], fp, Capabilities(), target_id="t1", plan_ref="p1", adaptive=True)
    assert plan.selected[0].baseline_resistance is None


def test_adaptive_baseline_absent_when_value_not_numeric() -> None:
    spec = make_spec(category=Category.JAILBREAK)
    fp = ModelFingerprint(
        target_id="t1",
        family=FingerprintGuess(guess="x", confidence=0.5),
        guardrails={"baseline_resistance": {"jailbreak": "high"}},  # non-numeric
    )
    plan = build_plan([spec], fp, Capabilities(), target_id="t1", plan_ref="p1", adaptive=True)
    assert plan.selected[0].baseline_resistance is None


def test_default_budgets_applied_when_unset() -> None:
    spec = make_spec()
    plan = build_plan([spec], None, Capabilities(), target_id="t1", plan_ref="p1")
    assert plan.budgets == DEFAULT_PLAN_BUDGETS


def test_explicit_budgets_override_default() -> None:
    spec = make_spec()
    budgets = PlanBudgets(max_tokens=10, max_requests=5, max_wall_s=1, max_attempts=3)
    plan = build_plan([spec], None, Capabilities(), target_id="t1", plan_ref="p1", budgets=budgets)
    assert plan.budgets == budgets


def test_plan_is_byte_stable_across_builds() -> None:
    spec = make_spec(mutations=["rot13", "base64_wrap"])
    a = build_plan([spec], None, Capabilities(), target_id="t1", plan_ref="p1")
    b = build_plan([spec], None, Capabilities(), target_id="t1", plan_ref="p1")
    assert a.model_dump_json() == b.model_dump_json()


def test_golden_adaptive_plan(regen_golden: bool) -> None:
    """The adaptive plan matches the checked-in golden fixture byte-for-byte."""

    specs = [
        make_spec("JB-REFUSAL-001", mutations=["rot13", "base64_wrap"]),
        make_spec(
            "AG-TOOL-001", category=Category.AGENT_TOOL_ABUSE, requires=[RequiresCapability.TOOLS]
        ),
    ]
    fp = _fingerprint_with_effective(["base64_wrap"])
    plan = build_plan(
        specs,
        fp,
        Capabilities(tools=False),
        target_id="t1",
        plan_ref="plan::golden",
        adaptive=True,
        budgets=PlanBudgets(max_tokens=1000, max_requests=100, max_wall_s=60, max_attempts=200),
    )
    dumped = plan.model_dump(mode="json")
    if regen_golden:
        _GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        _GOLDEN.write_text(json.dumps(dumped, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    expected = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    assert dumped == expected
    # Round-trips through the model unchanged.
    assert TestPlan.model_validate(expected).model_dump(mode="json") == expected


def _fingerprint_with_effective(effective: list[str]) -> ModelFingerprint:
    return ModelFingerprint(
        target_id="t1",
        family=FingerprintGuess(guess="anthropic-claude", confidence=0.9),
        capability_guess={"effective_mutators": effective},
        recommended_plan_ref="plan_ref_x",
    )
