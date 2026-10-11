"""The plan carries no ``baseline_resistance`` (OD-17, ADR-0008 option B, u08 and u00).

Decided 2026-10-11 under the owner's delegation (best practice, revisable): the field was dead
at both ends. No fingerprint layer writes the ``guardrails["baseline_resistance"]`` map the
planner read it from, and nothing in ``src/`` read the ``PlanSelection.baseline_resistance`` the
planner wrote, so every plan said ``null`` in a shape that looked like a working feature. It is
removed from the wire shape, the planner and the generated test-plan schema; it can come back
with the fingerprint layer that measures it, after a live run (``docs/16``).
"""

from __future__ import annotations

import pydantic
import pytest

from ildottore.core.planner import build_plan
from ildottore.shared.enums import Category
from ildottore.shared.models import (
    Capabilities,
    FingerprintGuess,
    ModelFingerprint,
    PlanSelection,
    TestPlan,
)
from ildottore.shared.schema_export import export_schemas

from .conftest import make_spec


def test_a_plan_selection_has_no_baseline_resistance() -> None:
    assert "baseline_resistance" not in PlanSelection.model_fields


def test_the_generated_test_plan_schema_has_no_baseline_resistance() -> None:
    schema = export_schemas()["test-plan"]
    selection = schema["$defs"]["PlanSelection"]
    assert "baseline_resistance" not in selection["properties"]
    assert selection["additionalProperties"] is False


def test_a_fingerprint_holding_the_old_key_changes_no_plan() -> None:
    """The planner reads no key of ``guardrails``: a map someone writes there orders nothing."""

    spec = make_spec(category=Category.JAILBREAK, mutations=["rot13", "base64_wrap"])
    with_key = ModelFingerprint(
        target_id="t1",
        family=FingerprintGuess(guess="anthropic-claude", confidence=0.9),
        guardrails={"baseline_resistance": {"jailbreak": 0.85}},
    )
    without = with_key.model_copy(update={"guardrails": {}})
    plans = [
        build_plan([spec], fp, Capabilities(), target_id="t1", plan_ref="p1", adaptive=True)
        for fp in (with_key, without)
    ]
    assert plans[0] == plans[1]
    assert "baseline_resistance" not in plans[0].model_dump(mode="json")["selected"][0]


def test_a_plan_written_with_the_old_field_is_refused() -> None:
    """Stated, not hidden: the shape forbids unknown keys, so a plan JSON from before is refused.

    No command reads a plan from disk (the plan lives in one invocation's result; the run store
    keeps the integrity context, not the plan), so nothing the tool does breaks; a program that
    stored ``dottore schema export --name test-plan`` output or a dumped plan has to drop the key.
    """

    old = {
        "plan_ref": "p1",
        "target_id": "t1",
        "adaptive": True,
        "selected": [
            {
                "spec_id": "JB-1",
                "reason": "r",
                "mutators": ["identity"],
                "baseline_resistance": None,
            }
        ],
    }
    with pytest.raises(pydantic.ValidationError, match="baseline_resistance"):
        TestPlan.model_validate(old)
