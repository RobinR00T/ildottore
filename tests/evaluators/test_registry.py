"""Tests for the evaluator registry (built-ins, protocol validation, judge injection)."""

from __future__ import annotations

import pytest

from ildottore.evaluators.registry import (
    EvaluatorProtocolError,
    EvaluatorRegistry,
    build_default_registry,
)
from ildottore.shared.enums import EvaluatorType
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse


class _Judge:
    id = "judge"

    def capabilities(self) -> Capabilities:
        return Capabilities()

    async def send(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(text="{}")


def test_default_registry_registers_every_evaluator_type() -> None:
    """EQUALITY against the enum, not ``issubset`` against a hand-kept list.

    The previous form listed 11 types and asserted only ``issubset``, so a new
    ``EvaluatorType`` could land in the enum, the JSON schema, the lint stub table and a
    shipped spec while its class was never added to ``_BUILTINS``, and the whole suite stayed
    green. The failure mode is silent: the runner turns an unregistered type into
    ``inconclusive`` ("evaluator type ... not registered") rather than erroring, so a spec's
    primary arbiter can be dead in production with nothing to show for it.

    ``semantic_judge`` is the one deliberate absentee: it needs an injected judge adapter and
    is registered only when one is supplied (asserted separately below).
    """

    reg = build_default_registry(discover=False)
    expected = {e.value for e in EvaluatorType} - {EvaluatorType.SEMANTIC_JUDGE.value}
    assert set(reg.types()) == expected


def test_semantic_judge_absent_without_injection() -> None:
    reg = build_default_registry(discover=False)
    assert not reg.has(EvaluatorType.SEMANTIC_JUDGE.value)


def test_semantic_judge_present_when_injected() -> None:
    reg = build_default_registry(judge=_Judge(), discover=False)
    assert reg.has(EvaluatorType.SEMANTIC_JUDGE.value)
    assert reg.get(EvaluatorType.SEMANTIC_JUDGE.value).type == "semantic_judge"


def test_get_unknown_type_raises_keyerror() -> None:
    reg = build_default_registry(discover=False)
    with pytest.raises(KeyError):
        reg.get("does_not_exist")


def test_duplicate_registration_rejected() -> None:
    reg = EvaluatorRegistry()
    from ildottore.evaluators.exact import ExactMatchEvaluator

    reg.register(ExactMatchEvaluator())
    with pytest.raises(EvaluatorProtocolError, match="duplicate evaluator type"):
        reg.register(ExactMatchEvaluator())


def test_replace_allows_reregistration() -> None:
    reg = EvaluatorRegistry()
    from ildottore.evaluators.exact import ExactMatchEvaluator

    reg.register(ExactMatchEvaluator())
    reg.register(ExactMatchEvaluator(), replace=True)  # no raise
    assert reg.has("exact_match")


def test_bad_plugin_missing_type_rejected() -> None:
    reg = EvaluatorRegistry()

    class NoType:
        async def evaluate(self, ctx: object) -> object:  # pragma: no cover
            return None

    with pytest.raises(EvaluatorProtocolError, match="missing a non-empty str 'type'"):
        reg.register(NoType())  # type: ignore[arg-type]


def test_bad_plugin_no_evaluate_rejected() -> None:
    reg = EvaluatorRegistry()

    class NoEvaluate:
        type = "custom"

    with pytest.raises(EvaluatorProtocolError, match="no callable 'evaluate'"):
        reg.register(NoEvaluate())  # type: ignore[arg-type]


def test_types_are_sorted() -> None:
    reg = build_default_registry(discover=False)
    assert reg.types() == sorted(reg.types())


def test_discover_plugins_no_plugins_returns_empty() -> None:
    reg = EvaluatorRegistry()
    # No third-party dottore.evaluators entry points are installed in this env.
    assert reg.discover_plugins() == []
