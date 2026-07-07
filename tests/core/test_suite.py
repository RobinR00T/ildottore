"""Suite-resolution tests (contract §5.2)."""

from __future__ import annotations

import pytest

from ildottore.core.suite import SuiteResolutionError, resolve_suite
from ildottore.shared.models import AttackSpec

from .conftest import make_spec


class FakeResolver:
    """A minimal :class:`~ildottore.core.suite.SuiteResolver` for tests."""

    def __init__(self, suites: dict[str, list[AttackSpec]]) -> None:
        self._suites = suites

    def has_suite(self, suite_id: str) -> bool:
        return suite_id in self._suites

    def resolve(self, suite_id: str) -> list[AttackSpec]:
        return self._suites[suite_id]


def test_resolve_returns_ordered_specs() -> None:
    a = make_spec("JB-REFUSAL-001")
    b = make_spec("JB-REFUSAL-002")
    resolver = FakeResolver({"owasp:llm": [a, b]})
    assert [s.id for s in resolve_suite(resolver, "owasp:llm")] == [
        "JB-REFUSAL-001",
        "JB-REFUSAL-002",
    ]


def test_resolve_normalizes_whitespace() -> None:
    resolver = FakeResolver({"owasp:llm": [make_spec()]})
    assert resolve_suite(resolver, "  owasp:llm  ")


def test_unknown_suite_raises() -> None:
    resolver = FakeResolver({})
    with pytest.raises(SuiteResolutionError, match="not registered"):
        resolve_suite(resolver, "nope")


def test_empty_suite_raises() -> None:
    resolver = FakeResolver({"empty": []})
    with pytest.raises(SuiteResolutionError, match="zero specs"):
        resolve_suite(resolver, "empty")
