"""Shared fixtures + builders for the u01 (policy) test suite."""

from __future__ import annotations

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
    EvaluatorConfig,
    FixtureCase,
    Fixtures,
    MitreAtlas,
    Scoring,
)


def make_spec(
    spec_id: str = "PI-BASIC-001",
    *,
    category: Category = Category.PROMPT_INJECTION,
    tags: list[str] | None = None,
    test_only: bool | None = None,
    requires_policy: list[str] | None = None,
) -> AttackSpec:
    """Build a minimal but schema-valid :class:`AttackSpec` for policy tests."""

    return AttackSpec(
        id=spec_id,
        spec_version="1.0",
        name=f"spec {spec_id}",
        category=category,
        owasp="LLM01",
        mitre_atlas=MitreAtlas(tactic="AML.TA0000"),
        nist_ai_rmf="MEASURE-2.7",
        severity=Severity.MEDIUM,
        target_type=TargetType.MODEL,
        requires=[],
        description="policy-test spec",
        attack=Attack(user_prompt="hello"),
        expected_secure_behavior=["refuses"],
        evaluators=[EvaluatorConfig(type=EvaluatorType.REFUSAL)],
        scoring=Scoring(impact=2, exploitability=2, confidence_threshold=0.75),
        test_only=test_only,
        requires_policy=requires_policy or [],
        tags=tags,
        fixtures=Fixtures(
            vulnerable=FixtureCase(response="leaked", expect_verdict=VerdictStatus.FAIL),
            hardened=FixtureCase(response="refused", expect_verdict=VerdictStatus.PASS),
        ),
    )


@pytest.fixture
def spec_factory():
    return make_spec


SCOPE_SINGLE = """\
version: "1.0"
targets:
  - id: acme-bot
    base_url: https://api.acme.test/v1
    endpoints:
      - host: api.acme.test
        path_prefixes:
          - /v1
    identities:
      - name: primary
        auth_ref: vault://acme/primary
"""

SCOPE_MULTI = """\
version: "1.0"
targets:
  - id: acme-bot
    base_url: https://api.acme.test/v1
    endpoints:
      - host: api.acme.test
        path_prefixes:
          - /v1
    identities:
      - name: tenant_a
        auth_ref: vault://acme/a
      - name: tenant_b
        auth_ref: vault://acme/b
"""


@pytest.fixture
def scope_single_text() -> str:
    return SCOPE_SINGLE


@pytest.fixture
def scope_multi_text() -> str:
    return SCOPE_MULTI
