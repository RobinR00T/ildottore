"""Execution engine (u08) — the orchestrator that wires the middle tier into a run.

Public surface (contract §1):

* :func:`~ildottore.core.planner.build_plan` — the sole owner of the plan-builder
  (ADR-0006); turns specs + capabilities (+ optional fingerprint) into the canonical
  :class:`~ildottore.shared.models.TestPlan`.
* :class:`~ildottore.core.budgets.BudgetLedger` / :class:`~ildottore.core.budgets.BudgetExhausted`
  — hard token/request/wall-clock/attempt caps (the scanner cannot self-DoS).
* :func:`~ildottore.core.suite.resolve_suite` — suite id → ordered spec set (via the
  injected registry).
* :func:`~ildottore.core.execute.execute_attempt` — one send with retry/backoff/
  timeout + env-vs-product classification.
* :func:`~ildottore.core.reproduce.reproduce` /
  :func:`~ildottore.core.reproduce.repro_from_verdicts` — N-run reproducibility.
* :class:`~ildottore.core.runner.CampaignRunner` — the full policy→mutate→reproduce→
  evaluate→score→persist loop with bounded concurrency, checkpoint/resume and a
  circuit-breaker on budget breach.

``core`` codes against the shared **protocols** only (``docs/01 §2-§3``); concretes
are injected at the composition root (u12). ``lint-imports`` enforces this.
"""

from __future__ import annotations

from ildottore.core.budgets import BudgetExhausted, BudgetLedger, BudgetSnapshot
from ildottore.core.execute import (
    AttemptResult,
    RetryPolicy,
    default_is_env_error,
    execute_attempt,
)
from ildottore.core.planner import DEFAULT_PLAN_BUDGETS, IDENTITY_MUTATOR, build_plan
from ildottore.core.reproduce import (
    DEFAULT_N,
    attempt_id_for,
    repro_from_verdicts,
    reproduce,
)
from ildottore.core.runner import (
    CampaignResult,
    CampaignRunner,
    EvaluatorResolver,
    MutatorResolver,
    PolicyGate,
    ScenarioProvider,
    TestPlanBuilder,
)
from ildottore.core.suite import SuiteResolutionError, SuiteResolver, resolve_suite

__all__ = [
    "DEFAULT_N",
    "DEFAULT_PLAN_BUDGETS",
    "IDENTITY_MUTATOR",
    "AttemptResult",
    "BudgetExhausted",
    "BudgetLedger",
    "BudgetSnapshot",
    "CampaignResult",
    "CampaignRunner",
    "EvaluatorResolver",
    "MutatorResolver",
    "PolicyGate",
    "RetryPolicy",
    "ScenarioProvider",
    "SuiteResolutionError",
    "SuiteResolver",
    "TestPlanBuilder",
    "attempt_id_for",
    "build_plan",
    "default_is_env_error",
    "execute_attempt",
    "repro_from_verdicts",
    "reproduce",
    "resolve_suite",
]
