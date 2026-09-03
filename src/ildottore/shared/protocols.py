"""Runtime ``Protocol`` seams that ``core`` codes against (``docs/01 §3``).

Interfaces only - no concretes. Concretes are injected at the composition root
(``cli``/``api``). Signatures are verbatim from ``docs/01 §3`` (``Mutator`` per
``docs/03 §4``).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ildottore.shared.models import (
    AttackSpec,
    Attempt,
    Capabilities,
    EvalContext,
    EvidenceRef,
    Finding,
    ModelRequest,
    ModelResponse,
    RiskScore,
    TestRun,
    Verdict,
)

__all__ = [
    "Evaluator",
    "EvidenceStore",
    "Mutator",
    "Reporter",
    "RiskScorer",
    "RunStore",
    "TargetAdapter",
]


@runtime_checkable
class TargetAdapter(Protocol):
    """Sends requests to a target model/endpoint and reports its capabilities."""

    id: str

    async def send(self, request: ModelRequest) -> ModelResponse: ...

    def capabilities(self) -> Capabilities: ...


@runtime_checkable
class Evaluator(Protocol):
    """Turns an evaluation context into a ``Verdict`` (``docs/04``)."""

    type: str

    async def evaluate(self, ctx: EvalContext) -> Verdict: ...


@runtime_checkable
class Mutator(Protocol):
    """Deterministic, intent-preserving prompt transform (``docs/03 §4``)."""

    name: str

    def mutate(self, text: str, seed: str) -> str: ...


@runtime_checkable
class RiskScorer(Protocol):
    """Computes a ``RiskScore`` from verdicts + attempts (``docs/05``)."""

    def score(
        self,
        spec: AttackSpec,
        verdicts: list[Verdict],
        attempts: list[Attempt],
    ) -> RiskScore: ...


@runtime_checkable
class EvidenceStore(Protocol):
    """Persists an attempt's evidence, returning a reference."""

    def put(self, run_id: str, attempt: Attempt) -> EvidenceRef: ...


@runtime_checkable
class RunStore(Protocol):
    """Persists runs and findings."""

    def save_run(self, run: TestRun) -> None: ...

    def save_finding(self, f: Finding) -> None: ...


@runtime_checkable
class Reporter(Protocol):
    """Renders a run + findings to a serialized report (``docs/01 §3``)."""

    format: str

    def render(self, run: TestRun, findings: list[Finding]) -> bytes: ...
