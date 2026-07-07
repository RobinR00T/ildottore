"""The golden-target detection-accuracy harness (u03, contract §5 steps 2-4).

This is **the safety net**: for every attack spec it drives the scanner against the
spec's own fixtures and asserts the verdicts the fixtures *claim*:

* scanner-against-``fixtures.vulnerable`` **must** yield ``fail`` (exploited),
* scanner-against-``fixtures.hardened`` **must** yield ``pass`` (secure).

A spec whose fixtures don't produce those verdicts is a **merge-blocking** failure
(``docs/07 §3`` = 100% gate). :func:`run_all` aggregates a :class:`GoldenReport`
(overall accuracy + per-family FP/FN) and the CLI/CI layer exits non-zero on any
mismatch (:meth:`GoldenReport.ok`).

Injection seams (contract §3/§8):

* the **evaluator** is injected via the :class:`~ildottore.shared.protocols.Evaluator`
  protocol — no concrete evaluator (u06) is imported here. In this unit's own tests a
  trivial stub evaluator stands in; u12 wires the real pipeline.
* the **policy engine** (u01) gates ``test_only`` fixtures: a scenario whose spec is
  ``test_only`` runs only when the active pack permits it, and the skip reason is
  recorded rather than silently dropped.

Capability honesty (contract §3): if a spec ``requires`` a target capability the
:class:`~ildottore.adapters.mock.MockTarget` does not declare, the scenario yields
``inconclusive: capability_unavailable`` — never a fabricated ``pass``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.shared.enums import Category, InconclusiveReason, RequiresCapability, VerdictStatus
from ildottore.shared.models import (
    AttackSpec,
    Capabilities,
    EvalContext,
    FixtureCase,
    ModelRequest,
    ModelResponse,
    Verdict,
)

if TYPE_CHECKING:
    from ildottore.shared.protocols import Evaluator

__all__ = [
    "FixturePair",
    "GoldenReport",
    "Mismatch",
    "ScenarioResult",
    "assert_flags_vulnerable",
    "assert_passes_hardened",
    "load_fixtures",
    "run_all",
    "run_spec",
]

Scenario = Literal["vulnerable", "hardened"]

# Spec-level ``requires`` → target ``Capabilities`` field. ``system_prompt`` is a
# setup prerequisite (not a target capability) and ``seed`` is a sampling capability
# absent from ``requires`` — neither participates in capability-gating here
# (contract §3: ``requires`` ⊇ ``Capabilities`` + ``{system_prompt, seed}``).
_REQUIRES_TO_CAPABILITY: dict[RequiresCapability, str] = {
    RequiresCapability.RAG: "rag",
    RequiresCapability.TOOLS: "tools",
    RequiresCapability.MEMORY: "memory",
    RequiresCapability.STREAMING: "streaming",
    RequiresCapability.LOGPROBS: "logprobs",
    RequiresCapability.MULTI_IDENTITY: "multi_identity",
    RequiresCapability.MULTIMODAL: "multimodal",
}


class FixturePair(BaseModel):
    """The two golden scenarios resolved from a spec's ``fixtures`` block."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    vulnerable: MockScenario
    hardened: MockScenario


class ScenarioResult(BaseModel):
    """The outcome of driving the scanner against one fixture scenario."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    spec_id: str
    category: Category
    scenario: Scenario
    expected: VerdictStatus
    verdict: Verdict
    skipped: bool = False
    skip_reason: str | None = None

    @property
    def matched(self) -> bool:
        """True when the verdict matches the fixture's declared expectation.

        A skipped scenario (policy-gated ``test_only``) is **not** counted as a
        mismatch — it is excluded from the accuracy denominator entirely.
        """

        return self.verdict.status is self.expected


class Mismatch(BaseModel):
    """A spec whose fixture did not produce the expected verdict (merge-blocking)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    spec_id: str
    scenario: Scenario
    expected: VerdictStatus
    got: VerdictStatus
    reasoning: str


class _FamilyCounts(BaseModel):
    """Per-family false-positive / false-negative tally (contract §6)."""

    model_config = ConfigDict(extra="forbid")

    fp: int = 0
    fn: int = 0
    n: int = 0


class GoldenReport(BaseModel):
    """Aggregate spec detection accuracy + per-family FP/FN (contract §6, ``docs/07 §2``).

    ``accuracy`` = ``correct / total`` over all **non-skipped** fixtures. The gate is
    100% (fixtures are ground truth): :meth:`ok` is the CI exit signal — false ⇒ the
    runner exits non-zero with a populated :attr:`mismatches` diff.
    """

    model_config = ConfigDict(extra="forbid")

    total: int = 0
    correct: int = 0
    skipped: int = 0
    by_family: dict[str, _FamilyCounts] = Field(default_factory=dict)
    mismatches: list[Mismatch] = Field(default_factory=list)

    @property
    def accuracy(self) -> float:
        """Fraction of non-skipped fixtures with the expected verdict (1.0 == clean)."""

        if self.total == 0:
            return 1.0
        return self.correct / self.total

    @property
    def ok(self) -> bool:
        """True iff every scored fixture matched (the 100% merge gate)."""

        return not self.mismatches

    def diff(self) -> str:
        """A human-readable per-spec mismatch diff (empty string when clean)."""

        if self.ok:
            return ""
        lines = [
            f"golden accuracy {self.accuracy:.4f} "
            f"({self.correct}/{self.total} fixtures, {self.skipped} skipped) — "
            f"{len(self.mismatches)} mismatch(es):"
        ]
        for miss in self.mismatches:
            lines.append(
                f"  {miss.spec_id} [{miss.scenario}]: "
                f"expected {miss.expected.value}, got {miss.got.value} "
                f"({miss.reasoning})"
            )
        return "\n".join(lines)


# --- fixture resolution ------------------------------------------------------------


def _scenario_from_case(spec: AttackSpec, case: FixtureCase) -> MockScenario:
    """Build a :class:`MockScenario` from a schema fixture case for ``spec``.

    Capabilities emulated by the mock are derived from the spec's ``requires`` so a
    hardened fixture that *should* exercise a capability declares it; a spec that
    requires a capability its fixtures do not model then surfaces as
    ``capability_unavailable`` (see :func:`run_spec`). The mock replays the fixture
    verbatim — no attack interpretation (contract §4 KEEP).
    """

    caps_kwargs = {
        _REQUIRES_TO_CAPABILITY[req]: True
        for req in spec.requires
        if req in _REQUIRES_TO_CAPABILITY
    }
    return MockScenario.from_fixture(case, capabilities=Capabilities(**caps_kwargs))


def load_fixtures(spec: AttackSpec) -> FixturePair:
    """Resolve a spec's ``fixtures`` block into a pair of replayable scenarios.

    OD-u03-a / OD-7 (00-INDEX): the schema supports both inline ``fixtures:`` and
    sidecar files; MVP-1 resolves **inline-first**. The u00 :class:`AttackSpec`
    already carries the inline block, so this consumes it directly. Sidecar
    resolution is a future seam (contract §9) — not this unit's call to author.
    """

    return FixturePair(
        vulnerable=_scenario_from_case(spec, spec.fixtures.vulnerable),
        hardened=_scenario_from_case(spec, spec.fixtures.hardened),
    )


# --- capability honesty ------------------------------------------------------------


def _missing_capability(spec: AttackSpec, caps: Capabilities) -> str | None:
    """Return the name of the first required-but-absent capability, else ``None``."""

    for req in spec.requires:
        field = _REQUIRES_TO_CAPABILITY.get(req)
        if field is not None and not getattr(caps, field):
            return req.value
    return None


def _capability_unavailable_verdict(spec: AttackSpec, missing: str) -> Verdict:
    """The honest ``inconclusive: capability_unavailable`` verdict (contract §3)."""

    return Verdict(
        status=VerdictStatus.INCONCLUSIVE,
        confidence=0.0,
        reasoning=f"spec {spec.id} requires capability {missing!r} not offered by the target",
        evaluator_type="golden_harness",
        inconclusive_reason=InconclusiveReason.CAPABILITY_UNAVAILABLE,
    )


# --- driving one scenario ----------------------------------------------------------


def _build_request(spec: AttackSpec) -> ModelRequest:
    """Build the :class:`ModelRequest` fed to the (mock) target for ``spec``.

    The harness only needs a well-formed request to carry into the evaluator's
    :class:`EvalContext`; the mock ignores the prompt (it replays a canned answer),
    so we surface the spec's attack text for evidence/debuggability without letting
    the target interpret it (contract §4 KEEP).
    """

    attack = spec.attack
    prompt = attack.user_prompt or attack.carrier
    messages = (
        [{"role": "user", "content": turn} for turn in attack.turns]
        if attack.turns is not None
        else None
    )
    return ModelRequest(
        prompt=prompt,
        messages=messages,
        system_prompt=spec.setup.system_prompt if spec.setup is not None else None,
    )


async def _evaluate(
    evaluator: Evaluator,
    spec: AttackSpec,
    request: ModelRequest,
    response: ModelResponse,
) -> Verdict:
    """Run the injected evaluator over the (mock) response for the first evaluator config.

    The single-evaluator path is sufficient for the golden gate (which proves a
    fixture is self-consistent); multi-evaluator combination is u06/u12. The spec
    guarantees ``evaluators`` is non-empty (schema ``minItems: 1``).
    """

    ctx = EvalContext(
        spec=spec,
        request=request,
        response=response,
        config=spec.evaluators[0],
        canaries=list(spec.setup.canaries) if spec.setup and spec.setup.canaries else [],
    )
    return await evaluator.evaluate(ctx)


async def run_spec(
    spec: AttackSpec,
    scenario: Scenario,
    evaluator: Evaluator,
    *,
    fixtures: FixturePair | None = None,
) -> Verdict:
    """Drive the scanner against one fixture scenario and return the :class:`Verdict`.

    Steps: resolve fixtures → capability-honesty check → build a :class:`MockTarget`
    from the canned scenario → ``send`` → hand the response to the injected
    ``evaluator``. Pure and offline end-to-end (the target is a
    :class:`~ildottore.adapters.mock.MockTarget`).
    """

    pair = fixtures if fixtures is not None else load_fixtures(spec)
    mock_scenario = pair.vulnerable if scenario == "vulnerable" else pair.hardened

    target = MockTarget(mock_scenario, id=f"mock:{spec.id}:{scenario}")

    missing = _missing_capability(spec, target.capabilities())
    if missing is not None:
        return _capability_unavailable_verdict(spec, missing)

    request = _build_request(spec)
    # Pin the attempt index so the response is a pure function of (scenario, index).
    request = request.model_copy(update={"metadata": {"mock_attempt": 0}})
    response = await target.send(request)
    return await _evaluate(evaluator, spec, request, response)


# --- assertion helpers (contract §5 step 2) ----------------------------------------


def _run_sync(coro: Awaitable[Verdict]) -> Verdict:
    """Run a coroutine to completion from sync test code (no running loop assumed)."""

    return asyncio.run(_as_coro(coro))


async def _as_coro(awaitable: Awaitable[Verdict]) -> Verdict:
    return await awaitable


def assert_flags_vulnerable(spec: AttackSpec, evaluator: Evaluator) -> Verdict:
    """Assert the scanner FLAGS (``fail``) the vulnerable fixture. Returns the verdict.

    Raises :class:`AssertionError` with a spec-scoped message on any other status —
    this is the per-spec form of the 100% gate.
    """

    verdict = _run_sync(run_spec(spec, "vulnerable", evaluator))
    if verdict.status is not VerdictStatus.FAIL:
        raise AssertionError(
            f"{spec.id}: vulnerable fixture expected 'fail', got "
            f"{verdict.status.value!r} ({verdict.reasoning})"
        )
    return verdict


def assert_passes_hardened(spec: AttackSpec, evaluator: Evaluator) -> Verdict:
    """Assert the scanner PASSES (``pass``) the hardened fixture. Returns the verdict."""

    verdict = _run_sync(run_spec(spec, "hardened", evaluator))
    if verdict.status is not VerdictStatus.PASS:
        raise AssertionError(
            f"{spec.id}: hardened fixture expected 'pass', got "
            f"{verdict.status.value!r} ({verdict.reasoning})"
        )
    return verdict


# --- aggregation (contract §5 step 3-4) --------------------------------------------

# A predicate deciding whether a ``test_only`` spec may run. Injected by the caller
# (u12 passes ``PolicyEngine``-backed logic); defaults to allow-all so the harness is
# usable without a policy in unit tests. Returns ``(allowed, reason)``.
TestOnlyGate = Callable[[AttackSpec], "tuple[bool, str | None]"]


def _default_test_only_gate(_spec: AttackSpec) -> tuple[bool, str | None]:
    return True, None


def _skipped_result(
    spec: AttackSpec, scenario: Scenario, expected: VerdictStatus, reason: str
) -> ScenarioResult:
    return ScenarioResult(
        spec_id=spec.id,
        category=spec.category,
        scenario=scenario,
        expected=expected,
        verdict=Verdict(
            status=VerdictStatus.INCONCLUSIVE,
            confidence=0.0,
            reasoning=reason,
            evaluator_type="golden_harness",
            inconclusive_reason=InconclusiveReason.BLOCKED_BY_POLICY,
        ),
        skipped=True,
        skip_reason=reason,
    )


async def _score_scenario(
    spec: AttackSpec,
    scenario: Scenario,
    expected: VerdictStatus,
    evaluator: Evaluator,
    fixtures: FixturePair,
) -> ScenarioResult:
    verdict = await run_spec(spec, scenario, evaluator, fixtures=fixtures)
    return ScenarioResult(
        spec_id=spec.id,
        category=spec.category,
        scenario=scenario,
        expected=expected,
        verdict=verdict,
    )


def _fold(report: GoldenReport, result: ScenarioResult) -> None:
    """Fold one scenario result into the aggregate report (mutates ``report``)."""

    family = result.category.value
    counts = report.by_family.setdefault(family, _FamilyCounts())

    if result.skipped:
        report.skipped += 1
        return

    report.total += 1
    counts.n += 1
    if result.matched:
        report.correct += 1
        return

    # Mismatch. Classify FP/FN by scenario:
    #  - hardened expected 'pass' but got 'fail' → false positive (fired on safe).
    #  - vulnerable expected 'fail' but not 'fail' → false negative (missed exploit).
    if result.scenario == "hardened" and result.verdict.status is VerdictStatus.FAIL:
        counts.fp += 1
    elif result.scenario == "vulnerable" and result.verdict.status is not VerdictStatus.FAIL:
        counts.fn += 1

    report.mismatches.append(
        Mismatch(
            spec_id=result.spec_id,
            scenario=result.scenario,
            expected=result.expected,
            got=result.verdict.status,
            reasoning=result.verdict.reasoning,
        )
    )


async def run_all_async(
    specs: Iterable[AttackSpec],
    evaluator: Evaluator,
    *,
    test_only_gate: TestOnlyGate | None = None,
) -> GoldenReport:
    """Async core of :func:`run_all` — score every spec's two fixtures into a report."""

    gate = test_only_gate if test_only_gate is not None else _default_test_only_gate
    report = GoldenReport()

    for spec in specs:
        fixtures = load_fixtures(spec)
        scenarios: Sequence[tuple[Scenario, VerdictStatus]] = (
            ("vulnerable", VerdictStatus.FAIL),
            ("hardened", VerdictStatus.PASS),
        )

        if spec.test_only:
            allowed, reason = gate(spec)
            if not allowed:
                skip_reason = reason or f"test_only spec {spec.id} not enabled by policy"
                for scenario, expected in scenarios:
                    _fold(report, _skipped_result(spec, scenario, expected, skip_reason))
                continue

        for scenario, expected in scenarios:
            result = await _score_scenario(spec, scenario, expected, evaluator, fixtures)
            _fold(report, result)

    return report


def run_all(
    specs: Iterable[AttackSpec],
    evaluator: Evaluator,
    *,
    test_only_gate: TestOnlyGate | None = None,
) -> GoldenReport:
    """Score every spec's fixtures and aggregate a :class:`GoldenReport` (sync entry).

    ``test_only_gate`` decides whether a ``test_only`` spec runs (u01 policy in
    production; defaults to allow-all for unit tests). The caller (CLI/CI) inspects
    :meth:`GoldenReport.ok` and exits non-zero with :meth:`GoldenReport.diff` on any
    mismatch — the 100% merge gate (``docs/07 §3``).
    """

    return asyncio.run(run_all_async(specs, evaluator, test_only_gate=test_only_gate))
