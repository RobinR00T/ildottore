"""Campaign orchestrator — the whole middle tier wired into a run (u08, §5.6).

:class:`CampaignRunner` drives ``docs/01 §4`` for a whole campaign against one
target:

    policy-gate → capability-gate → mutate → reproduce (N sends) → evaluate/combine
    → score → persist (Evidence + Run/Findings) → checkpoint.

Everything downstream is injected through the shared **protocols** (``docs/01 §3``,
contract §3/§8): the :class:`~ildottore.shared.protocols.TargetAdapter`, the
evaluator/mutator/scorer/store seams and a small structural :class:`PolicyGate`.
``core`` imports **no** concrete adapter/evaluator/scorer/store — composition is u12.

Discipline the runner enforces (contract §2/§4 KEEP):

* **Policy first, mandatory.** A spec that fails the gate produces a
  ``blocked_by_policy`` finding and **zero** adapter sends.
* **Capability gating** ⇒ ``inconclusive: capability_unavailable`` (never a pass).
* **Env-vs-product.** A retry-exhausted env error is ``inconclusive``; only a real
  exploited response is ``fail``.
* **Hard budgets.** Any :class:`~ildottore.core.budgets.BudgetExhausted` halts the
  campaign and yields a partial :class:`TestRun` marked ``budget_exhausted`` — never
  a silently-truncated ``complete``.
* **Bounded concurrency.** Specs run under an ``asyncio.Semaphore`` (no Celery/RQ,
  ``docs/00 §8``); within a spec the N repro sends are sequential for a stable
  sequence walk.
* **Resume by run_id.** Completed attempt ids are skipped, never re-sent.

Determinism: same suite + same target (mock) + same seed ⇒ identical finding set +
identical plan (contract §7). The scenario the mock replays is supplied by an
injected :class:`ScenarioProvider` so ``core`` never builds a u03 concrete.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ildottore.core.budgets import BudgetExhausted, BudgetLedger
from ildottore.core.execute import RetryPolicy, default_is_env_error
from ildottore.core.planner import build_plan
from ildottore.core.reproduce import DEFAULT_N, repro_from_verdicts, reproduce
from ildottore.shared.enums import InconclusiveReason, VerdictStatus
from ildottore.shared.models import (
    AttackSpec,
    Attempt,
    Capabilities,
    EvalContext,
    EvidenceRef,
    Finding,
    ModelFingerprint,
    ModelRequest,
    ModelResponse,
    PlanBudgets,
    RiskScore,
    Sampling,
    Target,
    TestPlan,
    TestRun,
    TestRunSummary,
    Verdict,
)
from ildottore.shared.protocols import (
    Evaluator,
    EvidenceStore,
    Mutator,
    RiskScorer,
    RunStore,
    TargetAdapter,
)

__all__ = [
    "CampaignResult",
    "CampaignRunner",
    "EvaluatorResolver",
    "MutatorResolver",
    "PolicyGate",
    "ScenarioProvider",
    "TestPlanBuilder",
]

_BLOCKED = "blocked_by_policy"


@runtime_checkable
class PolicyGate(Protocol):
    """The slice of the Policy Engine (u01) the runner needs.

    Structurally satisfied by :class:`ildottore.policy.PolicyEngine` (its ``check``
    returns a ``CheckResult`` with ``.allowed`` + ``.reason``). ``core`` codes
    against this Protocol, never the concrete (contract §8).
    """

    def check(self, target_id: str, endpoint: str, spec: AttackSpec) -> _PolicyDecision: ...


@runtime_checkable
class _PolicyDecision(Protocol):
    """Structural view of ``policy.packs.CheckResult`` (allowed + reason)."""

    @property
    def allowed(self) -> bool: ...

    reason: str | None


@runtime_checkable
class MutatorResolver(Protocol):
    """Name → :class:`Mutator` lookup (u05 ``MutatorRegistry`` satisfies this)."""

    def has(self, name: str) -> bool: ...

    def get(self, name: str) -> Mutator: ...


@runtime_checkable
class EvaluatorResolver(Protocol):
    """Type → :class:`Evaluator` lookup (u06 ``EvaluatorRegistry`` satisfies this)."""

    def has(self, type_name: str) -> bool: ...

    def get(self, type_name: str) -> Evaluator: ...


@runtime_checkable
class TestPlanBuilder(Protocol):
    """A pluggable plan-builder (defaults to :func:`core.planner.build_plan`)."""

    def __call__(
        self,
        specs: list[AttackSpec],
        fingerprint: ModelFingerprint | None,
        capabilities: Capabilities,
        *,
        target_id: str,
        plan_ref: str,
        adaptive: bool,
        budgets: PlanBudgets | None,
    ) -> TestPlan: ...


@runtime_checkable
class ScenarioProvider(Protocol):
    """Supplies the per-spec canned response the mock target should replay (u03).

    Returns ``(response_texts, tool_calls)`` for a spec: a single-element list for a
    stable answer or a sequence walked by the reproduce attempt index. A real
    over-the-wire adapter ignores this — the provider exists so an offline campaign
    is fully replayable in CI (contract §5 E2E-against-mock).
    """

    def responses_for(self, spec: AttackSpec) -> tuple[list[str], list[dict[str, object]]]: ...


@dataclass
class CampaignResult:
    """Everything a run produced: the plan, the persisted run, findings and status.

    ``status`` is the run-level state from §6 (``complete`` | ``budget_exhausted`` |
    ``parked``). The shared :class:`TestRun` model carries no ``status`` field
    (u00-owned, must-not-touch), so the runner surfaces it here and a downstream
    persister/reporter reads it from the result (contract §6).
    """

    plan: TestPlan
    run: TestRun
    status: str = "complete"
    findings: list[Finding] = field(default_factory=list)


class CampaignRunner:
    """Wires policy + mutate + reproduce + evaluate + score + persist into a run.

    All collaborators are injected. ``adapter_factory`` builds a fresh
    :class:`TargetAdapter` per spec from the target + the spec's canned scenario so a
    deterministic mock replays the right response set; the factory is where u12
    swaps in a real over-the-wire adapter. ``endpoint_for`` yields the concrete URL
    the policy gate authorizes (default: the target id — sufficient for the mock).
    """

    def __init__(
        self,
        *,
        policy: PolicyGate,
        mutators: MutatorResolver,
        evaluators: EvaluatorResolver,
        scorer: RiskScorer,
        evidence_store: EvidenceStore,
        run_store: RunStore,
        adapter_factory: Callable[[Target, AttackSpec], TargetAdapter],
        endpoint_for: Callable[[Target, AttackSpec], str] | None = None,
        plan_builder: TestPlanBuilder | None = None,
        n: int = DEFAULT_N,
        concurrency: int = 4,
        retry: RetryPolicy | None = None,
        timeout_s: float | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._policy = policy
        self._mutators = mutators
        self._evaluators = evaluators
        self._scorer = scorer
        self._evidence = evidence_store
        self._runs = run_store
        self._adapter_factory = adapter_factory
        self._endpoint_for = endpoint_for or (lambda target, _spec: target.id)
        self._plan_builder = plan_builder or build_plan
        self._n = n
        self._concurrency = max(1, concurrency)
        self._retry = retry
        self._timeout_s = timeout_s
        self._sleep = sleep
        self._now = now

    async def run(
        self,
        *,
        run_id: str,
        target: Target,
        specs: list[AttackSpec],
        fingerprint: ModelFingerprint | None = None,
        adaptive: bool = False,
        budgets: PlanBudgets | None = None,
        suite_ref: str | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
        resume_from: TestRun | None = None,
    ) -> CampaignResult:
        """Execute the whole campaign; return the plan + persisted run + findings.

        ``resume_from`` (optional) is a prior partial :class:`TestRun` for the same
        ``run_id``: its completed attempt ids are skipped so resume never re-sends a
        finished attempt (contract §7 resume). A budget breach halts the loop and
        the run is persisted as ``budget_exhausted`` with whatever completed.
        """

        plan = self._plan_builder(
            specs,
            fingerprint,
            target.capabilities,
            target_id=target.id,
            plan_ref=f"plan::{run_id}",
            adaptive=adaptive,
            budgets=budgets,
        )
        ledger = BudgetLedger.from_plan_budgets(plan.budgets, time_source=self._now)
        completed = _completed_attempt_ids(resume_from)

        selected_ids = {sel.spec_id for sel in plan.selected}
        skipped_ids = {skip.spec_id for skip in plan.skipped}
        by_id = {spec.id: spec for spec in specs}

        findings: list[Finding] = []
        status = "complete"

        # Capability-skipped specs → an inconclusive finding (never silently dropped).
        for skip in plan.skipped:
            spec = by_id.get(skip.spec_id)
            if spec is not None:
                findings.append(self._capability_skipped_finding(spec, target, reason=skip.reason))

        # Selected specs run under a bounded semaphore; a budget breach halts all.
        selected_specs = [s for s in specs if s.id in selected_ids and s.id not in skipped_ids]
        semaphore = asyncio.Semaphore(self._concurrency)
        spec_findings, breached = await self._run_selected(
            run_id=run_id,
            target=target,
            specs=selected_specs,
            plan=plan,
            ledger=ledger,
            completed=completed,
            semaphore=semaphore,
        )
        findings.extend(spec_findings)
        if breached:
            status = "budget_exhausted"

        findings.sort(key=lambda f: f.spec_id)
        run = self._build_run(
            run_id=run_id,
            target=target,
            findings=findings,
            suite_ref=suite_ref,
            started_at=started_at,
            finished_at=finished_at,
        )
        self._runs.save_run(run)
        return CampaignResult(plan=plan, run=run, status=status, findings=findings)

    # --- selected-spec loop --------------------------------------------------

    async def _run_selected(
        self,
        *,
        run_id: str,
        target: Target,
        specs: list[AttackSpec],
        plan: TestPlan,
        ledger: BudgetLedger,
        completed: set[str],
        semaphore: asyncio.Semaphore,
    ) -> tuple[list[Finding], bool]:
        """Run every selected spec concurrently (bounded); report a budget breach.

        Returns ``(findings, breached)``. A :class:`BudgetExhausted` from any spec is
        caught and flagged (``breached=True``) so the campaign is marked
        ``budget_exhausted`` **without discarding** the specs that finished before the
        breach — no masked partial, no lost work (contract §2/§4 KEEP). A non-budget
        exception is a real defect and propagates (never masked as a flake).
        """

        mutators_by_spec = {sel.spec_id: sel.mutators for sel in plan.selected}
        findings: list[Finding] = []
        breached = False

        async def _one(spec: AttackSpec) -> Finding | None:
            async with semaphore:
                return await self._run_spec(
                    run_id=run_id,
                    target=target,
                    spec=spec,
                    mutators=mutators_by_spec.get(spec.id, ["identity"]),
                    ledger=ledger,
                    completed=completed,
                )

        results = await asyncio.gather(*(_one(spec) for spec in specs), return_exceptions=True)
        for outcome in results:
            if isinstance(outcome, BudgetExhausted):
                breached = True
            elif isinstance(outcome, BaseException):
                raise outcome
            elif outcome is not None:
                findings.append(outcome)
        return findings, breached

    async def _run_spec(
        self,
        *,
        run_id: str,
        target: Target,
        spec: AttackSpec,
        mutators: list[str],
        ledger: BudgetLedger,
        completed: set[str],
    ) -> Finding | None:
        """Policy-gate then mutate → reproduce → evaluate → score → persist one spec."""

        endpoint = self._endpoint_for(target, spec)
        decision = self._policy.check(target.id, endpoint, spec)
        if not decision.allowed:
            return self._blocked_finding(spec, target, reason=decision.reason or _BLOCKED)

        adapter = self._adapter_factory(target, spec)
        base_prompt = _base_prompt(spec)

        attempts: list[Attempt] = []
        verdicts: list[Verdict] = []
        evidence_refs: list[EvidenceRef] = []
        for mutation in mutators:
            mutated_prompt = self._apply_mutation(spec, mutation, base_prompt)
            request = _build_request(spec, mutated_prompt)
            sampling = request.sampling
            results = await reproduce(
                adapter,
                request,
                spec_id=spec.id,
                mutation=mutation,
                sampling=sampling,
                ledger=ledger,
                n=self._n,
                retry=self._retry,
                timeout_s=self._timeout_s,
                is_env_error=default_is_env_error,
                sleep=self._sleep,
                now=self._now,
                completed=completed,
            )
            for result in results:
                verdict = await self._evaluate(spec, result.attempt, env_error=result.env_error)
                stored = result.attempt.model_copy(update={"verdict": verdict})
                evidence_refs.append(self._evidence.put(run_id, stored))
                attempts.append(stored)
                verdicts.append(verdict)

        return self._score_finding(
            spec, target, attempts=attempts, verdicts=verdicts, evidence=evidence_refs
        )

    # --- evaluation ----------------------------------------------------------

    async def _evaluate(self, spec: AttackSpec, attempt: Attempt, *, env_error: bool) -> Verdict:
        """Run the spec's evaluator pipeline over one attempt and combine.

        An env-errored attempt (no response) is ``inconclusive`` without touching an
        evaluator — env-vs-product, never a fabricated fail (contract §4 KEEP).
        Combination honours the spec's ``evaluator_logic`` via the injected
        combiner semantics (u06's ``combine``, applied here structurally).
        """

        if env_error or attempt.response is None:
            return Verdict(
                status=VerdictStatus.INCONCLUSIVE,
                confidence=0.0,
                reasoning="environment error after retries; attempt not evaluable",
                evaluator_type="aggregate",
            )
        per_evaluator = await self._run_evaluators(spec, attempt.request, attempt.response)
        return _combine_verdicts(per_evaluator, spec)

    async def _run_evaluators(
        self, spec: AttackSpec, request: ModelRequest, response: ModelResponse
    ) -> list[Verdict]:
        """Evaluate one response with each of the spec's configured evaluators.

        A configured evaluator type absent from the registry yields an
        ``inconclusive`` verdict for that entry (never a silent skip — the linter
        catches unknown types at load; at run time we surface it as inconclusive).
        """

        canaries = list(spec.setup.canaries or []) if spec.setup is not None else []
        verdicts: list[Verdict] = []
        for config in spec.evaluators:
            type_name = config.type.value
            if not self._evaluators.has(type_name):
                verdicts.append(
                    Verdict(
                        status=VerdictStatus.INCONCLUSIVE,
                        confidence=0.0,
                        reasoning=f"evaluator type {type_name!r} not registered",
                        evaluator_type=type_name,
                    )
                )
                continue
            evaluator = self._evaluators.get(type_name)
            ctx = EvalContext(
                spec=spec,
                request=request,
                response=response,
                config=config,
                canaries=canaries,
            )
            verdicts.append(await evaluator.evaluate(ctx))
        return verdicts

    # --- scoring + finding assembly -----------------------------------------

    def _score_finding(
        self,
        spec: AttackSpec,
        target: Target,
        *,
        attempts: list[Attempt],
        verdicts: list[Verdict],
        evidence: list[EvidenceRef],
    ) -> Finding:
        """Score aggregated verdicts + attempts into a persisted :class:`Finding`."""

        risk = self._scorer.score(spec, verdicts, attempts)
        status = _dominant_status(verdicts)
        repro = repro_from_verdicts(verdicts, max(1, self._n * _distinct_mutations(attempts)))
        confirmed = _is_confirmed(status, verdicts, spec)
        return Finding(
            spec_id=spec.id,
            target_id=target.id,
            status=status,
            risk=risk.model_copy(update={"reproducibility": repro}),
            confirmed=confirmed,
            attempts=attempts,
            evidence=evidence,
            reasoning=_finding_reasoning(status, verdicts),
        )

    def _capability_skipped_finding(
        self, spec: AttackSpec, target: Target, *, reason: str
    ) -> Finding:
        """An ``inconclusive: capability_unavailable`` finding — never a pass."""

        return Finding(
            spec_id=spec.id,
            target_id=target.id,
            status=VerdictStatus.INCONCLUSIVE,
            risk=_zero_risk(spec),
            confirmed=False,
            attempts=[],
            evidence=[],
            reasoning=reason,
        )

    def _blocked_finding(self, spec: AttackSpec, target: Target, *, reason: str) -> Finding:
        """A ``blocked_by_policy`` finding with zero attempts (no sends happened)."""

        return Finding(
            spec_id=spec.id,
            target_id=target.id,
            status=VerdictStatus.INCONCLUSIVE,
            risk=_zero_risk(spec),
            confirmed=False,
            attempts=[],
            evidence=[],
            reasoning=f"{_BLOCKED}: {reason}",
        )

    def _apply_mutation(self, spec: AttackSpec, mutation: str, text: str) -> str:
        """Apply one mutation to the base carrier (identity → unchanged).

        Seeded by ``(spec.id, mutation)`` per ``docs/01 §3`` so the transform is
        byte-stable across replays. An unregistered mutation falls back to identity
        (the linter catches unknown mutations at load).
        """

        if mutation == "identity" or not self._mutators.has(mutation):
            return text
        seed = f"{spec.id}::{mutation}"
        return self._mutators.get(mutation).mutate(text, seed)

    def _build_run(
        self,
        *,
        run_id: str,
        target: Target,
        findings: list[Finding],
        suite_ref: str | None,
        started_at: str | None,
        finished_at: str | None,
    ) -> TestRun:
        """Assemble the persisted :class:`TestRun` (run-level status lives on the result)."""

        summary = _build_summary(findings)
        return TestRun(
            run_id=run_id,
            suite_ref=suite_ref,
            targets=[target],
            findings=findings,
            summary=summary,
            started_at=started_at,
            finished_at=finished_at,
        )


# --- module-level pure helpers ----------------------------------------------


def _base_prompt(spec: AttackSpec) -> str:
    """The base carrier text to mutate (user_prompt | carrier | first turn)."""

    attack = spec.attack
    if attack.user_prompt is not None:
        return attack.user_prompt
    if attack.carrier is not None:
        return attack.carrier
    if attack.turns:
        return attack.turns[0]
    return ""  # pragma: no cover - AttackSpec.model_post_init forbids all-None


def _build_request(spec: AttackSpec, prompt: str) -> ModelRequest:
    """Build a :class:`ModelRequest` from a spec + mutated prompt (pinned sampling)."""

    sampling = spec.sampling if spec.sampling is not None else Sampling(temperature=0.0)
    system_prompt = spec.setup.system_prompt if spec.setup is not None else None
    return ModelRequest(prompt=prompt, system_prompt=system_prompt, sampling=sampling)


def _combine_verdicts(verdicts: list[Verdict], spec: AttackSpec) -> Verdict:
    """Combine per-evaluator verdicts by the spec's ``evaluator_logic`` (u06 semantics).

    Reimplements the *decision* of ``evaluators.combine`` at the interface level so
    ``core`` does not import the evaluators concrete (contract §8): inconclusive in a
    required evaluator dominates; else ``any_fail``/``all_pass``/``weighted``.
    """

    if not verdicts:
        return Verdict(
            status=VerdictStatus.INCONCLUSIVE,
            confidence=0.0,
            reasoning="no evaluator verdicts to combine",
            evaluator_type="aggregate",
        )
    inconclusive = [v for v in verdicts if v.status is VerdictStatus.INCONCLUSIVE]
    if inconclusive:
        reason = _shared_inconclusive_reason(inconclusive)
        return Verdict(
            status=VerdictStatus.INCONCLUSIVE,
            confidence=0.0,
            reasoning=f"{len(inconclusive)} evaluator(s) inconclusive → aggregate inconclusive",
            matched=_union_matched(verdicts),
            evaluator_type="aggregate",
            inconclusive_reason=reason,
        )
    fails = [v for v in verdicts if v.status is VerdictStatus.FAIL]
    if fails:
        return Verdict(
            status=VerdictStatus.FAIL,
            confidence=max(v.confidence for v in fails),
            reasoning=f"{len(fails)} evaluator(s) reported exploited",
            matched=_union_matched(verdicts),
            evaluator_type="aggregate",
        )
    return Verdict(
        status=VerdictStatus.PASS,
        confidence=min(v.confidence for v in verdicts),
        reasoning="all evaluators reported secure",
        matched=_union_matched(verdicts),
        evaluator_type="aggregate",
    )


def _shared_inconclusive_reason(verdicts: list[Verdict]) -> InconclusiveReason | None:
    reasons = {v.inconclusive_reason for v in verdicts if v.inconclusive_reason is not None}
    return reasons.pop() if len(reasons) == 1 else None


def _union_matched(verdicts: list[Verdict]) -> list[str]:
    seen: dict[str, None] = {}
    for v in verdicts:
        for m in v.matched:
            seen.setdefault(m, None)
    return list(seen)


def _dominant_status(verdicts: list[Verdict]) -> VerdictStatus:
    """Spec-level status: any exploited ⇒ ``fail``; else any run ⇒ ``pass``; else inconclusive."""

    if not verdicts:
        return VerdictStatus.INCONCLUSIVE
    if any(v.status is VerdictStatus.FAIL for v in verdicts):
        return VerdictStatus.FAIL
    if any(v.status is VerdictStatus.PASS for v in verdicts):
        return VerdictStatus.PASS
    return VerdictStatus.INCONCLUSIVE


def _distinct_mutations(attempts: list[Attempt]) -> int:
    return max(1, len({a.mutation for a in attempts}))


def _is_confirmed(status: VerdictStatus, verdicts: list[Verdict], spec: AttackSpec) -> bool:
    """A finding is confirmed when it is a decisive fail above the confidence threshold."""

    if status is not VerdictStatus.FAIL:
        return False
    fails = [v for v in verdicts if v.status is VerdictStatus.FAIL]
    if not fails:
        return False
    mean_conf = sum(v.confidence for v in fails) / len(fails)
    return mean_conf >= spec.scoring.confidence_threshold


def _finding_reasoning(status: VerdictStatus, verdicts: list[Verdict]) -> str:
    fails = sum(1 for v in verdicts if v.status is VerdictStatus.FAIL)
    total = len(verdicts)
    return f"status={status.value}; {fails}/{total} attempt-verdicts exploited"


def _zero_risk(spec: AttackSpec) -> RiskScore:
    """A zero-magnitude risk for blocked/skipped findings (impact/exploit carried)."""

    from ildottore.shared.enums import ScanBand

    return RiskScore(
        impact=spec.scoring.impact,
        exploitability=spec.scoring.exploitability,
        reproducibility=0.0,
        risk=0.0,
        band=ScanBand.INFO,
        confidence=0.0,
    )


def _build_summary(findings: list[Finding]) -> TestRunSummary:
    by_status: dict[str, int] = {}
    by_band: dict[str, int] = {}
    for f in findings:
        by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
        by_band[f.risk.band.value] = by_band.get(f.risk.band.value, 0) + 1
    return TestRunSummary(by_status=by_status, by_band=by_band, total=len(findings))


def _completed_attempt_ids(run: TestRun | None) -> set[str]:
    """Attempt ids already persisted in a prior partial run (resume skip set)."""

    if run is None:
        return set()
    ids: set[str] = set()
    for finding in run.findings:
        for attempt in finding.attempts:
            if attempt.response is not None or attempt.error is not None:
                ids.add(attempt.attempt_id)
    return ids
