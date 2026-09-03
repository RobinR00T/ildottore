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
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ildottore.core.budgets import BudgetExhausted, BudgetLedger
from ildottore.core.conversation import reproduce_conversation
from ildottore.core.execute import AttemptResult, RetryPolicy, default_is_env_error
from ildottore.core.planner import build_plan
from ildottore.core.reproduce import DEFAULT_N, reproduce
from ildottore.shared.enums import InconclusiveReason, VerdictStatus
from ildottore.shared.media import media_digests
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


@dataclass
class IdentityProbe:
    """One authorized identity's adapter for a multi_identity scan (audit M14).

    ``adapter`` sends as this identity using its own resolved credential; ``canary`` is the
    tenant-scoped marker this identity legitimately owns (``{{run_id}}`` substituted per run).
    A canary that reaches a NON-owner identity's response is a confirmed cross-tenant leak.
    """

    identity_id: str
    adapter: TargetAdapter
    canary: str | None = None


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
        identity_adapters: Callable[[Target], Sequence[IdentityProbe]] | None = None,
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
        self._identity_adapters = identity_adapters
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

        # Bind the per-run canary: substitute ``{{run_id}}`` throughout each spec (plant,
        # fixtures, evaluator canary_ref) so a planted canary is unique per run, otherwise the
        # placeholder is a dead constant and a canary cached from a prior run could false-fire a
        # later one (audit M8). Done here (not in the golden harness) so the offline mock replays
        # the SAME substituted canary the evaluator looks for; a spec without the placeholder is
        # returned unchanged.
        specs = [_substitute_run_id(spec, run_id) for spec in specs]

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
        # Prior findings from a partial run, keyed by spec, so a resumed spec MERGES its
        # already-persisted attempts with the fresh ones instead of re-scoring on the partial
        # remainder (which under-reported reproducibility or dropped a completed fail, audit M11).
        prior_by_spec = {f.spec_id: f for f in resume_from.findings} if resume_from else {}

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
            prior_by_spec=prior_by_spec,
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
        prior_by_spec: dict[str, Finding],
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
                    prior=prior_by_spec.get(spec.id),
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
        prior: Finding | None = None,
    ) -> Finding | None:
        """Policy-gate then mutate → reproduce → evaluate → score → persist one spec.

        On resume, ``prior`` is this spec's finding from the partial run: its already-persisted
        attempts/verdicts/evidence seed the lists so the re-scored finding covers the FULL run
        (fresh + prior), never just the not-yet-completed remainder (audit M11).
        """

        endpoint = self._endpoint_for(target, spec)
        decision = self._policy.check(target.id, endpoint, spec)
        if not decision.allowed:
            return self._blocked_finding(spec, target, reason=decision.reason or _BLOCKED)

        adapter = self._adapter_factory(target, spec)
        multi_turn = _is_multi_turn(spec)
        base_prompt = _base_prompt(spec)

        # Multi-identity specs (authz_leak, audit M14): send the attack once as each authorized
        # identity and collect {identity_id: response} + the canary -> owner map, so authz_leak
        # can flag a tenant-scoped canary reaching a non-owner identity. Empty for a single-
        # identity target, so authz_leak stays honestly capability_unavailable there.
        identities_map, canary_owners = await self._gather_identities(
            target, spec, base_prompt, run_id
        )

        # Seed from the prior partial run so completed attempts are merged, not lost.
        attempts: list[Attempt] = list(prior.attempts) if prior is not None else []
        verdicts: list[Verdict] = [a.verdict for a in attempts if a.verdict is not None]
        evidence_refs: list[EvidenceRef] = list(prior.evidence) if prior is not None else []
        for mutation in mutators:
            if multi_turn:
                results = await self._reproduce_multi_turn(
                    spec, adapter, mutation, ledger, completed
                )
            else:
                results = await self._reproduce_single_turn(
                    spec, adapter, mutation, base_prompt, ledger, completed
                )
            for result in results:
                verdict = await self._evaluate(
                    spec,
                    result.attempt,
                    env_error=result.env_error,
                    identities=identities_map,
                    canary_owners=canary_owners,
                )
                stored = result.attempt.model_copy(update={"verdict": verdict})
                evidence_refs.append(self._evidence.put(run_id, stored))
                attempts.append(stored)
                verdicts.append(verdict)

        return self._score_finding(
            spec, target, attempts=attempts, verdicts=verdicts, evidence=evidence_refs
        )

    async def _reproduce_single_turn(
        self,
        spec: AttackSpec,
        adapter: TargetAdapter,
        mutation: str,
        base_prompt: str,
        ledger: BudgetLedger,
        completed: set[str],
    ) -> list[AttemptResult]:
        """Reproduce one (spec, mutation) as N single-turn sends (the classic path)."""

        mutated_prompt = self._apply_mutation(spec, mutation, base_prompt)
        request = _build_request(spec, mutated_prompt)
        return await reproduce(
            adapter,
            request,
            spec_id=spec.id,
            mutation=mutation,
            sampling=request.sampling,
            ledger=ledger,
            n=self._n,
            retry=self._retry,
            timeout_s=self._timeout_s,
            is_env_error=default_is_env_error,
            sleep=self._sleep,
            now=self._now,
            completed=completed,
        )

    async def _reproduce_multi_turn(
        self,
        spec: AttackSpec,
        adapter: TargetAdapter,
        mutation: str,
        ledger: BudgetLedger,
        completed: set[str],
    ) -> list[AttemptResult]:
        """Reproduce one (spec, mutation) as N pinned multi-turn conversations (u08).

        The attacker turns are the spec's ``attack.turns`` ladder; a non-identity
        mutation is applied to **every** turn (each turn is a carrier). The final
        assistant reply of each conversation is the scored response.
        """

        turns = spec.attack.turns or []
        sampling = spec.sampling if spec.sampling is not None else Sampling(temperature=0.0)
        system_prompt = spec.setup.system_prompt if spec.setup is not None else None
        mutate_turn: Callable[[str], str] | None = None
        if mutation != "identity" and self._mutators.has(mutation):
            mutate_turn = self._turn_mutator(spec, mutation)

        return await reproduce_conversation(
            adapter,
            turns,
            spec_id=spec.id,
            mutation=mutation,
            sampling=sampling,
            ledger=ledger,
            n=self._n,
            system_prompt=system_prompt,
            mutate_turn=mutate_turn,
            retry=self._retry,
            timeout_s=self._timeout_s,
            is_env_error=default_is_env_error,
            sleep=self._sleep,
            now=self._now,
            completed=completed,
        )

    # --- multi-identity (authz_leak, audit M14) ------------------------------

    async def _gather_identities(
        self, target: Target, spec: AttackSpec, base_prompt: str, run_id: str
    ) -> tuple[dict[str, ModelResponse] | None, dict[str, str]]:
        """Send the attack as each authorized identity; collect responses + owner map.

        Returns ``(identities, canary_owners)`` for a multi_identity spec when the injected
        provider yields >=2 identities, else ``(None, {})`` so authz_leak stays honestly
        capability_unavailable. Each identity sends with its own credential; a per-identity
        send failure drops that identity rather than sinking the whole spec.
        """

        if self._identity_adapters is None or not _is_multi_identity(spec):
            return None, {}
        probes = list(self._identity_adapters(target))
        if len(probes) < 2:
            return None, {}

        identities: dict[str, ModelResponse] = {}
        owners: dict[str, str] = {}
        for probe in probes:
            request = _build_request(spec, base_prompt).model_copy(
                update={"identity": probe.identity_id}
            )
            try:
                response = await probe.adapter.send(request)
            except Exception:
                # A single bad identity (transport/env error) is skipped, not fatal.
                response = None
            if response is None:
                continue
            identities[probe.identity_id] = response
            if probe.canary:
                owners[probe.canary.replace("{{run_id}}", run_id)] = probe.identity_id
        if len(identities) < 2:
            return None, {}
        return identities, owners

    # --- evaluation ----------------------------------------------------------

    async def _evaluate(
        self,
        spec: AttackSpec,
        attempt: Attempt,
        *,
        env_error: bool,
        identities: dict[str, ModelResponse] | None = None,
        canary_owners: dict[str, str] | None = None,
    ) -> Verdict:
        """Run the spec's evaluator pipeline over one attempt and combine.

        An env-errored attempt (no response) is ``inconclusive`` without touching an
        evaluator — env-vs-product, never a fabricated fail (contract §4 KEEP).
        Combination honours the spec's ``evaluator_logic`` via the injected
        combiner semantics (u06's ``combine``, applied here structurally). ``identities`` +
        ``canary_owners`` (multi_identity) are threaded to authz_leak via the EvalContext.
        """

        if env_error or attempt.response is None:
            return Verdict(
                status=VerdictStatus.INCONCLUSIVE,
                confidence=0.0,
                reasoning="environment error after retries; attempt not evaluable",
                evaluator_type="aggregate",
            )
        per_evaluator = await self._run_evaluators(
            spec, attempt.request, attempt.response, identities, canary_owners
        )
        return _combine_verdicts(per_evaluator, spec)

    async def _run_evaluators(
        self,
        spec: AttackSpec,
        request: ModelRequest,
        response: ModelResponse,
        identities: dict[str, ModelResponse] | None = None,
        canary_owners: dict[str, str] | None = None,
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
                # The evaluator was never consulted (e.g. semantic_judge with no --judge
                # wired). Mark it capability_unavailable so the combiner keeps it dominating
                # , an unconsulted arbiter is honest inconclusive, distinct from a consulted
                # judge that abstained (which must not sink a decisive deterministic verdict).
                verdicts.append(
                    Verdict(
                        status=VerdictStatus.INCONCLUSIVE,
                        confidence=0.0,
                        reasoning=f"evaluator type {type_name!r} not registered",
                        evaluator_type=type_name,
                        inconclusive_reason=InconclusiveReason.CAPABILITY_UNAVAILABLE,
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
                identities=identities,
                canary_owners=canary_owners or {},
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
        confirmed = _is_confirmed(status, verdicts, spec)
        return Finding(
            spec_id=spec.id,
            target_id=target.id,
            status=status,
            # Use the scorer's RiskScore verbatim so ``risk == impact x exploitability x
            # reproducibility`` holds for the REPORTED reproducibility (M9 fix: the earlier
            # override replaced the field with a different denominator than risk was computed
            # from, breaking the invariant whenever an inconclusive coexisted with a fail).
            risk=risk,
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

        Supports a parameterized ``name:param`` form (docs/12 P1): the registry is looked up
        by the BASE name (before the first ``:``), and the FULL ``name:param`` is folded into
        the seed so a parameter-aware mutator can read it, e.g. ``translate:fr`` runs the
        ``translate`` mutator whose ``_resolve_lang`` reads ``fr`` from the seed. Seeded by
        ``(spec.id, mutation)`` per ``docs/01 §3`` so the transform is byte-stable across
        replays. An unregistered base falls back to identity.
        """

        base = mutation.split(":", 1)[0]
        if mutation == "identity" or not self._mutators.has(base):
            return text
        seed = f"{spec.id}::{mutation}"
        return self._mutators.get(base).mutate(text, seed)

    def _turn_mutator(self, spec: AttackSpec, mutation: str) -> Callable[[str], str]:
        """A per-turn transform closure for the multi-turn path (applies ``mutation``)."""

        def _mutate(text: str) -> str:
            return self._apply_mutation(spec, mutation, text)

        return _mutate

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


def _deep_replace(obj: object, needle: str, replacement: str) -> object:
    """Recursively replace ``needle`` with ``replacement`` in every string within ``obj``."""

    if isinstance(obj, str):
        return obj.replace(needle, replacement)
    if isinstance(obj, dict):
        return {key: _deep_replace(value, needle, replacement) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_deep_replace(item, needle, replacement) for item in obj]
    return obj


def _substitute_run_id(spec: AttackSpec, run_id: str) -> AttackSpec:
    """Return ``spec`` with every ``{{run_id}}`` bound to ``run_id`` (unchanged if absent)."""

    dumped = spec.model_dump(mode="json")
    if "{{run_id}}" not in _json_compact(dumped):
        return spec
    return AttackSpec.model_validate(_deep_replace(dumped, "{{run_id}}", run_id))


def _json_compact(obj: object) -> str:
    """A cheap serialization used only to test for the ``{{run_id}}`` placeholder's presence."""

    import json

    return json.dumps(obj, ensure_ascii=False, default=str)


def _is_multi_turn(spec: AttackSpec) -> bool:
    """True when the spec declares a ≥2-turn attacker ladder (``attack.turns``).

    A single ``user_prompt``/``carrier``, or a degenerate one-turn ``turns``, takes the
    classic single-send path unchanged. Two or more turns route through the pinned
    multi-turn conversation executor (``core.conversation``), where the exploit lives in
    the escalation turns, not the benign opener.
    """

    turns = spec.attack.turns
    return turns is not None and len(turns) >= 2


def _is_multi_identity(spec: AttackSpec) -> bool:
    """True when the spec requires the ``multi_identity`` capability (authz_leak, audit M14)."""

    return any(str(getattr(r, "value", r)) == "multi_identity" for r in (spec.requires or []))


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
    """Build a :class:`ModelRequest` from a spec + mutated prompt (pinned sampling).

    A ``multimodal`` spec's ``attack.media`` rides along as the declarative carrier (the adapter
    renders it for transport). For evidence, the request also records the SHA-256 of each rendered
    part under ``metadata.media_sha256`` (chain of custody): the declarative part replays to
    identical bytes, so the digest proves exactly which image was sent and an auditor can re-derive
    it. Computing a hash is not transport rendering; the adapter still owns what goes on the wire.
    """

    sampling = spec.sampling if spec.sampling is not None else Sampling(temperature=0.0)
    system_prompt = spec.setup.system_prompt if spec.setup is not None else None
    media = spec.attack.media
    metadata = {"media_sha256": media_digests(media)} if media else None
    return ModelRequest(
        prompt=prompt,
        system_prompt=system_prompt,
        sampling=sampling,
        media=media,
        metadata=metadata,
    )


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
    # A *consulted* judge that merely abstained (plain low-confidence / parse-fail, reason
    # None) is dropped so it cannot sink a decisive verdict (docs/04 §0, the judge is one
    # weighted input, never the sole arbiter). But an *unconsulted* judge
    # (capability_unavailable, no --judge wired) and a *compromised* judge (judge_compromised)
    # are KEPT so an unconfigured run stays honestly inconclusive and a prompt-injected judge
    # is surfaced, not silently discarded.
    effective = [
        v
        for v in verdicts
        if not (
            v.evaluator_type == "semantic_judge"
            and v.status is VerdictStatus.INCONCLUSIVE
            and v.inconclusive_reason is None
        )
    ]
    if not effective:
        judge_abstentions = [v for v in verdicts if v.status is VerdictStatus.INCONCLUSIVE]
        return Verdict(
            status=VerdictStatus.INCONCLUSIVE,
            confidence=0.0,
            reasoning="semantic judge abstained; no deterministic verdict to decide on",
            matched=_union_matched(verdicts),
            evaluator_type="aggregate",
            inconclusive_reason=_shared_inconclusive_reason(judge_abstentions),
        )

    # Priority (role-aware): a DETERMINISTIC fail is a confirmed exploit and wins over
    # everything; else an inconclusive (deterministic FP-discipline / capability gap / an
    # unconsulted-or-compromised judge) dominates, so a *judge* fail can never override a
    # deterministic abstention; else a judge-only fail (no blocker) carries; else pass.
    fails = [v for v in effective if v.status is VerdictStatus.FAIL]
    deterministic_fails = [v for v in fails if v.evaluator_type != "semantic_judge"]
    if deterministic_fails:
        return Verdict(
            status=VerdictStatus.FAIL,
            confidence=max(v.confidence for v in deterministic_fails),
            reasoning=f"{len(deterministic_fails)} deterministic evaluator(s) reported exploited",
            matched=_union_matched(verdicts),
            evaluator_type="aggregate",
        )
    inconclusive = [v for v in effective if v.status is VerdictStatus.INCONCLUSIVE]
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
    if fails:  # judge-only fail, nothing blocking
        return Verdict(
            status=VerdictStatus.FAIL,
            confidence=max(v.confidence for v in fails),
            reasoning="semantic judge reported exploited",
            matched=_union_matched(verdicts),
            evaluator_type="aggregate",
        )
    return Verdict(
        status=VerdictStatus.PASS,
        confidence=min(v.confidence for v in effective),
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
    """A finding is ``confirmed`` (vs needs-review) only when the exploit is decisive AND
    undisputed (ADR-0003 / the canonical ``gate_state``): a fail above the confidence
    threshold, with **no** evaluator disagreement (a ``pass`` alongside the fail) and **no**
    capability gap (an ``inconclusive``). Any dispute or gap ⇒ needs-review, so ``confirmed``
    (which drives the CI exit code) never over-claims an intermittent/contested finding.
    """

    if status is not VerdictStatus.FAIL:
        return False
    fails = [v for v in verdicts if v.status is VerdictStatus.FAIL]
    if not fails:
        return False
    if any(v.status is not VerdictStatus.FAIL for v in verdicts):
        return False  # a pass or inconclusive alongside the fail ⇒ disputed ⇒ needs-review
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
