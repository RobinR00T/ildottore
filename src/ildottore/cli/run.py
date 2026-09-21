"""``dottore run`` - resolve → scope-gate → plan → execute → render → exit-code.

The default command when a target is given (contract §2). It is pure wiring + I/O:
it resolves config/scope/selection, delegates execution to the u08 runner, streams
progress, renders the summary and maps the outcome to a scriptable exit code. It holds
**no** attack/eval/scoring logic (contract §8).

The **scope/allowlist gate is never bypassable** (contract §4 KEEP, ``docs/09 §5``):
``run`` refuses to send a single request without a ``--scope`` file, and ``--dry-run``
resolves + validates and sends nothing. ``-A``/``--quick``/``--deep`` do not weaken
this - they only change the battery.

Two rules this module learned the hard way, both from the same failure shape (a number or a
state computed and then dropped somewhere a human looks):

* **Every printed number is computed by the same code that will do the work.** The plan a
  ``--dry-run``/``--estimate`` prints comes from :func:`~ildottore.core.planner.build_plan`
  plus the real :class:`~ildottore.policy.PolicyEngine`, per target, because the previous
  version printed the *selection* (before the capability filter, once for all targets) and
  so promised 845 requests where the run sent 499, and 5 where it sent 10.
* **A run that did not finish never reports as if it had.** A budget ceiling halts the
  campaign; that state now reaches the terminal, the report and the exit code (3).
"""

from __future__ import annotations

import asyncio
import fnmatch
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode, exit_code_for
from ildottore.cli.flags import QUICK_SUITE, resolve_suite_id, resolve_timing
from ildottore.cli.render import ProgressPrinter
from ildottore.core.planner import DEFAULT_PLAN_BUDGETS, IDENTITY_MUTATOR, build_plan
from ildottore.core.runner import CampaignResult
from ildottore.policy import Scope, authorize_target
from ildottore.policy.errors import PolicyError, ScopeError
from ildottore.reporting import RunStatus
from ildottore.shared.enums import Category
from ildottore.shared.models import (
    AttackSpec,
    Finding,
    ModelFingerprint,
    PlanBudgets,
    Target,
)

__all__ = [
    "CATEGORY_ALIASES",
    "PlanEstimate",
    "RunOptions",
    "RunOutcome",
    "ScopeRequiredError",
    "TargetPlan",
    "budgets_for",
    "estimate_plan",
    "execute_run",
    "resolve_target_plans",
    "select_specs",
]

#: ``-p`` friendly category tokens → the canonical :class:`Category` (``docs/09 §2``).
CATEGORY_ALIASES: dict[str, Category] = {
    "pi": Category.PROMPT_INJECTION,
    "prompt_injection": Category.PROMPT_INJECTION,
    "jailbreak": Category.JAILBREAK,
    "jb": Category.JAILBREAK,
    "leakage": Category.DATA_LEAKAGE,
    "data_leakage": Category.DATA_LEAKAGE,
    "tool": Category.AGENT_TOOL_ABUSE,
    "agent": Category.AGENT_TOOL_ABUSE,
    "agent_tool_abuse": Category.AGENT_TOOL_ABUSE,
    "rag": Category.RAG_SECURITY,
    "rag_security": Category.RAG_SECURITY,
    "output": Category.OUTPUT_SECURITY,
    "output_security": Category.OUTPUT_SECURITY,
    "dos": Category.AVAILABILITY_COST,
    "availability_cost": Category.AVAILABILITY_COST,
    "safety": Category.SAFETY_CONTENT,
    "safety_content": Category.SAFETY_CONTENT,
    "bias": Category.BIAS_FAIRNESS,
    "fairness": Category.BIAS_FAIRNESS,
    "bias_fairness": Category.BIAS_FAIRNESS,
}


class ScopeRequiredError(PolicyError):
    """Raised when a traffic-sending command is invoked without a ``--scope`` file.

    This is the non-bypassable gate (contract §4 KEEP): no ``-A``/flag can satisfy it,
    only a real scope authorization record.
    """


@dataclass
class RunOptions:
    """Resolved options for one ``run`` invocation (CLI parses into this)."""

    targets: list[Path]
    scope: Path | None
    judge: Path | None = None
    suite: str | None = None
    categories: list[str] = field(default_factory=list)
    spec_globs: list[str] = field(default_factory=list)
    exclude_globs: list[str] = field(default_factory=list)
    top_tests: int | None = None
    template: int = 3
    # Intensity / mode flags. Every one of these used to be parsed by typer and never read:
    # ``-sn`` ("discovery only, no attacks") sent the full battery, ``-sV``/``-A`` did
    # nothing, and ``--quick``/``--deep`` only moved the timing template while six documents
    # said they changed the battery.
    discovery_only: bool = False  # -sn
    fingerprint_first: bool = False  # -sV
    quick: bool = False  # --quick
    deep: bool = False  # --deep
    verbose: int = 0  # -v
    rate: float | None = None
    concurrency: int | None = None
    timeout_s: float | None = None
    runs: int = 5
    dry_run: bool = False
    estimate: bool = False
    fail_on: str = "high"
    include_needs_review: bool = False
    compare: bool = False
    outputs: dict[str, Path] = field(default_factory=dict)  # fmt -> path
    output_all_prefix: Path | None = None
    hardened: bool = False
    no_color: bool = False
    quiet: bool = False
    evidence_root: Path | None = None
    run_db: Path | None = None
    seed: int | None = None


@dataclass
class RunOutcome:
    """The result of a ``run`` - findings, per-target results and the exit code."""

    exit_code: ExitCode
    findings: list[Finding] = field(default_factory=list)
    results: list[CampaignResult] = field(default_factory=list)
    dry_run: bool = False
    estimated: bool = False
    report_paths: list[Path] = field(default_factory=list)
    #: Non-``complete`` campaign states (``target_id`` → reason). Non-empty ⇒ exit 3: a
    #: truncated campaign is an operational failure, not a clean scan of a smaller battery.
    incomplete: dict[str, str] = field(default_factory=dict)


# --- spec selection ----------------------------------------------------------------


def select_specs(
    all_specs: list[AttackSpec],
    *,
    suite_specs: list[AttackSpec] | None = None,
    categories: list[str] | None = None,
    spec_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    top_tests: int | None = None,
) -> list[AttackSpec]:
    """Resolve the effective spec set from suite + category + glob selectors.

    Precedence (``docs/09 §2``): a ``--suite`` seeds the base set (else all specs);
    ``-p`` category filters and ``--spec`` id globs *narrow* it (AND across selector
    kinds, OR within a kind); ``--exclude`` removes matches; ``--top-tests N`` keeps
    the N highest-signal specs (by author severity/scoring, deterministic). Order is
    preserved for determinism (contract §7).
    """

    base = list(suite_specs) if suite_specs is not None else list(all_specs)

    cats = _resolve_categories(categories or [])
    if cats:
        base = [s for s in base if s.category in cats]

    globs = spec_globs or []
    if globs:
        base = [s for s in base if any(fnmatch.fnmatch(s.id, g) for g in globs)]

    for ex in exclude_globs or []:
        base = [s for s in base if not fnmatch.fnmatch(s.id, ex)]

    if top_tests is not None and top_tests >= 0:
        base = _top_by_signal(base, top_tests)

    return base


def _resolve_categories(tokens: list[str]) -> set[Category]:
    """Map ``-p`` tokens to :class:`Category` values (unknown token → ``ValueError``)."""

    out: set[Category] = set()
    for token in tokens:
        key = token.strip().lower()
        if key not in CATEGORY_ALIASES:
            raise ValueError(
                f"unknown category {token!r}; expected one of: "
                f"{', '.join(sorted({v.value for v in CATEGORY_ALIASES.values()}))}"
            )
        out.add(CATEGORY_ALIASES[key])
    return out


def _top_by_signal(specs: list[AttackSpec], n: int) -> list[AttackSpec]:
    """Keep the ``n`` highest-signal specs (impact*exploitability), preserving order.

    Signal is the author's ``scoring.impact * scoring.exploitability`` - a stable,
    offline proxy for "highest-signal" (``docs/09 §2`` ``--top-tests``). Ties break on
    the original order (stable sort) so selection is deterministic.
    """

    ranked = sorted(
        enumerate(specs),
        key=lambda pair: (
            -(pair[1].scoring.impact * pair[1].scoring.exploitability),
            pair[0],
        ),
    )
    keep_ids = {specs[i].id for i, _ in ranked[:n]}
    return [s for s in specs if s.id in keep_ids]


# --- execution ---------------------------------------------------------------------


@dataclass
class PlanEstimate:
    """A pre-run cost estimate (docs/12 P2): request + token volume, no sends, no fabricated $."""

    specs: int
    requests: int
    input_tokens: int
    output_tokens: int
    by_category: dict[str, int]

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class TargetPlan:
    """What ONE target's run would actually do, resolved with the engine's own pieces.

    Built by :func:`resolve_target_plans` from :func:`~ildottore.core.planner.build_plan`
    and the real :class:`~ildottore.policy.PolicyEngine`, so the printed plan and the run
    cannot disagree: both apply the same capability filter, the same policy pack and the
    same endpoint authorization, and the estimate counts the plan's own mutator lists.
    """

    target: Target
    path: Path
    endpoint: str
    authorized: str | None  # None ⇒ authorized; else the refusal reason
    selected: list[AttackSpec]
    skipped_capability: list[tuple[str, str]]
    blocked_by_policy: list[tuple[str, str]]
    estimate: PlanEstimate
    budgets: PlanBudgets
    mutators_by_spec: dict[str, list[str]]


def _effective_mutators(spec: AttackSpec) -> list[str]:
    """The mutators a spec will really run: ``identity`` plus its declared list, de-duplicated.

    Mirrors ``core.planner._select_mutators``. The estimate used to count
    ``len(spec.mutations or ["identity"])``, which under-counts every spec that declares
    mutations without repeating ``identity``: the planner always prepends the un-mutated
    baseline carrier, so a spec declaring one mutation runs two attempts, not one.
    """

    ordered = [IDENTITY_MUTATOR, *(spec.mutations or [])]
    return list(dict.fromkeys(ordered))


def estimate_plan(
    specs: list[AttackSpec],
    runs: int,
    *,
    mutators_by_spec: dict[str, list[str]] | None = None,
) -> PlanEstimate:
    """Estimate the wire cost of a plan without sending: requests + rough token volume.

    ``requests`` = sum over specs of ``mutators x runs x turns``. ``mutators_by_spec`` (from
    a resolved :class:`~ildottore.shared.models.TestPlan`) is authoritative when given;
    absent it, :func:`_effective_mutators` reproduces what the planner would choose. Tokens
    are a deliberately rough gloss (prompt length / 4 for input; the spec's
    ``sampling.max_tokens`` or 512 for output). No per-model pricing is known, so this
    reports volume, not a dollar figure.
    """

    total_requests = 0
    total_in = 0
    total_out = 0
    by_category: dict[str, int] = {}
    for spec in specs:
        mutators = (mutators_by_spec or {}).get(spec.id) or _effective_mutators(spec)
        turns = spec.attack.turns
        n_turns = len(turns) if turns is not None and len(turns) >= 2 else 1
        requests = len(mutators) * runs * n_turns
        prompt = spec.attack.user_prompt or spec.attack.carrier or (turns[0] if turns else "")
        in_tokens = max(1, len(prompt) // 4)
        out_tokens = (
            spec.sampling.max_tokens
            if spec.sampling is not None and spec.sampling.max_tokens
            else 512
        )
        total_requests += requests
        total_in += requests * in_tokens
        total_out += requests * out_tokens
        by_category[spec.category.value] = by_category.get(spec.category.value, 0) + requests
    return PlanEstimate(
        specs=len(specs),
        requests=total_requests,
        input_tokens=total_in,
        output_tokens=total_out,
        by_category=by_category,
    )


#: Headroom over the estimate for the derived ceilings. The estimate is a gloss (prompt
#: length / 4, a default 512-token completion), a retry is a second send of the same request,
#: and a ceiling that binds *below* the plan turns a full scan into a silent partial one. The
#: ceilings stay hard; they are simply sized from the plan that the operator reviewed.
BUDGET_HEADROOM = 1.5


def budgets_for(estimate: PlanEstimate, *, rate_rps: float | None = None) -> PlanBudgets:
    """Hard ceilings sized from the plan, never below the conservative defaults.

    The scanner must not self-DoS, which is why :data:`DEFAULT_PLAN_BUDGETS` exists. But a
    *constant* ceiling is a ceiling that drifts out of date as the battery grows, and this
    one had: the default battery needs ~537k tokens against a 500k default, so a plain
    ``dottore run`` halted after roughly two thirds of the specs, marked itself
    ``budget_exhausted`` internally, and reported the truncated run as a clean one. Deriving
    each axis from the reviewed plan keeps the cap (it still bounds the campaign to what the
    plan said, plus :data:`BUDGET_HEADROOM`) while removing the drift.

    ``rate_rps`` extends the wall-clock ceiling to fit the authorized pace: with pacing now
    enforced, a deliberately slow ``--rate`` would otherwise be halted by the wall axis, i.e.
    obeying one flag would break another.
    """

    tokens = int(estimate.total_tokens * BUDGET_HEADROOM)
    requests = int(estimate.requests * BUDGET_HEADROOM)
    wall_s = DEFAULT_PLAN_BUDGETS.max_wall_s or 0
    if rate_rps is not None and rate_rps > 0:
        wall_s = max(wall_s, int(estimate.requests / rate_rps * BUDGET_HEADROOM) + 1)
    return PlanBudgets(
        max_tokens=max(DEFAULT_PLAN_BUDGETS.max_tokens or 0, tokens),
        max_requests=max(DEFAULT_PLAN_BUDGETS.max_requests or 0, requests),
        max_wall_s=wall_s,
        max_attempts=max(DEFAULT_PLAN_BUDGETS.max_attempts or 0, requests),
    )


def resolve_target_plans(
    *,
    scope: Scope,
    targets: list[tuple[Path, Target]],
    specs: list[AttackSpec],
    runs: int,
    rate_rps: float | None = None,
    fingerprints: dict[str, ModelFingerprint] | None = None,
    adaptive: bool = False,
) -> list[TargetPlan]:
    """Resolve, per target, exactly what the run would do - without sending anything.

    Runs the two filters the campaign runs, in the same order and with the same inputs:
    the planner's capability filter (a spec whose ``requires`` the target does not declare
    is skipped) and the policy gate (scope reachability, the engagement pack, layer-B and
    ``requires_policy`` capabilities). What survives both is what would be sent.
    """

    pack = wiring.build_permissive_pack(specs)
    policy = wiring.build_policy_engine(scope, pack)
    plans: list[TargetPlan] = []
    for path, target in targets:
        endpoint = wiring.scope_endpoint_of(scope, target)
        decision = authorize_target(scope, target.id, endpoint)
        fingerprint = (fingerprints or {}).get(target.id)
        plan = build_plan(
            specs,
            fingerprint,
            target.capabilities,
            target_id=target.id,
            plan_ref=f"plan::preview::{target.id}",
            adaptive=adaptive,
        )
        mutators_by_spec = {sel.spec_id: list(sel.mutators) for sel in plan.selected}
        by_id = {spec.id: spec for spec in specs}
        runnable: list[AttackSpec] = []
        blocked: list[tuple[str, str]] = []
        for sel in plan.selected:
            spec = by_id.get(sel.spec_id)
            if spec is None:  # pragma: no cover - the plan is built from these specs
                continue
            verdict = policy.check(target.id, endpoint, spec)
            if verdict.allowed:
                runnable.append(spec)
            else:
                blocked.append((spec.id, verdict.reason or "blocked_by_policy"))
        estimate = estimate_plan(runnable, runs, mutators_by_spec=mutators_by_spec)
        plans.append(
            TargetPlan(
                target=target,
                path=path,
                endpoint=endpoint,
                authorized=None if decision.allowed else (decision.reason or "not authorized"),
                selected=runnable,
                skipped_capability=[(s.spec_id, s.reason) for s in plan.skipped],
                blocked_by_policy=blocked,
                estimate=estimate,
                budgets=budgets_for(estimate, rate_rps=rate_rps),
                mutators_by_spec=mutators_by_spec,
            )
        )
    return plans


def _print_estimate(plans: list[TargetPlan], *, runs: int, quiet: bool = False) -> None:
    """Print the pre-run estimate, per target and totalled (skipped under --quiet).

    Per target on purpose: the previous version estimated the selection once and printed it
    once, so a two-target run understated the spend by half - an error in the direction that
    costs the operator money.
    """

    if quiet:
        return
    requests = sum(p.estimate.requests for p in plans)
    tokens_in = sum(p.estimate.input_tokens for p in plans)
    tokens_out = sum(p.estimate.output_tokens for p in plans)
    specs = sum(p.estimate.specs for p in plans)
    print(
        f"estimate: {requests} requests over {specs} spec-runs "
        f"across {len(plans)} target(s) at runs={runs} (no sends made)"
    )
    print(
        f"  ~tokens: {tokens_in} in + {tokens_out} out "
        f"(~{tokens_in + tokens_out} total, rough gloss)"
    )
    for plan in plans:
        skipped = len(plan.skipped_capability)
        blocked = len(plan.blocked_by_policy)
        print(
            f"  {plan.target.id}: {plan.estimate.requests} requests over "
            f"{len(plan.selected)} specs"
            + (f", {skipped} skipped (capability)" if skipped else "")
            + (f", {blocked} blocked (policy)" if blocked else "")
        )
    by_category: dict[str, int] = {}
    for plan in plans:
        for cat, n in plan.estimate.by_category.items():
            by_category[cat] = by_category.get(cat, 0) + n
    for cat, n in sorted(by_category.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {cat}: {n} requests")
    print("  no per-model pricing known; multiply by your provider's per-token rate.")


def _print_dry_run_plan(
    *,
    scope_path: Path | None,
    plans: list[TargetPlan],
    suite: str | None,
    runs: int,
    paced: bool,
    rate_rps: float | None,
    quiet: bool = False,
) -> None:
    """Print the plan ``--dry-run`` just resolved (one line under ``--quiet``).

    ``--dry-run`` exists to answer "is my wiring right?", which it cannot do without showing
    what it resolved: which scope authorized which target *at which endpoint*, which battery
    survived both filters, and what the run would really cost. Under ``-q`` it prints a single
    machine-friendly line rather than nothing: a command whose only output is its exit code
    cannot answer the question it exists for.
    """

    requests = sum(p.estimate.requests for p in plans)
    specs = sum(len(p.selected) for p in plans)
    if quiet:
        print(f"dry-run: {specs} specs, {requests} requests, {len(plans)} target(s), sent nothing")
        return
    print("dry-run: plan resolved, sent nothing.")
    print(f"  scope:   {scope_path}")
    for plan in plans:
        # The authorized ENDPOINT, not the words "authorized by the scope": a scope naming
        # the target with an empty endpoint list is the exact case that used to read green.
        print(
            f"  target:  {plan.target.id} ({plan.target.type.value}) authorized at {plan.endpoint}"
        )
    print(f"  battery: {suite or 'full battery'}, {specs} specs selected")
    by_cat: dict[str, int] = {}
    for plan in plans:
        for spec in plan.selected:
            by_cat[spec.category.value] = by_cat.get(spec.category.value, 0) + 1
    for cat, n in sorted(by_cat.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"    {cat}: {n}")
    for plan in plans:
        if plan.skipped_capability:
            print(
                f"  skipped: {len(plan.skipped_capability)} spec(s) on {plan.target.id}, "
                "capability not declared by the target"
            )
        if plan.blocked_by_policy:
            print(
                f"  blocked: {len(plan.blocked_by_policy)} spec(s) on {plan.target.id}, "
                "refused by the policy pack"
            )
    print(f"  would send: {requests} requests over {specs} specs at runs={runs}")
    if paced and rate_rps:
        print(f"  pacing:  {rate_rps} req/s ceiling (S8)")
    elif rate_rps:
        print(
            f"  pacing:  not applied ({rate_rps} req/s requested) - this is an offline "
            "mock run, nothing leaves the process"
        )
    budgets = plans[0].budgets if plans else DEFAULT_PLAN_BUDGETS
    print(
        f"  budgets: {budgets.max_tokens} tokens, {budgets.max_requests} requests, "
        f"{budgets.max_wall_s}s wall (derived from this plan)"
    )


def _print_discovery(plans: list[TargetPlan], *, quiet: bool = False) -> None:
    """``-sn``: report what is authorized and what the target declares. Sends nothing.

    ``-sn`` means "discovery only, no attacks" and used to send the entire battery, which is
    the most dangerous shape a flag can have: an operator typing it against production got
    the attack run they were explicitly avoiding. It now reports and stops.

    Reachability here is **authorization-level, not a live probe**: the scope entry, the
    endpoint allowlist and the target's declared capabilities. Probing liveness would mean
    sending, which is precisely what ``-sn`` promises not to do, so it is not implied.
    """

    if quiet:
        print(f"discovery: {len(plans)} target(s), sent nothing")
        return
    print("discovery (-sn): no attacks sent.")
    for plan in plans:
        caps = [name for name, on in plan.target.capabilities.model_dump().items() if on]
        print(f"  target:      {plan.target.id} ({plan.target.type.value})")
        print(f"    endpoint:  {plan.endpoint} (authorized by the scope)")
        print(f"    provider:  {plan.target.provider or 'mock/offline'}")
        print(f"    model:     {plan.target.model or 'unknown'}")
        print(f"    declares:  {', '.join(caps) if caps else 'no optional capabilities'}")
        print(
            f"    battery:   {len(plan.selected)} spec(s) would run, "
            f"{len(plan.skipped_capability)} skipped for missing capabilities, "
            f"{len(plan.blocked_by_policy)} blocked by policy"
        )
    print("  reachability is authorization-level (scope + allowlist); no request was sent.")


def execute_run(opts: RunOptions, spec_paths: list[Path]) -> RunOutcome:
    """Run a full campaign for every target and return the aggregate outcome.

    Order of refusals, all before any adapter exists (contract §4 KEEP, zero sends):

    1. no ``--scope`` ⇒ :class:`ScopeRequiredError` (the gate no flag can satisfy);
    2. a target (or the ``--judge`` model) not **reachable** under the scope ⇒
       :class:`ScopeError`. Reachable, not merely present: an entry with an empty endpoint
       allowlist used to pass this gate and then be denied on every single attempt;
    3. an empty spec selection ⇒ :class:`ValueError`, rather than a green run of nothing.

    ``-sn`` reports and stops. ``--estimate``/``--dry-run`` resolve the real per-target plan,
    print it and stop. Otherwise the campaign runs, and a campaign that did not finish
    (a budget ceiling) is reported as such and exits 3.
    """

    if opts.scope is None:
        raise ScopeRequiredError(
            "run requires --scope <scope.yaml>: the authorization record is mandatory "
            "and cannot be bypassed by any flag (docs/09 §5)"
        )

    scope = wiring.build_scope(opts.scope)

    # Authorization gate, per target, BEFORE anything else is built or any early return.
    # A target whose id is absent from the scope used to produce a full run of blocked specs
    # that exited 0: nothing was sent (the allowlist is empty, so default-deny held), but the
    # operator got a clean exit and a report full of unexplained inconclusives. The reason was
    # computed and thrown away exactly where a human looks. `examples/README.md` already
    # promises "a run refuses any target that is not covered", and ExitCode.ERROR is the
    # documented slot for a bad scope, so this now refuses. It also has to happen here rather
    # than in the per-target loop, or `--dry-run` (whose entire job is validating the wiring)
    # would keep returning a false green without ever looking at the target.
    #
    # The test is the policy engine's own `authorize_target` (scope membership AND endpoint
    # reachability), not a second, weaker one written here: asking only whether the id is
    # present left the false green one character away, because `ScopeTarget.endpoints`
    # defaults to empty and a typo in `host` reads exactly like a missing allowlist.
    loaded_targets = [(path, wiring.load_target(path)) for path in opts.targets]
    judge_target = wiring.load_target(opts.judge) if opts.judge is not None else None
    to_authorize = list(loaded_targets)
    if judge_target is not None and opts.judge is not None:
        # The judge is a model we send prompts to, so it goes through the same gate. It used
        # to be loaded and never checked: with the judge absent from the scope (which is what
        # `fleet --judge` generated), every semantic_judge verdict came back inconclusive
        # with the reason only in the JSON, and the run exited 0.
        to_authorize.append((opts.judge, judge_target))
    refusals = [
        f"{target.id} ({reason})"
        for _, target in to_authorize
        if (reason := _refusal_for(scope, target)) is not None
    ]
    if refusals:
        authorized = ", ".join(sorted(t.id for t in scope.targets)) or "<none>"
        raise ScopeError(
            f"target(s) not authorized by the scope: {'; '.join(sorted(refusals))}. "
            f"The scope authorizes: {authorized}. A target id must match a scope entry "
            "exactly and that entry must allowlist the endpoint the target uses; add it "
            "or point --scope elsewhere."
        )
    if judge_target is not None:
        # Resolving the judge's credential is also scope-gated (the same defence the attack
        # targets get); raises ValueError when the scope did not declare that auth_ref.
        wiring.check_target_credential(scope, judge_target)

    registry = wiring.build_registry(spec_paths)
    all_specs = registry.list()
    specs_by_id = {s.id: s for s in all_specs}

    # --quick selects the T0 battery. It used to set only the timing template, while six
    # documents said it changed the battery, and the `quick` suite shipped unselectable.
    suite_name = opts.suite
    if opts.quick and suite_name is None:
        suite_name = QUICK_SUITE
    elif opts.quick and suite_name is not None:
        raise ValueError(
            f"--quick and --suite {opts.suite!r} both select a battery; pass one. "
            f"--quick is shorthand for --suite {QUICK_SUITE}."
        )

    suite_specs: list[AttackSpec] | None = None
    if suite_name is not None:
        suite_id = resolve_suite_id(suite_name)
        if not registry.has_suite(suite_id):
            known = ", ".join(sorted(s.id for s in registry.suites())) or "<none>"
            raise ScopeError(  # operational error surfaced to exit >2 by the caller
                f"suite {suite_name!r} (resolved to {suite_id!r}) is not registered. "
                f"Registered suites: {known}"
            )
        suite_specs = registry.resolve(suite_id)

    selected = select_specs(
        all_specs,
        suite_specs=suite_specs,
        categories=opts.categories,
        spec_globs=opts.spec_globs,
        exclude_globs=opts.exclude_globs,
        top_tests=opts.top_tests,
    )
    if not selected:
        # A selection that matches nothing used to run zero specs and exit 0: a green CI gate
        # over an empty battery, which is the worst possible answer to a typo in --spec.
        raise ValueError(
            "the selection matched no specs "
            f"(suite={suite_name!r}, categories={opts.categories or []}, "
            f"spec={opts.spec_globs or []}, exclude={opts.exclude_globs or []}); "
            "nothing would be tested. Check the selectors against `dottore registry ls`."
        )

    if opts.compare and len(loaded_targets) < 2:
        raise ValueError(
            "--compare renders a model-comparison matrix and needs two or more targets "
            f"(got {len(loaded_targets)}); pass -t/--target more than once."
        )

    timing = resolve_timing(
        opts.template,
        rate=opts.rate,
        concurrency=opts.concurrency,
        timeout_s=opts.timeout_s,
    )

    # Per-target routing decided once, here, so the preview and the run share it.
    routes = [(path, target, _route_for(opts, path)) for path, target in loaded_targets]
    any_live = any(real is not None for _, _, (_, real) in routes)
    # Pacing applies to traffic that leaves the process. An offline mock campaign is not
    # paced (there is nobody to be polite to, and pacing CI would only slow it); the plan
    # output says so out loud instead of quietly dropping the flag.
    pacing_rate = timing.rate_rps if any_live else None

    # -sV / -A: fingerprint before attacking, then let the plan use it.
    fingerprints: dict[str, ModelFingerprint] = {}
    if opts.fingerprint_first and not opts.discovery_only:
        for _, target, (_, real_target) in routes:
            fingerprints[target.id] = wiring.fingerprint_probe(
                scope, target, real_target=real_target
            )
    adaptive = opts.fingerprint_first or opts.deep

    plans = resolve_target_plans(
        scope=scope,
        targets=loaded_targets,
        specs=selected,
        runs=opts.runs,
        rate_rps=pacing_rate,
        fingerprints=fingerprints,
        adaptive=adaptive,
    )

    if opts.discovery_only:
        _print_discovery(plans, quiet=opts.quiet)
        return RunOutcome(exit_code=ExitCode.CLEAN, findings=[], results=[], dry_run=True)

    if opts.estimate:
        _print_estimate(plans, runs=opts.runs, quiet=opts.quiet)
        return RunOutcome(
            exit_code=ExitCode.CLEAN, findings=[], results=[], dry_run=True, estimated=True
        )

    if opts.dry_run or opts.verbose:
        _print_dry_run_plan(
            scope_path=opts.scope,
            plans=plans,
            suite=suite_name,
            runs=opts.runs,
            paced=pacing_rate is not None,
            rate_rps=timing.rate_rps,
            quiet=opts.quiet and opts.dry_run,
        )
    if opts.dry_run:
        return RunOutcome(exit_code=ExitCode.CLEAN, findings=[], results=[], dry_run=True)

    evidence_root = opts.evidence_root or Path(".dottore/evidence")
    run_db = opts.run_db or Path(".dottore/runs.sqlite")

    printer = ProgressPrinter(no_color=opts.no_color, quiet=opts.quiet)

    results: list[CampaignResult] = []
    all_findings: list[Finding] = []
    planned_specs = 0
    for (_, target, (mock_scenario, real_target)), plan in zip(routes, plans, strict=True):
        planned_specs += len(plan.selected) + len(plan.skipped_capability)
        result = _run_one_target(
            target=target,
            scope=scope,
            specs=selected,
            evidence_root=evidence_root,
            run_db=run_db,
            concurrency=timing.concurrency,
            timeout_s=timing.timeout_s,
            rate_rps=pacing_rate,
            n=opts.runs,
            mock_scenario=mock_scenario,
            real_target=real_target,
            judge_target=judge_target,
            budgets=plan.budgets,
            fingerprint=fingerprints.get(target.id),
            adaptive=adaptive,
        )
        results.append(result)
        _print_progress(printer, plan.selected, result.findings)
        all_findings.extend(result.findings)

    printer.summary(all_findings, specs_by_id, planned_specs=planned_specs)

    # A campaign that did not finish says so in all three places a consumer looks: the
    # terminal, the report and the exit code. The runner already computed this state and
    # every one of those three used to discard it, so a scan that dropped 27 of 72 specs
    # printed `total: 45, run: 45` and exited 0 - a denominator measured on the survivors.
    incomplete = {
        r.run.targets[0].id if r.run.targets else f"target-{i}": (r.status_reason or r.status)
        for i, r in enumerate(results)
        if r.status != "complete"
    }
    run_status = RunStatus(
        state=next((r.status for r in results if r.status != "complete"), "complete"),
        reason="; ".join(f"{k}: {v}" for k, v in sorted(incomplete.items())) or None,
    )
    for target_id, reason in sorted(incomplete.items()):
        printer.error(f"error: run on {target_id} did not complete: {reason}")

    report_paths = _write_reports(
        opts,
        results,
        all_findings,
        specs_by_id,
        planned_specs=planned_specs,
        run_status=run_status,
    )

    code = exit_code_for(
        all_findings,
        fail_on=opts.fail_on,
        include_needs_review=opts.include_needs_review,
        error=bool(incomplete),
    )
    return RunOutcome(
        exit_code=code,
        findings=all_findings,
        results=results,
        dry_run=False,
        report_paths=report_paths,
        incomplete=incomplete,
    )


def _refusal_for(scope: Scope, target: Target) -> str | None:
    """Why the scope does not authorize ``target``, or ``None`` when it does.

    Delegates to :func:`~ildottore.policy.authorize_target` so this pre-flight check and the
    per-attempt gate in the engine are literally the same predicate.
    """

    decision = authorize_target(scope, target.id, wiring.scope_endpoint_of(scope, target))
    return None if decision.allowed else (decision.reason or "not authorized by the scope")


def _route_for(opts: RunOptions, target_path: Path) -> tuple[str | None, Target | None]:
    """Decide the adapter route for one target: ``(mock_scenario, real_target)``.

    ``--hardened`` always forces the offline hardened replay (a mock-only flag); otherwise a
    target with no ``mock_scenario`` and a real, non-``mock://`` ``endpoint`` routes to the
    live provider adapter (u04). Anything else - including every existing mock-only
    ``target.yaml``, which never declares an endpoint - keeps resolving to the offline mock
    (contract §5).
    """

    if opts.hardened or wiring.target_uses_mock(target_path):
        scenario = "hardened" if opts.hardened else wiring.load_mock_scenario(target_path)
        return scenario, None
    return None, wiring.load_target(target_path)


def _run_one_target(
    *,
    target: Target,
    scope: Scope,
    specs: list[AttackSpec],
    evidence_root: Path,
    run_db: Path,
    concurrency: int,
    timeout_s: float,
    rate_rps: float | None,
    n: int,
    mock_scenario: str | None,
    real_target: Target | None = None,
    judge_target: Target | None = None,
    budgets: PlanBudgets | None = None,
    fingerprint: ModelFingerprint | None = None,
    adaptive: bool = False,
) -> CampaignResult:
    """Assemble a runner for one target and drive one campaign to completion.

    ``real_target`` (set only for a non-mock ``target.yaml``, see :func:`execute_run`)
    routes the campaign through :func:`wiring.real_adapter_factory` instead of the
    offline mock; ``mock_scenario`` is ``None`` in that case. ``judge_target`` (from
    ``--judge``) supplies the LLM-as-judge model for ``semantic_judge`` so a live scan
    yields decisive verdicts instead of abstaining.

    ``budgets`` are the ceilings derived from this target's own plan (see
    :func:`budgets_for`); ``fingerprint``/``adaptive`` carry ``-sV``/``-A`` into the plan.
    """

    built = wiring.build_runner(
        scope=scope,
        specs=specs,
        evidence_root=evidence_root,
        run_db=run_db,
        concurrency=concurrency,
        timeout_s=timeout_s,
        rate_rps=rate_rps,
        n=n,
        mock_scenario=mock_scenario,
        real_target=real_target,
        judge_target=judge_target,
    )
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    return asyncio.run(
        built.runner.run(
            run_id=run_id,
            target=target,
            specs=specs,
            fingerprint=fingerprint,
            adaptive=adaptive,
            budgets=budgets,
        )
    )


def _print_progress(
    printer: ProgressPrinter,
    specs: list[AttackSpec],
    findings: list[Finding],
) -> None:
    """Emit one progress line per finding in spec order."""

    by_spec = {f.spec_id: f for f in findings}
    total = len(specs)
    for i, spec in enumerate(specs, start=1):
        finding = by_spec.get(spec.id)
        if finding is not None:
            printer.progress(i, total, spec.id, finding)


def _write_reports(
    opts: RunOptions,
    results: list[CampaignResult],
    findings: list[Finding],
    specs_by_id: dict[str, AttackSpec],
    *,
    planned_specs: int | None = None,
    run_status: RunStatus | None = None,
) -> list[Path]:
    """Render every requested ``-o*`` report to disk; ``-oA`` writes all four formats.

    Uses the last target's :class:`TestRun` as the report envelope (a single-target
    run is the common case; ``--compare`` renders a matrix separately via ``-oJ``).
    Every reporter masks secrets/PII before serialization (u11).
    """

    if not results:
        return []
    run = results[-1].run
    outputs = dict(opts.outputs)
    if opts.output_all_prefix is not None:
        prefix = opts.output_all_prefix
        outputs.setdefault("json", prefix.with_suffix(".json"))
        outputs.setdefault("html", prefix.with_suffix(".html"))
        outputs.setdefault("sarif", prefix.with_suffix(".sarif"))
        outputs.setdefault("junit", prefix.with_suffix(".xml"))

    written: list[Path] = []
    for fmt, path in outputs.items():
        reporter = wiring.build_reporter(
            fmt, specs=specs_by_id, planned_specs=planned_specs, run_status=run_status
        )
        payload = reporter.render(run, findings)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        written.append(path)
    return written
