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
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ildottore.cli import resume as resume_mod
from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode, exit_code_for
from ildottore.cli.flags import QUICK_SUITE, resolve_suite_id, resolve_timing
from ildottore.cli.render import ProgressPrinter
from ildottore.core.budgets import Spend
from ildottore.core.planner import DEFAULT_PLAN_BUDGETS, IDENTITY_MUTATOR, build_plan
from ildottore.core.runner import CampaignResult
from ildottore.policy import Scope, authorize_target
from ildottore.policy.errors import PolicyError, ScopeError
from ildottore.reporting import RunStatus
from ildottore.shared.digest import spec_digests, target_digest
from ildottore.shared.enums import Category
from ildottore.shared.models import (
    AttackSpec,
    Finding,
    ModelFingerprint,
    PlanBudgets,
    Target,
    TestRun,
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
    # Explicit ceilings. The derived ones are clamped by BUDGET_DERIVATION_CAP, so these are
    # how an operator authorizes more than the derivation may grant itself.
    budget_tokens: int | None = None
    budget_requests: int | None = None
    budget_wall_s: int | None = None
    concurrency: int | None = None
    timeout_s: float | None = None
    runs: int = 5
    dry_run: bool = False
    estimate: bool = False
    #: ``--resume <run-id>``: finish a campaign that halted, reusing its run id and skipping
    #: the attempts already persisted in the evidence store.
    resume: str | None = None
    #: ``--resume-unverified``: continue a resume whose integrity record is missing (a run from
    #: before the record existed). Never a default: the missing record is also the missing
    #: SPEND record, so the invocation gets a fresh ceiling and the operator has to say so.
    resume_unverified: bool = False
    #: True when the operator typed ``--runs``. A resume without it INHERITS the campaign's
    #: sample size instead of refusing: the check exists so one report never scores some specs
    #: over three samples and others over five, and inheriting achieves that without making
    #: the operator remember a number the store already knows.
    runs_explicit: bool = False
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

#: The absolute cap on a DERIVED ceiling, and the reason it exists: without it, the plan sets
#: its own limit, so a spec pack sets the scanner's self-DoS bound. Measured on a pack nobody
#: would call hostile (200 specs, an ordinary 8k completion, 4 mutations): a 61-million-token
#: allowance, 123 times the old constant. The point of a budget is that something other than
#: the input decides the maximum, so the derivation is clamped here and an operator who
#: really needs more says so explicitly with ``--budget-tokens`` / ``--budget-requests``.
#: The shipped battery at the default ``--runs 5`` derives ~722k tokens and ~750 requests, so
#: these caps leave room for a battery several times larger before anyone has to think.
BUDGET_DERIVATION_CAP = PlanBudgets(
    max_tokens=5_000_000,
    max_requests=20_000,
    max_wall_s=7_200,
    max_attempts=20_000,
)


def budgets_for(
    estimate: PlanEstimate,
    *,
    rate_rps: float | None = None,
    overrides: PlanBudgets | None = None,
) -> PlanBudgets:
    """Hard ceilings sized from the plan, never below the defaults, never above the cap.

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

    Three bounds, in order: the conservative floor (:data:`DEFAULT_PLAN_BUDGETS`), the value
    derived from this plan, and the absolute :data:`BUDGET_DERIVATION_CAP`. ``overrides`` is
    the operator's own word (``--budget-tokens`` and friends) and wins outright on the axes it
    names, cap included: a human raising a ceiling is the authorization the derivation is not.
    """

    def _axis(floor: int | None, derived: int, cap: int | None, override: int | None) -> int:
        if override is not None:
            return override
        return min(max(floor or 0, derived), cap or derived)

    o = overrides if overrides is not None else PlanBudgets()
    tokens = int(estimate.total_tokens * BUDGET_HEADROOM)
    requests = int(estimate.requests * BUDGET_HEADROOM)
    wall_s = DEFAULT_PLAN_BUDGETS.max_wall_s or 0
    if rate_rps is not None and rate_rps > 0:
        wall_s = max(wall_s, int(estimate.requests / rate_rps * BUDGET_HEADROOM) + 1)
    return PlanBudgets(
        max_tokens=_axis(
            DEFAULT_PLAN_BUDGETS.max_tokens, tokens, BUDGET_DERIVATION_CAP.max_tokens, o.max_tokens
        ),
        max_requests=_axis(
            DEFAULT_PLAN_BUDGETS.max_requests,
            requests,
            BUDGET_DERIVATION_CAP.max_requests,
            o.max_requests,
        ),
        max_wall_s=_axis(
            DEFAULT_PLAN_BUDGETS.max_wall_s, wall_s, BUDGET_DERIVATION_CAP.max_wall_s, o.max_wall_s
        ),
        max_attempts=_axis(
            DEFAULT_PLAN_BUDGETS.max_attempts,
            requests,
            BUDGET_DERIVATION_CAP.max_attempts,
            o.max_attempts,
        ),
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
    budget_overrides: PlanBudgets | None = None,
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
                budgets=budgets_for(estimate, rate_rps=rate_rps, overrides=budget_overrides),
                mutators_by_spec=mutators_by_spec,
            )
        )
    return plans


def fingerprint_probe_count() -> int:
    """How many requests one ``-sV`` pass costs per target.

    Printed in the resolved plan because ``-sV`` is the one flag that sends *before* the
    battery does, and because the carrier layer made a fingerprint pass roughly three times
    more expensive than it was (one probe per registered mutator).
    """

    # Each layer declares its own count, because "one probe per layer" was a guess and it was
    # wrong for three of the six: behavioral sends 4, statistical 3 and capability 0 (it reads
    # the declared capabilities without asking the target anything). The figure was published
    # as 24 while a pass really sent 28.
    return sum(
        getattr(layer, "probe_count", 1) for layer in wiring.build_fingerprint_engine().layers
    )


def _safe_endpoint(endpoint: str) -> str:
    """Mask an endpoint before printing it. A stdio MCP target's "endpoint" is a COMMAND LINE.

    ``stdio:///usr/bin/env node server.js --token sk-...`` was printed verbatim by ``-sn`` and
    by ``--dry-run``, the two commands an operator runs with least suspicion and whose output
    lands in tickets and CI logs. The repo already ships a redactor that masks exactly that
    token; these printers simply were not routed through it.
    """

    from ildottore.reporting import default_redactor

    return str(default_redactor().redact(endpoint))


def _print_estimate(
    plans: list[TargetPlan],
    *,
    runs: int,
    quiet: bool = False,
    fingerprint_probes: int = 0,
    already_done: int = 0,
) -> None:
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
    if already_done:
        # `--estimate --resume` priced the whole battery, when the point of the flag is to
        # price the work that is LEFT.
        print(
            f"  minus {already_done} attempt(s) already completed in the resumed run "
            f"(~{max(0, requests - already_done)} still to send)"
        )
    if fingerprint_probes:
        # The one mode whose entire job is pre-run cost used to omit the probe pass entirely,
        # so `--estimate -sV` priced 3 requests for a command that would send 31.
        total = fingerprint_probes * len(plans)
        print(
            f"  + {total} fingerprint probe(s) before the battery (-sV: "
            f"{fingerprint_probes} per target across {len(plans)})"
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
    fingerprint_probes: int = 0,
    explicit_rate: float | None = None,
    quiet: bool = False,
    sending: bool = False,
    detail: int = 0,
) -> None:
    """Print the resolved plan (one line under ``--quiet``).

    ``--dry-run`` exists to answer "is my wiring right?", which it cannot do without showing
    what it resolved: which scope authorized which target *at which endpoint*, which battery
    survived both filters, and what the run would really cost. Under ``-q`` it prints a single
    machine-friendly line rather than nothing: a command whose only output is its exit code
    cannot answer the question it exists for.

    ``sending=True`` is the ``-v`` case, where the same plan is printed and the run then
    proceeds. It changes the wording, because ``-v`` reused this verbatim and announced
    "dry-run: plan resolved, sent nothing." immediately before sending. ``detail`` is the
    ``-v`` count: at ``-vv`` the skipped and blocked spec ids are listed, not just counted.
    """

    requests = sum(p.estimate.requests for p in plans)
    specs = sum(len(p.selected) for p in plans)
    headline = "resolved, sending now." if sending else "plan resolved, sent nothing."
    label = "plan" if sending else "dry-run"
    if quiet:
        print(f"{label}: {specs} specs, {requests} requests, {len(plans)} target(s)")
        return
    print(f"{label}: {headline}")
    print(f"  scope:   {scope_path}")
    for plan in plans:
        # The authorized ENDPOINT, not the words "authorized by the scope": a scope naming
        # the target with an empty endpoint list is the exact case that used to read green.
        print(
            f"  target:  {plan.target.id} ({plan.target.type.value}) "
            f"authorized at {_safe_endpoint(plan.endpoint)}"
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
            if detail >= 2:
                for spec_id, reason in plan.skipped_capability:
                    print(f"    - {spec_id}: {reason}")
        if plan.blocked_by_policy:
            print(
                f"  blocked: {len(plan.blocked_by_policy)} spec(s) on {plan.target.id}, "
                "refused by the policy pack"
            )
            if detail >= 2:
                for spec_id, reason in plan.blocked_by_policy:
                    print(f"    - {spec_id}: {reason}")
    print(f"  would send: {requests} requests over {specs} specs at runs={runs}")
    if fingerprint_probes:
        print(
            f"  fingerprint: +{fingerprint_probes} probe(s) per target before the battery "
            "(-sV), not sent by a dry run"
        )
    if paced and rate_rps:
        print(f"  pacing:  {rate_rps} req/s ceiling (S8)")
    elif explicit_rate is not None:
        # Only when the OPERATOR asked for a rate. Saying "5.0 req/s requested" about the
        # timing template's own default reads as an ignored instruction that nobody gave.
        print(
            f"  pacing:  not applied ({explicit_rate} req/s requested) - this is an offline "
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
        print(f"    endpoint:  {_safe_endpoint(plan.endpoint)} (authorized by the scope)")
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
        # A stdio MCP target is authorized by its COMMAND LINE, not by an endpoint, and the
        # generic advice ("allowlist the endpoint") pointed at the wrong field. The spelling
        # matters too: the scope's `commands` entries are matched against the joined argv, so
        # the exact string is printed rather than left to the reader to reconstruct.
        stdio_hint = ""
        for _, target in to_authorize:
            if (target.transport or "").strip().lower() == "stdio" and target.command:
                joined = " ".join(target.command)
                stdio_hint = (
                    f" {target.id!r} is a stdio MCP target, so it is authorized by its "
                    f'command line, not by an endpoint: add commands: ["{joined}"] to its '
                    "scope entry (one string, exactly as shown)."
                )
                break
        raise ScopeError(
            f"target(s) not authorized by the scope: {'; '.join(sorted(refusals))}. "
            f"The scope authorizes: {authorized}. A target id must match a scope entry "
            "exactly and that entry must allowlist the endpoint the target uses; add it "
            f"or point --scope elsewhere.{stdio_hint}"
        )
    # Credential authorization, pre-flight, for the judge AND for every attack target. Only
    # the judge got this check, so `--dry-run` printed a green plan for a target whose
    # auth_ref the scope refuses and the real run then failed at exit 3: the command whose
    # job is answering "is my wiring right?" gave the wrong answer about the credential.
    for _, candidate in to_authorize:
        wiring.check_target_credential(scope, candidate)

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

    if opts.resume is not None and len(loaded_targets) != 1:
        # A campaign stores one run id per target, so "resume this run" names exactly one.
        raise ValueError(
            f"--resume names a single run ({opts.resume!r}) and therefore a single target; "
            f"got {len(loaded_targets)}. Resume each target's run id in its own invocation."
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
    # Both store paths are resolved here, before anything can send: the probe pass files its
    # evidence under the run id, and the resume block reads the prior run's evidence and asks
    # the run store which target it belonged to.
    evidence_root = opts.evidence_root or Path(".dottore/evidence")
    run_db = opts.run_db or Path(".dottore/runs.sqlite")

    routes = [(path, target, _route_for(opts, path)) for path, target in loaded_targets]
    any_live = any(real is not None for _, _, (_, real) in routes)
    # Pacing applies to traffic that leaves the process. An offline mock campaign is not
    # paced (there is nobody to be polite to, and pacing CI would only slow it); the plan
    # output says so out loud instead of quietly dropping the flag.
    pacing_rate = timing.rate_rps if any_live else None

    # Resolved BEFORE the fingerprint pass, which SENDS. It used to sit after it, so
    # `-sV --resume <id-of-a-changed-battery>` put 17 probes on a real endpoint with a real
    # bearer token and then exited 3 having done no work. Nothing here needs the fingerprint.
    resume_from: TestRun | None = None
    if opts.resume is not None:
        resume_from = resume_mod.load_resume_run(
            evidence_root,
            opts.resume,
            loaded_targets[0][1],
            run_db=run_db,
            specs=selected,
            mock_scenario=routes[0][2][0],
            runs=opts.runs if opts.runs_explicit else None,
            allow_unverified=opts.resume_unverified,
        )
        inherited = resume_mod.stored_runs(run_db, opts.resume)
        if not opts.runs_explicit and inherited is not None and inherited != opts.runs:
            opts.runs = inherited
            if not opts.quiet:
                print(f"resume: continuing at --runs {inherited}, as the halted campaign ran")
        if not opts.quiet:
            done = sum(len(f.attempts) for f in resume_from.findings)
            print(
                f"resume: {opts.resume} has {done} completed attempt(s) across "
                f"{len(resume_from.findings)} spec(s); they will not be re-sent"
            )

    # -sV / -A: fingerprint before attacking, then let the plan use it.
    #
    # NOT under --dry-run/--estimate/-sn: fingerprinting SENDS (ten probes per target), and
    # those three commands promise the opposite. The guard used to exclude -sn only, so
    # `--dry-run -sV` printed "dry-run: plan resolved, sent nothing." after posting ten live
    # requests with a real bearer token, and `--quick --dry-run` is the first command the
    # README teaches. A no-send promise has to hold for every combination, not the ones that
    # happened to be tested.
    fingerprints: dict[str, ModelFingerprint] = {}
    sends_nothing = opts.discovery_only or opts.dry_run or opts.estimate
    if opts.fingerprint_first and opts.budget_requests is not None:
        # An explicit request ceiling has to bind the probe pass too. It did not: the ledger
        # lives in the runner and the probes never reach it, so `--budget-requests 2 -sV`
        # sent 30 requests and then announced "budget ceiling reached (limit 2, attempted 3)",
        # counting only the attack traffic. Checked here, before anything is sent, because the
        # fingerprint is what feeds the plan the ledger is later derived from.
        probe_total = fingerprint_probe_count() * len(loaded_targets)
        if probe_total > opts.budget_requests:
            raise ValueError(
                f"-sV sends {probe_total} probe(s) ({fingerprint_probe_count()} per target "
                f"across {len(loaded_targets)}), which is more than the --budget-requests "
                f"ceiling of {opts.budget_requests}. Raise the ceiling or drop -sV: the probe "
                "pass is traffic to the target like any other."
            )
    # One run id per target, minted HERE rather than inside the campaign, because the probe
    # pass happens first and its evidence has to file under the run it belongs to. A resumed
    # campaign keeps the original id (the evidence and the run store are keyed by it).
    run_ids = {
        target.id: (opts.resume if opts.resume is not None else f"run-{uuid.uuid4().hex[:12]}")
        for _, target in loaded_targets
    }

    if opts.fingerprint_first and not sends_nothing:
        probe_store = wiring.build_evidence_store(evidence_root, planted_canaries=[])
        for _, target, (mock_scenario, real_target) in routes:
            fingerprints[target.id] = wiring.fingerprint_probe(
                scope,
                target,
                real_target=real_target,
                rate_rps=pacing_rate,
                evidence=probe_store,
                run_id=run_ids[target.id],
                mock_scenario=mock_scenario,
            )
    if fingerprints and not opts.quiet:
        # Which targets were fingerprinted against a canned offline mock rather than over the
        # wire. The line printed `family=meta-llama (confidence 0.67) version=llama-3-8b` for a
        # mock, and the caveat that this is an offline fixture lived in six documents and not
        # in the one line anybody actually reads. An audit read it off the terminal as a result.
        offline = {target.id: scenario for _, target, (scenario, _) in routes if scenario}
        for target_id, fingerprint in sorted(fingerprints.items()):
            family = fingerprint.family
            version = fingerprint.version
            scenario = offline.get(target_id)
            print(
                f"fingerprint: {target_id} "
                + (f"[offline mock: {scenario}] " if scenario is not None else "")
                + (
                    f"family={family.guess} (confidence {family.confidence:.2f})"
                    if family is not None
                    else "family=unknown"
                )
                + (f" version={version.guess}" if version is not None else "")
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
        budget_overrides=PlanBudgets(
            max_tokens=opts.budget_tokens,
            max_requests=opts.budget_requests,
            max_wall_s=opts.budget_wall_s,
        ),
    )

    # A target with nothing left to run is refused, for the same reason an empty --spec
    # selection is: it would otherwise scan nothing, report coverage percentages over the
    # findings of specs that never sent a request, and exit 0. Reproduced by the audit with
    # three policy-blocked specs: "3 of 0 planned", exit 0, zero requests.
    barren = [
        f"{p.target.id} ({len(p.skipped_capability)} skipped for capabilities, "
        f"{len(p.blocked_by_policy)} blocked by policy)"
        for p in plans
        if not p.selected
    ]
    if barren and not opts.discovery_only:
        raise ValueError(
            "nothing would be sent: every selected spec is unrunnable on "
            f"{'; '.join(barren)}. Widen the selection, declare the capability on the "
            "target, or enable the category in the policy pack."
        )

    # Resolved BEFORE the three modes that send nothing, so a typo in the id is caught by the
    # command whose job is validation, and so the estimate prices the work that is actually
    # left. They used to return first, so `--dry-run --resume run-totally-bogus` exited 0
    # without a word and `--estimate --resume` priced the whole battery.
    if opts.discovery_only:
        _print_discovery(plans, quiet=opts.quiet)
        return RunOutcome(exit_code=ExitCode.CLEAN, findings=[], results=[], dry_run=True)

    if opts.estimate:
        _print_estimate(
            plans,
            runs=opts.runs,
            quiet=opts.quiet,
            fingerprint_probes=(fingerprint_probe_count() if opts.fingerprint_first else 0),
            already_done=sum(len(f.attempts) for f in resume_from.findings) if resume_from else 0,
        )
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
            fingerprint_probes=(fingerprint_probe_count() if opts.fingerprint_first else 0),
            explicit_rate=opts.rate,
            quiet=opts.quiet and opts.dry_run,
            sending=not opts.dry_run,
            detail=opts.verbose,
        )
    elif pacing_rate is None and opts.rate is not None and not opts.quiet:
        # An ignored flag has to be announced on the path the operator is actually using.
        # This notice existed only inside the plan block, so a plain run silently dropped
        # --rate: two of the four paths honoured what the threat model claims.
        print(
            f"note: --rate {opts.rate} is not applied to an offline mock run "
            "(nothing leaves the process)"
        )
    if opts.dry_run:
        return RunOutcome(exit_code=ExitCode.CLEAN, findings=[], results=[], dry_run=True)

    printer = ProgressPrinter(no_color=opts.no_color, quiet=opts.quiet)

    # A resumed campaign opens its ledger where the halted one stopped. Read once, before the
    # loop: `--resume` names a single target, so there is one prior spend to carry.
    prior_spend = (
        _prior_spend(run_db, opts.resume, plans[0].budgets) if opts.resume is not None else None
    )

    results: list[CampaignResult] = []
    all_findings: list[Finding] = []
    planned_specs = 0
    for (_, target, (mock_scenario, real_target)), plan in zip(routes, plans, strict=True):
        # The denominator is the WHOLE selected battery for this target, because the runner
        # emits a finding for a capability-skipped spec and for a policy-blocked one too: they
        # are reported, not dropped. Counting only `selected + skipped_capability` left the
        # two policy-blocked specs out of the denominator while their findings stayed in the
        # numerator, and a complete run published "Specs run: 72 of 70 planned", i.e. 102.9%.
        # Exactly the shape this whole branch exists to remove, introduced by the fix for it.
        planned_specs += len(selected)
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
            resume_from=resume_from,
            run_id=run_ids[target.id],
            prior_spend=prior_spend,
        )
        results.append(result)
        _persist_run_context(
            run_db,
            result,
            selected,
            target=target,
            mock_scenario=mock_scenario,
            runs=opts.runs,
        )
        _print_progress(printer, plan.selected, result.findings)
        all_findings.extend(result.findings)

    printer.summary(all_findings, specs_by_id, planned_specs=planned_specs)

    # A campaign that did not finish says so in all three places a consumer looks: the
    # terminal, the report and the exit code. The runner already computed this state and
    # every one of those three used to discard it, so a scan that dropped 27 of 72 specs
    # printed `total: 45, run: 45` and exited 0 - a denominator measured on the survivors.
    incomplete: dict[str, str] = {}
    states: list[str] = []
    for i, result in enumerate(results):
        target_id = result.run.targets[0].id if result.run.targets else f"target-{i}"
        if result.status != "complete":
            incomplete[target_id] = result.status_reason or result.status
            states.append(result.status)
            continue
        # A target that is authorized but NOT REACHABLE completed in the runner's sense and
        # is a failed scan in every other sense: every attempt died on transport, so every
        # verdict is inconclusive and the reason lives only inside the evidence. That is the
        # same false green the scope gate was fixed for, one layer further out, so it gets
        # the same treatment rather than a clean exit over a report of nothing.
        unreachable = _unreachable_reason(result)
        if unreachable is not None:
            incomplete[target_id] = unreachable
            states.append("unreachable")
    run_status = RunStatus(
        state=states[0] if states else "complete",
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


def _unreachable_reason(result: CampaignResult) -> str | None:
    """Why this target counts as unreachable, or ``None`` when it does not.

    Unreachable means: attempts were made, **every** attempt failed on transport (an error
    and no response), and therefore nothing was actually evaluated. One flaky endpoint or one
    bad spec is not this, because the run still measured something.
    """

    attempts = [a for finding in result.findings for a in finding.attempts]
    if not attempts:
        return None  # nothing was attempted: a barren plan, refused before the run
    if any(a.error is None and a.response is not None for a in attempts):
        return None
    first = next((a.error for a in attempts if a.error), "no response")
    return (
        f"every one of the {len(attempts)} attempt(s) failed on transport, so nothing was "
        f"evaluated: {first}"
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
    resume_from: TestRun | None = None,
    run_id: str | None = None,
    prior_spend: Spend | None = None,
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
    # A resumed campaign keeps the ORIGINAL run id: the evidence and the store are keyed by
    # it, and a new id would file the continuation as a separate, equally partial run. The
    # caller mints it (the probe pass needs it first), and falls back for direct callers.
    if run_id is None:
        run_id = resume_from.run_id if resume_from is not None else f"run-{uuid.uuid4().hex[:12]}"
    return asyncio.run(
        built.runner.run(
            run_id=run_id,
            target=target,
            specs=specs,
            fingerprint=fingerprint,
            adaptive=adaptive,
            budgets=budgets,
            resume_from=resume_from,
            prior_spend=prior_spend,
        )
    )


def _prior_spend(run_db: Path, run_id: str, budgets: PlanBudgets | None = None) -> Spend | None:
    """What a halted run already consumed, so its resume does not get a fresh ceiling.

    ``None`` when the store holds no spend for that run. That case is NOT silent: it is the
    same missing integrity record the resume checks refuse on, so reaching here with no record
    means the operator passed ``--resume-unverified`` and has been told that this invocation's
    ceiling covers this invocation alone.
    """

    from ildottore.store.run_sqlite import SqliteRunStore

    if not Path(run_db).exists():
        return None
    with SqliteRunStore(Path(run_db)) as store:
        stored = store.get_run_spend(run_id)
    if not stored:
        print(
            f"resume: no spend was recorded for run {run_id!r}, so this invocation's budget "
            "ceiling applies to this invocation alone and not to the campaign. What the "
            "halted half already cost is not known to this tool.",
            file=sys.stderr,
        )
        return None
    prior = Spend(
        tokens=int(stored.get("tokens", 0)),
        requests=int(stored.get("requests", 0)),
        attempts=int(stored.get("attempts", 0)),
        wall_s=float(stored.get("wall_s", 0.0)),
    )
    ceiling = budgets.max_wall_s if budgets is not None else None
    if ceiling is not None and prior.wall_s >= ceiling:
        raise ValueError(
            f"run {run_id!r} already spent {prior.wall_s:.1f}s of its {ceiling}s wall-clock "
            "ceiling, which the campaign's budget covers as a whole. Resuming it would do no "
            "work and halt again on the same axis. Raise --budget-wall-s for this campaign, or "
            "start a fresh run."
        )
    return prior


def _persist_run_context(
    run_db: Path,
    result: CampaignResult,
    specs: list[AttackSpec],
    *,
    target: Target,
    mock_scenario: str | None,
    runs: int,
) -> None:
    """Record the battery this run executed and what it has spent in total.

    Written after every campaign, not only a halted one: the halt is exactly when nobody is
    in a position to do it later, and a run that completed can still be resumed by mistake.
    """

    from ildottore.store.run_sqlite import SqliteRunStore

    with SqliteRunStore(Path(run_db)) as store:
        store.save_run_context(
            result.run.run_id,
            spec_digests=spec_digests(specs),
            context={
                "target_digest": target_digest(target, mock_scenario=mock_scenario),
                "runs": runs,
            },
            spend={
                "tokens": result.spend.tokens,
                "requests": result.spend.requests,
                "attempts": result.spend.attempts,
                "wall_s": round(result.spend.wall_s, 6),
            },
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
    # The envelope is the last target's run, but the findings and the denominator are summed
    # across every target, so a multi-target report used to name ONE target while its status
    # named another: a reader could not find the truncated target in the document at all.
    run = results[-1].run
    if len(results) > 1:
        seen: dict[str, Target] = {}
        for result in results:
            for target in result.run.targets:
                seen.setdefault(target.id, target)
        run = run.model_copy(update={"targets": list(seen.values())})
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
