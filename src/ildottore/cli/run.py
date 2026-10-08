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
import json
import os
import shutil
import signal
import stat
import sys
import unicodedata
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ildottore.cli import resume as resume_mod
from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode, exit_code_for, fail_on_band
from ildottore.cli.flags import QUICK_SUITE, resolve_suite_id, resolve_timing
from ildottore.cli.render import ProgressPrinter
from ildottore.core.budgets import DEFAULT_COMPLETION_TOKENS, BudgetLedger, Spend
from ildottore.core.planner import DEFAULT_PLAN_BUDGETS, IDENTITY_MUTATOR, build_plan
from ildottore.core.runner import CampaignResult, answered_attempt_ids, resume_progress
from ildottore.core.setup_delivery import (
    MAX_TOOL_ROUNDS,
    delivers_in_band,
    in_band_setup,
    seeded_canaries,
    seeding_gap,
    trace_gap,
)
from ildottore.policy import Scope, authorize_target
from ildottore.policy.errors import PolicyError, ScopeError
from ildottore.reporting import RunStatus
from ildottore.shared.config_errors import cut, listed, quoted
from ildottore.shared.digest import spec_digests, target_digest
from ildottore.shared.enums import Category, EvaluatorType
from ildottore.shared.models import (
    AttackSpec,
    Finding,
    ModelFingerprint,
    PlanBudgets,
    Target,
    TestRun,
    TestRunSummary,
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


class SpecLoadError(ValueError):
    """Spec files failed to load, so the run is refused rather than run on what parsed.

    ``spec_files`` are the names the CLI prints in clear: each is a path relative to a spec root
    that names an entry on disk under it. Whoever wrote the spec tree chose it (the operator, or
    the author of a pack they installed), so it carries nothing of this run, and it is what the
    operator has to find; a credential or PII shape inside it is still masked by the value and
    shape rules. The entropy rule masked them (`attacks/DL-PII-ELICIT-001.yaml` read
    `«REDACTED:high_entropy:…».yaml`), so the refusal could not say which file to fix (pre-merge
    audit of PR #47).
    """

    def __init__(self, message: str, *, spec_files: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.spec_files = spec_files


def _spec_files_on_disk(spec_paths: list[Path], names: list[str]) -> tuple[str, ...]:
    """The ``names`` that are a relative path to an entry on disk under one of ``spec_paths``.

    An entry, not only a regular file: a directory or a dangling link named ``*.yaml`` fails to
    load too, and its name is just as much the tree's. A spec path given as a file is its
    own parent's tree, as the loader displays it. ``os.path.lexists`` answers False, never
    raises, for a name the filesystem refuses (too long, a NUL byte).
    """

    roots = [path if path.is_dir() else path.parent for path in spec_paths]
    return tuple(
        name
        for name in dict.fromkeys(names)
        if not Path(name).is_absolute()
        and ".." not in Path(name).parts
        and any(os.path.lexists(root / name) for root in roots)
    )


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
    #: Requests to the ``--judge`` model and their rough token volume. Counted apart, because
    #: they go to another endpoint, and counted at all, because they debit the same ceiling:
    #: `--estimate --judge` used to print the same figure as without a judge (audit D-28).
    judge_requests: int = 0
    judge_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens + self.judge_tokens

    @property
    def total_requests(self) -> int:
        return self.requests + self.judge_requests


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
    # OD-18 B: specs that need the deployment's scene and that its target file does not declare
    # seeded. The runner reports them (`setup_not_seeded`) and sends nothing for them.
    not_seeded: list[tuple[str, str]] = field(default_factory=list)  # (spec id, reason)


def _effective_mutators(spec: AttackSpec) -> list[str]:
    """The mutators a spec will really run: ``identity`` plus its declared list, de-duplicated.

    Mirrors ``core.planner._select_mutators``. The estimate used to count
    ``len(spec.mutations or ["identity"])``, which under-counts every spec that declares
    mutations without repeating ``identity``: the planner always prepends the un-mutated
    baseline carrier, so a spec declaring one mutation runs two attempts, not one.
    """

    ordered = [IDENTITY_MUTATOR, *(spec.mutations or [])]
    return list(dict.fromkeys(ordered))


#: Requests the judge sends per evaluated attempt (``SemanticJudgeEvaluator`` self-consistency
#: passes, minimum 2), and the rough token gloss of one: the rubric and delimiters around the
#: target's reply on the way in, a short JSON verdict on the way out.
JUDGE_PASSES = 2
JUDGE_RUBRIC_TOKENS = 400
JUDGE_OUTPUT_TOKENS = 200


def estimate_plan(
    specs: list[AttackSpec],
    runs: int,
    *,
    mutators_by_spec: dict[str, list[str]] | None = None,
    judge: bool = False,
    target: Target | None = None,
    fixtures_hold_scene: bool = False,
) -> PlanEstimate:
    """Estimate the wire cost of a plan without sending: requests + rough token volume.

    ``requests`` = sum over specs of ``mutators x runs x turns``. A spec whose setup goes out
    in-band to ``target`` (OD-18) counts each turn with every tool round it may play, so the
    ceilings derived from this cover the worst case: a turn of a tool spec is up to
    ``1 + MAX_TOOL_ROUNDS`` sends, and its input carries the documents and tool definitions.
    A spec that needs a deployment's scene (OD-18 B) and is not declared seeded sends nothing,
    so it costs nothing, unless ``fixtures_hold_scene`` (the offline mock, whose fixtures are
    written for the scene).
    ``mutators_by_spec`` (from a resolved :class:`~ildottore.shared.models.TestPlan`) is
    authoritative when given; absent it, :func:`_effective_mutators` reproduces what the
    planner would choose. Tokens
    are a deliberately rough gloss (prompt length / 4 for input; the spec's
    ``sampling.max_tokens`` or 512 for output). No per-model pricing is known, so this
    reports volume, not a dollar figure.
    """

    total_requests = 0
    total_in = 0
    total_out = 0
    judge_requests = 0
    judge_tokens = 0
    by_category: dict[str, int] = {}
    for spec in specs:
        if (
            target is not None
            and not fixtures_hold_scene
            and (
                seeding_gap(spec, target)
                or trace_gap(
                    spec,
                    target,
                    returns_tool_calls=wiring.provider_returns_tool_calls(target),
                )
            )
        ):
            continue  # setup_not_seeded: the runner sends nothing for it (OD-18 B)
        mutators = (mutators_by_spec or {}).get(spec.id) or _effective_mutators(spec)
        turns = spec.attack.turns
        n_turns = len(turns) if turns is not None and len(turns) >= 2 else 1
        prompt = spec.attack.user_prompt or spec.attack.carrier or (turns[0] if turns else "")
        sends_per_turn = 1
        if target is not None and delivers_in_band(spec, target):
            scene = in_band_setup(spec)
            if scene.tools and not spec.attack.media:
                sends_per_turn += MAX_TOOL_ROUNDS
            prompt = (
                scene.memory
                + scene.context
                + prompt
                + (json.dumps(scene.tools) if scene.tools else "")
            )
        requests = len(mutators) * runs * n_turns * sends_per_turn
        in_tokens = max(1, len(prompt) // 4)
        out_tokens = (
            spec.sampling.max_tokens
            if spec.sampling is not None and spec.sampling.max_tokens
            else DEFAULT_COMPLETION_TOKENS
        )
        total_requests += requests
        total_in += requests * in_tokens
        total_out += requests * out_tokens
        by_category[spec.category.value] = by_category.get(spec.category.value, 0) + requests
        if judge and any(e.type is EvaluatorType.SEMANTIC_JUDGE for e in spec.evaluators):
            # One judgement per attempt (the final reply of a conversation), not per turn.
            judged = len(mutators) * runs * JUDGE_PASSES
            judge_requests += judged
            judge_tokens += judged * (
                in_tokens + out_tokens + JUDGE_RUBRIC_TOKENS + JUDGE_OUTPUT_TOKENS
            )
    return PlanEstimate(
        specs=len(specs),
        requests=total_requests,
        input_tokens=total_in,
        output_tokens=total_out,
        by_category=by_category,
        judge_requests=judge_requests,
        judge_tokens=judge_tokens,
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

#: The largest value an integer flag of ``run`` takes: ``2**53``, the last of the run of whole
#: numbers a float holds exactly. The plan multiplies ``--runs`` into float arithmetic, and a
#: ``--runs`` of 306 digits was an ``OverflowError`` there with one spec, a traceback with exit
#: 1 (pre-commit audit of ``fix/huge-int-repr``, F6, A-55). No flag needs more:
#: ``--budget-wall`` of ``2**53`` seconds is 285 million years.
MAX_FLAG_VALUE = 2**53


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
    requests = int(estimate.total_requests * BUDGET_HEADROOM)
    wall_s = DEFAULT_PLAN_BUDGETS.max_wall_s or 0
    if rate_rps is not None and rate_rps > 0:
        # Bounded before int(): a rate near zero made the quotient infinite, and int() of it was
        # an OverflowError, a traceback with exit 1 (`--rate 1e-308`, A-55). Anything past the
        # bound is past the cap, which bounds the result below as it did.
        paced = estimate.total_requests / rate_rps * BUDGET_HEADROOM
        wall_s = max(wall_s, int(min(paced, MAX_FLAG_VALUE)) + 1)
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
    targets: list[wiring.TargetFile],
    specs: list[AttackSpec],
    runs: int,
    rate_rps: float | None = None,
    fingerprints: dict[str, ModelFingerprint] | None = None,
    adaptive: bool = False,
    budget_overrides: PlanBudgets | None = None,
    judge: bool = False,
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
    for loaded in targets:
        path, target = loaded.path, loaded.target
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
        # The offline mock replays the specs' fixtures, written for the scene, so it holds every
        # scene; a live deployment holds only those its operator declared seeded (OD-18 B).
        fixtures_hold_scene = loaded.uses_mock
        # The runner's own questions (``setup_delivery.seeding_gap`` and ``trace_gap``): not
        # declared, a per-run canary with no run_token, two scene tools under one deployment
        # name, or a trace spec through an adapter that reads no tool calls.
        calls_visible = wiring.provider_returns_tool_calls(target)
        not_seeded = [
            (spec.id, gap)
            for spec in runnable
            if not fixtures_hold_scene
            and (
                gap := seeding_gap(spec, target)
                or trace_gap(spec, target, returns_tool_calls=calls_visible)
            )
            is not None
        ]
        unseeded = {spec_id for spec_id, _ in not_seeded}
        runnable = [spec for spec in runnable if spec.id not in unseeded]
        estimate = estimate_plan(
            runnable,
            runs,
            mutators_by_spec=mutators_by_spec,
            judge=judge,
            target=target,
            fixtures_hold_scene=fixtures_hold_scene,
        )
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
                not_seeded=not_seeded,
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


def _probe_pass_remedy(adaptive_campaign: bool, *, attack_room: bool) -> str:
    """The advice of a refusal because the ``-sV`` probe pass does not fit the request ceiling.

    Every half of it has to let the invocation through (u12 A-48). Dropping ``-sV`` turns
    adaptive planning off, and a resume of a campaign that planned adaptively is refused for
    that, so there it is not offered: the advice was "Raise --budget-requests, or drop -sV"
    for every campaign, and dropping ``-sV`` was refused again for one run with ``-sV`` or
    ``--deep``. Nor is it offered when the ceiling cannot hold the rest of the campaign without
    the probes either (``attack_room`` false, see :func:`_fits_without_probes`): a resume whose
    spend left one request of room halted after it, exit 3, keeping nothing.
    """

    if adaptive_campaign:
        return (
            "Raise --budget-requests (the campaign ran with adaptive planning, which its resume "
            "has to keep)"
        )
    if not attack_room:
        return (
            "Raise --budget-requests (without the probes, it would still not hold the rest of "
            "the campaign)"
        )
    return "Raise --budget-requests, or drop -sV"


def _fits_without_probes(plans: list[TargetPlan], ceiling: int, *, spent: int, done: int) -> bool:
    """Whether the rest of every target's campaign fits ``ceiling`` with no probe pass.

    ``spent`` is the spend the campaign has on record, ``done`` the requests a resume does not
    send again (:func:`_answered_requests`); the rest is priced as ``--estimate`` prices it.
    """

    return all(spent + max(0, plan.estimate.total_requests - done) <= ceiling for plan in plans)


def _no_judge_warning(
    plans: list[TargetPlan], routes: list[Any], judge_target: Target | None
) -> str | None:
    """Say, before sending, that a live run without ``--judge`` will decide little.

    74 of the 75 shipped specs carry ``semantic_judge``. A live deep run without a judge
    ended with pass 1, fail 0, inconclusive 74 and exit 0, and neither the run nor the dry run
    said why (audit 2026-10-03, R13). An offline mock decides on its fixtures, so it is exempt.

    Counted over what each live target will RUN (its plan, after the capability and policy
    filters), not over the selection: the warning said "74 of 75 selected specs" beside a plan
    of 34, because skipped and blocked specs are inconclusive with or without a judge.
    """

    if judge_target is not None:
        return None
    live = {route[1].id for route in routes if route[2][1] is not None}
    lines = []
    for plan in plans:
        if plan.target.id not in live:
            continue
        judged = sum(
            1
            for spec in plan.selected
            if any(e.type is EvaluatorType.SEMANTIC_JUDGE for e in spec.evaluators)
        )
        if judged:
            lines.append(
                f"warning: no --judge on a live target: {judged} of the {len(plan.selected)} "
                f"specs that will run on {plan.target.id} use semantic_judge and come back "
                "inconclusive wherever their deterministic evaluators do not decide. Pass "
                "--judge <judge-target.yaml> for a decisive run."
            )
    return "\n".join(lines) or None


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
    judge_requests = sum(p.estimate.judge_requests for p in plans)
    if judge_requests:
        judge_tokens = sum(p.estimate.judge_tokens for p in plans)
        print(
            f"  + {judge_requests} request(s) to the --judge model (~{judge_tokens} tokens), "
            "paced and debited from the same ceilings"
        )
    print(
        f"  ~tokens: {tokens_in} in + {tokens_out} out "
        f"(~{tokens_in + tokens_out} total, rough gloss)"
    )
    if already_done:
        # `--estimate --resume` priced the whole battery, when the point of the flag is to
        # price the work that is LEFT.
        print(
            f"  minus {already_done} request(s) already done in the resumed run "
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
            + (f", {len(plan.not_seeded)} not seeded" if plan.not_seeded else "")
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
    filtered: bool = False,
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
    # Named for what selected it: "full battery" was printed for `--spec PI-*` too. The count
    # is per target when there are several, not a sum that read as one battery's size.
    battery = suite or ("filtered selection" if filtered else "full battery")
    per_target = (
        f"{specs} specs selected"
        if len(plans) <= 1
        else f"{', '.join(str(len(p.selected)) for p in plans)} specs selected per target"
    )
    print(f"  battery: {battery}, {per_target}")
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
        if plan.not_seeded:
            print(
                f"  not seeded: {len(plan.not_seeded)} spec(s) on {plan.target.id}, their "
                "scene is not in the deployment as seeded_setup declares it, or their tool "
                "trace cannot be read through this adapter (-vv says which)"
            )
            if detail >= 2:
                for spec_id, reason in plan.not_seeded:
                    print(f"    - {spec_id}: {reason}")
        if detail >= 2:
            # What the operator plants: each seeded spec's own canary (run_token-<spec id>).
            for spec in plan.selected:
                canaries = seeded_canaries(spec, plan.target)
                if canaries:
                    print(f"  seed:    {spec.id}: {', '.join(canaries)}")
    print(f"  would send: {requests} requests over {specs} specs at runs={runs}")
    judge_requests = sum(p.estimate.judge_requests for p in plans)
    if judge_requests:
        print(
            f"  judge:   +{judge_requests} request(s) to the --judge model, paced and debited "
            "from the same ceilings"
        )
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
            + (f", {len(plan.not_seeded)} not seeded" if plan.not_seeded else "")
        )
    print("  reachability is authorization-level (scope + allowlist); no request was sent.")


def _flag_figure(value: int) -> str:
    """``value`` with thousands separators, or its sign and size past 21 digits.

    Separated, so the CLI's redactor does not mask it as a phone number, and described past 21
    digits, so a 4,300-digit value is not printed back.
    """

    if abs(value) < 10**21:
        return f"{value:,}"
    return f"a {'negative ' if value < 0 else ''}number of more than 21 digits"


def _validate_options(opts: RunOptions) -> None:
    """Refuse an option the campaign would only trip over at the end, before anything is sent.

    ``--fail-on bogus`` and an unwritable ``-oA`` path were accepted, the whole campaign ran,
    and the run then failed with exit 3 on the way out; ``--timeout 0``, ``--concurrency -2``
    and ``--top-tests -3`` were accepted outright (audit 2026-10-03, R9).
    """

    fail_on_band(opts.fail_on)
    if opts.timeout_s is not None and not opts.timeout_s > 0:
        raise ValueError(f"--timeout must be greater than 0 seconds (got {opts.timeout_s})")
    # An upper bound too (A-55): a `--runs` of 306 digits was an OverflowError in the plan's
    # float arithmetic, a traceback with exit 1, and `--budget-tokens -1` passed the dry run and
    # the estimate with exit 0 while the run refused it.
    for flag, value, least in (
        ("--concurrency", opts.concurrency, 1),
        ("--top-tests", opts.top_tests, 1),
        ("--runs", opts.runs, 1),
        ("--budget-tokens", opts.budget_tokens, 0),
        ("--budget-requests", opts.budget_requests, 0),
        ("--budget-wall", opts.budget_wall_s, 0),
    ):
        if value is not None and not least <= value <= MAX_FLAG_VALUE:
            bound = f"at least {least}" if value < least else f"at most {MAX_FLAG_VALUE:,}"
            raise ValueError(f"{flag} must be {bound} (got {_flag_figure(value)})")
    report_paths = list(_report_outputs(opts).values())
    for path in report_paths:
        parent = Path(path).parent
        if not parent.is_dir():
            raise ValueError(f"cannot write the report {path}: {parent} is not a directory")
    # Two formats pointed at one path: the second silently overwrote the first (audit low).
    # Compared case-folded: on a case-insensitive volume (the macOS default) `R.json` and
    # `r.json` are one file, and the JSON report was lost to the HTML (pre-commit audit).
    # Unicode-normalized too: APFS treats `café` in NFC and in NFD as one name.
    resolved = [
        unicodedata.normalize("NFC", str(Path(path).resolve())).casefold() for path in report_paths
    ]
    duplicates = sorted({path for path in resolved if resolved.count(path) > 1})
    if duplicates:
        raise ValueError(f"two report formats would write the same file: {', '.join(duplicates)}")


@contextmanager
def _termination_as_interrupt() -> Iterator[None]:
    """Turn SIGTERM and SIGHUP into the KeyboardInterrupt Ctrl-C raises, for one campaign.

    The runner records its spend however it stops, but a SIGTERM (what `timeout`, `docker
    stop`, systemd, Kubernetes and CI timeouts send) or a SIGHUP killed the process outright,
    so the spend was lost there too (audit of the hygiene block). Restored afterwards; outside
    the main thread, where signals cannot be set, nothing changes.
    """

    previous: dict[signal.Signals, Any] = {}
    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        # An ignored signal stays ignored: `nohup dottore run` set SIGHUP to SIG_IGN so a scan
        # survives an SSH logout, and mapping it anyway aborted the scan on hangup.
        if sig is None or signal.getsignal(sig) is signal.SIG_IGN:
            continue
        try:
            previous[sig] = signal.signal(sig, signal.default_int_handler)
        except ValueError:
            break
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def execute_run(opts: RunOptions, spec_paths: list[Path]) -> RunOutcome:
    """Run the campaign :func:`_execute_run` describes, SIGTERM and SIGHUP as Ctrl-C."""

    with _termination_as_interrupt():
        return _execute_run(opts, spec_paths)


def _execute_run(opts: RunOptions, spec_paths: list[Path]) -> RunOutcome:
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

    # `--rate 0` or a negative rate used to switch pacing OFF (the limiter reads <= 0 as
    # "unpaced"), and the dry run then described a live target as an offline mock run. A
    # rate is a ceiling the operator authorizes; zero or less is not one (audit 2026-10-03, R8).
    if opts.rate is not None and not opts.rate > 0:
        raise ValueError(
            f"--rate must be greater than 0 requests per second (got {opts.rate}); omit it to "
            "use the timing template's rate"
        )
    _validate_options(opts)
    if opts.scope is None:
        raise ScopeRequiredError(
            "run requires --scope <scope.yaml>: the authorization record is mandatory "
            "and cannot be bypassed by any flag (docs/09 §5)"
        )

    scope, scope_sha256 = wiring.build_scope_with_digest(opts.scope)

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
    # Each file parsed once: everything below asks the same read (u12 A-42).
    loaded_targets = [wiring.read_target_file(path) for path in opts.targets]
    # Two target files with the same id shared one run id and one evidence tree, so one
    # report held a PASS and a FAIL for the same spec on "the same" target (audit R11).
    seen_ids: dict[str, Path] = {}
    for loaded in loaded_targets:
        path, target = loaded.path, loaded.target
        if target.id in seen_ids:
            raise ValueError(
                f"two target files declare the id {quoted(target.id)} ({seen_ids[target.id]} and "
                f"{path}); each target in one run needs its own id"
            )
        seen_ids[target.id] = path
    judge_target = wiring.load_target(opts.judge) if opts.judge is not None else None
    to_authorize = [(loaded.path, loaded.target) for loaded in loaded_targets]
    if judge_target is not None and opts.judge is not None:
        # The judge is a model we send prompts to, so it goes through the same gate. It used
        # to be loaded and never checked: with the judge absent from the scope (which is what
        # `fleet --judge` generated), every semantic_judge verdict came back inconclusive
        # with the reason only in the JSON, and the run exited 0.
        to_authorize.append((opts.judge, judge_target))
    # Each id cut at 300 characters, as the reason quotes it, and the scope's own ids listed up
    # to 20, each cut (clause A-51).
    refusals = [
        f"{cut(target.id)} ({reason})"
        for _, target in to_authorize
        if (reason := _refusal_for(scope, target)) is not None
    ]
    if refusals:
        authorized = listed(sorted(t.id for t in scope.targets)) or "<none>"
        # A stdio MCP target is authorized by its COMMAND LINE, not by an endpoint, and the
        # generic advice ("allowlist the endpoint") pointed at the wrong field. The spelling
        # matters too: the scope's `commands` entries are matched against the joined argv, so
        # the exact string is printed rather than left to the reader to reconstruct.
        stdio_hint = ""
        for _, target in to_authorize:
            if (target.transport or "").strip().lower() == "stdio" and target.command:
                joined = " ".join(target.command)
                stdio_hint = (
                    f" {quoted(target.id)} is a stdio MCP target, so it is authorized by its "
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

    # A spec file that fails to load is refused, not dropped. `build_registry` keeps only what
    # parsed, so a one-letter typo removed a spec from the battery and the run still printed
    # "Specs run: 1 of 1 planned" and `complete` (audit 2026-10-03, F-10).
    registry, load_errors = wiring.load_registry(spec_paths)
    if load_errors:
        # Counted by FILE: one bad file yields many findings (17 for one target example), and
        # the message said "17 spec file(s)" (review of PR #32).
        files = list(dict.fromkeys(e.path or e.spec_id or "?" for e in load_errors))
        shown = "; ".join(
            f"{e.path or e.spec_id or '?'}: {e.message[:120]}" for e in load_errors[:5]
        )
        more = f" (and {len(load_errors) - 5} more problem(s))" if len(load_errors) > 5 else ""
        raise SpecLoadError(
            f"{len(files)} spec file(s) failed to load and would silently leave the "
            f"battery: {shown}{more}. Run `dottore lint` on the spec path and fix them first.",
            spec_files=_spec_files_on_disk(spec_paths, [e.path for e in load_errors[:5] if e.path]),
        )
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

    routes = [(loaded.path, loaded.target, _route_for(opts, loaded)) for loaded in loaded_targets]
    any_live = any(real is not None for _, _, (_, real) in routes)
    # Pacing applies to traffic that leaves the process. An offline mock campaign is not
    # paced (there is nobody to be polite to, and pacing CI would only slow it); the plan
    # output says so out loud instead of quietly dropping the flag.
    pacing_rate = timing.rate_rps if any_live else None
    # Under one request per wall-clock ceiling, a run waits past the ceiling: the ledger checks
    # it when a send is charged, not while the rate limiter sleeps, so `--rate 1e-308` ran on
    # without end once its derived ceiling stopped overflowing, and with `--budget-wall 0 -sV`
    # too, the probe pass reading no ceiling (pre-commit and delta audits of A-55). The pace
    # checked is the one that applies, a template's included, before anything is sent.
    wall = (
        opts.budget_wall_s if opts.budget_wall_s is not None else BUDGET_DERIVATION_CAP.max_wall_s
    )
    # Written so a NaN refuses: `--rate inf` against a zero ceiling is `inf * 0`, which no
    # comparison holds for (pre-merge audit of A-55).
    if pacing_rate is not None and wall is not None and not pacing_rate * wall >= 1:
        if wall == 0:  # no pace sends under it, so raising the rate is no advice
            raise ValueError(
                "--budget-wall 0 leaves a live run no time to send anything, at any pace; "
                "raise --budget-wall"
            )
        pace = (
            f"--rate {pacing_rate:.3e}"
            if opts.rate is not None
            else f"the -T{opts.template} pace of {pacing_rate:.3e} requests per second"
        )
        raise ValueError(
            f"{pace} is less than one request per {wall:,}-second wall-clock ceiling, so the "
            "run would wait past that ceiling between two sends; raise the rate or --budget-wall"
        )

    # Resolved BEFORE the fingerprint pass, which SENDS. It used to sit after it, so
    # `-sV --resume <id-of-a-changed-battery>` put 17 probes on a real endpoint with a real
    # bearer token and then exited 3 having done no work. Nothing here needs the fingerprint.
    adaptive = opts.fingerprint_first or opts.deep

    prior_spend: Spend | None = None
    resume_from: TestRun | None = None
    provisional: list[TargetPlan] | None = None

    def provisional_plans() -> list[TargetPlan]:
        # No fingerprint: it needs the probe pass, which SENDS (see the resume block below).
        return resolve_target_plans(
            scope=scope,
            targets=loaded_targets,
            specs=selected,
            runs=opts.runs,
            rate_rps=pacing_rate,
            fingerprints={},
            adaptive=adaptive,
            budget_overrides=PlanBudgets(
                max_tokens=opts.budget_tokens,
                max_requests=opts.budget_requests,
                max_wall_s=opts.budget_wall_s,
            ),
            judge=judge_target is not None,
        )

    #: Whether a refusal of the -sV probe pass may not offer dropping -sV: a resume of a
    #: campaign that planned adaptively is refused without it (u12 A-48).
    adaptive_campaign = False
    if opts.resume is not None:
        # Same campaign first, then money. The ceiling refusals below used to run first and
        # advise "Raise --budget-requests, or drop -sV" to a resume this check then refused
        # whichever was followed: raising, for a campaign run without -sV ("halted with
        # adaptive planning off"); dropping it, for one run with it (u12 A-48). Read-only here:
        # the evidence is adopted into the journal below, past the last refusal before traffic.
        resume_from = resume_mod.load_resume_run(
            evidence_root,
            opts.resume,
            loaded_targets[0].target,
            run_db=run_db,
            specs=selected,
            mock_scenario=routes[0][2][0],
            runs=opts.runs if opts.runs_explicit else None,
            judge=judge_target,
            adaptive=adaptive,
            allow_unverified=opts.resume_unverified,
            adopt=False,
        )
        adaptive_campaign = resume_mod.stored_adaptive(run_db, opts.resume) is True
        inherited = resume_mod.stored_runs(run_db, opts.resume)
        if not opts.runs_explicit and inherited is not None and inherited != opts.runs:
            # stderr and never suppressed: this changes the denominator of the reproducibility
            # axis, which is a state change and not progress chatter. Under --quiet (which is
            # what CI uses) the downgrade was invisible in every surface.
            print(
                f"resume: continuing at --runs {inherited}, as the halted campaign ran "
                f"(you asked for {opts.runs})",
                file=sys.stderr,
            )
            opts.runs = inherited
        # Inherited BEFORE the provisional plan below: it derives the ceilings the refusals
        # read, and at this invocation's --runs (5 by default) a campaign run at --runs 20
        # was refused against a 2,000-request ceiling where its own was 3,300 (pre-commit
        # audit of u12 A-48).
        # The budgets are derived from a plan, and the real plan needs the fingerprint, which
        # SENDS. A provisional plan resolved with no fingerprint derives the same ceilings (the
        # estimate counts specs and mutators, which -sV reorders rather than changes), so the
        # wall-clock refusal can happen here rather than after 17 probes have gone out. The
        # first version of this check sat below the probe pass, which is the exact defect the
        # clause above it says was fixed.
        provisional = provisional_plans()
        prior_spend = _prior_spend(run_db, opts.resume, provisional[0].budgets)
        if opts.fingerprint_first and prior_spend is not None:
            ceiling = provisional[0].budgets.max_requests
            probes = fingerprint_probe_count() * len(loaded_targets)
            if ceiling is not None and prior_spend.requests + probes > ceiling:
                remedy = _probe_pass_remedy(
                    adaptive_campaign,
                    attack_room=_fits_without_probes(
                        provisional,
                        ceiling,
                        spent=prior_spend.requests,
                        done=_answered_requests(resume_from, selected),
                    ),
                )
                raise ValueError(
                    f"run {opts.resume!r} has already spent {prior_spend.requests} of its "
                    f"{ceiling}-request ceiling, and -sV would send {probes} more before any "
                    "attack traffic. Three sequential resumes used to run a whole probe pass "
                    f"each, past an exhausted ceiling. {remedy}."
                )
        if not opts.quiet:
            done, again = resume_progress(resume_from)
            print(
                f"resume: {opts.resume} keeps {done} attempt(s) across "
                f"{len(resume_from.findings)} spec(s) (answered, or failed in a way a retry "
                "would repeat); they will not be re-sent"
                + (
                    f"; {again} that ended in an environment error will be sent again"
                    if again
                    else ""
                )
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
            # On a resume this is reached only with no spend on record (the pre-check above
            # refuses first otherwise), so the ceiling covers this invocation alone.
            remedy = _probe_pass_remedy(
                adaptive_campaign,
                attack_room=_fits_without_probes(
                    provisional or provisional_plans(),
                    opts.budget_requests,
                    spent=0,
                    done=_answered_requests(resume_from, selected),
                ),
            )
            raise ValueError(
                f"-sV sends {probe_total} probe(s) ({fingerprint_probe_count()} per target "
                f"across {len(loaded_targets)}), which is more than the --budget-requests "
                f"ceiling of {opts.budget_requests}: the probe pass is traffic to the target "
                f"like any other. {remedy}."
            )
    if resume_from is not None and not sends_nothing:
        # Adopted only here, past the last refusal before any traffic, so a refused resume
        # writes nothing; and the modes that send nothing write nothing either (u12 A-48).
        resume_mod.adopt_resumed(run_db, resume_from)
    # One run id per target, minted HERE rather than inside the campaign, because the probe
    # pass happens first and its evidence has to file under the run it belongs to. A resumed
    # campaign keeps the original id (the evidence and the run store are keyed by it).
    run_ids = {
        loaded.target.id: (
            opts.resume if opts.resume is not None else f"run-{uuid.uuid4().hex[:12]}"
        )
        for loaded in loaded_targets
    }

    printer = ProgressPrinter(no_color=opts.no_color, quiet=opts.quiet)
    # Before anything is sent, the -sV probe pass included, and before the dry-run return:
    # the dry run is where an operator decides whether to add a judge. The warning used to be
    # computed after both, so 17 probes went out first and the dry run never showed it.
    no_judge = None
    if judge_target is None and any_live:
        # Provisional plans (no fingerprint): which specs a target skips or blocks depends on
        # its declared capabilities and the policy, never on the fingerprint, so the count is
        # exact before -sV has sent anything.
        preview = provisional or resolve_target_plans(
            scope=scope,
            targets=loaded_targets,
            specs=selected,
            runs=opts.runs,
            rate_rps=pacing_rate,
            fingerprints={},
            adaptive=adaptive,
        )
        no_judge = _no_judge_warning(preview, routes, judge_target)
    if no_judge:
        printer.error(no_judge)

    if not sends_nothing and opts.resume is not None and opts.fingerprint_first:
        # A resumed run has its row: with -sV the scope is recorded before the probe pass, its
        # first traffic. Otherwise each run records it with its integrity record below, before
        # its attack traffic: a fresh run stopped by its probe pass leaves no run row at all.
        for _, target, _ in routes:
            _record_scope(run_db, run_ids[target.id], scope_sha256, resumed=True)

    probes_sent: dict[str, int] = {}
    # Each target's start is stamped before its probe pass, which is traffic of that run: the
    # runner's own stamp came after it (66 s of -sV probes before the recorded start). Without
    # -sV the runner stamps each target itself; a resume keeps its stored start.
    starts: dict[str, str] = {}
    if opts.fingerprint_first and not sends_nothing:
        probe_store = wiring.build_evidence_store(evidence_root, planted_canaries=[])
        probe_ceiling = (
            opts.budget_requests - (prior_spend.requests if prior_spend is not None else 0)
            if opts.budget_requests is not None
            else None
        )

        def ceiling_remedy() -> str:
            # A resumed pass that reaches the ceiling with a spend on record has its sends
            # recorded, and they fill it; otherwise the ceiling covers this invocation alone.
            return _probe_pass_remedy(
                adaptive_campaign,
                attack_room=prior_spend is None
                and _fits_without_probes(
                    provisional or provisional_plans(),
                    opts.budget_requests or 0,
                    spent=0,
                    done=_answered_requests(resume_from, selected),
                ),
            )

        for _, target, (mock_scenario, real_target) in routes:
            if opts.resume is None:
                starts[target.id] = wiring.utc_timestamp()
            # The pass's ledger is made here, not inside the pass, so what it sent is known
            # however it ends, and a resumed run records it then, success included (u12 A-46).
            # Only the ceiling used to: a probe answered 503 three times left the store at 20
            # while the target had served 23, and so did a product error, Ctrl-C, SIGTERM, or
            # anything stopping the run before the runner's ledger opened. Each retry of the
            # same resume then sent its probes against a ceiling that had never seen them.
            probe_ledger = BudgetLedger(max_requests=probe_ceiling)
            try:
                probe_pass = wiring.fingerprint_probe(
                    scope,
                    target,
                    real_target=real_target,
                    rate_rps=pacing_rate,
                    evidence=probe_store,
                    run_id=run_ids[target.id],
                    mock_scenario=mock_scenario,
                    ledger=probe_ledger,
                )
                # Inside the try: a signal landing between the pass and this write lost the
                # whole pass (2 of 16 real SIGINTs a few ms after the last probe, pre-commit
                # audit). Interrupted here, the handler below writes it again.
                _charge_probe_pass(run_db, run_ids[target.id], prior_spend, probe_ledger)
            except wiring.ProbeCeilingReached as exc:
                _charge_probe_pass(run_db, run_ids[target.id], prior_spend, probe_ledger)
                raise ValueError(
                    f"the -sV probe pass on {target.id!r} reached the --budget-requests ceiling "
                    f"({exc}) after {exc.requests} request(s), before any attack traffic: "
                    f"retries count as requests. {ceiling_remedy()}. The exchanges are in "
                    f"{evidence_root / run_ids[target.id] / 'probes'}."
                ) from exc
            except BaseException:
                # The error's own message can understate the sends: a probe adapter has no
                # retries of its own (the meter owns them), so three 503s read "exhausted 1
                # attempt(s)". The count is the ledger's. Plain print, as the resume notice.
                recorded = _charge_probe_pass(run_db, run_ids[target.id], prior_spend, probe_ledger)
                sent = probe_ledger.spend().requests
                if prior_spend is not None and sent:
                    print(
                        f"resume: the -sV probe pass on {target.id!r} stopped after {sent} "
                        "request(s), retries included; "
                        + (
                            f"{run_ids[target.id]} now records {recorded} request(s) spent"
                            if recorded is not None
                            else f"they could not be added to the spend of {run_ids[target.id]}"
                        ),
                        file=sys.stderr,
                    )
                raise
            fingerprints[target.id] = probe_pass.fingerprint
            probes_sent[target.id] = probe_pass.requests
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
                + (
                    " [the target answered every attributing probe alike: no text signal]"
                    if "non_discriminating_target" in fingerprint.spoofing_flags
                    else ""
                )
            )
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
        judge=judge_target is not None,
    )

    # A target with nothing left to run is refused, for the same reason an empty --spec
    # selection is: it would otherwise scan nothing, report coverage percentages over the
    # findings of specs that never sent a request, and exit 0. Reproduced by the audit with
    # three policy-blocked specs: "3 of 0 planned", exit 0, zero requests.
    barren = [
        f"{p.target.id} ({len(p.skipped_capability)} skipped for capabilities, "
        f"{len(p.blocked_by_policy)} blocked by policy"
        + (f", {len(p.not_seeded)} not seeded" if p.not_seeded else "")
        + ")"
        for p in plans
        if not p.selected
    ]
    if barren and not opts.discovery_only:
        raise ValueError(
            "nothing would be sent: every selected spec is unrunnable on "
            f"{'; '.join(barren)}. Widen the selection or declare the capability on the "
            "target. A spec blocked by policy needs a policy pack that enables it, and the CLI "
            "cannot load one today (open decision), so it cannot run from `dottore`."
            + (
                " A spec counted as not seeded runs once what `--dry-run -vv` names for it is "
                "fixed: its id in seeded_setup.specs, a seeded_setup.run_token, its own "
                "deployment name for each of its scene tools in seeded_setup.tools, or an "
                "adapter that returns tool calls."
                if any(p.not_seeded for p in plans if not p.selected)
                else ""
            )
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
            already_done=_answered_requests(resume_from, selected),
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
            filtered=bool(
                opts.categories or opts.spec_globs or opts.exclude_globs or opts.top_tests
            ),
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

    # A resumed campaign opens its ledger where the halted one stopped. Read once, before the
    # loop: `--resume` names a single target, so there is one prior spend to carry.
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
        _persist_run_integrity(
            run_db,
            run_ids[target.id],
            selected,
            target=target,
            mock_scenario=mock_scenario,
            runs=opts.runs,
            judge=judge_target,
            adaptive=adaptive,
        )
        _record_scope(run_db, run_ids[target.id], scope_sha256, resumed=opts.resume is not None)
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
            # The probe pass runs outside the runner's ledger, so it is opened INTO the ledger
            # as spend already made. Recording it after the fact (which is what the first fix
            # did) told the next resume what had been spent and never stopped this invocation
            # spending it: `-sV --budget-requests 20` sent 17 probes and then a further 20.
            prior_spend=(prior_spend or Spend()).plus(
                Spend(requests=probes_sent.get(target.id, 0))
            ),
            started_at=starts.get(target.id),
        )
        results.append(result)
        _persist_run_spend(run_db, result)
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
    # Masked before the terminal sees it, for the same reason the reporters mask it (SEC-01).
    from ildottore.reporting import default_redactor

    _mask = default_redactor()
    for target_id, reason in sorted(incomplete.items()):
        printer.error(f"error: run on {target_id} did not complete: {_mask.redact_text(reason)}")

    report_paths = _write_reports(
        opts,
        results,
        all_findings,
        specs_by_id,
        planned_specs=planned_specs,
        run_status=run_status,
        scope_sha256=scope_sha256,
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


def _route_for(opts: RunOptions, loaded: wiring.TargetFile) -> tuple[str | None, Target | None]:
    """Decide the adapter route for one target: ``(mock_scenario, real_target)``.

    ``--hardened`` always forces the offline hardened replay (a mock-only flag); otherwise a
    target with no ``mock_scenario`` and a real, non-``mock://`` ``endpoint`` routes to the
    live provider adapter (u04). Anything else - including every existing mock-only
    ``target.yaml``, which never declares an endpoint - keeps resolving to the offline mock
    (contract §5).
    """

    if opts.hardened and not loaded.uses_mock:
        # It replayed offline fixtures, sent nothing, and published ten passes, "complete" and
        # exit 0 under the live target's name, with no marker anywhere that it was a replay
        # (audit 2026-10-03, R3). A clean report about a model nobody contacted is refused.
        raise ValueError(
            f"--hardened replays the offline hardened fixtures and sends nothing, so it cannot "
            f"be used with the live target {quoted(loaded.target.id)} ({loaded.path}): the "
            "report would describe a model that was never contacted. Drop --hardened, or point "
            "it at a mock target."
        )
    if opts.hardened or loaded.uses_mock:
        scenario = "hardened" if opts.hardened else loaded.mock_scenario()
        return scenario, None
    return None, loaded.target


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
    started_at: str | None = None,
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

    # A resumed campaign keeps the ORIGINAL run id: the evidence and the store are keyed by
    # it, and a new id would file the continuation as a separate, equally partial run. The
    # caller mints it (the probe pass needs it first), and falls back for direct callers.
    if run_id is None:
        run_id = resume_from.run_id if resume_from is not None else f"run-{uuid.uuid4().hex[:12]}"
    campaign_run_id = run_id
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
        # Recorded however the campaign stops, Ctrl-C included, so a resume's ceiling is right.
        spend_sink=lambda spend: _record_spend_quietly(run_db, campaign_run_id, spend),
    )
    try:
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
                started_at=started_at,
            )
        )
    finally:
        built.close()


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


def _answered_requests(resume_from: TestRun | None, specs: list[AttackSpec]) -> int:
    """The requests a resume will not send again: one per turn of every answered attempt.

    `--estimate --resume` subtracted an attempt count from a request count, so a multi-turn spec
    was priced at 15 still to send when 12 went out (pre-commit audit of F11). An in-band
    attempt (OD-18) adds the tool rounds it played, which its request records.
    """

    if resume_from is None:
        return 0
    turns_by_spec = {
        spec.id: (
            len(spec.attack.turns) if spec.attack.turns and len(spec.attack.turns) >= 2 else 1
        )
        for spec in specs
    }
    answered = answered_attempt_ids(resume_from)
    seen: set[str] = set()
    total = 0
    for finding in resume_from.findings:
        for attempt in finding.attempts:
            if attempt.attempt_id in answered and attempt.attempt_id not in seen:
                seen.add(attempt.attempt_id)
                rounds = (attempt.request.metadata or {}).get("tool_rounds", 0)
                total += turns_by_spec.get(finding.spec_id, 1) + (
                    rounds if isinstance(rounds, int) and not isinstance(rounds, bool) else 0
                )
    return total


def _record_scope(run_db: Path, run_id: str, scope_sha256: str, *, resumed: bool) -> None:
    """Record the scope this invocation sends under, and say so when it is not the run's last.

    A resume under a different scope.yaml is not refused (that would be a policy of its own);
    it is recorded, so the run store names each authorization record the run went out under,
    and noted on stderr (threat model S4, audit D-17).
    """

    from ildottore.store.run_sqlite import SqliteRunStore

    with SqliteRunStore(Path(run_db)) as store:
        before, _after = store.add_run_scope(run_id, scope_sha256, resumed=resumed)
    if before and before[-1] != scope_sha256:
        first = (
            "before scope digests were recorded"
            if before[0] == "unrecorded"
            else f"under scope sha256 {before[0][:12]}..."
        )
        last = "" if len(before) == 1 else f", last ran under {before[-1][:12]}...,"
        print(
            f"note: {run_id} started {first}{last} and goes on under {scope_sha256[:12]}...; "
            "the run store records each scope in order",
            file=sys.stderr,
        )


def _persist_run_integrity(
    run_db: Path,
    run_id: str,
    specs: list[AttackSpec],
    *,
    target: Target,
    mock_scenario: str | None,
    runs: int,
    judge: Target | None = None,
    adaptive: bool = False,
) -> None:
    """Record WHAT this campaign is about to run, before it sends anything.

    Written first, not last. Both halves used to be written when the campaign returned, so a
    run killed mid-flight (SIGKILL, a lost laptop, a CI timeout) left evidence on disk and no
    row, and the resume was then refused outright because the target it belonged to could not
    be verified: the resume you most want after a crash was the one you could not have.

    Everything here is known before the first request, so there is no reason to make a resume
    depend on the campaign finishing. What genuinely cannot be known in advance is the spend,
    and that is written separately, when the campaign stops.
    """

    from ildottore.store.run_sqlite import SqliteRunStore

    with SqliteRunStore(Path(run_db)) as store:
        store.save_run_context(
            run_id,
            target_id=target.id,
            spec_digests=spec_digests(specs),
            context={
                "target_digest": target_digest(target, mock_scenario=mock_scenario),
                "judge_digest": target_digest(judge) if judge is not None else None,
                "adaptive": adaptive,
                "runs": runs,
            },
        )


def _write_atomically(path: Path, payload: bytes) -> None:
    """Write ``payload`` beside ``path`` and rename it into place.

    A SIGTERM during the write left a truncated JSON report under its final name, which a CI
    step would then parse (audit of the hygiene block). A symlinked report is written through
    (the link is kept), an existing report keeps its permission bits, a new one is readable by
    its owner only (0600), and the partial file is removed on any failure. The partial is
    created exclusively and never through a symlink, so one planted at its fixed name in a
    shared directory cannot redirect the write. A report path that is not a regular file (a
    FIFO, a device, `/dev/stdout`) is written directly, as is one in a read-only directory
    holding a writable report. Hard links to an existing report are not kept: the rename gives
    the name a new file.
    """

    try:
        existing = os.stat(path)
    except FileNotFoundError:
        existing = None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        path.write_bytes(payload)  # nothing to rename onto
        return
    target = Path(os.path.realpath(path))
    partial = target.with_name(f".{target.name}.partial")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        partial.unlink(missing_ok=True)
        # Created with the report's own mode, so a 0600 report is never world-readable while
        # its replacement is being written (pre-merge audit of the hygiene block). A new report
        # is readable by its owner only, like the evidence it is built from (audit SEC-10).
        mode = stat.S_IMODE(existing.st_mode) if existing is not None else 0o600
        descriptor = os.open(partial, flags, mode)
    except PermissionError:
        path.write_bytes(payload)
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        if existing is not None:
            shutil.copymode(target, partial)
        os.replace(partial, target)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def _persist_run_spend(run_db: Path, result: CampaignResult) -> None:
    """Record what the campaign consumed, once it is known.

    The runner also hands its spend to the store however it stops (a ceiling, an abort,
    Ctrl-C, and SIGTERM or SIGHUP, which ``execute_run`` turns into Ctrl-C), and a resumed run's
    ``-sV`` probe pass is recorded however it ends (:func:`_charge_probe_pass`). A SIGKILL still
    loses the dead half's spend: closing that would mean a write per request.
    """

    _persist_spend(run_db, result.run.run_id, result.spend)


def _record_spend_quietly(run_db: Path, run_id: str, spend: Spend) -> None:
    """The runner's spend sink: a failure to record is a warning, never the campaign's error.

    Raised from the runner's ``finally``, a locked database replaced a Ctrl-C with an
    ``OperationalError`` traceback and exit 1, and lost a finished run's findings (audit of the
    hygiene block). A finished run still records its spend through ``_persist_run_spend``.
    """

    _recorded_requests(run_db, run_id, spend)


def _recorded_requests(run_db: Path, run_id: str, spend: Spend) -> int | None:
    """Record ``spend`` and return the requests the store then holds for ``run_id``.

    ``None`` when it could not be recorded, which is said on stderr and is never the run's
    error: a locked database must not replace the Ctrl-C or the error that stopped the run.
    """

    try:
        return _persist_spend(run_db, run_id, spend)
    except Exception as exc:  # the database, not the campaign
        from ildottore.redactor import Redactor

        reason = Redactor().redact_text(str(exc))
        print(f"warning: the spend of {run_id} could not be recorded: {reason}", file=sys.stderr)
        return None


def _charge_probe_pass(
    run_db: Path, run_id: str, prior: Spend | None, ledger: BudgetLedger
) -> int | None:
    """Record a resumed run's spend with what its ``-sV`` probe pass sent (u12 A-46).

    Called however the pass ends, success included, so a stop before the runner's ledger opens
    loses nothing either. The figure is written whole, not added: the store keeps the highest
    per axis, so the runner's later record of the same probes plus the attack counts each probe
    once. Returns the requests the store then holds, or ``None`` when nothing was recorded:
    nothing sent, no prior spend, or a failed write (a warning says so). No prior spend is a
    fresh run, whose run row is written after the pass so there is nothing to resume, or a
    ``--resume-unverified`` run with no recorded spend, told its ceiling covers this invocation
    alone; neither recorded the probes before, at the ceiling either.
    """

    sent = ledger.spend().requests
    if prior is None or sent == 0:
        return None
    # Not retried when a signal lands during the write. In the probe loop's handlers nothing
    # catches it after, so one landing there loses the pass (2 of 41 real SIGINTs just after a
    # 503 stop, delta audit). Writing again closed that, and on a locked store made Ctrl-C wait
    # one more busy timeout per interrupted write (9.9 s instead of 4.7 after a 503, 15.1
    # instead of 9.8 after a pass that succeeded) for a record lost anyway (pre-merge audit).
    # The window stays, like a SIGKILL's, and u12 A-46 says so.
    return _recorded_requests(run_db, run_id, prior.plus(Spend(requests=sent)))


def _persist_spend(run_db: Path, run_id: str, spend: Spend) -> int:
    """Record ``spend`` (the highest per axis is kept) and return the requests now recorded."""

    from ildottore.store.run_sqlite import SqliteRunStore

    with SqliteRunStore(Path(run_db)) as store:
        store.save_run_context(
            run_id,
            spend={
                "tokens": spend.tokens,
                "requests": spend.requests,
                "attempts": spend.attempts,
                "wall_s": round(spend.wall_s, 6),
            },
        )
        return int((store.get_run_spend(run_id) or {}).get("requests", 0))


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


def _envelope_summary(findings: list[Finding]) -> TestRunSummary:
    by_status: dict[str, int] = {}
    by_band: dict[str, int] = {}
    for finding in findings:
        by_status[finding.status.value] = by_status.get(finding.status.value, 0) + 1
        by_band[finding.risk.band.value] = by_band.get(finding.risk.band.value, 0) + 1
    return TestRunSummary(by_status=by_status, by_band=by_band, total=len(findings))


def _report_outputs(opts: RunOptions) -> dict[str, Path]:
    """Every report path the options ask for, ``-oA PREFIX`` expanded to four files.

    The prefix is extended, not suffix-swapped: ``with_suffix`` turned ``-oA report.v2`` into
    ``report.json``, dropping the last dotted part (audit low).
    """

    outputs = dict(opts.outputs)
    if opts.output_all_prefix is not None:
        prefix = opts.output_all_prefix
        # A prefix that already ends in one of the four extensions is a base name with that
        # extension, not part of it: `-oA report.json` writes report.json, report.html and so
        # on, as it always did, instead of report.json.json.
        if prefix.suffix.lower() in (".json", ".html", ".sarif", ".xml"):
            prefix = prefix.with_suffix("")
        extensions = {"json": ".json", "html": ".html", "sarif": ".sarif", "junit": ".xml"}
        for fmt, ext in extensions.items():
            outputs.setdefault(fmt, prefix.with_name(prefix.name + ext))
    return outputs


def _write_reports(
    opts: RunOptions,
    results: list[CampaignResult],
    findings: list[Finding],
    specs_by_id: dict[str, AttackSpec],
    *,
    planned_specs: int | None = None,
    run_status: RunStatus | None = None,
    scope_sha256: str | None = None,
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
        # The envelope's own findings and summary cover every target too. They held the LAST
        # target only, beside a top-level summary of all of them, so the same JSON document
        # gave two answers (audit R10). The run id stays the last target's; each target's own
        # id is in its findings' evidence references.
        run = run.model_copy(
            update={
                "targets": list(seen.values()),
                "findings": list(findings),
                "summary": _envelope_summary(findings),
            }
        )
    if scope_sha256 is not None:
        run = run.model_copy(update={"scope_sha256": scope_sha256})
    outputs = _report_outputs(opts)

    written: list[Path] = []
    for fmt, path in outputs.items():
        reporter = wiring.build_reporter(
            fmt, specs=specs_by_id, planned_specs=planned_specs, run_status=run_status
        )
        payload = reporter.render(run, findings)
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_atomically(path, payload)
        written.append(path)
    return written
