"""``dottore run`` - resolve → scope-gate → plan → execute → render → exit-code.

The default command when a target is given (contract §2). It is pure wiring + I/O:
it resolves config/scope/selection, delegates execution to the u08 runner, streams
progress, renders the summary and maps the outcome to a scriptable exit code. It holds
**no** attack/eval/scoring logic (contract §8).

The **scope/allowlist gate is never bypassable** (contract §4 KEEP, ``docs/09 §5``):
``run`` refuses to send a single request without a ``--scope`` file, and ``--dry-run``
resolves + validates and sends nothing. ``-A``/``--quick``/``--deep`` do not weaken
this - they only widen the battery.
"""

from __future__ import annotations

import asyncio
import fnmatch
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode, exit_code_for
from ildottore.cli.flags import resolve_suite_id, resolve_timing
from ildottore.cli.render import ProgressPrinter
from ildottore.core.runner import CampaignResult
from ildottore.policy import Scope
from ildottore.policy.errors import PolicyError, ScopeError
from ildottore.shared.enums import Category
from ildottore.shared.models import AttackSpec, Finding, Target

__all__ = [
    "CATEGORY_ALIASES",
    "RunOptions",
    "RunOutcome",
    "ScopeRequiredError",
    "execute_run",
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


def estimate_plan(specs: list[AttackSpec], runs: int) -> PlanEstimate:
    """Estimate the wire cost of a plan without sending: requests + rough token volume.

    ``requests`` = sum over specs of ``mutations x runs x turns``. Tokens are a deliberately
    rough gloss (prompt length / 4 for input; the spec's ``sampling.max_tokens`` or 512 for
    output). No per-model pricing is known, so this reports volume, not a dollar figure.
    """

    total_requests = 0
    total_in = 0
    total_out = 0
    by_category: dict[str, int] = {}
    for spec in specs:
        mutations = spec.mutations or ["identity"]
        turns = spec.attack.turns
        n_turns = len(turns) if turns is not None and len(turns) >= 2 else 1
        requests = len(mutations) * runs * n_turns
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


def _print_estimate(est: PlanEstimate, *, quiet: bool = False) -> None:
    """Print the pre-run estimate (skipped under --quiet)."""

    if quiet:
        return
    print(f"estimate: {est.specs} specs, {est.requests} requests (no sends made)")
    print(
        f"  ~tokens: {est.input_tokens} in + {est.output_tokens} out "
        f"(~{est.input_tokens + est.output_tokens} total, rough gloss)"
    )
    for cat, n in sorted(est.by_category.items(), key=lambda kv: -kv[1]):
        print(f"  {cat}: {n} requests")
    print("  no per-model pricing known; multiply by your provider's per-token rate.")


def execute_run(opts: RunOptions, spec_paths: list[Path]) -> RunOutcome:
    """Run a full campaign for every target and return the aggregate outcome.

    Enforces the non-bypassable scope gate first (contract §4 KEEP): without a
    ``--scope`` file this raises :class:`ScopeRequiredError` before any adapter is even
    constructed - zero sends. ``--dry-run`` resolves + validates the plan and returns
    with **no** sends and exit code 0.
    """

    if opts.scope is None:
        raise ScopeRequiredError(
            "run requires --scope <scope.yaml>: the authorization record is mandatory "
            "and cannot be bypassed by any flag (docs/09 §5)"
        )

    scope = wiring.build_scope(opts.scope)
    judge_target = wiring.load_target(opts.judge) if opts.judge is not None else None
    registry = wiring.build_registry(spec_paths)
    all_specs = registry.list()
    specs_by_id = {s.id: s for s in all_specs}

    suite_specs: list[AttackSpec] | None = None
    if opts.suite is not None:
        suite_id = resolve_suite_id(opts.suite)
        if not registry.has_suite(suite_id):
            raise ScopeError(  # operational error surfaced to exit >2 by the caller
                f"suite {opts.suite!r} (resolved to {suite_id!r}) is not registered"
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

    if opts.estimate:
        _print_estimate(estimate_plan(selected, opts.runs), quiet=opts.quiet)
        return RunOutcome(
            exit_code=ExitCode.CLEAN, findings=[], results=[], dry_run=True, estimated=True
        )

    if opts.dry_run:
        return RunOutcome(exit_code=ExitCode.CLEAN, findings=[], results=[], dry_run=True)

    timing = resolve_timing(
        opts.template,
        rate=opts.rate,
        concurrency=opts.concurrency,
        timeout_s=opts.timeout_s,
    )
    evidence_root = opts.evidence_root or Path(".dottore/evidence")
    run_db = opts.run_db or Path(".dottore/runs.sqlite")

    printer = ProgressPrinter(no_color=opts.no_color, quiet=opts.quiet)

    results: list[CampaignResult] = []
    all_findings: list[Finding] = []
    for target_path in opts.targets:
        target = wiring.load_target(target_path)
        # --hardened always forces the offline hardened replay (a mock-only flag);
        # otherwise a target with no ``mock_scenario`` and a real, non-``mock://``
        # ``endpoint`` routes to the live provider adapter (u04) - anything else
        # (including every existing mock-only target.yaml, which never declares an
        # endpoint) keeps resolving to the offline mock, unchanged (contract §5).
        mock_scenario: str | None
        real_target: Target | None
        if opts.hardened or wiring.target_uses_mock(target_path):
            mock_scenario = "hardened" if opts.hardened else wiring.load_mock_scenario(target_path)
            real_target = None
        else:
            mock_scenario = None
            real_target = target
        result = _run_one_target(
            target=target,
            scope=scope,
            specs=selected,
            evidence_root=evidence_root,
            run_db=run_db,
            concurrency=timing.concurrency,
            timeout_s=timing.timeout_s,
            n=opts.runs,
            mock_scenario=mock_scenario,
            real_target=real_target,
            judge_target=judge_target,
        )
        results.append(result)
        _print_progress(printer, selected, result.findings)
        all_findings.extend(result.findings)

    printer.summary(all_findings, specs_by_id)

    report_paths = _write_reports(opts, results, all_findings, specs_by_id)

    code = exit_code_for(
        all_findings,
        fail_on=opts.fail_on,
        include_needs_review=opts.include_needs_review,
    )
    return RunOutcome(
        exit_code=code,
        findings=all_findings,
        results=results,
        dry_run=False,
        report_paths=report_paths,
    )


def _run_one_target(
    *,
    target: Target,
    scope: Scope,
    specs: list[AttackSpec],
    evidence_root: Path,
    run_db: Path,
    concurrency: int,
    timeout_s: float,
    n: int,
    mock_scenario: str | None,
    real_target: Target | None = None,
    judge_target: Target | None = None,
) -> CampaignResult:
    """Assemble a runner for one target and drive one campaign to completion.

    ``real_target`` (set only for a non-mock ``target.yaml``, see :func:`execute_run`)
    routes the campaign through :func:`wiring.real_adapter_factory` instead of the
    offline mock; ``mock_scenario`` is ``None`` in that case. ``judge_target`` (from
    ``--judge``) supplies the LLM-as-judge model for ``semantic_judge`` so a live scan
    yields decisive verdicts instead of abstaining.
    """

    built = wiring.build_runner(
        scope=scope,
        specs=specs,
        evidence_root=evidence_root,
        run_db=run_db,
        concurrency=concurrency,
        timeout_s=timeout_s,
        n=n,
        mock_scenario=mock_scenario,
        real_target=real_target,
        judge_target=judge_target,
    )
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    return asyncio.run(built.runner.run(run_id=run_id, target=target, specs=specs))


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
        reporter = wiring.build_reporter(fmt, specs=specs_by_id)
        payload = reporter.render(run, findings)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        written.append(path)
    return written
