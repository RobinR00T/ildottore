"""Typer root - the ``dottore`` command surface (contract §1/§5).

The composition-root CLI. Every command is a thin wrapper that parses nmap-style
flags (``docs/09``) into the resolved option objects the ``run``/``fingerprint``/…
modules consume, then maps the outcome to a scriptable exit code (``exit_codes``).
No business logic lives here: commands wire and print (contract §2/§8).

Safety is not a flag you can turn off: ``run`` and ``fingerprint`` refuse to send a
single request without ``--scope``; ``--dry-run`` resolves and sends nothing. ``-A``
widens the battery, never the authorization gate (``docs/09 §5``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from ildottore.adapters.base import AdapterError
from ildottore.cli import calibrate as calibrate_mod
from ildottore.cli import coverage as coverage_mod
from ildottore.cli import describe as describe_mod
from ildottore.cli import diff as diff_mod
from ildottore.cli import fingerprint as fingerprint_mod
from ildottore.cli import fleet as fleet_mod
from ildottore.cli import new_spec as new_spec_mod
from ildottore.cli import registry as registry_mod
from ildottore.cli import render_media as render_media_mod
from ildottore.cli import replay as replay_mod
from ildottore.cli import run as run_mod
from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.flags import DEFAULT_TEMPLATE
from ildottore.cli.lint import run_lint
from ildottore.cli.run import RunOptions, ScopeRequiredError
from ildottore.policy.errors import PolicyError
from ildottore.shared.schema_export import export_schemas

__version__ = "0.0.1"

DEFAULT_SPEC_PATHS = [Path("specs")]

app = typer.Typer(
    name="dottore",
    help="Il Dottore, nmap-for-AI: a spec-driven security scanner for LLMs and AI apps.",
    no_args_is_help=True,
    add_completion=False,
)

registry_app = typer.Typer(help="Inspect the attack-spec registry (read-only).")
schema_app = typer.Typer(help="Export the generated JSON schemas.")
app.add_typer(registry_app, name="registry")
app.add_typer(schema_app, name="schema")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"dottore {__version__}")
        raise typer.Exit(ExitCode.CLEAN)


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Il Dottore root - see ``dottore <command> --help`` for each command."""


def _spec_paths(spec: list[Path] | None) -> list[Path]:
    return list(spec) if spec else DEFAULT_SPEC_PATHS


# --- run -------------------------------------------------------------------------


@app.command()
def run(
    target: Annotated[
        list[Path] | None,
        typer.Option("-t", "--target", help="Target file(s) (target.yaml). Repeatable."),
    ] = None,
    target_pos: Annotated[
        list[Path] | None,
        # A target.yaml, not a URL: the help promised "url/model-id/target.yaml" and only
        # ever accepted a file (a URL turned into "No such file or directory"). Declaring an
        # endpoint is the target file's job, because a URL alone cannot carry the provider,
        # the credential reference or the declared capabilities.
        typer.Argument(help="Target file(s) as positional args (target.yaml)."),
    ] = None,
    judge: Annotated[
        Path | None,
        typer.Option(
            "--judge",
            help="Judge model target.yaml (LLM-as-judge for semantic_judge on live scans).",
        ),
    ] = None,
    scope: Annotated[
        Path | None,
        typer.Option(
            "--scope",
            help="REQUIRED authorization record (scope.yaml).",
            # readable=False so an unreadable file surfaces as OUR operational error (exit 3)
            # instead of click's usage error (exit 2, which this tool uses for "findings at or
            # above --fail-on"): a CI step reading exit 2 as "vulnerabilities" would be wrong.
            readable=False,
        ),
    ] = None,
    suite: Annotated[
        str | None,
        typer.Option("--suite", help="Suite id/alias (owasp:llm, mitre:atlas, …)."),
    ] = None,
    categories: Annotated[
        str | None,
        typer.Option("-p", "--categories", help="Comma-separated categories (pi,jailbreak,…)."),
    ] = None,
    spec_glob: Annotated[
        list[str] | None,
        typer.Option("--spec", help="Spec id or glob (e.g. 'PI-*'). Repeatable."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Exclude spec id/glob. Repeatable."),
    ] = None,
    top_tests: Annotated[
        int | None, typer.Option("--top-tests", help="Keep the N highest-signal specs.")
    ] = None,
    sn: Annotated[bool, typer.Option("-sn", help="Discovery only (no attacks).")] = False,
    sv: Annotated[bool, typer.Option("-sV", help="Fingerprint before attacking.")] = False,
    aggressive: Annotated[
        bool, typer.Option("-A", help="Aggressive: -sV + deep + adaptive.")
    ] = False,
    quick: Annotated[bool, typer.Option("--quick", help="T0 minimum battery.")] = False,
    deep: Annotated[bool, typer.Option("--deep", help="T2 deep/agentic suite.")] = False,
    template: Annotated[
        int | None,
        typer.Option("-T", help="Timing template 0..5 (default 3; --quick/--deep imply one)."),
    ] = None,
    rate: Annotated[float | None, typer.Option("--rate", help="Max requests/sec.")] = None,
    budget_tokens: Annotated[
        int | None,
        typer.Option("--budget-tokens", help="Hard token ceiling (overrides the derived one)."),
    ] = None,
    budget_requests: Annotated[
        int | None,
        typer.Option("--budget-requests", help="Hard request ceiling (overrides the derived)."),
    ] = None,
    budget_wall: Annotated[
        int | None,
        typer.Option("--budget-wall", help="Hard wall-clock ceiling in seconds (overrides)."),
    ] = None,
    concurrency: Annotated[
        int | None, typer.Option("--concurrency", help="Max concurrent specs.")
    ] = None,
    timeout_s: Annotated[
        float | None, typer.Option("--timeout", help="Per-attempt timeout (s).")
    ] = None,
    runs: Annotated[int, typer.Option("--runs", help="Reproducibility runs (default 5).")] = 5,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Resolve + validate; send nothing.")
    ] = False,
    estimate: Annotated[
        bool,
        typer.Option(
            "--estimate", help="Print a pre-run cost estimate (requests + tokens); no sends."
        ),
    ] = False,
    fail_on: Annotated[
        str, typer.Option("--fail-on", help="CI gate band (low|medium|high|critical).")
    ] = "high",
    include_needs_review: Annotated[
        bool, typer.Option("--include-needs-review", help="Also gate low-confidence findings.")
    ] = False,
    compare: Annotated[bool, typer.Option("--compare", help="Model-comparison matrix.")] = False,
    hardened: Annotated[
        bool, typer.Option("--hardened", help="Replay hardened fixtures (clean-run smoke).")
    ] = False,
    o_json: Annotated[Path | None, typer.Option("-oJ", help="Write JSON report.")] = None,
    o_html: Annotated[Path | None, typer.Option("-oH", help="Write HTML report.")] = None,
    o_sarif: Annotated[Path | None, typer.Option("-oS", help="Write SARIF report.")] = None,
    o_junit: Annotated[Path | None, typer.Option("-oX", help="Write JUnit XML report.")] = None,
    o_all: Annotated[
        Path | None, typer.Option("-oA", help="Write all four formats to <prefix>.*")
    ] = None,
    evidence_root: Annotated[
        Path | None, typer.Option("--evidence-root", help="Evidence store root dir.")
    ] = None,
    run_db: Annotated[Path | None, typer.Option("--run-db", help="Run store SQLite path.")] = None,
    spec_path: Annotated[
        list[Path] | None, typer.Option("--spec-path", help="Spec search path (default specs/).")
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colour output.")] = False,
    quiet: Annotated[
        bool, typer.Option("-q", "--quiet", help="Suppress per-spec progress.")
    ] = False,
    verbose: Annotated[int, typer.Option("-v", "--verbose", count=True, help="Verbosity.")] = 0,
) -> None:
    """Run a campaign against one or more targets (the default command)."""

    targets = list(target or []) + list(target_pos or [])
    outputs: dict[str, Path] = {}
    if o_json is not None:
        outputs["json"] = o_json
    if o_html is not None:
        outputs["html"] = o_html
    if o_sarif is not None:
        outputs["sarif"] = o_sarif
    if o_junit is not None:
        outputs["junit"] = o_junit

    # Intensity flags change the battery / timing but never touch the scope gate.
    # ``-A`` is documented as "-sV + deep + adaptive", so it implies both of those here
    # rather than being a third, separate behaviour.
    #
    # An EXPLICIT -T always wins. `--quick`/`--deep` used to overwrite it in both directions
    # without a word: `-T0 --deep` quietly became T2 (0.5 to 2.0 req/s, concurrency 1 to 2),
    # and -T0 is exactly what an operator picks for a fragile production target. The implied
    # template is a default, so it applies only when the operator did not choose one.
    resolved_deep = deep or aggressive
    if template is not None:
        resolved_template = template
    elif quick:
        resolved_template = 0
    elif resolved_deep:
        resolved_template = 2
    else:
        resolved_template = DEFAULT_TEMPLATE

    opts = RunOptions(
        targets=targets,
        scope=scope,
        judge=judge,
        suite=suite,
        categories=[c.strip() for c in categories.split(",")] if categories else [],
        spec_globs=list(spec_glob or []),
        exclude_globs=list(exclude or []),
        top_tests=top_tests,
        template=resolved_template,
        discovery_only=sn,
        fingerprint_first=sv or aggressive,
        quick=quick,
        deep=resolved_deep,
        verbose=verbose,
        rate=rate,
        budget_tokens=budget_tokens,
        budget_requests=budget_requests,
        budget_wall_s=budget_wall,
        concurrency=concurrency,
        timeout_s=timeout_s,
        runs=runs,
        dry_run=dry_run,
        estimate=estimate,
        fail_on=fail_on,
        include_needs_review=include_needs_review,
        compare=compare,
        outputs=outputs,
        output_all_prefix=o_all,
        hardened=hardened,
        no_color=no_color,
        quiet=quiet,
        evidence_root=evidence_root,
        run_db=run_db,
    )

    if not targets:
        typer.echo("error: no target given (use -t/--target or a positional target)", err=True)
        raise typer.Exit(ExitCode.ERROR)

    try:
        outcome = run_mod.execute_run(opts, _spec_paths(spec_path))
    except ScopeRequiredError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    except (PolicyError, AdapterError, ValueError, OSError) as exc:
        # AdapterError (and its EndpointNotAllowed subclass) is an authorization/transport
        # failure, i.e. an operational error: exit 3. It derives from Exception, not from
        # ValueError, so it used to escape this handler entirely and surface as a traceback
        # with exit **1**, which in this tool means "findings below the threshold" - a CI
        # step treating 1 as "carry on" would read a refused endpoint as a clean-ish scan.
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    # The dry-run plan is printed by execute_run itself (it owns the resolved plan);
    # echoing a second, contentless line here just duplicated the header.
    raise typer.Exit(int(outcome.exit_code))


# --- fleet -----------------------------------------------------------------------


@app.command()
def fleet(
    config: Annotated[
        Path, typer.Argument(help="fleet.yaml declaring every LLM/URL/MCP target to validate.")
    ],
    out: Annotated[
        Path, typer.Option("--out", help="Output dir for the generated scope + target files.")
    ] = Path(".dottore/fleet"),
    run_now: Annotated[
        bool, typer.Option("--run", help="Scan every expanded target immediately.")
    ] = False,
    judge: Annotated[
        Path | None, typer.Option("--judge", help="Judge model target.yaml (for semantic_judge).")
    ] = None,
    runs: Annotated[int, typer.Option("--runs", help="Reproducibility runs (default 5).")] = 5,
    categories: Annotated[
        str | None, typer.Option("-p", "--categories", help="Comma-separated categories.")
    ] = None,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colour output.")] = False,
) -> None:
    """Expand a fleet.yaml into an authorization scope + one target file per model.

    Declares the whole set of targets to validate in one place (hosted LLMs by API-key env
    reference, a local model, a raw URL, or an MCP server). Keys are never written, each
    entry references an env var. With ``--run`` it scans every expanded target right away.
    """

    try:
        cfg = fleet_mod.load_fleet(config)
        # The judge model goes into the generated scope: it is a target we send prompts to.
        judge_target = wiring.load_target(judge) if judge is not None else None
        materialized = fleet_mod.materialize_fleet(cfg, out, judge=judge_target)
    except (ValueError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    typer.echo(f"scope:   {materialized.scope_path}")
    for path in materialized.target_paths:
        typer.echo(f"target:  {path}")
    for target_id, reason in materialized.skipped:
        typer.echo(f"skipped: {target_id} ({reason})")

    if not run_now:
        joined = " ".join(f'"{p}"' for p in materialized.target_paths)
        # Carry --judge into the hint: the scope was widened to authorize the judge, and an
        # operator following a hint that omits it drops the judge from the run.
        judge_arg = f' --judge "{judge}"' if judge is not None else ""
        typer.echo(
            f'\nRun it:\n  dottore run {joined} --scope "{materialized.scope_path}"{judge_arg}'
        )
        raise typer.Exit(ExitCode.CLEAN)

    opts = RunOptions(
        targets=list(materialized.target_paths),
        scope=materialized.scope_path,
        judge=judge,
        categories=[c.strip() for c in categories.split(",")] if categories else [],
        runs=runs,
        no_color=no_color,
    )
    try:
        outcome = run_mod.execute_run(opts, _spec_paths(None))
    # AdapterError included for the same reason `run` includes it (see that handler): it
    # derives from Exception, so `fleet --run` used to turn an HTTP 401 or an off-allowlist
    # endpoint into a traceback and exit **1**, which in this tool means "findings below the
    # threshold". Identical condition, identical code path underneath, two exit codes.
    except (ScopeRequiredError, PolicyError, AdapterError, ValueError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    raise typer.Exit(int(outcome.exit_code))


# --- fingerprint -----------------------------------------------------------------


@app.command()
def fingerprint(
    target: Annotated[Path, typer.Argument(help="Target file (target.yaml).")],
    scope: Annotated[
        Path | None,
        typer.Option("--scope", help="REQUIRED authorization record.", readable=False),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Probe the deterministic mock instead of the live endpoint (no sends).",
        ),
    ] = False,
) -> None:
    """Fingerprint a target's model + guardrails (``-sV``).

    A target declaring a real endpoint is probed over the wire (scope-gated). Use
    ``--offline`` for the deterministic mock, which sends nothing and works in CI.
    """

    try:
        fp = fingerprint_mod.fingerprint_target(target, scope, offline=offline)
    except ScopeRequiredError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    except (PolicyError, AdapterError, ValueError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    typer.echo(fp.model_dump_json(indent=2))
    raise typer.Exit(ExitCode.CLEAN)


# --- coverage (read-only, no target) ---------------------------------------------


@app.command()
def coverage(
    paths: Annotated[list[Path] | None, typer.Argument(help="Spec paths to measure.")] = None,
    framework: Annotated[
        str, typer.Option("--framework", help="all | owasp | atlas | iopc.")
    ] = "all",
    suite: Annotated[
        str | None, typer.Option("--suite", help="Narrow to one suite (id or alias).")
    ] = None,
    gaps: Annotated[
        bool, typer.Option("--gaps/--no-gaps", help="List the codes NOT covered.")
    ] = True,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """What the battery TESTS, per framework, without running a scan.

    Reads the spec registry only: no target, no credential, nothing sent. Answers the
    question asked before a run (and before a purchase): "covered, of what?".
    """

    if framework not in coverage_mod.FRAMEWORK_KEYS:
        typer.echo(
            f"error: --framework must be one of {', '.join(coverage_mod.FRAMEWORK_KEYS)}",
            err=True,
        )
        raise typer.Exit(ExitCode.ERROR)
    try:
        result = coverage_mod.battery_coverage(list(paths or DEFAULT_SPEC_PATHS), suite=suite)
    except (OSError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    if as_json:
        typer.echo(coverage_mod.render_coverage_json(result, framework=framework, show_gaps=gaps))
    else:
        typer.echo(coverage_mod.render_coverage(result, framework=framework, show_gaps=gaps))
    raise typer.Exit(ExitCode.CLEAN)


# --- lint (mounted from u02) -----------------------------------------------------


@app.command()
def lint(
    paths: Annotated[list[Path] | None, typer.Argument(help="Spec paths to lint.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Schema + policy + fixtures-prove-detection lint (u02 command body)."""

    search = paths or DEFAULT_SPEC_PATHS
    code, output = run_lint(search, as_json=as_json)
    typer.echo(output)
    raise typer.Exit(code)


# --- registry --------------------------------------------------------------------


@registry_app.command("ls")
def registry_ls(
    category: Annotated[str | None, typer.Option("--category")] = None,
    owasp: Annotated[str | None, typer.Option("--owasp")] = None,
    tag: Annotated[str | None, typer.Option("--tag")] = None,
    suite: Annotated[str | None, typer.Option("--suite")] = None,
    spec_path: Annotated[list[Path] | None, typer.Option("--spec-path")] = None,
) -> None:
    """List registered specs (filterable by category/owasp/tag/suite)."""

    specs = registry_mod.list_specs(
        _spec_paths(spec_path), category=category, owasp=owasp, tag=tag, suite=suite
    )
    for row in registry_mod.render_spec_rows(specs):
        typer.echo(row)


@app.command()
def describe(
    spec_id: Annotated[str, typer.Argument(help="Spec id to describe.")],
    spec_path: Annotated[list[Path] | None, typer.Option("--spec-path")] = None,
) -> None:
    """Show one spec's detail card."""

    try:
        spec = describe_mod.describe_spec(_spec_paths(spec_path), spec_id)
    except describe_mod.DescribeError as exc:
        typer.echo(f"error: spec {spec_id!r} not found", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    typer.echo(describe_mod.render_describe(spec))


# --- render-media ----------------------------------------------------------------


@app.command("render-media")
def render_media(
    spec_id: Annotated[str, typer.Argument(help="Multimodal spec id (declares attack.media).")],
    out_dir: Annotated[Path, typer.Option("--out", help="Output directory.")] = Path(),
    spec_path: Annotated[list[Path] | None, typer.Option("--spec-path")] = None,
) -> None:
    """Render a multimodal spec's image carrier(s) to disk to inspect them (read-only, no target).

    Writes one PNG per ``attack.media`` part and prints each path, size and SHA-256 digest (the
    same chain-of-custody hash a run records). Sends nothing.
    """

    try:
        carriers = render_media_mod.render_spec_media(_spec_paths(spec_path), spec_id, out_dir)
    except render_media_mod.RenderMediaError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    typer.echo(render_media_mod.render_carrier_report(carriers))


# --- new-spec --------------------------------------------------------------------


@app.command("new-spec")
def new_spec(
    spec_id: Annotated[str, typer.Option("--id", help="New spec id (e.g. PI-NEW-001).")],
    family: Annotated[str, typer.Option("--family", help="Spec family/tag.")],
    category: Annotated[str, typer.Option("--category", help="Category.")] = "prompt_injection",
    out_dir: Annotated[
        Path, typer.Option("--out", help="Output directory (default: current dir).")
    ] = Path(),
    stdout: Annotated[
        bool, typer.Option("--stdout", help="Print scaffold instead of writing.")
    ] = False,
) -> None:
    """Scaffold a new attack spec + empty fixtures."""

    try:
        if stdout:
            typer.echo(new_spec_mod.scaffold_spec(spec_id, family=family, category=category))
            return
        path = new_spec_mod.write_scaffold(out_dir, spec_id, family=family, category=category)
    except (ValueError, FileExistsError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    typer.echo(f"wrote {path}")


# --- replay ----------------------------------------------------------------------


@app.command()
def replay(
    run_id: Annotated[str, typer.Argument(help="Run id to replay from stored evidence.")],
    evidence_root: Annotated[
        Path, typer.Option("--evidence-root", help="Evidence store root dir.")
    ] = Path(".dottore/evidence"),
) -> None:
    """Re-read a run from stored evidence (reproducibility, no re-sending)."""

    try:
        result = replay_mod.replay(evidence_root, run_id)
    except (OSError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    typer.echo(replay_mod.render_replay(result))


# --- diff (baseline / drift) ------------------------------------------------------


@app.command()
def diff(
    baseline: Annotated[Path, typer.Argument(help="Baseline JSON run report (-oJ output).")],
    current: Annotated[Path, typer.Argument(help="Current JSON run report (-oJ output).")],
) -> None:
    """Compare a run against a stored baseline and surface regressions (docs/12 P1).

    Classifies each spec id as NEW-FAIL (regression), FIXED, STILL-FAIL or UNCHANGED and
    exits nonzero when any regression is present, so this is CI-gateable like ``run``.
    """

    try:
        # A truncated report is the input that silently breaks this gate: the specs that never
        # ran are absent, absence classifies as ONLY-IN-BASELINE, and ONLY-IN-BASELINE is not
        # a regression, so a scan that dropped a third of the battery diffs green. Refuse it.
        for label, path in (("baseline", baseline), ("current", current)):
            incomplete = diff_mod.incomplete_reason(path)
            if incomplete is not None:
                typer.echo(
                    f"error: the {label} report describes a run that did not complete "
                    f"({incomplete}). Its missing specs would diff as ONLY-IN-BASELINE, "
                    "which is not a regression, so the comparison would read clean. "
                    "Re-run that scan, or diff two complete reports.",
                    err=True,
                )
                raise typer.Exit(ExitCode.ERROR)
        report = diff_mod.diff_reports(baseline, current)
    except (OSError, ValueError, KeyError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    typer.echo(diff_mod.render_diff(report))
    code = ExitCode.FINDINGS_AT_OR_ABOVE if report.has_regressions() else ExitCode.CLEAN
    raise typer.Exit(int(code))


@app.command()
def calibrate(
    report: Annotated[Path, typer.Argument(help="A JSON run report (-oJ output).")],
    labels: Annotated[Path, typer.Argument(help="Operator labels file (spec_id -> pass|fail).")],
) -> None:
    """Compare a run's findings against operator labels (human-in-the-loop, docs/12 P2).

    Reports agreement plus precision/recall (fail = positive). Read-only: it consumes operator
    verdicts to measure the scanner and its judge; it changes nothing and sends nothing.
    """

    try:
        result = calibrate_mod.calibrate_reports(report, labels)
    except (OSError, ValueError, KeyError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    typer.echo(calibrate_mod.render_calibration(result))
    raise typer.Exit(ExitCode.CLEAN)


# --- schema export ---------------------------------------------------------------


@schema_app.command("export")
def schema_export(
    name: Annotated[
        str | None, typer.Option("--name", help="One schema (suite|pack|test-plan|attack-spec).")
    ] = None,
) -> None:
    """Export the generated JSON schemas to stdout."""

    schemas = export_schemas()
    if name is not None:
        if name not in schemas:
            typer.echo(
                f"error: unknown schema {name!r}; available: {', '.join(sorted(schemas))}",
                err=True,
            )
            raise typer.Exit(ExitCode.ERROR)
        typer.echo(json.dumps(schemas[name], indent=2, sort_keys=True))
        return
    typer.echo(json.dumps(schemas, indent=2, sort_keys=True))
