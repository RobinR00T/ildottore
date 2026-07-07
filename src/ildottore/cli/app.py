"""Typer root — the ``dottore`` command surface (contract §1/§5).

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

from ildottore.cli import describe as describe_mod
from ildottore.cli import fingerprint as fingerprint_mod
from ildottore.cli import new_spec as new_spec_mod
from ildottore.cli import registry as registry_mod
from ildottore.cli import replay as replay_mod
from ildottore.cli import run as run_mod
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.lint import run_lint
from ildottore.cli.run import RunOptions, ScopeRequiredError
from ildottore.policy.errors import PolicyError
from ildottore.shared.schema_export import export_schemas

__version__ = "0.0.1"

DEFAULT_SPEC_PATHS = [Path("specs")]

app = typer.Typer(
    name="dottore",
    help="Il Dottore — nmap-for-AI: a spec-driven security scanner for LLMs and AI apps.",
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
    """Il Dottore root — see ``dottore <command> --help`` for each command."""


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
        typer.Argument(help="Target(s) as positional args (url/model-id/target.yaml)."),
    ] = None,
    scope: Annotated[
        Path | None,
        typer.Option("--scope", help="REQUIRED authorization record (scope.yaml)."),
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
    template: Annotated[int, typer.Option("-T", help="Timing template 0..5 (default 3).")] = 3,
    rate: Annotated[float | None, typer.Option("--rate", help="Max requests/sec.")] = None,
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

    # Intensity flags widen the battery / timing but never touch the scope gate.
    resolved_template = template
    if quick:
        resolved_template = 0
    elif deep:
        resolved_template = 2

    opts = RunOptions(
        targets=targets,
        scope=scope,
        suite=suite,
        categories=[c.strip() for c in categories.split(",")] if categories else [],
        spec_globs=list(spec_glob or []),
        exclude_globs=list(exclude or []),
        top_tests=top_tests,
        template=resolved_template,
        rate=rate,
        concurrency=concurrency,
        timeout_s=timeout_s,
        runs=runs,
        dry_run=dry_run,
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
    except (PolicyError, ValueError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc

    if outcome.dry_run:
        typer.echo("dry-run: resolved plan; sent nothing.")
    raise typer.Exit(int(outcome.exit_code))


# --- fingerprint -----------------------------------------------------------------


@app.command()
def fingerprint(
    target: Annotated[Path, typer.Argument(help="Target file (target.yaml).")],
    scope: Annotated[
        Path | None, typer.Option("--scope", help="REQUIRED authorization record.")
    ] = None,
) -> None:
    """Fingerprint a target's model + guardrails (``-sV``)."""

    try:
        fp = fingerprint_mod.fingerprint_target(target, scope)
    except ScopeRequiredError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    except (PolicyError, ValueError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    typer.echo(fp.model_dump_json(indent=2))
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
    except OSError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(ExitCode.ERROR) from exc
    typer.echo(replay_mod.render_replay(result))


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
