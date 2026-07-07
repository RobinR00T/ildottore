"""End-to-end acceptance (contract §5/§7).

The CLI is the composition root, so its E2E exercises the whole wired system against
the deterministic :class:`MockTarget`: ``dottore run`` against a target.yaml + scope +
spec tree produces a JSON report with findings and a scriptable exit code, and ``-oA``
writes exactly the four report formats.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.run import RunOptions, execute_run

from .conftest import (
    make_spec,
    write_pack_with_suite,
    write_scope,
    write_spec_tree,
    write_target,
)

runner = CliRunner()


def _tree(tmp_path: Path):
    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001"), make_spec("JB-ROLEPLAY-001")])
    return scope, target, specs


def test_e2e_run_produces_json_report_with_findings(tmp_path: Path) -> None:
    scope, target, specs = _tree(tmp_path)
    out = tmp_path / "report.json"
    res = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "-oJ",
            str(out),
            "--runs",
            "1",
        ],
    )
    # Vulnerable fixtures ⇒ exploited ⇒ at/above default high gate ⇒ exit 2.
    assert res.exit_code == int(ExitCode.FINDINGS_AT_OR_ABOVE)
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "findings" in data
    assert len(data["findings"]) == 2


def test_e2e_run_via_execute_run_returns_findings(tmp_path: Path) -> None:
    scope, target, specs = _tree(tmp_path)
    opts = RunOptions(targets=[target], scope=scope, runs=1)
    outcome = execute_run(opts, [specs])
    assert outcome.exit_code is ExitCode.FINDINGS_AT_OR_ABOVE
    assert len(outcome.findings) == 2
    assert all(f.status.value == "fail" for f in outcome.findings)


def test_e2e_hardened_target_is_clean(tmp_path: Path) -> None:
    scope, target, specs = _tree(tmp_path)
    opts = RunOptions(targets=[target], scope=scope, runs=1, hardened=True)
    outcome = execute_run(opts, [specs])
    # Hardened fixtures ⇒ target stays secure ⇒ nothing gates ⇒ exit 0.
    assert outcome.exit_code is ExitCode.CLEAN


def test_oA_writes_exactly_four_report_files(tmp_path: Path) -> None:
    scope, target, specs = _tree(tmp_path)
    prefix = tmp_path / "acme"
    res = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "-oA",
            str(prefix),
            "--runs",
            "1",
        ],
    )
    assert res.exit_code in (int(ExitCode.FINDINGS_AT_OR_ABOVE), int(ExitCode.FINDINGS_BELOW))
    written = {p.suffix for p in tmp_path.glob("acme.*")}
    assert written == {".json", ".html", ".sarif", ".xml"}


def test_registered_suite_resolves_under_dry_run(tmp_path: Path) -> None:
    # A registered suite resolves its spec set; --dry-run sends nothing.
    pack = write_pack_with_suite(tmp_path, [make_spec("PI-DIRECT-001")])
    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    opts = RunOptions(targets=[target], scope=scope, suite="owasp:llm", dry_run=True)
    outcome = execute_run(opts, [pack])
    assert outcome.dry_run is True
    assert outcome.exit_code is ExitCode.CLEAN


def test_unregistered_suite_is_operational_error(tmp_path: Path) -> None:
    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--suite",
            "owasp:llm",
            "--dry-run",
        ],
    )
    assert res.exit_code > 2


def test_no_target_is_operational_error() -> None:
    res = runner.invoke(app, ["run", "--scope", "scope.yaml"])
    assert res.exit_code > 2
    assert "no target" in res.stdout.lower() or "no target" in (res.stderr or "").lower()


def test_fail_on_low_still_gates_low_findings(tmp_path: Path) -> None:
    scope, target, specs = _tree(tmp_path)
    opts = RunOptions(targets=[target], scope=scope, runs=1, fail_on="low")
    outcome = execute_run(opts, [specs])
    assert outcome.exit_code is ExitCode.FINDINGS_AT_OR_ABOVE
