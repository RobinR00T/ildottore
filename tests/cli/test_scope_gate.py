"""Scope gate is non-bypassable (contract §7).

``run``/``fingerprint``/``-A`` without ``--scope`` exit >2 with a clear error and
perform **zero** adapter sends. No flag (``-A``, ``--quick``, ``--deep``) can satisfy
the gate — only a real authorization record (``docs/09 §5``, ``docs/01 §6``).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import ildottore.cli.wiring as wiring
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.cli.run import RunOptions, ScopeRequiredError, execute_run

from .conftest import CountingAdapter, make_spec, write_scope, write_spec_tree, write_target

runner = CliRunner()


def test_run_without_scope_raises_before_any_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    """`execute_run` with no scope raises and never constructs an adapter (zero sends)."""

    adapter = CountingAdapter()

    def _no_adapters(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("adapter factory must not be reached without a scope")

    # Any attempt to build the runner / registry would be a leak past the gate.
    monkeypatch.setattr(wiring, "build_runner", _no_adapters)
    monkeypatch.setattr(wiring, "build_registry", _no_adapters)

    opts = RunOptions(targets=[Path("target.yaml")], scope=None)
    with pytest.raises(ScopeRequiredError):
        execute_run(opts, [Path("specs")])
    assert adapter.sends == 0


def test_run_cli_without_scope_exits_gt_two(tmp_path: Path) -> None:
    target = write_target(tmp_path)
    res = runner.invoke(app, ["run", "-t", str(target)])
    assert res.exit_code == int(ExitCode.ERROR)
    assert res.exit_code > 2
    assert "scope" in res.stdout.lower() or "scope" in (res.stderr or "").lower()


def test_aggressive_flag_does_not_bypass_scope(tmp_path: Path) -> None:
    target = write_target(tmp_path)
    # -A widens the battery, never the authorization gate.
    res = runner.invoke(app, ["run", "-A", "-t", str(target)])
    assert res.exit_code > 2


def test_quick_flag_does_not_bypass_scope(tmp_path: Path) -> None:
    target = write_target(tmp_path)
    res = runner.invoke(app, ["run", "--quick", "-t", str(target)])
    assert res.exit_code > 2


def test_fingerprint_cli_without_scope_exits_gt_two(tmp_path: Path) -> None:
    target = write_target(tmp_path)
    res = runner.invoke(app, ["fingerprint", str(target)])
    assert res.exit_code > 2


def test_dry_run_sends_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`--dry-run` resolves + validates the plan and performs zero adapter sends."""

    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    spec_dir = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])

    def _no_runner(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("--dry-run must not build a runner or send")

    monkeypatch.setattr(wiring, "build_runner", _no_runner)

    opts = RunOptions(targets=[target], scope=scope, dry_run=True)
    outcome = execute_run(opts, [spec_dir])
    assert outcome.dry_run is True
    assert outcome.exit_code is ExitCode.CLEAN
    assert outcome.findings == []


def test_dry_run_cli_reports_and_exits_clean(tmp_path: Path) -> None:
    scope = write_scope(tmp_path)
    target = write_target(tmp_path)
    spec_dir = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    res = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(spec_dir),
            "--dry-run",
        ],
    )
    assert res.exit_code == int(ExitCode.CLEAN)
    assert "dry-run" in res.stdout.lower()
