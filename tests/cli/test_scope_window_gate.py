"""``run`` and ``fingerprint`` refuse a scope outside its validity window (u01 A-97).

The refusal is ``ScopeError``, exit 3, before any target file is built into an adapter, under
``--dry-run`` too: the command whose job is checking the wiring checks the dates.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from typer.testing import CliRunner

import ildottore.cli.run as run_mod
import ildottore.policy.packs as packs
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app

from .conftest import write_scope, write_target

runner = CliRunner()
DAY = dt.date(2026, 10, 26)


def _scope_with(tmp_path: Path, window: str) -> Path:
    path = write_scope(tmp_path)
    path.write_text(path.read_text(encoding="utf-8") + window, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _today(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_mod, "utc_today", lambda: DAY)
    monkeypatch.setattr(packs, "utc_today", lambda: DAY)


def test_dry_run_refuses_an_expired_scope_with_exit_three(tmp_path: Path) -> None:
    scope = _scope_with(tmp_path, "valid_until: 2026-10-25\n")
    res = runner.invoke(
        app, ["run", "--dry-run", "-t", str(write_target(tmp_path)), "--scope", str(scope)]
    )
    assert res.exit_code == int(ExitCode.ERROR), res.output
    assert "authorizes nothing today: the scope expired on 2026-10-25" in res.output
    assert "today (UTC) is 2026-10-26" in res.output and "valid_until" in res.output
    assert "plan resolved" not in res.output


def test_dry_run_refuses_a_scope_not_valid_yet(tmp_path: Path) -> None:
    scope = _scope_with(tmp_path, "valid_from: 2026-11-01\n")
    res = runner.invoke(
        app, ["run", "--dry-run", "-t", str(write_target(tmp_path)), "--scope", str(scope)]
    )
    assert res.exit_code == int(ExitCode.ERROR)
    assert "the scope is valid from 2026-11-01" in res.output


def test_the_plan_states_the_window_of_a_valid_scope(tmp_path: Path) -> None:
    scope = _scope_with(tmp_path, "valid_from: 2026-10-01\nvalid_until: 2026-10-26\n")
    res = runner.invoke(
        app, ["run", "--dry-run", "-t", str(write_target(tmp_path)), "--scope", str(scope)]
    )
    assert res.exit_code == int(ExitCode.CLEAN), res.output
    assert (
        f"  scope:   {scope} (valid from 2026-10-01 until 2026-10-26, UTC days, both included)"
        in res.output
    )


def test_a_scope_without_a_window_plans_as_before(tmp_path: Path) -> None:
    scope = write_scope(tmp_path)
    res = runner.invoke(
        app, ["run", "--dry-run", "-t", str(write_target(tmp_path)), "--scope", str(scope)]
    )
    assert res.exit_code == int(ExitCode.CLEAN), res.output
    assert f"  scope:   {scope}\n" in res.output


def test_fingerprint_refuses_an_expired_scope(tmp_path: Path) -> None:
    scope = _scope_with(tmp_path, "valid_until: 2026-10-25\n")
    res = runner.invoke(app, ["fingerprint", str(write_target(tmp_path)), "--scope", str(scope)])
    assert res.exit_code == int(ExitCode.ERROR), res.output
    assert "the scope expired on 2026-10-25" in res.output
