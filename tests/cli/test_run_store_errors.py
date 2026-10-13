"""A run store that cannot be used exits 3 before anything is sent, and nothing exits 1 but
findings (u10 A-80, u12 A-9).

Exit 1 means "findings below --fail-on", so a CI gate that lets 1 through read a crashed scan as
a pass. Before this: a `--run-db` naming a directory or a file that is not SQLite, `replay
--run-db <garbage>`, and five of six concurrent runs on a new store all ended in a traceback with
exit 1; with `-sV` the 18 probes went out first, as the store was first opened inside the
per-target loop.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import app as app_mod
from ildottore.cli import registry as registry_mod
from ildottore.cli import run as run_mod
from ildottore.cli import wiring
from ildottore.cli.app import app

from .conftest import make_spec, write_scope, write_spec_tree, write_target

REPO = Path(__file__).resolve().parents[2]


def _workspace(tmp_path: Path, *, targets: int = 1) -> tuple[list[Path], Path, Path]:
    spec_dir = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    if targets == 1:
        return [write_target(tmp_path, mock_scenario="vulnerable")], write_scope(tmp_path), spec_dir
    paths = []
    scope_lines = ['version: "1.0"\n', "targets:\n"]
    for i in range(targets):
        tid = f"mock-{i}"
        sub = tmp_path / tid
        sub.mkdir()
        paths.append(write_target(sub, target_id=tid, mock_scenario="vulnerable"))
        scope_lines.append(
            f'  - id: {tid}\n    base_url: "mock://{tid}"\n    endpoints:\n'
            f'      - host: "{tid}"\n        path_prefixes: ["/"]\n'
            '    identities:\n      - name: default\n        auth_ref: "env://MOCK_KEY"\n'
        )
    scope = tmp_path / "scope.yaml"
    scope.write_text("".join(scope_lines), encoding="utf-8")
    return paths, scope, spec_dir


def _run(tmp_path: Path, *extra: str, targets: int = 1) -> tuple[int, str]:
    paths, scope, spec_dir = _workspace(tmp_path, targets=targets)
    argv = ["run", *(a for p in paths for a in ("-t", str(p))), "--scope", str(scope)]
    argv += ["--spec-path", str(spec_dir), "--runs", "1", "-q", "--no-color"]
    if "--evidence-root" not in extra:
        argv += ["--evidence-root", str(tmp_path / "ev")]
    result = CliRunner().invoke(app, [*argv, *extra])
    return result.exit_code, result.output


@pytest.fixture
def no_sends(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every way the run sends (the probe pass, the campaign) recorded as called."""

    calls: list[str] = []

    def refuse(name: str):  # type: ignore[no-untyped-def]
        def _called(*args: object, **kwargs: object) -> object:
            calls.append(name)
            raise AssertionError(f"{name} was reached")

        return _called

    monkeypatch.setattr(wiring, "fingerprint_probe", refuse("fingerprint_probe"))
    monkeypatch.setattr(wiring, "build_runner", refuse("build_runner"))
    return calls


@pytest.mark.parametrize("sv", [False, True], ids=["plain", "with-sV"])
def test_a_directory_as_run_db_exits_3_before_any_send(
    tmp_path: Path, no_sends: list[str], sv: bool
) -> None:
    store = tmp_path / "dbdir"
    store.mkdir()
    code, shown = _run(tmp_path, "--run-db", str(store), *(["-sV"] if sv else []))
    assert code == 3, shown
    assert f"error: cannot open the run store at {store}: it is a directory, not a file" in shown
    assert "Traceback" not in shown
    assert no_sends == []


@pytest.mark.parametrize("sv", [False, True], ids=["plain", "with-sV"])
def test_a_garbage_run_db_exits_3_before_any_send(
    tmp_path: Path, no_sends: list[str], sv: bool
) -> None:
    store = tmp_path / "garbage.db"
    store.write_text("garbage" * 50)
    code, shown = _run(tmp_path, "--run-db", str(store), *(["-sV"] if sv else []))
    assert code == 3, shown
    assert f"error: cannot open the run store at {store}: file is not a database" in shown
    assert no_sends == []
    assert store.read_text() == "garbage" * 50


def test_several_targets_check_the_store_before_the_first_one_sends(
    tmp_path: Path, no_sends: list[str]
) -> None:
    store = tmp_path / "garbage.db"
    store.write_text("garbage")
    code, shown = _run(tmp_path, "--run-db", str(store), targets=2)
    assert code == 3, shown
    assert "cannot open the run store at" in shown
    assert no_sends == []


@pytest.mark.parametrize("mode", ["--dry-run", "--estimate"])
def test_the_no_send_modes_say_the_store_is_unusable_and_write_nothing(
    tmp_path: Path, mode: str
) -> None:
    """Their job is "is my wiring right?": a store that cannot be opened is wrong wiring."""

    store = tmp_path / "garbage.db"
    store.write_text("garbage")
    code, shown = _run(tmp_path, "--run-db", str(store), mode)
    assert code == 3, shown
    assert f"cannot open the run store at {store}: file is not a database" in shown
    assert not (tmp_path / "ev").exists()


@pytest.mark.parametrize("mode", ["--dry-run", "--estimate"])
def test_the_no_send_modes_still_create_nothing_for_a_new_store(tmp_path: Path, mode: str) -> None:
    code, shown = _run(tmp_path, "--run-db", str(tmp_path / "new" / "runs.sqlite"), mode)
    assert code == 0, shown
    assert not (tmp_path / "new").exists()
    assert not (tmp_path / "ev").exists()


def test_a_store_path_under_a_regular_file_exits_3(tmp_path: Path, no_sends: list[str]) -> None:
    (tmp_path / "plain").write_text("x")
    code, shown = _run(tmp_path, "--run-db", str(tmp_path / "plain" / "runs.sqlite"))
    assert code == 3, shown
    assert "cannot open the run store at" in shown
    assert no_sends == []


def test_replay_with_a_garbage_run_db_exits_3(tmp_path: Path) -> None:
    code, _ = _run(tmp_path, "--run-db", str(tmp_path / "runs.sqlite"))
    assert code == 2
    run_id = next(p.name for p in (tmp_path / "ev").iterdir())
    garbage = tmp_path / "garbage.db"
    garbage.write_text("garbage" * 100)
    result = CliRunner().invoke(
        app,
        ["replay", run_id, "--evidence-root", str(tmp_path / "ev"), "--run-db", str(garbage)],
    )
    assert result.exit_code == 3, result.output
    assert f"error: cannot open the run store at {garbage}: file is not a database" in (
        result.output
    )
    assert "Traceback" not in result.output


def test_a_store_that_fails_mid_run_exits_3_naming_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sqlite3 error that reaches the command (here from the end-of-run spend write)."""

    import sqlite3

    def locked(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(run_mod, "_persist_run_spend", locked)
    store = tmp_path / "runs.sqlite"
    code, shown = _run(tmp_path, "--run-db", str(store))
    assert code == 3, shown
    assert f"error: the run store at {store} failed: database is locked" in shown


def test_concurrent_runs_on_a_new_store_all_finish(tmp_path: Path) -> None:
    """The auditor's reproduction: six `dottore run` on one new --run-db, started together."""

    _, scope, spec_dir = _workspace(tmp_path)
    target = tmp_path / "target.yaml"
    store = tmp_path / "new.sqlite"
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); sys.argv = ['dottore', *sys.argv[2:]]\n"
        "from ildottore.cli.main import app; app()"
    )
    argv = [
        str(REPO / "src"),
        "run",
        str(target),
        "--scope",
        str(scope),
        "--spec-path",
        str(spec_dir),
        "--runs",
        "1",
        "-q",
        "--no-color",
        "--evidence-root",
        str(tmp_path / "ev"),
        "--run-db",
        str(store),
    ]
    env = {**os.environ, "MOCK_KEY": "x", "NO_COLOR": "1"}
    start = time.monotonic()
    runs = [
        subprocess.Popen(  # noqa: S603 - this interpreter, fixed arguments
            [sys.executable, "-c", code, *argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )
        for _ in range(6)
    ]
    outcomes = [(r.wait(timeout=180), r.communicate()[0]) for r in runs]
    assert time.monotonic() - start < 180
    for returncode, output in outcomes:
        # 2: the vulnerable mock's finding at or above --fail-on high, as a lone run exits.
        assert returncode == 2, output
        assert "Traceback" not in output


# --- the top-level guard: an unexpected exception is exit 3, never 1 --------------------


def test_an_unexpected_exception_in_run_exits_3_in_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(run_mod, "execute_run", boom)
    code, shown = _run(tmp_path, "--run-db", str(tmp_path / "runs.sqlite"))
    assert code == 3, shown
    errors = [line for line in shown.splitlines() if line.startswith("error:")]
    assert errors == [
        "error: unexpected RuntimeError: boom (an internal error, not a scan result; "
        "rerun as `dottore -v ...` for the traceback)"
    ]
    assert "Traceback" not in shown


@pytest.mark.parametrize("where", ["root", "run"])
def test_the_traceback_is_printed_under_v(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError("boom")

    monkeypatch.setattr(run_mod, "execute_run", boom)
    paths, scope, spec_dir = _workspace(tmp_path)
    argv = ["run", str(paths[0]), "--scope", str(scope), "--spec-path", str(spec_dir)]
    argv = ["-v", *argv] if where == "root" else [*argv, "-v"]
    result = CliRunner().invoke(app, argv)
    assert result.exit_code == 3, result.output
    assert "Traceback (most recent call last):" in result.output
    assert "RuntimeError: boom" in result.output


def test_an_unexpected_exception_in_a_sub_command_exits_3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise KeyError("spec")

    monkeypatch.setattr(registry_mod, "list_specs_and_unloaded", boom)
    result = CliRunner().invoke(app, ["registry", "ls"])
    assert result.exit_code == 3, result.output
    assert "error: unexpected KeyError: 'spec'" in result.output


def test_the_guard_masks_what_the_exception_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "sk-ant-api03-Q7xZ2mV9pL4kR8tN1wB6yH3jF5dS0aC-QwErTyUiOpAsDfGh"

    def boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError(f"failed with key {secret}")

    monkeypatch.setattr(run_mod, "execute_run", boom)
    for verbose in ([], ["-v"]):
        paths, scope, spec_dir = _workspace(tmp_path / f"v{len(verbose)}")
        result = CliRunner().invoke(
            app,
            [*verbose, "run", str(paths[0]), "--scope", str(scope), "--spec-path", str(spec_dir)],
        )
        assert result.exit_code == 3, result.output
        assert secret not in result.output
        assert secret[:20] not in result.output


def test_a_broken_output_pipe_exits_3(monkeypatch: pytest.MonkeyPatch) -> None:
    def closed(*args: object, **kwargs: object) -> list[str]:
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(registry_mod, "render_spec_rows", closed)
    result = CliRunner().invoke(app, ["registry", "ls"])
    assert result.exit_code == 3, result.output


def test_ctrl_c_still_exits_130(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted(*args: object, **kwargs: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(run_mod, "execute_run", interrupted)
    code, _ = _run(tmp_path, "--run-db", str(tmp_path / "runs.sqlite"))
    assert code == 130


def test_the_guard_is_on_the_installed_entry_point() -> None:
    """`dottore` and `dott` are `ildottore.cli.main:app`: the guarded group is that object."""

    from ildottore.cli import main

    assert main.app is app_mod.app
    assert isinstance(app_mod.app.info.cls, type)
    assert issubclass(app_mod.app.info.cls, app_mod.OperationalErrorGroup)


# --- pre-merge audit of e6a1ab9b, LOW 5: the library's own errors and a stray exit ----------


@pytest.mark.parametrize(
    "raised",
    ["click-exception", "file-error", "abort", "system-exit-1", "system-exit-2", "system-exit-str"],
)
def test_nothing_the_command_line_library_raises_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raised: str
) -> None:
    """A `ClickException` (exit 1 by default), an `Abort` (exit 1, "Aborted!") and a stray
    `SystemExit(1)` (rich's answer to a broken pipe) passed the guard with exit 1."""

    import typer._click.exceptions as click_errors

    def boom(*args: object, **kwargs: object) -> object:
        if raised == "click-exception":
            raise click_errors.ClickException("boom")
        if raised == "file-error":
            raise click_errors.FileError("x.yaml", hint="cannot read")
        if raised == "abort":
            raise click_errors.Abort()
        if raised == "system-exit-1":
            raise SystemExit(1)
        if raised == "system-exit-2":
            raise SystemExit(2)
        raise SystemExit("stopped")

    monkeypatch.setattr(run_mod, "execute_run", boom)
    code, shown = _run(tmp_path, "--run-db", str(tmp_path / "runs.sqlite"))
    assert code == 3, shown


def test_a_stray_exit_0_is_still_0(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def done(*args: object, **kwargs: object) -> object:
        raise SystemExit(0)

    monkeypatch.setattr(run_mod, "execute_run", done)
    code, _ = _run(tmp_path, "--run-db", str(tmp_path / "runs.sqlite"))
    assert code == 0


def test_the_root_verbose_option_reads_as_a_counted_flag() -> None:
    """LOW 8: its help read `-v, --verbose  INTEGER  [default: 0]`, as if it took a value."""

    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    line = next(row for row in result.output.splitlines() if "--verbose" in row)
    assert "INTEGER" not in line
    assert "default: 0" not in line


def test_a_store_another_process_keeps_locked_exits_3_naming_it_before_any_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_sends: list[str]
) -> None:
    """LOW 1 of the pre-merge audit: the wait is said, and the store it gave up on is named."""

    import sqlite3

    from ildottore.store import SqliteRunStore, migrations

    monkeypatch.setattr(migrations, "BUSY_TIMEOUT_S", 0.5)
    monkeypatch.setattr(migrations, "NOTICE_AFTER_S", 0.05)
    store = tmp_path / "runs.sqlite"
    with SqliteRunStore(store):
        pass
    holder = sqlite3.connect(store, timeout=0)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        code, shown = _run(tmp_path, "--run-db", str(store))
    finally:
        holder.close()
    assert code == 3, shown
    assert f"note: waiting for the run store at {store}: another process holds its lock" in shown
    assert f"the run store at {store} stayed locked by another process for 0.5 s" in shown
    assert no_sends == []


def test_fleet_run_maps_a_store_error_to_exit_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sqlite3

    def locked(*args: object, **kwargs: object) -> object:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(run_mod, "execute_run", locked)
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text('version: "1"\ntargets:\n  - id: m\n    endpoint: mock://m\n')
    store = tmp_path / "r.db"
    result = CliRunner().invoke(
        app, ["fleet", str(fleet), "--out", str(tmp_path / "o"), "--run", "--run-db", str(store)]
    )
    assert result.exit_code == 3, result.output
    assert f"error: the run store at {store} failed: database is locked" in result.output


def test_replay_maps_a_store_error_to_exit_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sqlite3

    from ildottore.cli import replay as replay_mod

    def locked(*args: object, **kwargs: object) -> object:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(replay_mod, "replay_checked", locked)
    store = tmp_path / "r.db"
    result = CliRunner().invoke(app, ["replay", "run-0123456789ab", "--run-db", str(store)])
    assert result.exit_code == 3, result.output
    assert f"error: the run store at {store} failed: database is locked" in result.output


def test_replay_refuses_a_directory_as_its_run_store(tmp_path: Path) -> None:
    """LOW 7: it warned "no run store at <dir>" and replayed without the manifest check."""

    code, _ = _run(tmp_path, "--run-db", str(tmp_path / "runs.sqlite"))
    assert code == 2
    run_id = next(p.name for p in (tmp_path / "ev").iterdir())
    store = tmp_path / "dbdir"
    store.mkdir()
    result = CliRunner().invoke(
        app, ["replay", run_id, "--evidence-root", str(tmp_path / "ev"), "--run-db", str(store)]
    )
    assert result.exit_code == 3, result.output
    assert f"cannot open the run store at {store}: it is a directory, not a file" in result.output
