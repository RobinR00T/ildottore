"""`fleet --run` runs from anywhere and takes run's store and report options (u12 A-80).

It read `specs/` in the working directory and had no option to change it, so it worked from the
repository root only ("path not found: specs"), and it had no `--evidence-root`, `--run-db` or
`-o*`: its stores went to `.dottore/` wherever it was started and it wrote no report. `run` and
every other command share one default spec path now: `specs/` in the working directory when
there is one, else the battery beside the installed package.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import run as run_mod
from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.cli.exit_codes import ExitCode

REPO = Path(__file__).resolve().parents[2]

_FLEET = (
    'version: "1"\ntargets:\n  - id: local\n    endpoint: '
    "http://127.0.0.1:9/v1/chat/completions\n    model: m\n"
)


def test_the_default_spec_path_outside_the_repository_is_the_packaged_battery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert wiring.default_spec_paths() == [REPO / "specs"]
    (tmp_path / "specs").mkdir()
    assert wiring.default_spec_paths() == [Path("specs")]  # a local pack still comes first


def test_run_from_outside_the_repository_reads_the_packaged_battery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "scope.yaml").write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text("id: mock-target\ntype: chatbot\n")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app, ["run", "target.yaml", "--scope", "scope.yaml", "--dry-run", "-q", "--no-color"]
    )
    assert result.exit_code == 0, result.output
    assert result.output.startswith("dry-run: ")


def test_a_spec_path_that_does_not_exist_is_named_as_such(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(wiring, "PACKAGED_SPEC_PATH", tmp_path / "no-battery")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "scope.yaml").write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text("id: mock-target\ntype: chatbot\n")
    result = CliRunner().invoke(
        app, ["run", "target.yaml", "--scope", "scope.yaml", "--dry-run", "--no-color"]
    )
    assert result.exit_code == 3, result.output
    assert "error: spec path not found: specs. Pass --spec-path <dir>" in result.output
    assert "failed to load" not in result.output


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> list[tuple[run_mod.RunOptions, list[Path]]]:
    """What `fleet --run` hands the run, without running it."""

    seen: list[tuple[run_mod.RunOptions, list[Path]]] = []

    def capture(opts: run_mod.RunOptions, spec_paths: list[Path]) -> run_mod.RunOutcome:
        seen.append((opts, spec_paths))
        return run_mod.RunOutcome(exit_code=ExitCode.CLEAN)

    monkeypatch.setattr(run_mod, "execute_run", capture)
    return seen


def test_fleet_run_from_outside_the_repository_uses_the_shared_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    captured: list[tuple[run_mod.RunOptions, list[Path]]],
) -> None:
    (tmp_path / "fleet.yaml").write_text(_FLEET)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["fleet", "fleet.yaml", "--out", "o", "--run"])
    assert result.exit_code == 0, result.output
    assert [spec_paths for _, spec_paths in captured] == [[REPO / "specs"]]


def test_fleet_run_passes_the_run_options_through(
    tmp_path: Path, captured: list[tuple[run_mod.RunOptions, list[Path]]]
) -> None:
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(_FLEET)
    pack = tmp_path / "pack"
    pack.mkdir()
    result = CliRunner().invoke(
        app,
        [
            "fleet",
            str(fleet),
            "--out",
            str(tmp_path / "o"),
            "--run",
            "--spec-path",
            str(pack),
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "r.db"),
            "-oJ",
            str(tmp_path / "r.json"),
            "-oA",
            str(tmp_path / "all"),
        ],
    )
    assert result.exit_code == 0, result.output
    ((opts, spec_paths),) = captured
    assert spec_paths == [pack]
    assert opts.evidence_root == tmp_path / "ev"
    assert opts.run_db == tmp_path / "r.db"
    assert opts.outputs == {"json": tmp_path / "r.json"}
    assert opts.output_all_prefix == tmp_path / "all"
    assert opts.extra_inputs == [("the fleet file", fleet)]


def test_without_run_the_options_are_carried_into_the_printed_command(tmp_path: Path) -> None:
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(_FLEET)
    result = CliRunner().invoke(
        app,
        [
            "fleet",
            str(fleet),
            "--out",
            str(tmp_path / "o"),
            "--spec-path",
            "pack",
            "--run-db",
            "r.db",
            "-oS",
            "out.sarif",
        ],
    )
    assert result.exit_code == 0, result.output
    hint = result.output.splitlines()[-1]
    assert hint.endswith(' --spec-path "pack" --run-db "r.db" -oS "out.sarif"'), hint


def test_fleet_run_writes_its_report_and_stores_where_it_is_told(tmp_path: Path) -> None:
    """End to end against a mock fleet entry: the report and both stores land where asked."""

    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(
        'version: "1"\ntargets:\n  - id: mock-target\n    endpoint: mock://mock-target\n'
    )
    result = CliRunner().invoke(
        app,
        [
            "fleet",
            str(fleet),
            "--out",
            str(tmp_path / "o"),
            "--run",
            "--runs",
            "1",
            "-p",
            "pi",
            "--spec-path",
            str(REPO / "specs"),
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "r.db"),
            "-oJ",
            str(tmp_path / "r.json"),
            "--no-color",
        ],
    )
    assert result.exit_code in (0, 1, 2), result.output
    report = json.loads((tmp_path / "r.json").read_text())
    assert report["run"]["run_id"]
    assert (tmp_path / "r.db").is_file()
    assert any((tmp_path / "ev").iterdir())
