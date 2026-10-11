"""A report never overwrites an input of the run (u12 A-80).

`-oJ scope.yaml -oH target.yaml` overwrote the authorization record and the target file with
the reports, after the run had sent its traffic. An output that resolves to the scope, a
target, the judge file, the run store, a file of the spec path, or another output is refused
before anything is sent (exit 3).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import wiring
from ildottore.cli.app import app

from .conftest import make_spec, write_scope, write_spec_tree, write_target


@pytest.fixture
def no_sends(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def refuse(*args: object, **kwargs: object) -> object:
        calls.append("build_runner")
        raise AssertionError("build_runner was reached")

    monkeypatch.setattr(wiring, "build_runner", refuse)
    return calls


def _files(tmp_path: Path) -> tuple[Path, Path, Path]:
    return (
        write_target(tmp_path, mock_scenario="vulnerable"),
        write_scope(tmp_path),
        write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")]),
    )


def _run(tmp_path: Path, *extra: str, store: Path | None = None) -> tuple[int, str]:
    target, scope, specs = _files(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "run",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(store or tmp_path / "runs.sqlite"),
            "--runs",
            "1",
            "-q",
            "--no-color",
            *extra,
        ],
    )
    return result.exit_code, result.output


def test_the_auditors_reproduction_is_refused_and_both_inputs_survive(
    tmp_path: Path, no_sends: list[str]
) -> None:
    target, scope, _ = _files(tmp_path)
    before = (scope.read_text(), target.read_text())
    code, shown = _run(tmp_path, "-oJ", str(scope), "-oH", str(target))
    assert code == 3, shown
    assert f"the JSON report would overwrite the --scope file {scope}" in shown
    assert (scope.read_text(), target.read_text()) == before
    assert no_sends == []


@pytest.mark.parametrize(
    ("flag", "name", "label"),
    [
        ("-oH", "target.yaml", "a target file"),
        ("-oS", "specs/PI-DIRECT-001.yaml", "a file of the spec path"),
        ("-oX", "runs.sqlite", "the run store (--run-db)"),
    ],
)
def test_each_input_is_protected(
    tmp_path: Path, no_sends: list[str], flag: str, name: str, label: str
) -> None:
    _files(tmp_path)
    code, shown = _run(tmp_path, flag, str(tmp_path / name))
    assert code == 3, shown
    assert f"would overwrite {label}" in shown
    assert no_sends == []


def test_the_run_store_is_protected_before_it_exists(tmp_path: Path, no_sends: list[str]) -> None:
    store = tmp_path / "new" / "runs.sqlite"
    (tmp_path / "new").mkdir()
    code, shown = _run(tmp_path, "-oJ", str(store), store=store)
    assert code == 3, shown
    assert "would overwrite the run store (--run-db)" in shown
    for sibling in ("-wal", "-shm"):
        code, shown = _run(tmp_path, "-oJ", f"{store}{sibling}", store=store)
        assert code == 3, shown


def test_the_judge_file_is_protected(tmp_path: Path, no_sends: list[str]) -> None:
    judge = tmp_path / "judge.yaml"
    judge.write_text("id: judge\ntype: model\nmock_scenario: hardened\n")
    code, shown = _run(tmp_path, "--judge", str(judge), "-oJ", str(judge))
    assert code == 3, shown
    assert f"would overwrite the --judge file {judge}" in shown
    assert judge.read_text().startswith("id: judge")


def test_a_symlink_to_an_input_is_the_input(tmp_path: Path, no_sends: list[str]) -> None:
    _, scope, _ = _files(tmp_path)
    link = tmp_path / "report.json"
    link.symlink_to(scope)
    code, shown = _run(tmp_path, "-oJ", str(link))
    assert code == 3, shown
    assert "would overwrite the --scope file" in shown


def _case_insensitive(directory: Path) -> bool:
    probe = directory / "CaseProbe"
    probe.write_text("x")
    try:
        return (directory / "caseprobe").exists()
    finally:
        probe.unlink()


def test_another_spelling_of_an_input_on_a_case_insensitive_volume(
    tmp_path: Path, no_sends: list[str]
) -> None:
    if not _case_insensitive(tmp_path):
        pytest.skip("a case-sensitive volume: SCOPE.YAML is another file")
    _files(tmp_path)
    code, shown = _run(tmp_path, "-oJ", str(tmp_path / "SCOPE.YAML"))
    assert code == 3, shown
    assert "would overwrite the --scope file" in shown


def test_an_all_formats_prefix_that_hits_an_input_is_refused(
    tmp_path: Path, no_sends: list[str]
) -> None:
    _files(tmp_path)
    os.link(tmp_path / "scope.yaml", tmp_path / "hard.xml")  # one file under two names
    code, shown = _run(tmp_path, "-oA", str(tmp_path / "hard"))
    assert code == 3, shown
    assert "the JUnit report would overwrite the --scope file" in shown


def test_outputs_next_to_the_inputs_are_still_written(tmp_path: Path) -> None:
    code, shown = _run(tmp_path, "-oJ", str(tmp_path / "report.json"))
    assert code == 2, shown
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "scope.yaml").read_text().startswith('version: "1.0"')


def test_fleet_run_protects_its_own_inputs(tmp_path: Path, no_sends: list[str]) -> None:
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(
        'version: "1"\ntargets:\n  - id: local\n    endpoint: '
        "http://127.0.0.1:9/v1/chat/completions\n    model: m\n"
    )
    before = fleet.read_text()
    result = CliRunner().invoke(
        app,
        ["fleet", str(fleet), "--out", str(tmp_path / "o"), "--run", "-oJ", str(fleet)],
    )
    assert result.exit_code == 3, result.output
    assert "would overwrite the fleet file" in result.output
    assert fleet.read_text() == before
