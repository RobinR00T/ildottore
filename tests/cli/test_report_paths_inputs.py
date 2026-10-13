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


# --- the pre-merge audit of e6a1ab9b -------------------------------------------------------


def test_a_spec_file_spelled_in_another_case_is_protected(
    tmp_path: Path, no_sends: list[str]
) -> None:
    """MEDIUM 1: `os.path.realpath` keeps the case it is given, so on the macOS default volume
    `-oJ SPECS/PI-DIRECT-001.yaml` beside `--spec-path specs` overwrote the spec (exit 2)."""

    if not _case_insensitive(tmp_path):
        pytest.skip("a case-sensitive volume: SPECS/ is another directory")
    _, _, specs = _files(tmp_path)
    spec = specs / "PI-DIRECT-001.yaml"
    before = spec.read_text()
    other = tmp_path / "SPECS" / "PI-DIRECT-001.YAML"
    code, shown = _run(tmp_path, "-oJ", str(other))
    assert code == 3, shown
    assert "would overwrite a file of the spec path" in shown
    assert spec.read_text() == before


def test_a_hard_link_to_a_spec_file_outside_the_spec_path_is_protected(
    tmp_path: Path, no_sends: list[str]
) -> None:
    _, _, specs = _files(tmp_path)
    linked = tmp_path / "report.json"
    os.link(specs / "PI-DIRECT-001.yaml", linked)
    code, shown = _run(tmp_path, "-oJ", str(linked))
    assert code == 3, shown
    assert "would overwrite a file of the spec path" in shown


def test_the_store_siblings_are_those_of_the_file_a_link_names(
    tmp_path: Path, no_sends: list[str]
) -> None:
    """LOW 2: SQLite keeps `-wal` beside the file a symlinked `--run-db` names, not the link."""

    real = tmp_path / "realdir"
    real.mkdir()
    (real / "real.sqlite").write_bytes(b"")
    link = tmp_path / "link.sqlite"
    link.symlink_to(real / "real.sqlite")
    code, shown = _run(tmp_path, "-oJ", str(real / "real.sqlite-wal"), store=link)
    assert code == 3, shown
    assert "would overwrite the run store (--run-db)" in shown


def test_a_report_inside_a_run_directory_of_the_evidence_store_is_refused(
    tmp_path: Path, no_sends: list[str]
) -> None:
    """LOW 3: a report written over an artifact made the next resume refuse the run as
    tampered; the run directories hold only what a run writes."""

    run_dir = tmp_path / "ev" / "run-0123456789ab" / "attempts"
    run_dir.mkdir(parents=True)
    for target in (run_dir / "x.json", tmp_path / "ev" / "run-0123456789ab" / "r.json"):
        code, shown = _run(tmp_path, "-oJ", str(target))
        assert code == 3, shown
        assert "would write inside the evidence store" in shown


def test_a_report_beside_the_run_directories_is_still_written(tmp_path: Path) -> None:
    (tmp_path / "ev").mkdir()
    code, shown = _run(tmp_path, "-oJ", str(tmp_path / "ev" / "report.json"))
    assert code == 2, shown
    assert (tmp_path / "ev" / "report.json").is_file()


# --- round-2 audit of f51a7d07, LOW 1: only the files the loader read are protected ----------


def _pack_at(root: Path) -> None:
    (root / "pack.yaml").write_text("id: mine\npack_version: '1.0'\nname: mine\n")
    (root / "attacks").mkdir()
    spec = make_spec("PI-DIRECT-001")
    (root / "attacks" / "PI-DIRECT-001.yaml").write_text(spec.model_dump_json(indent=2))


def _run_in(root: Path, *extra: str) -> tuple[int, str]:
    target = write_target(root, mock_scenario="vulnerable")
    scope = write_scope(root)
    result = CliRunner().invoke(
        app,
        [
            "run",
            str(target),
            "--scope",
            str(scope),
            "--evidence-root",
            str(root / "ev"),
            "--run-db",
            str(root / "runs.sqlite"),
            "--runs",
            "1",
            "-q",
            "--no-color",
            *extra,
        ],
    )
    return result.exit_code, result.output


def test_a_rerun_writing_its_report_inside_the_spec_path_is_not_refused(tmp_path: Path) -> None:
    """`run --spec-path . -oJ out.json` twice: the second run refused "would overwrite a file of
    the spec path . (out.json)", a file the loader never reads (main allows it)."""

    _pack_at(tmp_path)
    report = tmp_path / "out.json"
    for _ in range(2):
        code, shown = _run_in(tmp_path, "--spec-path", str(tmp_path), "-oJ", str(report))
        assert code == 2, shown
    assert report.is_file()


def test_a_file_the_loader_read_inside_the_spec_path_is_still_protected(
    tmp_path: Path, no_sends: list[str]
) -> None:
    _pack_at(tmp_path)
    for name in ("pack.yaml", "attacks/PI-DIRECT-001.yaml"):
        code, shown = _run_in(tmp_path, "--spec-path", str(tmp_path), "-oJ", str(tmp_path / name))
        assert code == 3, (name, shown)
        assert "would overwrite a file of the spec path" in shown
    assert (tmp_path / "pack.yaml").read_text().startswith("id: mine")


def test_a_media_asset_the_loader_read_is_protected(tmp_path: Path, no_sends: list[str]) -> None:
    """A spec's media asset (an audio clip beside it) is read by the loader too."""

    import shutil

    repo = Path(__file__).resolve().parents[2]
    pack = tmp_path / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: mine\npack_version: '1.0'\nname: mine\n")
    audio = next(
        p for p in (repo / "specs" / "attacks").glob("*.yaml") if "asset:" in p.read_text()
    )
    shutil.copy(audio, pack / "attacks" / audio.name)
    for line in audio.read_text().splitlines():
        if "asset:" in line:
            asset = line.split("asset:", 1)[1].strip().strip("'\"")
            (pack / "attacks" / asset).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(audio.parent / asset, pack / "attacks" / asset)
    code, shown = _run_in(
        tmp_path, "--spec-path", str(pack), "-oJ", str(pack / "attacks" / asset)
    )
    assert code == 3, shown
    assert "would overwrite a file of the spec path" in shown
