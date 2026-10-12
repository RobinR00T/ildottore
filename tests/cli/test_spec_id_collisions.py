"""A spec id declared twice refuses the run, naming both files (u02 and u12 A-82; CLI audit of
2026-10-11, L2).

``lint`` reported ``ID_COLLISION`` and ``run`` dropped it (``wiring.load_registry`` returned the
registry and its load errors, not its collisions): the first file loaded won without a word, so
a ``--spec-path`` pack that redeclared a shipped id ran the shipped spec, and two files with one
id in one directory ran whichever sorts first. ``run`` now refuses, before anything is sent, and
the collision names both files, in ``lint`` too.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from ildottore.cli.app import app

from .conftest import write_scope, write_target

runner = CliRunner()
_REPO = Path(__file__).resolve().parents[2]
_SPEC = (_REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text(encoding="utf-8")


def _run(tmp_path: Path, *spec_paths: Path, extra: tuple[str, ...] = ("--dry-run",)) -> Any:
    return runner.invoke(
        app,
        [
            "run",
            "-t",
            str(write_target(tmp_path, mock_scenario="vulnerable")),
            "--scope",
            str(write_scope(tmp_path)),
            "--spec",
            "PI-DIRECT-001",
            "--runs",
            "1",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "r.db"),
            *[arg for path in spec_paths for arg in ("--spec-path", str(path))],
            *extra,
        ],
    )


def test_two_files_with_one_id_in_one_directory_refuse_the_run(tmp_path: Path) -> None:
    sp = tmp_path / "sp"
    sp.mkdir()
    (sp / "a.yaml").write_text(_SPEC)
    (sp / "b.yaml").write_text(_SPEC.replace("name: ", "name: Copy of ", 1))
    for extra in (("--dry-run",), ()):
        result = _run(tmp_path, sp, extra=extra)
        assert result.exit_code == 3, result.output
        said = result.output.replace("\n", "")
        assert "error: spec id 'PI-DIRECT-001' is declared twice" in said
        assert f"{sp / 'a.yaml'}" in said and f"{sp / 'b.yaml'}" in said
        assert not (tmp_path / "ev").exists()


def test_a_spec_path_that_redeclares_a_shipped_id_refuses_the_run(tmp_path: Path) -> None:
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "mine.yaml").write_text(_SPEC)
    result = _run(tmp_path, _REPO / "specs", extra)
    assert result.exit_code == 3, result.output
    said = result.output.replace("\n", "")
    assert "spec id 'PI-DIRECT-001' is declared twice" in said
    assert str(_REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml") in said
    assert str(extra / "mine.yaml") in said


def test_lint_names_both_files_too(tmp_path: Path) -> None:
    sp = tmp_path / "sp"
    sp.mkdir()
    (sp / "a.yaml").write_text(_SPEC)
    (sp / "b.yaml").write_text(_SPEC)
    result = runner.invoke(app, ["lint", str(sp)])
    assert result.exit_code == 1, result.output
    said = result.output.replace("\n", "")
    assert "[ERROR] ID_COLLISION (PI-DIRECT-001)" in said
    assert f"already declared by {sp / 'a.yaml'} (pack 'loose-specs'); " in said
    assert f"{sp / 'b.yaml'} (pack 'loose-specs') re-declares it" in said


def test_one_declaration_per_id_runs_as_before(tmp_path: Path) -> None:
    assert _run(tmp_path, _REPO / "specs").exit_code == 0


def test_one_file_read_twice_is_no_collision(tmp_path: Path) -> None:
    """The same spec path twice, or a pack and its own attacks/ directory, read the same bytes."""

    specs = _REPO / "specs"
    assert _run(tmp_path, specs, specs).exit_code == 0
    assert _run(tmp_path, specs, specs / "attacks").exit_code == 0


def test_lint_reads_one_file_read_twice_as_one_declaration_too() -> None:
    """`lint sp sp` reported 75 ID_COLLISION naming the same file twice while `run` took the
    file once (pre-merge audit of A-82, LOW b)."""

    specs = str(_REPO / "specs")
    for args in ([specs, specs], [specs, str(_REPO / "specs" / "attacks")]):
        result = runner.invoke(app, ["lint", *args])
        assert result.exit_code == 0, result.output
        assert "ID_COLLISION" not in result.output
