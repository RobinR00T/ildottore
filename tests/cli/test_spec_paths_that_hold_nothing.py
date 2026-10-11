"""A spec path that yields nothing is refused, and lint says what it reads (u02 and u12 A-82;
CLI audit of 2026-10-11, M9 and L7).

M9, measured on ``de122e26``: ``dottore lint sp`` with the specs under ``sp/attacks/`` and no
``pack.yaml`` printed ``lint OK: 0 error(s), 0 warning(s) across 0 spec(s)`` and exited 0, an
invalid spec there included; an empty directory passed the same way; and ``lint nonexistent``
exited 1 (the code for "your specs failed lint") instead of the I/O code 3. A directory without a
``pack.yaml`` is read as loose specs, its own ``*.yaml`` and ``*.yml`` files only (docs/06 §2,
unchanged), so:

* a path that does not exist is ``PATH_NOT_FOUND`` and one that yields no spec and no suite file
  ``NO_SPECS``, naming the YAML files in its subdirectories that a loose tree does not read; both
  make ``lint`` exit 3 (an error in a spec is still 1, and 3 wins);
* a loose tree that reads specs but leaves YAML files in its subdirectories gets a
  ``FILES_NOT_READ`` warning naming them;
* ``run``, ``registry ls``, ``coverage`` and ``describe`` refuse such a path with exit 3 (L7:
  ``registry ls --spec-path nonexistent`` and ``coverage`` of a missing or empty path exited 0,
  the latter printing 0%), and so does ``registry ls --suite nope``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

from .conftest import write_scope, write_target

runner = CliRunner()
_REPO = Path(__file__).resolve().parents[2]
_SPEC = (_REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text(encoding="utf-8")


def _lint(*args: str) -> Any:
    return runner.invoke(app, ["lint", *args])


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_a_pack_layout_without_its_manifest_checks_nothing_and_says_so(tmp_path: Path) -> None:
    sp = _tree(
        tmp_path / "sp",
        {"attacks/PI-DIRECT-001.yaml": _SPEC, "attacks/BROKEN-X-001.yaml": "id: [\n"},
    )
    result = _lint(str(sp))
    assert result.exit_code == 3, result.output
    assert "[ERROR] NO_SPECS" in result.output
    assert (
        f"spec path {sp} holds no attack spec or suite to read: a directory without a pack.yaml "
        "is read as loose specs, the *.yaml and *.yml files directly in it, and it has none; 2 "
        "YAML file(s) in its subdirectories (attacks/) are not read: add a pack.yaml to it "
        "(docs/06 §2) to load attacks/ and suites/, or point at the directory that holds the specs"
    ) in result.output.replace("\n", " ")
    assert "lint FAILED" in result.output


def test_an_empty_directory_checks_nothing(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    result = _lint(str(tmp_path / "empty"))
    assert result.exit_code == 3, result.output
    assert "NO_SPECS" in result.output and "has none" in result.output
    assert "not read" not in result.output


def test_a_pack_with_no_spec_and_no_suite_checks_nothing(tmp_path: Path) -> None:
    sp = _tree(tmp_path / "p", {"pack.yaml": 'id: p\npack_version: "1"\nname: P\n'})
    result = _lint(str(sp))
    assert result.exit_code == 3, result.output
    assert "NO_SPECS" in result.output and "its attacks/ and suites/ hold no" in result.output


@pytest.mark.parametrize("as_json", [False, True])
def test_a_path_that_does_not_exist_is_the_io_code(tmp_path: Path, as_json: bool) -> None:
    missing = tmp_path / "nonexistent"
    result = _lint(str(missing), *(["--json"] if as_json else []))
    assert result.exit_code == 3, result.output
    if as_json:
        report = json.loads(result.output)
        assert [e["code"] for e in report["errors"]] == ["PATH_NOT_FOUND"]
        assert report["ok"] is False
    else:
        assert f"[ERROR] PATH_NOT_FOUND (-): path not found: {missing}" in result.output


def test_three_wins_over_one(tmp_path: Path) -> None:
    sp = _tree(tmp_path / "sp", {"X-BAD-001.yaml": "id: X-BAD-001\n"})
    assert _lint(str(sp)).exit_code == 1
    assert _lint(str(sp), str(tmp_path / "nope")).exit_code == 3


def test_a_loose_tree_names_the_files_it_does_not_read(tmp_path: Path) -> None:
    sp = _tree(
        tmp_path / "sp",
        {
            "PI-DIRECT-001.yaml": _SPEC,
            "more/X-ONE-001.yaml": "id: X\n",
            "more/deeper/X-TWO-001.yml": "id: Y\n",
        },
    )
    result = _lint(str(sp))
    assert result.exit_code == 0, result.output
    assert "[WARN] FILES_NOT_READ" in result.output
    assert (
        "2 YAML file(s) in the subdirectories of a directory without a pack.yaml are not read "
        "(more/, more/deeper/)"
    ) in result.output.replace("\n", " ")
    assert "across 1 spec(s)" in result.output


def test_the_shipped_pack_and_a_file_named_directly_are_unchanged(tmp_path: Path) -> None:
    result = _lint(str(_REPO / "specs"))
    assert result.exit_code == 0, result.output
    assert "NO_SPECS" not in result.output and "FILES_NOT_READ" not in result.output
    single = _tree(tmp_path, {"PI-DIRECT-001.yaml": _SPEC}) / "PI-DIRECT-001.yaml"
    assert _lint(str(single)).exit_code == 0


# --- the other commands (L7) ----------------------------------------------------------------


def _run(tmp_path: Path, *spec_paths: Path) -> Any:
    return runner.invoke(
        app,
        [
            "run",
            "-t",
            str(write_target(tmp_path, mock_scenario="vulnerable")),
            "--scope",
            str(write_scope(tmp_path)),
            "--dry-run",
            *[arg for path in spec_paths for arg in ("--spec-path", str(path))],
        ],
    )


def test_run_refuses_a_spec_path_that_holds_nothing(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    for path, said in (
        (tmp_path / "nope", f"path not found: {tmp_path / 'nope'}"),
        (tmp_path / "empty", f"spec path {tmp_path / 'empty'} holds no attack spec or suite"),
    ):
        result = _run(tmp_path, _REPO / "specs", path)
        assert result.exit_code == 3, result.output
        assert "error: a spec path gives nothing to run" in result.output
        assert said in result.output.replace("\n", "")
        assert "failed to load" not in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["registry", "ls", "--spec-path", "{missing}"],
        ["registry", "ls", "--spec-path", "{empty}"],
        ["coverage", "{missing}"],
        ["coverage", "{empty}"],
        ["describe", "PI-DIRECT-001", "--spec-path", "{empty}"],
    ],
    ids=["registry-missing", "registry-empty", "coverage-missing", "coverage-empty", "describe"],
)
def test_the_inspection_commands_refuse_a_path_that_holds_nothing(
    tmp_path: Path, args: list[str]
) -> None:
    (tmp_path / "empty").mkdir()
    shown = [a.format(missing=tmp_path / "nonexistent", empty=tmp_path / "empty") for a in args]
    result = runner.invoke(app, shown)
    assert result.exit_code == 3, result.output
    assert "error: a spec path gives nothing to" in result.output
    assert "0%" not in result.output


def test_registry_ls_refuses_a_suite_that_is_not_registered() -> None:
    result = runner.invoke(
        app, ["registry", "ls", "--suite", "nope", "--spec-path", str(_REPO / "specs")]
    )
    assert result.exit_code == 3, result.output
    assert "error: suite 'nope' is not registered. Registered suites: " in result.output
    assert "owasp-llm-top10" in result.output


def test_registry_ls_and_coverage_of_the_shipped_pack_are_unchanged() -> None:
    specs = str(_REPO / "specs")
    assert runner.invoke(app, ["registry", "ls", "--spec-path", specs]).exit_code == 0
    assert (
        runner.invoke(app, ["registry", "ls", "--suite", "quick", "--spec-path", specs]).exit_code
        == 0
    )
    assert runner.invoke(app, ["coverage", specs]).exit_code == 0
