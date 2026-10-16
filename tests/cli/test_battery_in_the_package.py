"""The built-in battery lives in the package, and an old path is refused naming the new one (u12
A-84).

Until A-84 the battery sat at the repository root (``specs/pack.yaml``, ``specs/attacks``,
``specs/suites``) beside three example files (``specs/scope.example.yaml``,
``specs/fleet.example.yaml``, ``specs/targets/example-openai.yaml``), found three directories above
the package, which a wheel does not have. The battery is ``src/ildottore/battery`` now, the
examples are in ``examples/``, and ``specs/`` holds the unit contracts only. So:

* with no ``--spec-path``, ``specs/`` in the working directory is read only when it holds a YAML
  file (a project's own pack or specs, as before), else the built-in battery, which is how the
  repository root, whose ``specs/`` holds Markdown only, reads the battery; the stderr note says
  which;
* a path a user may have written for the old layout (``--spec-path <checkout>/specs/attacks``,
  ``-t <checkout>/specs/targets/example-openai.yaml``, ...) is refused as before, exit 3, and the
  refusal names where it is now when that exists in the same checkout.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.shared.package_data import BATTERY, moved_note, moved_to

from .conftest import write_scope, write_target

runner = CliRunner()
REPO = Path(__file__).resolve().parents[2]
_LATER = "(CHANGELOG, Unreleased)"


# --- the default spec path ----------------------------------------------------------------------


def test_a_specs_directory_is_a_spec_path_only_when_it_holds_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    specs = tmp_path / "specs"
    specs.mkdir()
    assert wiring.default_spec_paths() == [BATTERY]  # empty
    (specs / "contracts").mkdir()
    (specs / "contracts" / "u00.md").write_text("# a contract\n")
    assert wiring.default_spec_paths() == [BATTERY]  # Markdown only, as the repository's own
    (specs / "attacks").mkdir()
    (specs / "attacks" / "MINE-001.yaml").write_text("id: MINE-001\n")
    # YAML below it and no pack.yaml: read, and refused as before (A-82's NO_SPECS), never
    # replaced by the built-in battery.
    assert wiring.default_spec_paths() == [Path("specs")]


def test_a_tree_too_large_to_look_through_is_read_as_before(tmp_path: Path) -> None:
    for index in range(1001):
        (tmp_path / f"note-{index}.md").write_text("")
    assert wiring.holds_yaml(tmp_path)


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions, not root"
)
def test_a_tree_it_cannot_list_is_read_as_before(tmp_path: Path) -> None:
    """Not replaced by the built-in battery: the loader then says what it cannot read."""

    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        assert wiring.holds_yaml(tmp_path)
    finally:
        locked.chmod(0o755)


def test_the_repository_root_reads_the_built_in_battery_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(REPO)
    assert wiring.default_spec_paths() == [BATTERY]
    result = runner.invoke(app, ["registry", "ls"])
    assert result.exit_code == 0, result.output
    assert result.stderr == (
        "note: specs/ here holds no YAML file, so this reads the built-in battery inside the "
        f"installed package: {BATTERY} (pass --spec-path to read another)\n"
    )
    assert len(result.stdout.splitlines()) == 75


def test_the_repository_specs_directory_holds_no_yaml() -> None:
    """Else the repository root would read it, not the battery, with no --spec-path."""

    assert (REPO / "specs" / "contracts" / "00-INDEX.md").is_file()
    assert not wiring.holds_yaml(REPO / "specs")
    assert not (REPO / "schemas").exists()


# --- an old path names the new one --------------------------------------------------------------


def _checkout(root: Path) -> Path:
    """A checkout of the layout after A-84: specs/ with contracts only, the battery in the
    package, the examples in examples/."""

    (root / "specs" / "contracts").mkdir(parents=True)
    (root / "specs" / "contracts" / "00-INDEX.md").write_text("# index\n")
    battery = root / "src" / "ildottore" / "battery"
    (battery / "attacks").mkdir(parents=True)
    (battery / "suites").mkdir()
    (battery / "pack.yaml").write_bytes((BATTERY / "pack.yaml").read_bytes())
    (battery / "attacks" / "PI-DIRECT-001.yaml").write_bytes(
        (BATTERY / "attacks" / "PI-DIRECT-001.yaml").read_bytes()
    )
    schemas = root / "src" / "ildottore" / "registry" / "schemas"
    schemas.mkdir(parents=True)
    (schemas / "attack-spec.schema.json").write_text("{}\n")
    (root / "examples").mkdir()
    for name in ("scope.example.yaml", "fleet.example.yaml", "target.example-openai.yaml"):
        (root / "examples" / name).write_bytes((REPO / "examples" / name).read_bytes())
    return root


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("specs/attacks", "src/ildottore/battery/attacks"),
        ("specs/attacks/PI-DIRECT-001.yaml", "src/ildottore/battery/attacks/PI-DIRECT-001.yaml"),
        ("specs/suites", "src/ildottore/battery/suites"),
        ("specs/pack.yaml", "src/ildottore/battery/pack.yaml"),
    ],
)
def test_lint_of_an_old_battery_path_names_the_new_one(tmp_path: Path, old: str, new: str) -> None:
    root = _checkout(tmp_path / "ck")
    result = runner.invoke(app, ["lint", str(root / old)])
    assert result.exit_code == 3, result.output
    # The old path does not exist, so the CLI's mask may hide its tail; the new one is kept.
    assert "PATH_NOT_FOUND (-): path not found: " in result.output
    assert f"; it is now {root / new} {_LATER}" in result.output


def test_a_spec_path_at_the_old_specs_names_the_battery_it_held(tmp_path: Path) -> None:
    """The CI example of #118 passed ``--spec-path .ildottore/specs``: past A-84 that directory
    holds the contracts only, and the refusal says where the battery is."""

    root = _checkout(tmp_path / "ck")
    for argv in (
        ["registry", "ls", "--spec-path", str(root / "specs")],
        ["lint", str(root / "specs")],
    ):
        result = runner.invoke(app, argv)
        assert result.exit_code == 3, result.output
        assert (
            f"holds no attack spec or suite to read: a directory without a pack.yaml is read as "
            f"loose specs, the *.yaml and *.yml files directly in it, and it has none; the "
            f"built-in battery it held is now {root / 'src' / 'ildottore' / 'battery'} {_LATER}"
        ) in result.output


def test_the_old_example_files_name_the_new_ones(tmp_path: Path) -> None:
    root = _checkout(tmp_path / "ck")
    scope, target = write_scope(tmp_path), write_target(tmp_path)
    old_target = root / "specs" / "targets" / "example-openai.yaml"
    result = runner.invoke(app, ["run", "-t", str(old_target), "--scope", str(scope), "--dry-run"])
    assert result.exit_code == 3, result.output
    assert f"; it is now {root / 'examples' / 'target.example-openai.yaml'} {_LATER}" in (
        result.output
    )

    old_scope = root / "specs" / "scope.example.yaml"
    result = runner.invoke(app, ["run", "-t", str(target), "--scope", str(old_scope), "--dry-run"])
    assert result.exit_code == 3, result.output
    assert f"cannot read scope file {old_scope}: " in result.output
    assert f"; it is now {root / 'examples' / 'scope.example.yaml'} {_LATER}" in result.output

    old_fleet = root / "specs" / "fleet.example.yaml"
    result = runner.invoke(app, ["fleet", str(old_fleet), "--out", str(tmp_path / "out")])
    assert result.exit_code == 3, result.output
    assert f"; it is now {root / 'examples' / 'fleet.example.yaml'} {_LATER}" in result.output
    assert not (tmp_path / "out").exists()


def test_the_schema_and_a_path_outside_a_checkout(tmp_path: Path) -> None:
    root = _checkout(tmp_path / "ck")
    assert moved_to(root / "schemas" / "attack-spec.schema.json") == (
        root / "src" / "ildottore" / "registry" / "schemas" / "attack-spec.schema.json"
    )
    # Not a checkout of the new layout: nothing is said to have moved.
    (tmp_path / "other" / "specs").mkdir(parents=True)
    for path in ("other/specs/attacks", "other/specs", "other/specs/scope.example.yaml"):
        assert moved_note(tmp_path / path) == ""
    result = runner.invoke(app, ["lint", str(tmp_path / "other" / "specs" / "attacks")])
    assert result.exit_code == 3, result.output
    assert "it is now" not in result.output
    # The contracts directory did not move, and a name too long to look up is no match.
    assert moved_to(root / "specs" / "contracts") is None
    assert moved_note("specs/" + "9" * 5000) == ""


def test_the_real_repository_is_a_checkout_of_the_new_layout() -> None:
    assert moved_to(REPO / "specs" / "attacks") == BATTERY / "attacks"
    assert moved_to(REPO / "specs") == BATTERY
    assert moved_to(REPO / "specs" / "targets" / "example-openai.yaml") == (
        REPO / "examples" / "target.example-openai.yaml"
    )
