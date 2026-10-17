"""The built-in battery lives in the package, and an old path is refused naming the new one (u12
A-84).

Until A-84 the battery sat at the repository root (``specs/pack.yaml``, ``specs/attacks``,
``specs/suites``) beside three example files (``specs/scope.example.yaml``,
``specs/fleet.example.yaml``, ``specs/targets/example-openai.yaml``), found three directories above
the package, which a wheel does not have. The battery is ``src/ildottore/battery`` now, the
examples are in ``examples/``, and ``specs/`` holds the unit contracts only. So:

* with no ``--spec-path``, ``specs/`` in the working directory is read whenever it is a directory,
  as before, and refused (exit 3) when it holds nothing to read, never replaced by the battery
  (pre-merge audit of A-84, HIGH 2: an empty ``specs/attacks`` scanned the built-in battery and
  exited 2, and a ``specs/`` reaching its pack through a link exited 0 on it); with no ``specs/``
  the built-in battery is read, and so it is at the root of this package's own checkout, whose
  ``specs/`` holds the unit contracts; the stderr note says which, and under GitHub Actions a
  ``::warning::`` line says it too;
* a path a user may have written for the old layout (``--spec-path <checkout>/specs/attacks``,
  ``-t <checkout>/specs/targets/example-openai.yaml``, ...) is refused as before, exit 3, and the
  refusal names where it is now when that exists in the same checkout.
"""

from __future__ import annotations

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
_BATTERY = "(the built-in battery moved into the package)"
_EXAMPLES = "(the example files moved from specs/ to examples/)"


# --- the default spec path ----------------------------------------------------------------------


def _mock_pair(where: Path) -> tuple[Path, Path]:
    return write_target(where, mock_scenario="vulnerable"), write_scope(where)


def _run_here(where: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    target, scope = _mock_pair(where)
    monkeypatch.chdir(where)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    return runner.invoke(
        app,
        [
            *["run", str(target), "--scope", str(scope), "--quick", "--runs", "1", "-q"],
            *["--evidence-root", str(where / "ev"), "--run-db", str(where / "runs.sqlite")],
        ],
    )


def test_an_empty_specs_directory_is_refused_not_replaced_by_the_battery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The audit's repro: an empty `specs/attacks` beside a vulnerable mock exited 2 after 18
    built-in specs; `7d01521f` exits 3, and so does this."""

    (tmp_path / "specs" / "attacks").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    assert wiring.default_spec_paths() == [Path("specs")]
    result = _run_here(tmp_path, monkeypatch)
    assert result.exit_code == 3, result.output  # type: ignore[attr-defined]
    assert "built-in battery" not in result.output  # type: ignore[attr-defined]
    assert not (tmp_path / "ev").exists() or not any((tmp_path / "ev").rglob("*.json"))


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_a_specs_directory_reaching_its_pack_through_a_link_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The audit's second repro: the branch exited 0 on the 75 built-in specs; it is exit 3, as
    on `7d01521f`, whatever the link reaches."""

    real = tmp_path / "real"
    (real / "attacks").mkdir(parents=True)
    (real / "pack.yaml").write_text("id: mine\npack_version: '1.0'\nname: mine\n")
    (real / "attacks" / "PI-DIRECT-001.yaml").write_bytes(
        (BATTERY / "attacks" / "PI-DIRECT-001.yaml").read_bytes()
    )
    work = tmp_path / "work"
    (work / "specs").mkdir(parents=True)
    (work / "specs" / "mine").symlink_to(real, target_is_directory=True)
    monkeypatch.chdir(work)
    assert wiring.default_spec_paths() == [Path("specs")]
    result = _run_here(work, monkeypatch)
    assert result.exit_code == 3, result.output  # type: ignore[attr-defined]
    assert "built-in battery" not in result.output  # type: ignore[attr-defined]


def test_no_specs_directory_reads_the_battery_and_says_so_twice_under_github_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert wiring.default_spec_paths() == [BATTERY]
    note = (
        "there is no specs/ directory here, so this reads the built-in battery inside the "
        f"installed package: {BATTERY} (pass --spec-path to read another)"
    )
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    result = runner.invoke(app, ["registry", "ls"])
    assert result.exit_code == 0, result.output
    assert result.stderr == f"note: {note}\n"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    result = runner.invoke(app, ["registry", "ls"])
    assert result.exit_code == 0, result.output
    assert result.stderr == f"note: {note}\n::warning title=dottore spec path::{note}\n"


def test_the_repository_root_reads_the_built_in_battery_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one exception: the root of this package's own checkout, whose specs/ is the contracts'
    directory. A copy of that tree elsewhere is no exception."""

    monkeypatch.chdir(REPO)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert wiring.is_own_checkout()
    assert wiring.default_spec_paths() == [BATTERY]
    result = runner.invoke(app, ["registry", "ls"])
    assert result.exit_code == 0, result.output
    assert result.stderr == (
        "note: this is Il Dottore's own checkout, whose specs/ holds the unit contracts, so this "
        f"reads the built-in battery inside the installed package: {BATTERY} (pass --spec-path "
        "to read another)\n"
    )
    assert len(result.stdout.splitlines()) == 75
    # `lint` stays strict there: it reads the contracts' specs/ and names the battery.
    result = runner.invoke(app, ["lint"])
    assert result.exit_code == 3, result.output
    relative = BATTERY.relative_to(REPO)
    assert f"the built-in battery it held moved into the package: it is now {relative}" in (
        result.output
    )


def test_a_directory_that_only_looks_like_the_checkout_reads_its_own_specs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "specs" / "contracts").mkdir(parents=True)
    (tmp_path / "specs" / "contracts" / "00-INDEX.md").write_text("# index\n")
    (tmp_path / "src" / "ildottore" / "battery").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    assert not wiring.is_own_checkout()
    assert wiring.default_spec_paths() == [Path("specs")]


def _operators_pack(root: Path) -> None:
    """A one-spec pack in ``root/specs``, the operator's own."""

    (root / "specs" / "attacks").mkdir(parents=True)
    (root / "specs" / "pack.yaml").write_text("id: mine\npack_version: '1.0'\nname: mine\n")
    (root / "specs" / "attacks" / "PI-DIRECT-001.yaml").write_bytes(
        (BATTERY / "attacks" / "PI-DIRECT-001.yaml").read_bytes()
    )


@pytest.mark.parametrize("vendor", ["deps", "vendor", "package", "lib"])
def test_a_package_installed_with_target_beside_the_operators_specs_reads_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, vendor: str
) -> None:
    """Round 2 of the audit, HIGH 1: with `pip install --target <dir>/deps`, the battery's
    parents[2] is `<dir>`, so from there the operator's specs/ went unread and the built-in 75
    ran under an "own checkout" note. The checkout's shape is required now."""

    battery = tmp_path / vendor / "ildottore" / "battery"
    battery.mkdir(parents=True)
    _operators_pack(tmp_path)
    monkeypatch.setattr(wiring, "PACKAGED_SPEC_PATH", battery)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert not wiring.is_own_checkout()
    assert wiring.default_spec_paths() == [Path("specs")]
    result = runner.invoke(app, ["registry", "ls"])
    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines() and len(result.stdout.splitlines()) == 1
    assert "own checkout" not in result.stderr and "note:" not in result.stderr


@pytest.mark.parametrize(
    "pyproject",
    [None, '[project]\nname = "someone-else"\n', "[project\nname = ildottore", "x" * 10],
    ids=["none", "another-project", "not-toml", "no-project-table"],
)
def test_a_src_layout_that_is_not_ildottore_reads_its_own_specs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pyproject: str | None
) -> None:
    battery = tmp_path / "src" / "ildottore" / "battery"
    battery.mkdir(parents=True)
    if pyproject is not None:
        (tmp_path / "pyproject.toml").write_text(pyproject)
    _operators_pack(tmp_path)
    monkeypatch.setattr(wiring, "PACKAGED_SPEC_PATH", battery)
    monkeypatch.chdir(tmp_path)
    assert not wiring.is_own_checkout()
    assert wiring.default_spec_paths() == [Path("specs")]


def test_a_checkout_of_ildottore_reads_the_battery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The positive control of the shape: src/ildottore/battery and a pyproject.toml naming the
    project, run from its root (and only from its root)."""

    battery = tmp_path / "src" / "ildottore" / "battery"
    battery.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "ildottore"\n')
    _operators_pack(tmp_path)
    monkeypatch.setattr(wiring, "PACKAGED_SPEC_PATH", battery)
    monkeypatch.chdir(tmp_path)
    assert wiring.is_own_checkout()
    assert wiring.default_spec_paths() == [battery]
    monkeypatch.chdir(tmp_path / "specs")
    assert not wiring.is_own_checkout()


def test_the_repository_specs_directory_holds_no_yaml() -> None:
    """Its specs/ holds the unit contracts only, and schemas/ is gone."""

    assert (REPO / "specs" / "contracts" / "00-INDEX.md").is_file()
    assert not [p for p in (REPO / "specs").rglob("*") if p.suffix in (".yaml", ".yml")]
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
    assert f"; it is now {root / new} {_BATTERY}" in result.output


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
            "built-in battery it held moved into the package: it is now "
            f"{root / 'src' / 'ildottore' / 'battery'}"
        ) in result.output


def test_the_old_example_files_name_the_new_ones(tmp_path: Path) -> None:
    root = _checkout(tmp_path / "ck")
    scope, target = write_scope(tmp_path), write_target(tmp_path)
    old_target = root / "specs" / "targets" / "example-openai.yaml"
    result = runner.invoke(app, ["run", "-t", str(old_target), "--scope", str(scope), "--dry-run"])
    assert result.exit_code == 3, result.output
    assert f"; it is now {root / 'examples' / 'target.example-openai.yaml'} {_EXAMPLES}" in (
        result.output
    )

    old_scope = root / "specs" / "scope.example.yaml"
    result = runner.invoke(app, ["run", "-t", str(target), "--scope", str(old_scope), "--dry-run"])
    assert result.exit_code == 3, result.output
    assert f"cannot read scope file {old_scope}: " in result.output
    assert f"; it is now {root / 'examples' / 'scope.example.yaml'} {_EXAMPLES}" in result.output

    old_fleet = root / "specs" / "fleet.example.yaml"
    result = runner.invoke(app, ["fleet", str(old_fleet), "--out", str(tmp_path / "out")])
    assert result.exit_code == 3, result.output
    assert f"; it is now {root / 'examples' / 'fleet.example.yaml'} {_EXAMPLES}" in result.output
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
