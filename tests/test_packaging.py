"""A wheel built from this repository carries every file the program reads (u12 A-84).

Measured on ``7d01521f``: the wheel ``pyproject.toml`` selects (``packages = ["src/ildottore"]``)
shipped neither ``specs/`` nor ``schemas/``, which the program found three directories above the
package, so from outside a checkout ``dottore run --dry-run`` and ``registry ls`` exited 3 on
``spec path not found: specs`` and ``lint`` on the missing ``schemas/attack-spec.schema.json``.
The battery and the schema are inside the package now, found through ``importlib.resources``.

Two kinds of check:

* in every run of the suite, cheap: every file the program reads is under the package directory,
  the wheel and sdist selection of ``pyproject.toml`` can drop none of them (no ``exclude``,
  ``only-include``, ``force-include`` or ``sources`` that could), and ``.gitignore``, which
  hatchling applies, matches none of them;
* with hatchling importable (the ``package`` job of ``.github/workflows/ci.yml``, which sets
  ``DOTTORE_REQUIRE_HATCHLING=1`` so a missing backend fails there; the venv of a plain
  ``pip install -e ".[dev]"`` has no hatchling, and these tests may not download it): a real
  wheel and a real sdist, the wheel installed into a directory of its own and run from outside
  the checkout, each command's output compared with the checkout's.
"""

from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

import ildottore
from ildottore.cli.wiring import load_registry_reading
from ildottore.shared.judging_rules import covered_files
from ildottore.shared.package_data import ATTACK_SPEC_SCHEMA, BATTERY, package_path

REPO = Path(__file__).resolve().parents[1]
PACKAGE = Path(ildottore.__file__).resolve().parent


def _read_by_the_program() -> list[Path]:
    """The battery files a load of the built-in battery reads, and the attack-spec schema."""

    _, errors, files = load_registry_reading([BATTERY])
    assert not errors, errors
    return sorted({Path(f).resolve() for f in files} | {ATTACK_SPEC_SCHEMA.resolve()})


def test_the_battery_and_the_schema_are_inside_the_package() -> None:
    assert package_path() == PACKAGE
    assert BATTERY == PACKAGE / "battery"
    assert ATTACK_SPEC_SCHEMA == PACKAGE / "registry" / "schemas" / "attack-spec.schema.json"
    read = _read_by_the_program()
    assert all(path.is_relative_to(PACKAGE) for path in read), read
    relative = {path.relative_to(PACKAGE).as_posix() for path in read}
    assert {"battery/pack.yaml", "registry/schemas/attack-spec.schema.json"} <= relative
    assert "battery/attacks/assets/mm-audio-override-pineapple.wav" in relative
    assert any(name.startswith("battery/suites/") for name in relative)


def test_every_file_the_program_reads_is_bound_by_the_judging_digest() -> None:
    labels = {label for label, _ in covered_files()}
    for path in _read_by_the_program():
        assert path.relative_to(PACKAGE).as_posix() in labels, path


def _hatch() -> dict[str, object]:
    with (REPO / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    build: dict[str, object] = data["tool"]["hatch"]["build"]
    return build


def test_the_wheel_and_sdist_selection_can_drop_none_of_them() -> None:
    """Any of these keys could leave a data file out: add one, and check the wheel by hand
    (the ``package`` CI job) before changing this test."""

    build = _hatch()
    assert set(build) == {"targets"}, build
    targets = build["targets"]
    assert isinstance(targets, dict)
    assert targets == {"wheel": {"packages": ["src/ildottore"]}}, targets


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_gitignore_matches_none_of_them() -> None:
    """hatchling leaves out what ``.gitignore`` matches, tracked or not."""

    if not (REPO / ".git").exists():
        pytest.skip("not a git checkout (an sdist)")
    names = "\n".join(str(path.relative_to(REPO)) for path in _read_by_the_program()) + "\n"
    ignored = subprocess.run(  # noqa: S603 - git on this checkout, fixed arguments
        ["git", "-C", str(REPO), "check-ignore", "--no-index", "--stdin"],  # noqa: S607
        input=names,
        capture_output=True,
        text=True,
        check=False,
    )
    assert ignored.returncode == 1, ignored.stdout  # 1: none is ignored


# --- a real wheel and sdist, where hatchling is installed (the `package` CI job) --------------


def _build(kind: str, project: Path, out: Path) -> Path:
    """PEP 517's ``build_wheel`` or ``build_sdist`` of hatchling, in ``project``."""

    if os.environ.get("DOTTORE_REQUIRE_HATCHLING") == "1":
        importlib.import_module("hatchling")  # the `package` job: missing fails, never skips
    else:
        pytest.importorskip("hatchling", reason="hatchling is installed by the `package` CI job")
    out.mkdir(parents=True, exist_ok=True)
    name = subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [
            sys.executable,
            "-c",
            f"import sys, hatchling.build as b; print(b.build_{kind}(sys.argv[1]))",
            str(out),
        ],
        cwd=project,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return out / name.splitlines()[-1]


def _expected_members() -> set[str]:
    return {f"ildottore/{path.relative_to(PACKAGE).as_posix()}" for path in _read_by_the_program()}


def _dottore(site: Path | None, cwd: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    """``dottore <argv>`` in ``cwd``, from the copy installed in ``site``, else the one these
    tests import (the checkout)."""

    env = {**os.environ, "NO_COLOR": "1", "PYTHONPATH": str(site or PACKAGE.parent)}
    return subprocess.run(  # noqa: S603 - this interpreter running this CLI
        [sys.executable, "-m", "ildottore.cli.main", *argv],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_wheel_built_by_hatchling_runs_from_outside_the_checkout(tmp_path: Path) -> None:
    wheel = _build("wheel", REPO, tmp_path / "dist")
    with zipfile.ZipFile(wheel) as archive:
        members = set(archive.namelist())
    assert _expected_members() <= members, sorted(_expected_members() - members)
    assert not any("contracts" in member for member in members)

    site = tmp_path / "site"
    install = [sys.executable, "-m", "pip", "install", "-q", "--no-index", "--no-deps"]
    subprocess.run([*install, "--target", str(site), str(wheel)], check=True)  # noqa: S603
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "scope.yaml").write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (outside / "target.yaml").write_text("id: mock-target\ntype: chatbot\n")
    probe = subprocess.run(
        [sys.executable, "-c", "import ildottore; print(ildottore.__file__)"],
        env={**os.environ, "PYTHONPATH": str(site)},
        capture_output=True,
        text=True,
        check=True,
    )
    assert Path(probe.stdout.strip()).is_relative_to(site), probe.stdout

    battery = site / "ildottore" / "battery"
    commands = [
        ["--version"],
        ["registry", "ls"],
        ["schema", "export"],
        ["run", "target.yaml", "--scope", "scope.yaml", "--dry-run", "--no-color"],
    ]
    for argv in commands:
        installed, checkout = _dottore(site, outside, *argv), _dottore(None, outside, *argv)
        assert installed.returncode == checkout.returncode == 0, (argv, installed.stderr)
        assert installed.stdout == checkout.stdout, argv
        if argv[0] in ("registry", "run"):
            assert f"built-in battery inside the installed package: {battery} " in (
                installed.stderr
            )
    linted = _dottore(site, outside, "lint", str(battery))
    assert linted.returncode == 0, linted.stdout + linted.stderr
    assert "across 75 spec(s), 14 suite(s), 1 pack(s)" in linted.stdout
    digests = [
        subprocess.run(
            [
                sys.executable,
                "-c",
                "from ildottore.shared.judging_rules import judging_digest as d; print(d())",
            ],
            env={**os.environ, "PYTHONPATH": str(path)},
            cwd=outside,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        for path in (site, PACKAGE.parent)
    ]
    assert digests[0] == digests[1], "a wheel and its checkout judge under one digest"


def test_an_sdist_built_by_hatchling_builds_a_wheel_that_carries_them(tmp_path: Path) -> None:
    sdist = _build("sdist", REPO, tmp_path / "dist")
    with tarfile.open(sdist) as archive:
        archive.extractall(tmp_path / "x", filter="data")
    (project,) = (tmp_path / "x").iterdir()
    wheel = _build("wheel", project, tmp_path / "from-sdist")
    with zipfile.ZipFile(wheel) as archive:
        members = set(archive.namelist())
    assert _expected_members() <= members, sorted(_expected_members() - members)
    metadata = next(m for m in members if m.endswith(".dist-info/METADATA"))
    with zipfile.ZipFile(wheel) as archive:
        assert "Name: ildottore" in archive.read(metadata).decode()
