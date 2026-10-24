"""The constraints the ``floors`` CI job installs with pin each direct dependency to its floor (u12
A-84).

``scripts/dependency_floors.py`` turns ``pyproject.toml`` into ``name==floor`` lines; the job then
runs the suite on them, which is the only place the declared lower bounds are exercised (every
other job installs the newest releases). What is checked here, offline: every direct dependency
is pinned to exactly the version after its ``>=`` (or its ``==``), a runtime dependency with no
floor or with a specifier the script does not read is refused rather than left free, and the job
uses the script.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "dependency_floors.py"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_floors", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _declared() -> list[str]:
    with (REPO / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    return [*project["dependencies"], *project["optional-dependencies"]["dev"]]


def test_every_direct_dependency_is_pinned_to_its_floor() -> None:
    out = subprocess.run(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=True
    ).stdout
    pins = dict(line.split("==") for line in out.splitlines() if not line.startswith("#"))
    for requirement in _declared():
        name, floor = re.split(">=|==", requirement) if "=" in requirement else (requirement, "")
        if floor:
            assert pins.pop(name) == floor, requirement
        else:
            assert f"# {name}: no floor declared, left to resolve" in out.splitlines()
    assert pins == {}, pins


@pytest.mark.parametrize(
    ("requirement", "why"),
    [
        ("pydantic", "declares no floor"),
        ("pydantic>=2.6,<3", "not `name`, `name>=X` or `name==X`"),
        ("pydantic~=2.6", "not `name`, `name>=X` or `name==X`"),
        ("pydantic==2.6,!=2.6.1", "not `name`, `name>=X` or `name==X`"),
        ('pydantic>=2.6; python_version >= "3.12"', "not `name`, `name>=X` or `name==X`"),
    ],
)
def test_a_runtime_requirement_it_cannot_pin_is_refused(requirement: str, why: str) -> None:
    pyproject = f'[project]\ndependencies = ["{requirement}"]\n'.replace('"3.12"', "'3.12'")
    script = _script()
    with pytest.raises(script.FloorError, match=re.escape(why)):
        script.floors(pyproject)


def test_an_exact_pin_is_its_own_floor() -> None:
    """``ruff`` is pinned exactly so local gates and CI lint alike: the floors job keeps the pin."""

    script = _script()
    pyproject = '[project]\ndependencies = ["pydantic>=2.6"]\n'
    pyproject += '[project.optional-dependencies]\ndev = ["ruff==0.17.2"]\n'
    assert script.floors(pyproject) == ["pydantic==2.6", "ruff==0.17.2"]


def test_the_floors_job_installs_with_the_script_and_runs_the_suite() -> None:
    workflow = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = workflow.split("\n  floors:\n", 1)[1].split("\n  package:\n", 1)[0]
    assert "python scripts/dependency_floors.py > floors.txt" in job
    assert 'python -m pip install -c floors.txt -e ".[dev]"' in job
    assert 'python-version: "3.11"' in job  # the requires-python floor
    assert "pytest -q" in job
