"""The PR jobs of ``ci.yml`` install one pinned dependency set; ``audit.yml`` meets new releases
(OD-49, u14 A-123).

``scripts/ci_constraints.py`` resolves ``pyproject.toml`` for the CI interpreter into
``ci-constraints-requirements.txt``, which Dependabot bumps. What is checked here, offline: the
committed file pins every package once, exactly, sorted; every direct dependency is in it at a
version its specifier allows (so a ``pyproject.toml`` change that the file no longer satisfies
fails here, not as a pip conflict in CI); the PR jobs install with it and the nightly sweep
without it.
"""

from __future__ import annotations

import importlib.util
import re
import tomllib
from pathlib import Path
from types import ModuleType

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "ci_constraints.py"
CONSTRAINTS = REPO / "ci-constraints-requirements.txt"
INSTALL = "python -m pip install -c ci-constraints-requirements.txt -e"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ci_constraints", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pins() -> list[tuple[str, str]]:
    lines = CONSTRAINTS.read_text(encoding="utf-8").splitlines()
    return [tuple(line.split("==")) for line in lines if not line.startswith("#")]  # type: ignore[misc]


def _jobs(workflow: str) -> dict[str, str]:
    """Each job of ``.github/workflows/<workflow>``, by name, as its raw YAML text."""

    text = (REPO / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([a-z-]+):\n", body, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def test_every_line_pins_one_package_exactly_once_in_order() -> None:
    pins = _pins()
    assert pins, "the constraints file pins nothing"
    for name, version in pins:
        assert name == canonicalize_name(name), name
        assert re.fullmatch(r"[0-9A-Za-z.+!-]+", version), (name, version)
    names = [name for name, _ in pins]
    assert names == sorted(set(names))


def test_every_direct_dependency_is_pinned_inside_its_specifier() -> None:
    pins = dict(_pins())
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    for line in _script().requirements(pyproject):
        requirement = Requirement(line)
        version = pins.get(canonicalize_name(requirement.name))
        assert version is not None, f"{requirement.name} is not in {CONSTRAINTS.name}"
        assert requirement.specifier.contains(version, prereleases=True), (line, version)


def test_the_pr_jobs_install_the_pinned_set() -> None:
    jobs = _jobs("ci.yml")
    for name in ("static", "validate", "package"):
        assert INSTALL in jobs[name], name
    assert INSTALL not in jobs["floors"]  # the floors are their own constraints


def test_the_nightly_sweep_installs_the_newest_releases() -> None:
    audit = (REPO / ".github" / "workflows" / "audit.yml").read_text(encoding="utf-8")
    assert 'cron: "0 3 * * *"' in audit
    jobs = _jobs("audit.yml")
    assert "if:" not in jobs["full-sweep"].split("steps:", 1)[0]  # every night, not weekly
    for name, job in jobs.items():
        assert "ci-constraints-requirements.txt" not in job.split("run:", 1)[1], name
        assert 'python -m pip install -e ".[dev]"' in job, name
    assert "pytest -q" in jobs["full-sweep"]
    assert "mypy src" in jobs["full-sweep"]


def test_the_report_becomes_sorted_canonical_pins() -> None:
    report = {
        "install": [
            {"metadata": {"name": "Typing_Extensions", "version": "4.16.0"}},
            {"metadata": {"name": "PyYAML", "version": "6.0.3"}},
            {"metadata": {"name": "annotated-types", "version": "0.8.0"}},
        ]
    }
    assert _script().constraints(report) == [
        "annotated-types==0.8.0",
        "pyyaml==6.0.3",
        "typing-extensions==4.16.0",
    ]


@pytest.mark.parametrize("report", [{}, {"install": []}, {"install": "x"}])
def test_a_report_that_installs_nothing_is_refused(report: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="installs nothing"):
        _script().constraints(report)


def test_the_build_backend_is_resolved_with_the_rest() -> None:
    """The ``package`` job installs hatchling beside the dev extra, under the same constraints."""

    pyproject = '[project]\ndependencies = ["pydantic>=2.6"]\n'
    pyproject += '[project.optional-dependencies]\ndev = ["ruff==0.17.2"]\n'
    assert _script().requirements(pyproject) == ["pydantic>=2.6", "ruff==0.17.2", "hatchling"]
    assert tomllib.loads(pyproject)  # the fixture is valid TOML
