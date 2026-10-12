"""A report names its target the same way in every run (u01 A-78, pre-merge audit H1).

Reports mask the target id, which the operator wrote, and masked it with the per-process salt:
an id holding a UUID (`tenant-<uuid>`, a common naming scheme) had another mask in every run
once A-78 masked UUIDs, and ``dottore diff`` refused two reports of one target as two targets
(exit 3). A report now masks the target id by the rules before A-78 with the fixed identity
salt (``redactor.report_identity``): such an id reads as reports before A-78 showed it, so a
baseline written before A-78 still compares, and two runs in two processes compare.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

import ildottore
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app

from .conftest import make_spec, write_scope, write_spec_tree, write_target

TARGET = "tenant-6a1f0c2e-91b4-4d7a-8e3b-2f5c9d0a7b14"


def _run_in_its_own_process(tmp_path: Path, name: str) -> dict[str, object]:
    """One `dottore run` in a fresh interpreter, so with its own random salt."""

    env = {k: v for k, v in os.environ.items() if k != "ILDOTTORE_REDACTION_SALT"}
    src = str(Path(ildottore.__file__).resolve().parents[1])
    env["PYTHONPATH"] = os.pathsep.join([src, env.get("PYTHONPATH", "")])
    out = tmp_path / f"{name}.json"
    done = subprocess.run(  # noqa: S603 - this interpreter, the tool's own module
        [
            sys.executable,
            "-m",
            "ildottore.cli.main",
            "run",
            "-t",
            str(tmp_path / "target.yaml"),
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--spec-path",
            str(tmp_path / "specs"),
            "-oJ",
            str(out),
            "--runs",
            "1",
        ],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert done.returncode == int(ExitCode.FINDINGS_AT_OR_ABOVE), done.stderr
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    write_scope(tmp_path, target_id=TARGET)
    write_target(tmp_path, target_id=TARGET, mock_scenario="vulnerable")
    write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001"), make_spec("JB-ROLEPLAY-001")])
    return tmp_path


def test_two_runs_of_a_uuid_named_target_compare(tree: Path) -> None:
    first = _run_in_its_own_process(tree, "first")
    second = _run_in_its_own_process(tree, "second")
    for report in (first, second):
        findings = report["findings"]
        assert isinstance(findings, list) and findings
        assert {f["target_id"] for f in findings} == {TARGET}
    res = CliRunner().invoke(app, ["diff", str(tree / "first.json"), str(tree / "second.json")])
    assert res.exit_code == 0, res.output
    assert "a drift report compares one target with itself" not in res.output


@pytest.mark.parametrize(
    ("target_id", "shown"),
    [
        # As reports before A-78 showed it: the UUID readable.
        (TARGET, TARGET),
        (
            "agent-3f2a9c1d-7b4e-4a1f-9c2d-1234567890ab",
            "agent-3f2a9c1d-7b4e-4a1f-9c2d-1234567890ab",
        ),
        ("mock-target", "mock-target"),
    ],
)
def test_a_report_names_the_target_as_before_a78(target_id: str, shown: str) -> None:
    from ildottore.redactor import report_identity

    assert report_identity(target_id) == shown


def test_a_high_entropy_id_masks_to_the_same_text_in_every_process() -> None:
    # Before, a different digest in every run, so two reports of it never compared.
    code = (
        "from ildottore.redactor import report_identity; "
        "print(report_identity('Tk9xQ2mZ7pL4vR8wN3sB6yH1dF5gJ0cX'))"
    )
    src = str(Path(ildottore.__file__).resolve().parents[1])
    env = {k: v for k, v in os.environ.items() if k != "ILDOTTORE_REDACTION_SALT"}
    env["PYTHONPATH"] = src
    seen = {
        subprocess.run(  # noqa: S603 - this interpreter, a fixed snippet
            [sys.executable, "-c", code],
            env=env,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout.strip()
        for _ in range(2)
    }
    assert len(seen) == 1
    (mask,) = seen
    assert mask.startswith("«REDACTED:high_entropy:")
