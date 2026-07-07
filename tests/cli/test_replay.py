"""``dottore replay`` (contract §5.5).

Replay re-reads a run from the content-addressed evidence store and reports
reproducibility — no re-sending. We first drive a real campaign (which writes
evidence) then replay by run id.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from typer.testing import CliRunner

from ildottore.cli import replay as replay_mod
from ildottore.cli import wiring
from ildottore.cli.main import app

from .conftest import make_spec, write_scope, write_target

runner = CliRunner()


def _run_campaign_to_evidence(tmp_path: Path) -> tuple[Path, str]:
    """Drive one campaign and return (evidence_root, run_id) for replay."""

    scope = wiring.build_scope(write_scope(tmp_path))
    target = wiring.load_target(write_target(tmp_path))
    specs = [make_spec("PI-DIRECT-001")]
    evidence_root = tmp_path / "evidence"
    built = wiring.build_runner(
        scope=scope,
        specs=specs,
        evidence_root=evidence_root,
        run_db=tmp_path / "runs.sqlite",
        n=1,
    )
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    asyncio.run(built.runner.run(run_id=run_id, target=target, specs=specs))
    return evidence_root, run_id


def test_replay_reconstructs_run(tmp_path: Path) -> None:
    evidence_root, run_id = _run_campaign_to_evidence(tmp_path)
    result = replay_mod.replay(evidence_root, run_id)
    assert result.run_id == run_id
    assert result.n >= 1


def test_render_replay_has_footer(tmp_path: Path) -> None:
    evidence_root, run_id = _run_campaign_to_evidence(tmp_path)
    result = replay_mod.replay(evidence_root, run_id)
    text = replay_mod.render_replay(result)
    assert run_id in text
    assert "reproducibility:" in text


def test_replay_cli(tmp_path: Path) -> None:
    evidence_root, run_id = _run_campaign_to_evidence(tmp_path)
    res = runner.invoke(app, ["replay", run_id, "--evidence-root", str(evidence_root)])
    assert res.exit_code == 0
    assert run_id in res.stdout
