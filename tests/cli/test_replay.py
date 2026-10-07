"""``dottore replay`` (contract §5.5).

Replay re-reads a run from the content-addressed evidence store and reports
reproducibility - no re-sending. We first drive a real campaign (which writes
evidence) then replay by run id.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from click.testing import Result
from typer.testing import CliRunner

from ildottore.cli import replay as replay_mod
from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.store.run_sqlite import SqliteRunStore

from .conftest import deep_json, make_spec, write_scope, write_target

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
    assert "pooled rate:" in text


def test_replay_cli(tmp_path: Path) -> None:
    evidence_root, run_id = _run_campaign_to_evidence(tmp_path)
    res = runner.invoke(app, ["replay", run_id, "--evidence-root", str(evidence_root)])
    assert res.exit_code == 0
    assert run_id in res.stdout


def _replay_with(tmp_path: Path, evidence_root: Path, run_id: str, sql: str, value: str) -> Result:
    """Replay against the run store after one column was overwritten with ``value``."""

    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute(sql, (value, run_id))
        store._conn.commit()
    return runner.invoke(
        app,
        [
            *("replay", run_id, "--evidence-root", str(evidence_root)),
            *("--run-db", str(tmp_path / "runs.sqlite")),
        ],
    )


def test_replay_reads_evidence_refs_nested_too_deeply_as_unreadable(tmp_path: Path) -> None:
    """As any reference column that is not JSON (its spec cannot be verified, and says so):
    past the parser's stack it was a RecursionError, a traceback and exit 1 (2026-10-07)."""

    evidence_root, run_id = _run_campaign_to_evidence(tmp_path)
    sql = "UPDATE findings SET evidence_refs_json = ? WHERE run_id = ?"

    unreadable = _replay_with(tmp_path, evidence_root, run_id, sql, "not json")
    deep = _replay_with(tmp_path, evidence_root, run_id, sql, deep_json())

    assert unreadable.exit_code == 0
    assert (deep.exit_code, deep.stdout, deep.stderr) == (
        unreadable.exit_code,
        unreadable.stdout,
        unreadable.stderr,
    )


def test_replay_exits_3_on_a_battery_record_nested_too_deeply(tmp_path: Path) -> None:
    evidence_root, run_id = _run_campaign_to_evidence(tmp_path)
    sql = "UPDATE runs SET spec_digests_json = ? WHERE run_id = ?"

    result = _replay_with(tmp_path, evidence_root, run_id, sql, deep_json("object"))

    assert result.exit_code == ExitCode.ERROR, (result.exception, result.stderr)
    lines = result.stderr.splitlines()
    assert len(lines) == 1 and lines[0].startswith("error: ")
    assert "spec_digests_json is not readable JSON" in lines[0]
