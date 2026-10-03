"""An edited artifact renamed to its new hash is refused (audit 2026-10-03, F12).

Each artifact verifies against its own file name, so editing one and renaming it to the
new content hash used to verify: `dottore replay` replayed it and `--resume` published it,
and a clean pass became a confirmed critical. The run store's findings now keep the
evidence digests unmasked and serve as the manifest both commands check against.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from click.testing import Result
from typer.testing import CliRunner

from ildottore.cli.app import app

REPO = Path(__file__).resolve().parents[2]


def _workspace(tmp_path: Path) -> Path:
    (tmp_path / "scope.yaml").write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n',
        encoding="utf-8",
    )
    (tmp_path / "target.yaml").write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: hardened\n"
        "capabilities:\n  tools: false\n  rag: false\n",
        encoding="utf-8",
    )
    return tmp_path


def _run(d: Path, *extra: str) -> Result:
    return CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(d / "target.yaml"),
            "--scope",
            str(d / "scope.yaml"),
            "--evidence-root",
            str(d / "ev"),
            "--run-db",
            str(d / "runs.sqlite"),
            "--spec-path",
            str(REPO / "specs"),
            "--no-color",
            "-q",
            "--spec",
            "PI-DIRECT-001",
            *extra,
        ],
    )


def _tamper(d: Path) -> str:
    run_id = next(p.name for p in (d / "ev").iterdir())
    for artifact in sorted((d / "ev" / run_id / "attempts").glob("*.json")):
        obj = json.loads(artifact.read_text())
        obj["verdict"]["status"] = "fail"
        payload = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        artifact.unlink()
        (artifact.parent / f"{hashlib.sha256(payload.encode()).hexdigest()}.json").write_text(
            payload
        )
    return run_id


def test_replay_and_resume_refuse_an_artifact_the_run_never_recorded(tmp_path: Path) -> None:
    d = _workspace(tmp_path)
    assert _run(d).exit_code == 0
    run_id = _tamper(d)

    replay = CliRunner().invoke(
        app,
        ["replay", run_id, "--evidence-root", str(d / "ev"), "--run-db", str(d / "runs.sqlite")],
    )
    assert replay.exit_code == 3, replay.output
    assert "not one the run store recorded" in replay.output

    resumed = _run(d, "--resume", run_id)
    assert resumed.exit_code == 3, resumed.output
    assert "cannot be resumed" in resumed.output


def test_an_untouched_run_still_replays(tmp_path: Path) -> None:
    d = _workspace(tmp_path)
    assert _run(d).exit_code == 0
    run_id = next(p.name for p in (d / "ev").iterdir())
    replay = CliRunner().invoke(
        app,
        ["replay", run_id, "--evidence-root", str(d / "ev"), "--run-db", str(d / "runs.sqlite")],
    )
    assert replay.exit_code == 0, replay.output
