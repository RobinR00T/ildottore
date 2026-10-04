"""F11 through the real CLI, against a local OpenAI-compatible stub that fails, then answers.

The core tests build the evidence store with the journal themselves; this one goes through the
composition root, which is where the journal is wired (`cli.wiring.build_runner`).
"""

from __future__ import annotations

import json
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

_REPLY = {
    "id": "stub",
    "object": "chat.completion",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "I cannot help with that."},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
}


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, Any]]]:
    state: dict[str, Any] = {"up": False, "delay": 0.0, "served": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("content-length", "0")))
            state["served"] += 1
            time.sleep(state["delay"])
            if not state["up"]:
                self.send_response(503)
                self.end_headers()
                return
            body = json.dumps(_REPLY).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], state
    finally:
        server.shutdown()
        server.server_close()


def _files(tmp_path: Path, port: int) -> list[str]:
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    return [
        "run",
        "-t",
        str(tmp_path / "target.yaml"),
        "--scope",
        str(tmp_path / "scope.yaml"),
        "--spec",
        "PI-DIRECT-001",
        "--runs",
        "2",
        "--rate",
        "1000",
        "--concurrency",
        "1",
        "--evidence-root",
        str(tmp_path / "ev"),
        "--run-db",
        str(tmp_path / "runs.sqlite"),
        "--no-color",
    ]


def _replay(tmp_path: Path, run_id: str) -> list[str]:
    return [
        "replay",
        run_id,
        "--evidence-root",
        str(tmp_path / "ev"),
        "--run-db",
        str(tmp_path / "runs.sqlite"),
    ]


def _no_delay(_self: object, _index: int) -> float:
    return 0.0


def _spent(tmp_path: Path, run_id: str) -> int:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        row = conn.execute("SELECT spend_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    finally:
        conn.close()
    return int(json.loads(row[0])["requests"])


def test_an_outage_then_an_interrupted_resume_then_a_resume_finishes_clean(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, state = stub
    monkeypatch.setattr("ildottore.core.execute.RetryPolicy.delay_for", _no_delay)
    base = _files(tmp_path, port)
    cli = CliRunner()

    down = cli.invoke(app, base)
    assert down.exit_code == 3, down.output
    run_id = next(p.name for p in (tmp_path / "ev").iterdir())

    state["up"] = True
    interrupted = cli.invoke(
        app, [*base, "--resume", run_id, "--budget-requests", str(_spent(tmp_path, run_id) + 3)]
    )
    assert "that ended in an environment error will be sent again" in interrupted.output
    assert interrupted.exit_code == 3, interrupted.output

    estimate = cli.invoke(app, [*base, "--resume", run_id, "--estimate"])
    assert estimate.exit_code == 0, estimate.output
    from ildottore.store import replay_run

    answered = sum(
        1 for a in replay_run(tmp_path / "ev", run_id).effective_attempts() if a.response
    )
    assert answered and f"minus {answered} request(s) already done" in estimate.output

    done = cli.invoke(app, [*base, "--resume", run_id, "-oJ", str(tmp_path / "r.json")])
    assert done.exit_code != 3, done.output
    report = json.loads((tmp_path / "r.json").read_text())
    attempts = [a for f in report["findings"] for a in f["attempts"]]
    assert attempts and all(a["response"] is not None for a in attempts)
    assert len({a["attempt_id"] for a in attempts}) == len(attempts), "one attempt per id"

    replay = cli.invoke(app, _replay(tmp_path, run_id))
    assert replay.exit_code == 0, replay.output
    assert "share an attempt id" in replay.output or "shares an attempt id" in replay.output


def test_a_pending_journal_row_without_its_file_is_tolerated_by_replay_and_resume(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash between the journal entry and the write: the file was never written."""

    port, state = stub
    monkeypatch.setattr("ildottore.core.execute.RetryPolicy.delay_for", _no_delay)
    state["up"] = True
    base = _files(tmp_path, port)
    cli = CliRunner()
    first = cli.invoke(app, [*base, "--budget-requests", "2"])
    assert first.exit_code == 3, first.output
    run_id = next(p.name for p in (tmp_path / "ev").iterdir())
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        conn.execute(
            "INSERT INTO artifacts (run_id, spec_id, sha256, state) VALUES (?, ?, ?, 'pending')",
            (run_id, "PI-DIRECT-001", "f" * 64),
        )
        conn.commit()
    finally:
        conn.close()
    replay = cli.invoke(app, _replay(tmp_path, run_id))
    assert replay.exit_code == 0, replay.output
    resumed = cli.invoke(app, [*base, "--resume", run_id])
    assert resumed.exit_code != 3, resumed.output


def _rows(tmp_path: Path) -> int:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        return int(conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0])
    finally:
        conn.close()


def test_a_dry_run_resume_adopts_nothing_and_a_real_one_does(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, state = stub
    monkeypatch.setattr("ildottore.core.execute.RetryPolicy.delay_for", _no_delay)
    state["up"] = True
    base = _files(tmp_path, port)
    cli = CliRunner()
    assert cli.invoke(app, [*base, "--budget-requests", "2"]).exit_code == 3
    run_id = next(p.name for p in (tmp_path / "ev").iterdir())
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        conn.execute("DELETE FROM artifacts")  # as a run written before the journal
        conn.commit()
    finally:
        conn.close()
    dry = cli.invoke(app, [*base, "--resume", run_id, "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert _rows(tmp_path) == 0, "a mode that sends nothing writes nothing"
    assert cli.invoke(app, [*base, "--resume", run_id]).exit_code != 3
    assert _rows(tmp_path) > 0


def test_an_artifact_under_a_spec_the_run_never_ran_is_refused_by_replay_and_resume(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.store import paths

    port, state = stub
    monkeypatch.setattr("ildottore.core.execute.RetryPolicy.delay_for", _no_delay)
    state["up"] = True
    base = _files(tmp_path, port)
    cli = CliRunner()
    assert cli.invoke(app, [*base, "--budget-requests", "2"]).exit_code == 3
    run_id = next(p.name for p in (tmp_path / "ev").iterdir())
    attempts = tmp_path / "ev" / run_id / "attempts"
    payload = json.loads(next(attempts.glob("*.json")).read_text(encoding="utf-8"))
    payload["spec_id"] = "NEVER-RAN-001"
    text = json.dumps(payload)
    (attempts / f"{paths.content_hash(text)}.json").write_text(text, encoding="utf-8")
    replay = cli.invoke(app, _replay(tmp_path, run_id))
    assert replay.exit_code == 3 and "added or replaced" in replay.output
    resumed = cli.invoke(app, [*base, "--resume", run_id])
    assert resumed.exit_code == 3 and "cannot be resumed" in resumed.output


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_a_sigterm_records_the_spend_so_far(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """What `timeout`, `docker stop` and CI timeouts send: it killed the process outright and
    the spend was lost."""

    port, state = stub
    state["up"] = True
    state["delay"] = 0.3
    process = subprocess.Popen(  # noqa: S603 - this interpreter running this CLI
        [sys.executable, "-m", "ildottore.cli.main", *_files(tmp_path, port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while state["served"] < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert state["served"] >= 2, "the campaign started sending"
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        (run_id,) = conn.execute("SELECT run_id FROM runs").fetchone()
    finally:
        conn.close()
    assert _spent(tmp_path, run_id) >= 2, "the requests sent before the SIGTERM are recorded"
