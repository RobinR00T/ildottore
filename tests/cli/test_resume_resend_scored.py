"""A resume's re-send is scored, and named, as the attempt it replaces: through the real CLI.

Against a loopback OpenAI-compatible stub. On ``de122e26`` (audit of the scoring, 2026-10-11):

* HIGH 1 (``cli_resume_unreadable.py``): ``BIAS-STEREOTYPE-001 --runs 5 --judge`` whose first
  attempt ended in four HTTP 503s, resumed when the stub answered an HTML page, published a PASS
  with 0 unreadable replies and exit 0 under ``--fail-on info --include-needs-review``, while
  ``dottore replay`` of the same run counted 1 unreadable reply. The runner kept the first artifact
  of the id at a tie, and the prior one arrived first.
* LOW 1: the resume note counted one attempt id in every category one of its artifacts fell in, so
  an id holding a reply stored without a verdict and its unreadable re-send was counted twice and
  the environment errors came out at ``-1``.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app
from tests.cli.test_malformed_reply_campaign import _HTML, _REPLY, _SECURE, _argv, _run_id


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, Any]]]:
    """The judge (model ``j``) says secure; attack requests follow ``state["answer"]``.

    ``"busy"`` answers the first ``state["busy"]`` attack requests with HTTP 503 and the rest with
    a refusal; ``"html"`` answers every one with an HTML page.
    """

    state: dict[str, Any] = {"answer": "busy", "busy": 0, "served": 0, "judged": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers.get("content-length", "0")))
            code = 200
            if json.loads(raw).get("model") == "j":
                state["judged"] += 1
                body = _SECURE
            else:
                state["served"] += 1
                if state["answer"] == "html":
                    body = _HTML
                elif state["served"] <= state["busy"]:
                    body, code = '{"error": "busy"}', 503
                else:
                    body = _REPLY
            data = body.encode()
            self.send_response(code)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

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


def _finding(tmp_path: Path) -> dict[str, Any]:
    (finding,) = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["findings"]
    return finding  # type: ignore[no-any-return]


def test_an_unreadable_re_send_keeps_the_resumed_spec_from_passing(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    port, state = stub
    state["busy"] = 4  # the first attempt and its three retries
    argv = _argv(
        tmp_path,
        port,
        *("--runs", "5", "--fail-on", "info", "--include-needs-review"),
        specs=("BIAS-STEREOTYPE-001",),
        judge=True,
    )
    first = CliRunner().invoke(app, argv)
    assert first.exit_code == 0, first.output
    assert state["served"] == 8
    assert _finding(tmp_path)["status"] == "pass", "4 of 5 held, 1 environment error"

    state["answer"], before = "html", state["served"]
    resumed = CliRunner().invoke(app, [*argv, "--resume", _run_id(tmp_path)])
    assert resumed.exit_code == 0, resumed.output  # an inconclusive result never gates
    assert state["served"] - before == 1, "only the environment error is sent again"
    finding = _finding(tmp_path)
    assert finding["status"] == "inconclusive", finding["reasoning"]
    assert finding["reasoning"].endswith(
        "; 1/5 could not be read as the provider's reply, which may be the one an attack changed"
    )
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert report["summary"]["unreadable_reply"] == {
        "attempts": 1,
        "specs": ["BIAS-STEREOTYPE-001"],
    }
    assert "Unreadable replies: 1 attempt(s) in 1 spec(s)" in resumed.stdout
    scored = next(a for a in finding["attempts"] if a["attempt_id"].endswith("#0"))
    assert scored["request"]["metadata"]["send_number"] == 2
    assert len(finding["evidence"]) == 6, "the environment error stays cited"

    replay = CliRunner().invoke(
        app,
        [
            *("replay", _run_id(tmp_path), "--evidence-root", str(tmp_path / "ev")),
            *("--run-db", str(tmp_path / "runs.sqlite")),
        ],
    )
    assert replay.exit_code == 0, replay.output
    assert "1 of 5 attempt(s) whose reply could not be read" in replay.output


def test_the_resume_note_names_each_attempt_it_sends_again_once(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """An id holding a reply the ceiling kept from the judge, and the resume's unreadable re-send.

    ``PI-DIRECT-001 --runs 2 --judge --budget-requests 7``: ``identity`` is answered and judged
    (2 + 4), ``roleplay_wrap#0`` answered and not judged (7). The first resume, with one request
    left, sends ``roleplay_wrap#0`` again and gets an HTML page. The second resume's note said
    ``-1 that ended in an environment error``, ``1 that could not be read`` and ``1 answered but
    not evaluated`` for that one id on ``de122e26``.
    """

    port, state = stub
    argv = _argv(tmp_path, port, "--runs", "2", specs=("PI-DIRECT-001",), judge=True)
    halted = CliRunner().invoke(app, [*argv, "--budget-requests", "7"])
    assert halted.exit_code == 3, halted.output
    run_id = _run_id(tmp_path)

    state["answer"] = "html"
    again = CliRunner().invoke(app, [*argv, "--budget-requests", "8", "--resume", run_id])
    assert again.exit_code == 3, again.output
    assert "1 answered but not evaluated before the halt will be sent again" in again.output

    last = CliRunner().invoke(app, [*argv, "--budget-requests", "8", "--resume", run_id])
    (note,) = [line for line in last.output.splitlines() if line.startswith("resume: ")]
    assert note == (
        f"resume: {run_id} keeps 2 attempt(s) across 1 spec(s) (answered, or failed in a way a "
        "retry would repeat); they will not be re-sent; 1 that could not be read will be sent "
        "again"
    )
