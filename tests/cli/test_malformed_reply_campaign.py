"""A 200 the adapters cannot read fails its attempt; a target that answers nothing readable stops
early (OD-21, u04 and u08 A-74), through the real CLI.

Against a local OpenAI-compatible stub. On ``main`` at ``6d5f7ae`` one ``<html>`` reply made
``dottore run`` exit 3 at that reply ("aborted on AdapterProductError: hostile: success response
was not valid JSON ...; 1 of 2 specs never ran or did not finish" when it answered the fourth
request), whichever request it answered.
Decided 2026-10-11 under the owner's delegation (best practice), revisable: the attempt is
inconclusive, not retried, kept by a resume and re-derived by ``replay``, and the campaign goes on;
a campaign whose first five replies all are unreadable, with none readable, stops (exit 3) and says
to check the endpoint, so a wrong endpoint is not an all-inconclusive run.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

_REPLY = json.dumps(
    {
        "id": "stub",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "I cannot help with that."},
                "finish_reason": "stop",
            }
        ],
    }
)
_HTML = "<html><body>Service portal: please sign in</body></html>"

#: Two single-turn specs, as in ``test_hostile_nesting.py``.
_SPECS = ("JB-REFUSAL-SUPPRESS-001", "PI-DIRECT-001")


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, Any]]]:
    """Answers the n-th request (from 1) with ``script[n]``, else with ``default``."""

    state: dict[str, Any] = {"script": {}, "default": _REPLY, "served": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("content-length", "0")))
            state["served"] += 1
            body = state["script"].get(state["served"], state["default"]).encode()
            self.send_response(200)
            self.send_header("content-type", "text/html" if body.startswith(b"<") else "json")
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


def _argv(tmp_path: Path, port: int, *extra: str, specs: tuple[str, ...] = _SPECS) -> list[str]:
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: hostile\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        f'id: hostile\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    return [
        *("run", "-t", str(tmp_path / "target.yaml"), "--scope", str(tmp_path / "scope.yaml")),
        *(arg for spec in specs for arg in ("--spec", spec)),
        *("--rate", "1000", "--concurrency", "1", "--no-color"),
        *("--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "runs.sqlite")),
        *("-oJ", str(tmp_path / "r.json")),
        *extra,
    ]


def _report(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _run_id(tmp_path: Path) -> str:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        (run_id,) = conn.execute("SELECT run_id FROM runs").fetchone()
    finally:
        conn.close()
    return str(run_id)


@pytest.mark.parametrize("at", [1, 4])
def test_one_reply_that_is_not_json_fails_its_attempt_and_the_scan_goes_on(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], at: int
) -> None:
    port, state = stub
    state["script"] = {at: _HTML}
    result = CliRunner().invoke(app, _argv(tmp_path, port, "--runs", "1"))

    assert result.exit_code != 3, result.output
    assert "did not complete" not in result.output
    report = _report(tmp_path)
    assert {f["spec_id"] for f in report["findings"]} == set(_SPECS)
    attempts = [a for f in report["findings"] for a in f["attempts"]]
    failed = [a for a in attempts if a["error"]]
    assert len(failed) == 1, [a["error"] for a in attempts]
    assert failed[0]["error"].startswith("ResponseMalformed: hostile: success response was not")
    assert failed[0]["error"].endswith("[not retryable]")
    assert failed[0]["response"] is None
    assert failed[0]["verdict"]["status"] == "inconclusive"
    assert all(a["response"] is not None for a in attempts if not a["error"])
    assert state["served"] == len(attempts)  # the unreadable one was not sent again

    # `dottore replay` re-derives it from the evidence, as stored.
    replay = CliRunner().invoke(
        app,
        [
            *("replay", _run_id(tmp_path), "--evidence-root", str(tmp_path / "ev")),
            *("--run-db", str(tmp_path / "runs.sqlite")),
        ],
    )
    assert replay.exit_code == 0, replay.output


def test_a_target_that_answers_nothing_readable_stops_after_five_requests(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    port, state = stub
    state["default"] = _HTML
    result = CliRunner().invoke(app, _argv(tmp_path, port))

    assert result.exit_code == 3, result.output
    assert state["served"] == 5
    assert (
        "error: run on hostile did not complete: aborted on UnreadableReplies: the target's "
        "first 5 replies in this run could not be read"
    ) in result.stderr
    assert "check the target file's endpoint, provider and response template" in result.stderr
    assert "ResponseMalformed: hostile: success response was not valid JSON" in result.stderr
    assert result.stderr.rstrip().endswith("2 of 2 specs never ran or did not finish")
    report = _report(tmp_path)
    assert report["summary"]["status"]["state"] == "aborted"


def test_a_resume_after_the_stop_keeps_the_unreadable_attempts_and_sends_the_rest(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """The four replies stored before the stop are kept (not sent again, not retried); the
    fifth, which raised the stop, is sent again. With the endpoint answering, the run finishes."""

    port, state = stub
    state["default"] = _HTML
    first = CliRunner().invoke(app, _argv(tmp_path, port, "--runs", "2"))
    assert first.exit_code == 3, first.output
    assert state["served"] == 5
    run_id = _run_id(tmp_path)

    state["default"] = _REPLY
    resumed = CliRunner().invoke(app, _argv(tmp_path, port, "--runs", "2", "--resume", run_id))
    assert resumed.exit_code != 3, resumed.output
    report = _report(tmp_path)
    attempts = [a for f in report["findings"] for a in f["attempts"]]
    unreadable = [a for a in attempts if (a["error"] or "").startswith("ResponseMalformed")]
    assert len(unreadable) == 4
    assert state["served"] == 5 + len(attempts) - 4


def test_fewer_attempts_than_the_stop_all_unreadable_is_not_a_clean_scan(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """Two attempts, both unreadable: the stop is never reached, and the run is reported as one
    that evaluated nothing, its reason naming the unreadable replies (not "failed on transport")."""

    port, state = stub
    state["default"] = _HTML
    # One spec with one variant (`mutations: [identity]`), sent twice.
    argv = _argv(tmp_path, port, "--runs", "2", specs=("BIAS-STEREOTYPE-001",))
    result = CliRunner().invoke(app, argv)

    assert result.exit_code == 3, result.output
    assert state["served"] == 2
    assert (
        "every one of the 2 attempt(s) got a reply that could not be read as the provider's, so "
        "nothing was evaluated: check the target file's endpoint, provider and response template"
    ) in result.stderr
    assert _report(tmp_path)["summary"]["status"]["state"] == "unreachable"


@pytest.mark.parametrize(
    ("errors", "said"),
    [
        (
            ["ResponseMalformed: t: x; not evaluated [not retryable]"] * 2,
            "every one of the 2 attempt(s) got a reply that could not be read as the provider's",
        ),
        (
            ["AdapterEnvError: t: exhausted 4 attempt(s)", "ResponseMalformed: t: x"],
            "every one of the 2 attempt(s) failed on transport or (1 of them) with a reply that "
            "could not be read as the provider's",
        ),
        (
            ["AdapterEnvError: t: exhausted 4 attempt(s)"] * 2,
            "every one of the 2 attempt(s) failed on transport, so nothing was evaluated: "
            "AdapterEnvError",
        ),
    ],
    ids=["unreadable", "mixed", "transport"],
)
def test_the_unreachable_reason_names_what_the_attempts_got(errors: list[str], said: str) -> None:
    from ildottore.cli.run import _unreachable_reason
    from ildottore.core.runner import CampaignResult
    from ildottore.shared.models import Attempt, ModelRequest, TestPlan, TestRun
    from tests.cli.conftest import make_finding

    base = make_finding("PI-DIRECT-001")
    attempts = [
        Attempt(
            attempt_id=f"a{i}",
            spec_id="PI-DIRECT-001",
            request=ModelRequest(prompt="p"),
            error=error,
        )
        for i, error in enumerate(errors)
    ]
    result = CampaignResult(
        plan=TestPlan(plan_ref="p", target_id="t", adaptive=False),
        run=TestRun(run_id="r"),
        findings=[base.model_copy(update={"attempts": attempts})],
    )
    reason = _unreachable_reason(result) or ""
    assert reason.startswith(said), reason
    if "could not be read" in said:
        assert "check the target file's endpoint, provider and response template" in reason
