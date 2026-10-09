"""One hostile reply nested too deeply fails its attempt; the scan goes on (2026-10-07).

Through the real CLI against a local OpenAI-compatible stub whose FIRST reply is nested too
deeply and every later one is ordinary. Before, ``dottore run`` exited 3 on that first reply with
"aborted on RecursionError" (or, for a reply the parser accepts, "aborted on ValueError: Circular
reference detected") and every other spec never ran.
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
}

#: Two single-turn specs: a conversation persists only its last reply, so a deep reply in an
#: earlier turn never reached the serializer.
_SPECS = ("JB-REFUSAL-SUPPRESS-001", "PI-DIRECT-001")

_HEAD = '{"choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}],'

#: The parser overflows on the first; the second parses, then overflowed pydantic's serializer
#: when the evidence was written (about 600 bytes).
_HOSTILE = {
    "past the parser": _HEAD + '"x":' + "[" * 200_000 + "]" * 200_000 + "}",
    "past the serializer": _HEAD + '"id":' + "[" * 300 + "]" * 300 + "}",
}


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, Any]]]:
    state: dict[str, Any] = {"first": "", "served": 0, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            state["requests"].append(self.rfile.read(int(self.headers.get("content-length", "0"))))
            state["served"] += 1
            text = state["first"] if state["served"] == 1 else json.dumps(_REPLY)
            body = text.encode()
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


def _argv(
    tmp_path: Path, port: int, specs: tuple[str, ...] = _SPECS, target_type: str = "chatbot"
) -> list[str]:
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    tools = "true" if target_type == "model" else "false"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: hostile\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        f'id: hostile\ntype: {target_type}\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        f"capabilities:\n  tools: {tools}\n  rag: false\n"
    )
    return [
        "run",
        "-t",
        str(tmp_path / "target.yaml"),
        "--scope",
        str(tmp_path / "scope.yaml"),
        *(arg for spec in specs for arg in ("--spec", spec)),
        "--runs",
        "1",
        "--rate",
        "1000",
        "--concurrency",
        "1",
        "--evidence-root",
        str(tmp_path / "ev"),
        "--run-db",
        str(tmp_path / "runs.sqlite"),
        "--no-color",
        "-oJ",
        str(tmp_path / "r.json"),
    ]


@pytest.mark.parametrize("hostile", sorted(_HOSTILE))
def test_a_reply_nested_too_deeply_fails_one_attempt_and_the_scan_goes_on(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], hostile: str
) -> None:
    port, state = stub
    state["first"] = _HOSTILE[hostile]
    result = CliRunner().invoke(app, _argv(tmp_path, port))

    assert result.exit_code != 3, result.output
    assert "did not complete" not in result.output
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert {f["spec_id"] for f in report["findings"]} == set(_SPECS)
    attempts = [a for f in report["findings"] for a in f["attempts"]]
    failed = [a for a in attempts if a["error"]]
    assert len(failed) == 1, [a["error"] for a in attempts]
    assert "ResponseTooDeep" in failed[0]["error"]
    assert "nested more than" in failed[0]["error"]
    assert failed[0]["error"].endswith("[not retryable]")
    assert failed[0]["response"] is None
    assert failed[0]["verdict"]["status"] == "inconclusive"
    # Every other attempt was sent once and answered; the deep one was not sent again.
    assert all(a["response"] is not None for a in attempts if not a["error"])
    assert state["served"] == len(attempts)


def test_arguments_at_the_limit_go_through_the_deepest_path_a_reply_reaches(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """The margin, pinned: arguments exactly ``MAX_DEPTH`` deep are accepted, threaded back to
    the target by the in-band tool loop and written about 11 levels deeper in the report, the
    deepest place a reply reaches. With the limit raised to 200 or 250, ``replay`` of this run
    fails (its validation stops at 200 levels), and at 300 the run itself aborts on pydantic's
    serializer ("Circular reference detected"; pre-commit and delta audits). It passes up to
    about 195, so it guards the limit; on ``main``, with no limit, it has nothing to catch."""

    from ildottore.shared.nesting import MAX_DEPTH, text_depth

    port, state = stub
    arguments = json.dumps('{"query":' + "[" * (MAX_DEPTH - 1) + "]" * (MAX_DEPTH - 1) + "}")
    state["first"] = (
        '{"choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":'
        '[{"id":"c1","type":"function","function":{"name":"search_kb","arguments":'
        + arguments
        + '}}]},"finish_reason":"tool_calls"}]}'
    )
    argv = _argv(tmp_path, port, specs=("AG-TOOL-UNAUTH-001",), target_type="model")
    result = CliRunner().invoke(app, argv)

    assert result.exit_code != 3, result.output
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    attempts = [a for f in report["findings"] for a in f["attempts"]]
    assert attempts and not [a["error"] for a in attempts if a["error"]]
    # Not vacuous: the arguments went back out to the target, and the report holds them parsed,
    # past the limit once its own nesting is added (111 levels when this was written).
    assert any(b"search_kb" in body for body in state["requests"][1:])
    assert text_depth((tmp_path / "r.json").read_text(encoding="utf-8")) > MAX_DEPTH + 5
    replay = CliRunner().invoke(
        app,
        [
            "replay",
            report["run"]["run_id"],
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
        ],
    )
    assert replay.exit_code == 0, replay.output
