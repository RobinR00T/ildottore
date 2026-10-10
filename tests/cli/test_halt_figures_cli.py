"""The figure that stopped a run, through the real CLI, on every surface that shows the reason.

A local OpenAI-compatible stub reports ``usage.total_tokens`` of 2**53 against the default token
ceiling of 500,000. The halt reason is masked before the terminal and before each report, and a
bare 16-digit figure reads as a phone number to the redactor, so every surface printed
``attempted «REDACTED:phone»``: the one number the operator needed was the one hidden.

Two specs run one after the other. The stub answers the first (its system prompt says "business
assistant") with an ordinary usage figure, so that spec finishes and its reply, which carries a
real phone number, is stored; the second gets the 2**53 and stops the campaign. One run shows
both halves of the fix: the figure is readable and the target's phone number is still masked.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

_PHONE = "+1 415 555 0134"
_HUGE = 2**53


def _reply(total_tokens: int) -> bytes:
    return json.dumps(
        {
            "id": "stub",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": f"I cannot help. Call {_PHONE}."},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": total_tokens},
        }
    ).encode()


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, bool]]]:
    state = {"refuse": False}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            request = self.rfile.read(int(self.headers.get("content-length", "0")))
            if state["refuse"]:
                self.send_response(400)
                self.end_headers()
                return
            body = _reply(10 if b"business assistant" in request else _HUGE)
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


@pytest.fixture
def port(stub: tuple[int, dict[str, bool]]) -> int:
    return stub[0]


def _run(tmp_path: Path, port: int, path: str = "/v1/chat/completions") -> str:
    endpoint = f"http://127.0.0.1:{port}{path}"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        f'        path_prefixes: ["{path}"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(tmp_path / "target.yaml"),
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--spec",
            "PI-DIRECT-001",
            "--spec",
            "SP-LEAK-001",
            "--runs",
            "1",
            "--concurrency",
            "1",
            "--rate",
            "1000",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            "--no-color",
            "-oA",
            str(tmp_path / "report"),
        ],
    )
    assert result.exit_code == 3, result.output
    return " ".join(result.output.split())  # rich wraps at 80 columns


def test_every_surface_shows_the_token_figure_that_stopped_the_run(
    tmp_path: Path, port: int
) -> None:
    output = _run(tmp_path, port)

    halt = re.search(r"budget ceiling reached on 'max_tokens' \(([^)]*)\)", output)
    assert halt is not None, output
    figures = halt.group(1)
    assert "REDACTED" not in figures
    shown = re.fullmatch(r"limit ([\d,]+), attempted ([\d,]+)", figures)
    assert shown is not None, figures
    assert shown.group(1) == "500,000"
    # The reply's 2**53 on top of what the ledger already held: exact, and readable.
    assert int(shown.group(2).replace(",", "")) >= _HUGE

    reports = sorted(tmp_path.glob("report.*"))
    assert {p.suffix for p in reports} == {".json", ".html", ".sarif", ".xml"}
    for report in reports:
        text = report.read_text(encoding="utf-8")
        assert figures in text, report.name
        assert not re.search(r"attempted [^,)]*REDACTED", text), report.name
    reason = json.loads((tmp_path / "report.json").read_text())["summary"]["status"]["reason"]
    assert f"({figures});" in reason


def test_the_phone_number_the_target_wrote_is_still_masked(tmp_path: Path, port: int) -> None:
    """The figures are written so the redactor keeps them; the redactor itself is unchanged, so
    the phone number in the finished spec's reply is still masked wherever that reply is
    stored."""

    _run(tmp_path, port)

    stored = [p for p in (tmp_path / "ev").rglob("*") if p.is_file()]
    texts = [p.read_bytes().decode("utf-8", "replace") for p in stored]
    replies = [t for t in texts if "I cannot help. Call" in t]
    assert replies, "the finished spec's reply was not stored"
    assert all("REDACTED:phone" in t for t in replies)
    assert not any("415 555 0134" in t for t in texts)
    for report in tmp_path.glob("report.*"):
        assert "415 555 0134" not in report.read_text(encoding="utf-8"), report.name


def test_the_terminal_still_masks_what_a_halt_reason_carries(
    tmp_path: Path, stub: tuple[int, dict[str, bool]]
) -> None:
    """Writing the figures differently is the whole fix: the reason is not exempted. An aborted
    run's reason quotes the endpoint path, and a key in that path is masked on the terminal as
    in every report. Nothing else tested the terminal line: removing its masking left the whole
    suite green (pre-commit audit of this fix, F2)."""

    port, state = stub
    state["refuse"] = True
    key = "sk-abcdefghijklmnopqrstuvwxyz0123456789"

    output = _run(tmp_path, port, path=f"/v1/{key}/chat/completions")

    # A non-retryable 4xx is an AdapterProductError that carries its status (u09 A-67).
    assert "did not complete: aborted on AdapterStatusError" in output
    assert "REDACTED:openai_key" in output
    assert key not in output
    for report in tmp_path.glob("report.*"):
        assert key not in report.read_text(encoding="utf-8"), report.name
