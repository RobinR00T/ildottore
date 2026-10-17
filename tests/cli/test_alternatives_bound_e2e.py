"""A hostile target's alternatives cost the evidence and the report in proportion to its reply
(u01 A-86), through the CLI against a loopback stub.

The OpenAI adapter asks for logprobs with alternatives by default. A stub whose reply is `ghp_`
keys glued by U+0000, in 4-character tokens with one alternative each, had every alternative of
every token show every mask of the stretch they all lie in: on `fef4963e` the evidence of the
three attempts of one spec at an 8 KiB reply took 42 MB, 122 times what a clean reply of the
same size took (348 KB), and 64 KiB wrote 840 MB (pre-merge audits of A-83). Each alternative
shows one ``«REDACTED:fragment»`` there now.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

FRAGMENT = "«REDACTED:fragment»"


def _glued_keys(size: int) -> str:
    keys: list[str] = []
    written = 0
    while written < size:
        keys.append("ghp_" + format(written * 7919 % 36**8, "08x") * 4 + "abcd")
        written += len(keys[-1]) + 1
    return "\x00".join(keys)[:size]


def _reply(text: str) -> bytes:
    tokens = [
        {
            "token": text[i : i + 4],
            "logprob": -0.5,
            "top_logprobs": [{"token": "zz", "logprob": -2.0}],
        }
        for i in range(0, len(text), 4)
    ]
    return json.dumps(
        {
            "id": "stub",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                    "logprobs": {"content": tokens},
                }
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": len(tokens), "total_tokens": 40},
        }
    ).encode()


@contextmanager
def _serving(body: bytes) -> Iterator[int]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("content-length", "0")))
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _run(tmp_path: Path, specs: Path, text: str) -> tuple[list[dict[str, Any]], int, int]:
    """Run one spec against a stub that answers ``text`` in 4-character tokens: the attempts
    stored, the bytes of the evidence files and of the JSON report."""

    with _serving(_reply(text)) as port:
        endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
        (tmp_path / "scope.yaml").write_text(
            f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
            f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
            '        path_prefixes: ["/v1/chat/completions"]\n'
            '    identities:\n      - name: default\n        auth_ref: "env://ILDOTTORE_BOUND_KEY"\n'
        )
        (tmp_path / "target.yaml").write_text(
            f'id: stub\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
            'auth_ref: "env://ILDOTTORE_BOUND_KEY"\n'
            "capabilities:\n  tools: false\n  rag: false\n"
        )
        target, scope = tmp_path / "target.yaml", tmp_path / "scope.yaml"
        result = CliRunner().invoke(
            app,
            [
                *("run", "-t", str(target), "--scope", str(scope)),
                *("--spec-path", str(specs), "--spec", "PI-DIRECT-001", "--runs", "1"),
                *("--rate", "1000", "--no-color"),
                *("--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "r.db")),
                *("-oJ", str(tmp_path / "r.json")),
            ],
        )
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    files = sorted((tmp_path / "ev").rglob("*.json"))
    attempts = [json.loads(path.read_text(encoding="utf-8")) for path in files]
    assert any((a.get("response") or {}).get("logprobs") for a in attempts), result.output
    stored = sum(path.stat().st_size for path in files)
    return attempts, stored, (tmp_path / "r.json").stat().st_size


def test_a_hostile_stream_costs_the_evidence_and_the_report_what_a_clean_one_does(
    tmp_path: Path, specs_dir: Path, monkeypatch: pytest.MonkeyPatch, no_known_secrets: None
) -> None:
    """The same spec against two stubs of the same reply size, one clean and one hostile: what
    the run keeps of the hostile reply is within twice the clean one's (1.3 times now)."""

    monkeypatch.setenv("ILDOTTORE_BOUND_KEY", "sk-test-not-a-real-key-0000")
    size = 8 * 1024
    prose = ("the model said that it cannot help with this request " * (size // 50))[:size]
    (tmp_path / "clean").mkdir()
    (tmp_path / "hostile").mkdir()
    _, clean_stored, clean_report = _run(tmp_path / "clean", specs_dir, prose)
    attempts, stored, report = _run(tmp_path / "hostile", specs_dir, _glued_keys(size))

    alternatives = {
        pair[0]
        for attempt in attempts
        for entry in (attempt.get("response") or {}).get("logprobs") or []
        for pair in entry["top"]
    }
    assert stored < 2 * clean_stored, (stored, clean_stored)
    assert report < 2 * clean_report, (report, clean_report)
    assert alternatives == {FRAGMENT}
