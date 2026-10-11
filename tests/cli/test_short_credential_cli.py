"""A credential under 8 characters stops the run before any request, through the CLI (u04 A-78).

Pre-merge security audit of 2026-10-11, LOW 6. Against a loopback OpenAI-compatible stub, on
``main`` a target key of 7 characters was sent with every request (3 for ``PI-DIRECT-001`` at
``--runs 1``, 21 with ``-sV``), and so was a judge's, each exit 0; the redactor masks by value
only from 8 characters, so a target echoing it would have put it in every report. Now the
pre-flight refuses the target's and the judge's (so ``--dry-run``, ``-sn`` and ``--estimate`` say
what the run would), the identity sweep refuses an identity's, naming it, and each adapter
refuses again before its first request: exit 3, nothing sent, the WebSocket adapter's message.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli.main import app

REPO = Path(__file__).resolve().parents[2]
SHORT = "tok4567"
LONG = "tok-45678-long"
MESSAGE = (
    "the credential is shorter than 8 characters, which the redactor cannot mask by value; "
    "nothing was sent"
)


class _Stub(BaseHTTPRequestHandler):
    seen: list[str]

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
        self.seen.append(self.headers.get("authorization", ""))
        text = (
            json.dumps({"verdict": "secure", "confidence": 0.9, "reasoning": "refused"})
            if body.get("model") == "j"
            else "I cannot help with that."
        )
        choice = {"index": 0, "message": {"role": "assistant", "content": text}}
        payload = json.dumps({"id": "x", "model": "m", "choices": [choice]}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def stub() -> Iterator[tuple[int, list[str]]]:
    seen: list[str] = []
    handler = type("Handler", (_Stub,), {"seen": seen})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], seen
    finally:
        server.shutdown()
        thread.join()


def _entry(target_id: str, port: int, *keys: str) -> str:
    identities = "".join(
        f'      - name: {name}\n        auth_ref: "env://{key}"\n'
        for name, key in zip(("default", "second"), keys, strict=False)
    )
    return (
        f'  - id: {target_id}\n    base_url: "http://127.0.0.1:{port}"\n    endpoints:\n'
        f'      - host: "127.0.0.1:{port}"\n        path_prefixes: ["/v1"]\n'
        f"    identities:\n{identities}"
    )


def _workspace(tmp_path: Path, port: int, *, target_keys: tuple[str, ...], judge_key: str | None):
    url = f"http://127.0.0.1:{port}/v1/chat/completions"
    scope = tmp_path / "scope.yaml"
    entries = _entry("live", port, *target_keys)
    if judge_key is not None:
        entries += _entry("judge", port, judge_key)
    scope.write_text('version: "1.0"\ntargets:\n' + entries)
    target = tmp_path / "target.yaml"
    capabilities = "capabilities:\n  multi_identity: true\n  rag: true\n"
    target.write_text(
        f'id: live\ntype: model\nprovider: openai\nendpoint: "{url}"\nmodel: m\n'
        f'auth_ref: "env://{target_keys[0]}"\n' + (capabilities if len(target_keys) > 1 else "")
    )
    args = ["-t", str(target), "--scope", str(scope), "--spec-path", str(REPO / "specs")]
    if judge_key is not None:
        judge = tmp_path / "judge.yaml"
        judge.write_text(
            f'id: judge\ntype: model\nprovider: openai\nendpoint: "{url}"\nmodel: j\n'
            f'auth_ref: "env://{judge_key}"\n'
        )
        args += ["--judge", str(judge)]
    store = ["--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "runs.sqlite")]
    return args + store


CASES = [
    ("target", ("SHORT",), None, "PI-DIRECT-001", [], "live: "),
    ("target -sV", ("SHORT",), None, "PI-DIRECT-001", ["-sV"], "live: "),
    ("target --dry-run", ("SHORT",), None, "PI-DIRECT-001", ["--dry-run"], "live: "),
    ("target -sn", ("SHORT",), None, "PI-DIRECT-001", ["-sn"], "live: "),
    ("target --estimate", ("SHORT",), None, "PI-DIRECT-001", ["--estimate"], "live: "),
    ("judge", ("LONG",), "SHORT", "PI-DIRECT-001", [], "judge: "),
    ("identity", ("LONG", "SHORT"), None, "DL-XTENANT-001", [], "live, identity 'second': "),
]


@pytest.mark.parametrize(
    ("case", "target_keys", "judge_key", "spec", "extra", "named"),
    [pytest.param(*case, id=case[0]) for case in CASES],
)
def test_a_short_credential_stops_the_run_before_any_request(
    tmp_path: Path,
    stub: tuple[int, list[str]],
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    target_keys: tuple[str, ...],
    judge_key: str | None,
    spec: str,
    extra: list[str],
    named: str,
) -> None:
    port, seen = stub
    monkeypatch.setenv("SHORT", SHORT)
    monkeypatch.setenv("LONG", LONG)
    args = _workspace(tmp_path, port, target_keys=target_keys, judge_key=judge_key)
    result = CliRunner().invoke(app, ["run", *args, "--spec", spec, "--runs", "1", *extra])
    assert result.exit_code == 3, (case, result.output)
    assert named + MESSAGE in result.output, (case, result.output)
    assert seen == [], case
    assert SHORT not in result.output


def test_credentials_of_8_characters_or_more_run_as_before(
    tmp_path: Path, stub: tuple[int, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, seen = stub
    monkeypatch.setenv("LONG", LONG)
    args = _workspace(tmp_path, port, target_keys=("LONG",), judge_key="LONG")
    result = CliRunner().invoke(app, ["run", *args, "--spec", "PI-DIRECT-001", "--runs", "1"])
    assert result.exit_code == 0, result.output
    assert seen and all(header == f"Bearer {LONG}" for header in seen)
