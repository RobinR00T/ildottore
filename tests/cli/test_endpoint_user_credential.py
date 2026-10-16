"""A credential written as an endpoint URL's user is masked by value, as a password is (u01/u12
A-83, item 7).

A target file's endpoint can carry its credential in the user info: ``https://<token>@host``, the
form a token takes as a URL's user, which the HTTP client sends as Basic credentials. The loader
registered the password only (SEC-02), so with no password the token was never masked by value:
inside the URL the URL rule masks a password and keeps the user readable, and a reply quoting the
token kept it readable in the evidence and in every report. A password written percent-encoded was
registered as written only, so the value the client sends, decoded, was not masked either.

Against a loopback OpenAI-compatible stub that answers with the credentials it was sent, through
the CLI (``run -oA``), every output and every evidence file is searched for the token.
"""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from typer.testing import CliRunner

from ildottore.cli.main import app
from ildottore.cli.wiring import _endpoint_credentials

#: Registered credentials are process-wide: none from an earlier test changes a mask here.
pytestmark = pytest.mark.usefixtures("no_known_secrets")

REPO = Path(__file__).resolve().parents[2]
#: Shaped like an identifier, so no shape rule of the redactor masks it: only its value can.
TOKEN = "deploy-token-alpha-2026"


class _Echo(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("content-length", "0")))
        basic = self.headers.get("authorization", "").removeprefix("Basic ")
        try:
            sent = base64.b64decode(basic).decode()
        except ValueError:
            sent = basic
        text = f"I cannot help with that. You sent me {sent.split(':')[0]} and {sent}."
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
def port() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join()


def _outputs(root: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.suffix in {".json", ".sarif", ".xml", ".html"}
    )


@pytest.mark.parametrize(
    ("userinfo", "secret"),
    [
        (f"{TOKEN}@", TOKEN),
        (f"{TOKEN}:@", TOKEN),
        # Percent-encoded: the client sends `alpha@token-2026`, which the file does not write.
        ("deploy-alpha%40token-2026@", "deploy-alpha@token-2026"),
        # A password was masked before; the user beside it stays a readable name.
        (f"ops:{TOKEN}@", TOKEN),
    ],
    ids=["user", "user-empty-password", "user-encoded", "password"],
)
def test_the_credential_in_an_endpoint_url_is_masked_in_every_output(
    tmp_path: Path, port: int, userinfo: str, secret: str
) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n'
        f'  - id: live\n    base_url: "http://127.0.0.1:{port}"\n    endpoints:\n'
        f'      - host: "127.0.0.1:{port}"\n        path_prefixes: ["/v1"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    target = tmp_path / "target.yaml"
    target.write_text(
        "id: live\ntype: model\nprovider: openai\n"
        f'endpoint: "http://{userinfo}127.0.0.1:{port}/v1/chat/completions"\nmodel: m\n'
    )
    out = tmp_path / "out"
    out.mkdir()
    result = CliRunner().invoke(
        app,
        [
            *("run", "-t", str(target), "--scope", str(scope)),
            *("--spec-path", str(REPO / "specs"), "--spec", "PI-DIRECT-001", "--runs", "1"),
            *("--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "r.sqlite")),
            *("-oA", str(out / "report"), "-v"),
        ],
    )
    assert result.exit_code in (0, 1, 2), result.output
    written = _outputs(out)
    evidence = _outputs(tmp_path / "ev")
    assert "You sent me" in evidence, "the stub's reply did not reach the evidence"
    for place, text in (("terminal", result.output), ("reports", written), ("evidence", evidence)):
        assert secret not in text, place


@pytest.mark.parametrize(
    ("url", "credentials"),
    [
        ("https://tok%40en-123456@h/v1", ["tok%40en-123456", "tok@en-123456"]),
        ("https://tok:@h", ["tok"]),
        ("https://user:p%40ssword9@h", ["p%40ssword9", "p@ssword9"]),
        ("https://:pw12345678@h", ["pw12345678"]),
        ("https://h/v1", []),
    ],
)
def test_which_part_of_the_user_info_is_the_credential(url: str, credentials: list[str]) -> None:
    assert _endpoint_credentials(urlsplit(url)) == credentials
