"""A target file's ``provider`` and ``transport`` are values the tool knows, or the file is
refused (u12 A-82; CLI audit of 2026-10-11, M5).

A-53 closed a misspelled KEY and left a misspelled VALUE open, in its own words. Measured on
``de122e26``: ``provider: skynet`` on an OpenAI endpoint passed ``--dry-run`` with exit 0 and the
run sent three ``{"prompt": ...}`` bodies (the generic REST adapter's) to
``/v1/chat/completions``; ``transport: carrier-pigeon`` read as ``http``; and a stdio MCP target
with ``transport: stido`` or ``provider: mpc`` ran on the offline mock, where its ``mcp`` spec
scored a PASS with exit 0. Each is now refused when the file loads, naming the field and the
values it takes; case and surrounding spaces are read as before (``" MCP "``, ``STDIO``). An
absent ``provider`` still means the generic REST adapter, as the manual says; ``transport`` is
``http`` (the default) or ``stdio``, and ``stdio`` is for ``provider: mcp`` only.
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

from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.policy import EndpointAllowlist
from ildottore.shared.enums import TargetType
from ildottore.shared.models import Target

runner = CliRunner()
_PROVIDERS = "anthropic, mcp, openai, rest, websocket"


@pytest.fixture
def stub() -> Iterator[tuple[int, list[dict[str, Any]]]]:
    seen: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            seen.append(json.loads(self.rfile.read(int(self.headers.get("content-length", "0")))))
            raw = json.dumps({"text": "no"}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    try:
        yield server.server_address[1], seen
    finally:
        server.shutdown()
        server.server_close()


def _scope(tmp_path: Path, port: int, *, commands: str = "") -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        f'version: "1.0"\ntargets:\n  - id: t\n    base_url: "http://127.0.0.1:{port}/v1"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n' + commands
    )
    return path


def _run(tmp_path: Path, target: str, port: int, *extra: str, commands: str = "") -> Any:
    (tmp_path / "t.yaml").write_text(target)
    return runner.invoke(
        app,
        [
            "run",
            "-t",
            str(tmp_path / "t.yaml"),
            "--scope",
            str(_scope(tmp_path, port, commands=commands)),
            "--spec",
            "PI-DIRECT-001",
            "--runs",
            "1",
            "--rate",
            "1000",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "r.db"),
            "-q",
            *extra,
        ],
    )


def _live(provider: str, port: int, extra: str = "") -> str:
    return (
        f'id: t\ntype: chatbot\nprovider: "{provider}"\n'
        f'endpoint: "http://127.0.0.1:{port}/v1/chat/completions"\nmodel: m\n{extra}'
    )


@pytest.mark.parametrize("provider", ["skynet", "opnai", "open-ai", ""])
@pytest.mark.parametrize("mode", [["--dry-run"], []], ids=["dry-run", "run"])
def test_an_unknown_provider_is_refused_before_anything_is_sent(
    tmp_path: Path, stub: tuple[int, list[dict[str, Any]]], provider: str, mode: list[str]
) -> None:
    port, seen = stub
    result = _run(tmp_path, _live(provider, port), port, *mode)
    assert result.exit_code == 3, result.output
    assert (
        f"target file {tmp_path / 't.yaml'} has invalid provider '{provider}'; expected one of "
        f"{_PROVIDERS}"
    ) in result.output.replace("\n", "")
    assert seen == []


@pytest.mark.parametrize("provider", ["OpenAI", " openai ", "OPENAI"])
def test_case_and_spaces_are_read_as_before(
    tmp_path: Path, stub: tuple[int, list[dict[str, Any]]], provider: str
) -> None:
    port, _ = stub
    result = _run(tmp_path, _live(provider, port), port, "--dry-run")
    assert result.exit_code == 0, result.output


def test_an_absent_provider_is_still_the_rest_adapter(
    tmp_path: Path, stub: tuple[int, list[dict[str, Any]]]
) -> None:
    port, seen = stub
    target = f'id: t\ntype: chatbot\nendpoint: "http://127.0.0.1:{port}/chat"\n'
    result = _run(tmp_path, target, port)
    assert result.exit_code in (0, 1, 2), result.output
    assert seen and all("prompt" in body for body in seen)


@pytest.mark.parametrize("transport", ["carrier-pigeon", "stido", "https", "sse"])
def test_an_unknown_transport_is_refused(
    tmp_path: Path, stub: tuple[int, list[dict[str, Any]]], transport: str
) -> None:
    port, seen = stub
    target = (
        f'id: t\ntype: api\nprovider: mcp\ntransport: "{transport}"\ncommand: ["server"]\n'
        "capabilities: { tools: true }\n"
    )
    result = _run(tmp_path, target, port, "--dry-run")
    assert result.exit_code == 3, result.output
    assert (
        f"has invalid transport '{transport}'; expected http or stdio"
    ) in result.output.replace("\n", "")
    assert seen == []


def test_a_misspelled_stdio_mcp_target_no_longer_runs_on_the_mock(tmp_path: Path) -> None:
    """``provider: mpc`` on a stdio target routed it to the offline mock, which scored the
    ``mcp`` suite's spec PASS with exit 0 (A-53's open item)."""

    (tmp_path / "t.yaml").write_text(
        'id: t\ntype: api\nprovider: mpc\ntransport: stdio\ncommand: ["server"]\n'
        "capabilities: { tools: true }\n"
    )
    result = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(tmp_path / "t.yaml"),
            "--scope",
            str(_scope(tmp_path, 9, commands='    commands: ["server"]\n')),
            "--suite",
            "mcp",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "r.db"),
        ],
    )
    assert result.exit_code == 3, result.output
    assert "has invalid provider 'mpc'" in result.output


@pytest.mark.parametrize("provider", ["openai", "anthropic", "rest", "websocket"])
def test_stdio_is_for_an_mcp_server_only(tmp_path: Path, provider: str) -> None:
    path = tmp_path / "t.yaml"
    path.write_text(
        f"id: t\ntype: chatbot\nprovider: {provider}\ntransport: stdio\n"
        'endpoint: "https://api.example.com/v1/chat/completions"\n'
    )
    with pytest.raises(ValueError, match="transport stdio is for provider mcp"):
        wiring.load_target(path)


@pytest.mark.parametrize("transport", ["http", "HTTP", " stdio ", "STDIO"])
def test_the_two_transports_load_in_any_case(tmp_path: Path, transport: str) -> None:
    path = tmp_path / "t.yaml"
    path.write_text(
        f'id: t\ntype: api\nprovider: mcp\ntransport: "{transport}"\ncommand: ["server"]\n'
    )
    assert wiring.load_target(path).transport == transport


def test_an_offline_mock_target_is_held_to_the_same_values(tmp_path: Path) -> None:
    path = tmp_path / "t.yaml"
    path.write_text("id: t\ntype: chatbot\nprovider: skynet\nmock_scenario: vulnerable\n")
    with pytest.raises(ValueError, match="invalid provider 'skynet'"):
        wiring.load_target(path)


def test_a_target_built_in_code_with_an_unknown_provider_builds_no_adapter() -> None:
    """Defence in depth for a caller that skips the loader: no silent REST fallback."""

    target = Target(
        id="t",
        type=TargetType.CHATBOT,
        provider="skynet",
        endpoint="https://api.example.com/v1/chat/completions",
    )
    with pytest.raises(ValueError, match="unknown provider 'skynet'"):
        wiring.build_real_adapter(target, EndpointAllowlist([]), api_key=None)


def _fleet(tmp_path: Path, body: str) -> Any:
    (tmp_path / "fleet.yaml").write_text(body)
    return runner.invoke(app, ["fleet", str(tmp_path / "fleet.yaml"), "--out", str(tmp_path / "o")])


def test_fleet_refuses_an_unknown_provider_before_writing(tmp_path: Path) -> None:
    for body, where in (
        (
            'version: "1"\ntargets:\n  - id: a\n    provider: skynet\n'
            "    endpoint: https://api.example.com/v1/chat/completions\n",
            "targets.0.provider",
        ),
        (
            'version: "1"\ntargets:\n  - id: a\n    endpoint: https://api.example.com/v1\n'
            "judge:\n  id: j\n  provider: skynet\n  endpoint: https://api.example.com/v1\n",
            "judge.provider",
        ),
    ):
        result = _fleet(tmp_path, body)
        assert result.exit_code == 3, result.output
        assert f"{where}: Value error, is not a provider this tool has" in result.output
        assert not (tmp_path / "o").exists()


def test_fleet_keeps_the_websocket_refusal_of_od37(tmp_path: Path) -> None:
    result = _fleet(
        tmp_path,
        'version: "1"\ntargets:\n  - id: w\n    provider: WebSocket\n'
        "    endpoint: wss://chat.example.com/ws\n",
    )
    assert result.exit_code == 3, result.output
    assert "targets.0.provider of 'w' is websocket" in result.output
