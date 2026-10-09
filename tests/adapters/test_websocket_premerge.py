"""Regressions from the two pre-merge audits of the WebSocket adapter (PR #87, 2026-10-09).

Each test pins a finding of that audit: a frame parsed with a plain ``json.loads`` (half a
character in it aborted the campaign, A-47), a tool call's JSON-text arguments never measured,
a text frame that is not UTF-8 retried, a socket that failed to open dialled again inside one
debited send, values JSON cannot hold accepted in the ``websocket:`` block, a ``ws://`` or
``wss://`` endpoint accepted on another provider, names quoted whole in the loader's refusals,
and a fleet's ``wss://`` entry authorizing every port. The second audit: error class names the
redactor masked, a close the server started with 1007 or 1009 read as this side's, and keys
that are not text sent as Python's ``str``. The servers are loopback; nothing leaves the host.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from websockets.asyncio.server import ServerConnection

from ildottore.adapters import RetryConfig
from ildottore.adapters.base import ResponseTooDeep, ResponseUndecodable
from ildottore.adapters.websocket import (
    WebSocketClosed,
    WebSocketFrameTooDeep,
    WebSocketUndecodable,
)
from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.fleet import FleetTarget, _scope_entry, _target_doc
from ildottore.cli.run import RunOptions, execute_run
from ildottore.core.budgets import BudgetLedger
from ildottore.core.execute import (
    NOT_RETRYABLE_MARK,
    RetryPolicy,
    default_is_env_error,
    execute_attempt,
)
from ildottore.policy import Endpoint, EndpointAllowlist
from ildottore.shared.config_errors import MAX_PROBLEM_CHARS
from ildottore.shared.models import ModelRequest
from ildottore.shared.nesting import MAX_DEPTH
from ildottore.shared.toolcalls import call_arguments
from tests.adapters.test_websocket import _adapter, _spec
from tests.cli.conftest import make_spec, write_spec_tree
from tests.cli.test_websocket_target import _BLOCK, _write_scope, _write_target
from tests.ws_chat_server import TOKEN, FakeChatServer
from tests.ws_raw_servers import HandlerServer, Log, auth_then, send_json

#: The JSON escape for U+D800, six characters, built so no tool decodes it on the way in.
_HIGH = chr(92) + "ud800"
_R = chr(0xFFFD)
_POLICY = RetryPolicy(max_retries=3, base_delay_s=0.0)
_NO_RETRIES = RetryConfig(max_retries=0, backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=2.0)
_ENDPOINT = "wss://assistant.example.test/ws/chat"


async def _noop(_: float) -> None:
    return None


def _query_server(on_query: Any) -> HandlerServer:
    async def handler(connection: ServerConnection, log: Log) -> None:
        await auth_then(connection, log, on_query)

    return HandlerServer(handler)


async def _attempt(adapter: Any, ledger: BudgetLedger) -> Any:
    return await execute_attempt(
        adapter,
        ModelRequest(prompt="hi"),
        attempt_id="a1",
        spec_id="S",
        mutation="identity",
        sampling=None,
        ledger=ledger,
        retry=_POLICY,
        sleep=_noop,
    )


# --- HIGH 2: frames parsed as every reply is (bounded, and well formed: A-47) -------------------


async def test_half_a_character_in_a_frame_reads_as_the_replacement_character() -> None:
    """An escaped lone surrogate in the text, the model echo and the id reads as U+FFFD."""

    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        delta = '{"type":"delta","delta":{"text":"I cannot ' + _HIGH + ' do that."}}'
        await connection.send(delta)
        done = '{"type":"done","model":"m' + _HIGH + '","id":"r' + _HIGH + '"}'
        await connection.send(done)

    spec = _spec(response={"model_path": "model", "id_path": "id"})
    with _query_server(on_query) as server:
        response = await _adapter(server, spec).send(ModelRequest(prompt="hi"))
    assert response.text == f"I cannot {_R} do that."
    assert response.raw_ids["model"] == f"m{_R}" and response.raw_ids["id"] == f"r{_R}"
    # Every UTF-8 writer downstream takes it: the evidence store hashed exactly this.
    dumped = response.model_dump_json()
    assert _R in json.loads(dumped)["text"]
    frames = response.raw_ids["websocket"]["frames"]
    assert frames[-2]["frame"]["delta"]["text"] == f"I cannot {_R} do that."


def test_half_a_character_in_a_frame_does_not_abort_the_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The run completes and both specs are scored; on the PR head it aborted (exit 3)."""

    monkeypatch.setenv("TEST_WS_TOKEN", TOKEN)

    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await connection.send('{"type":"delta","delta":{"text":"I can' + _HIGH + 't help."}}')
        await send_json(connection, {"type": "done"})

    with _query_server(on_query) as server:
        target = _write_target(tmp_path, endpoint=server.url)
        scope = _write_scope(tmp_path, server)
        specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001"), make_spec("PI-DIRECT-002")])
        opts = RunOptions(
            targets=[target],
            scope=scope,
            runs=1,
            evidence_root=tmp_path / "ev",
            run_db=tmp_path / "runs.sqlite",
        )
        outcome = execute_run(opts, [specs])
    assert outcome.exit_code is not ExitCode.ERROR
    assert outcome.incomplete == {}
    assert len(outcome.findings) == 2
    stored = [p.read_text(encoding="utf-8") for p in (tmp_path / "ev").rglob("*.json")]
    assert any("\\ufffd" in text or _R in text for text in stored)


@pytest.mark.parametrize("depth", [MAX_DEPTH + 1, 150])
async def test_a_frame_past_the_parsers_bound_is_too_deep_before_it_is_parsed(depth: int) -> None:
    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await connection.send('{"type":"delta","x":' + "[" * depth + "]" * depth + "}")
        await send_json(connection, {"type": "done"})

    with _query_server(on_query) as server, pytest.raises(WebSocketFrameTooDeep) as info:
        await _adapter(server).send(ModelRequest(prompt="hi"))
    assert isinstance(info.value, ResponseTooDeep)
    assert default_is_env_error(info.value) is True and info.value.retryable is False


def test_a_frame_too_deep_is_the_too_deep_failure_of_every_adapter() -> None:
    """#65's one-attempt failure is ``ResponseTooDeep``; the frame's refusal is one."""

    assert issubclass(WebSocketFrameTooDeep, ResponseTooDeep)
    assert WebSocketFrameTooDeep.retryable is False and WebSocketFrameTooDeep.is_env_error is True


async def test_unbalanced_brackets_past_the_bound_are_not_json() -> None:
    """As on every adapter: brackets that do not balance are a malformed reply (OD-21)."""

    from ildottore.adapters import AdapterProductError

    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await connection.send('{"x":' + "[" * (MAX_DEPTH + 5))

    with (
        _query_server(on_query) as server,
        pytest.raises(AdapterProductError, match="not valid JSON"),
    ):
        await _adapter(server).send(ModelRequest(prompt="hi"))


# --- close code 1007: a text frame that is not UTF-8 is not retried ----------------------------


async def test_a_text_frame_that_is_not_utf8_is_inconclusive_and_sent_once() -> None:
    """Raw ``ED A0 80`` (half a character as bytes): the library closes with 1007."""

    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await connection.send(b'{"type":"delta","delta":{"text":"\xed\xa0\x80"}}', text=True)

    ledger = BudgetLedger(max_requests=100)
    with _query_server(on_query) as server:
        result = await _attempt(_adapter(server), ledger)
    assert result.env_error is True and result.retries == 0
    assert result.errors[0].startswith("WebSocketUndecodable")
    assert result.errors[0].endswith(NOT_RETRYABLE_MARK)
    assert ledger.spend().requests == 1
    assert server.log.queries == 1  # retried, the same frame came back three more times
    assert issubclass(WebSocketUndecodable, ResponseUndecodable)


# --- MEDIUM 4: a tool call's JSON-text arguments are measured ---------------------------------


def _tool_call_server(arguments: str) -> HandlerServer:
    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await send_json(connection, {"type": "delta", "delta": {"text": "ok"}})
        call = {"name": "send_email", "arguments": arguments}
        await send_json(connection, {"type": "done", "tool_calls": [call]})

    return _query_server(on_query)


async def test_tool_call_arguments_nested_too_deeply_fail_the_attempt_once() -> None:
    deep = "[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1)
    spec = _spec(response={"tool_calls_path": "tool_calls"})
    ledger = BudgetLedger(max_requests=100)
    with _tool_call_server(deep) as server:
        result = await _attempt(_adapter(server, spec), ledger)
    assert result.env_error is True and result.retries == 0
    assert result.errors[0].startswith("WebSocketFrameTooDeep")
    assert "tool call whose arguments are nested more than 100 levels" in result.errors[0]
    assert ledger.spend().requests == 1 and server.log.queries == 1


async def test_tool_call_arguments_under_the_bound_or_not_json_are_read() -> None:
    spec = _spec(response={"tool_calls_path": "tool_calls"})
    for arguments, expected in (('{"to": "x@example.test"}', {"to": "x@example.test"}),):
        with _tool_call_server(arguments) as server:
            response = await _adapter(server, spec).send(ModelRequest(prompt="hi"))
        assert call_arguments(response.tool_calls[0]) == expected
    unbalanced = "[" * (MAX_DEPTH + 5)  # not JSON: reads as no arguments, as on every adapter
    with _tool_call_server(unbalanced) as server:
        response = await _adapter(server, spec).send(ModelRequest(prompt="hi"))
    assert call_arguments(response.tool_calls[0]) == {}


# --- MEDIUM 3: reconnects stay under the adapter's retry allowance ----------------------------


async def test_no_redial_inside_a_send_when_the_adapter_retries_nothing() -> None:
    """A campaign builds the adapter with ``max_retries=0``: one dial per debited send."""

    with FakeChatServer("refuse_first") as server:
        adapter = _adapter(server, _spec(reconnect={"max_attempts": 2}))
        adapter.retry = _NO_RETRIES
        with pytest.raises(WebSocketClosed, match="exhausted 1 attempt"):
            await adapter.send(ModelRequest(prompt="hi"))
    assert server.log.connections == 1


async def test_redials_are_capped_by_the_adapters_retries() -> None:
    retry = RetryConfig(max_retries=1, backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=2.0)
    with FakeChatServer(upgrade_status=503) as server:
        adapter = _adapter(server, _spec(reconnect={"max_attempts": 5}))
        adapter.retry = retry
        with pytest.raises(WebSocketClosed, match="HTTP 503"):
            await adapter.send(ModelRequest(prompt="hi"))
    assert server.log.upgrade_requests == 2


def test_a_campaign_debits_every_dial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Under ``run``, each dial of a socket that fails to open is a send the runner debited."""

    monkeypatch.setenv("TEST_WS_TOKEN", TOKEN)

    async def no_wait(_: float) -> None:
        return None

    monkeypatch.setattr("ildottore.core.execute.asyncio.sleep", no_wait)
    with FakeChatServer(upgrade_status=503) as server:
        target = _write_target(tmp_path, endpoint=server.url)  # reconnect: {max_attempts: 1}
        scope = _write_scope(tmp_path, server)
        specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
        opts = RunOptions(
            targets=[target],
            scope=scope,
            runs=1,
            evidence_root=tmp_path / "ev",
            run_db=tmp_path / "runs.sqlite",
        )
        outcome = execute_run(opts, [specs])
    debited = sum(result.spend.requests for result in outcome.results)
    assert debited == 4  # one send and the runner's three retries
    assert server.log.upgrade_requests == debited  # it was 8 for 4 on the PR head


# --- MEDIUM 5: the block holds JSON values only (A-54's walk) ---------------------------------


@pytest.mark.parametrize(
    ("old", "new", "where", "what"),
    [
        (
            'text: "{{prompt}}"}',
            'text: "{{prompt}}", when: 2031-05-17}',
            "websocket/message/send/when",
            "a date",
        ),
        ('text: "{{prompt}}"}', 'text: "{{prompt}}", n: .nan}', "websocket/message/send/n", "NaN"),
        (
            'type: "new_conversation"}',
            'type: "new_conversation", tags: !!set {a, b}}',
            "websocket/session/start/tags",
            "a set",
        ),
        (
            'client: "ildottore"}',
            'client: "ildottore", blob: !!binary aGVsbG8=}',
            "websocket/vars/blob",
            "binary data",
        ),
        (
            'client: "ildottore"}',
            'client: "il\\ud800dottore"}',
            "websocket/vars/client",
            "half a character",
        ),
        ('final_value: "done"', "final_value: .inf", "websocket/response/final_value", "infinity"),
    ],
)
def test_the_loader_refuses_a_value_json_cannot_hold(
    tmp_path: Path, old: str, new: str, where: str, what: str
) -> None:
    assert old in _BLOCK
    path = _write_target(tmp_path, endpoint=_ENDPOINT, block=_BLOCK.replace(old, new, 1))
    with pytest.raises(ValueError, match="JSON cannot hold") as info:
        wiring.load_target(path)
    message = str(info.value)
    assert f"{where}: " in message and what in message
    assert "2031-05-17" not in message and "aGVsbG8" not in message  # the value is not quoted


# --- LOW: a ws:// or wss:// endpoint needs provider websocket ---------------------------------


@pytest.mark.parametrize("provider", ["rest", "openai", "anthropic", "mcp", None])
@pytest.mark.parametrize("endpoint", [_ENDPOINT, "ws://127.0.0.1:8765/ws/chat", " WSS://h/x"])
def test_a_websocket_endpoint_on_another_provider_is_refused(
    tmp_path: Path, provider: str | None, endpoint: str
) -> None:
    path = tmp_path / "target.yaml"
    line = f"provider: {provider}\n" if provider is not None else ""
    path.write_text(
        f'id: t\ntype: chatbot\n{line}endpoint: "{endpoint}"\nauth_ref: "env://K"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="dialled only by provider websocket"):
        wiring.load_target(path)


def test_an_http_endpoint_on_another_provider_still_loads(tmp_path: Path) -> None:
    path = tmp_path / "target.yaml"
    path.write_text(
        'id: t\ntype: chatbot\nprovider: rest\nendpoint: "https://h.example.test/chat"\n',
        encoding="utf-8",
    )
    assert wiring.load_target(path).provider == "rest"


# --- LOW: the loader's refusals cut the names the operator wrote (A-51) -----------------------


def test_reserved_header_names_are_listed_up_to_twenty(tmp_path: Path) -> None:
    """Case variants of one header are distinct YAML keys: the refusal lists 20 and counts."""

    variants = [
        "".join(c.upper() if (i >> k) & 1 else c for k, c in enumerate("host")) for i in range(16)
    ]
    variants += [
        "".join(c.upper() if (i >> k) & 1 else c for k, c in enumerate("upgrade"))
        for i in range(14)
    ]
    headers = "".join(f'    "{name}": "v"\n' for name in variants)
    path = _write_target(tmp_path, endpoint=_ENDPOINT, block=_BLOCK + "  headers:\n" + headers)
    with pytest.raises(ValueError, match="which the WebSocket library writes") as info:
        wiring.load_target(path)
    assert ", and 10 more, which" in str(info.value)


def test_a_long_placeholder_name_is_cut(tmp_path: Path) -> None:
    name = "p" * 5000
    block = _BLOCK.replace('text: "{{prompt}}"', 'text: "{{prompt}} {{' + name + '}}"')
    path = _write_target(tmp_path, endpoint=_ENDPOINT, block=block)
    with pytest.raises(ValueError, match="neither a reserved placeholder") as info:
        wiring.load_target(path)
    assert name not in str(info.value)
    assert f"({len(name) + 4} characters)" in str(info.value)
    assert len(str(info.value)) < len(str(path)) + MAX_PROBLEM_CHARS + 300


# --- the fleet's scope pins a wss entry's port, as the allowlist reads it ---------------------


@pytest.mark.parametrize(
    ("endpoint", "host"),
    [
        ("wss://assistant.example.test/ws/chat", "assistant.example.test:443"),
        ("ws://127.0.0.1/ws/chat", "127.0.0.1:80"),
        ("wss://assistant.example.test:8443/ws/chat", "assistant.example.test:8443"),
    ],
)
def test_a_fleet_wss_entry_authorizes_one_port(endpoint: str, host: str) -> None:
    entry = _scope_entry("ws", endpoint, None)
    assert entry["endpoints"] == [{"host": host, "path_prefixes": ["/ws/chat"]}]
    allowlist = EndpointAllowlist([Endpoint(host=host, path_prefixes=["/ws/chat"])])
    assert allowlist.is_allowed(endpoint)
    other = endpoint.replace("/ws/chat", "").rstrip("/") + ":2375/ws/chat"
    if ":8443" not in endpoint:
        assert not allowlist.is_allowed(other)


def test_a_fleet_wss_entry_writes_a_target_run_refuses(tmp_path: Path) -> None:
    """``fleet`` infers ``rest`` and writes no block (OD-37); ``run`` refuses that file."""

    import yaml

    doc = _target_doc(FleetTarget(id="ws", endpoint="wss://assistant.example.test/ws/chat"))
    assert doc["provider"] == "rest" and "websocket" not in doc
    path = tmp_path / "target-ws.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(ValueError, match="dialled only by provider websocket"):
        wiring.load_target(path)


# --- second pre-merge audit, MEDIUM 1: no error class name reads as a credential --------------

# Every error class of the package, these included, is checked against the redactor by
# tests/test_redactor_error_class_names.py (u01 A-63); this campaign test pins one name end to
# end, through the reason and the stored evidence.


def test_the_campaign_names_an_undecodable_frame_in_its_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_WS_TOKEN", TOKEN)

    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await connection.send(b'{"type":"delta","delta":{"text":"\xed\xa0\x80"}}', text=True)

    with _query_server(on_query) as server:
        target = _write_target(tmp_path, endpoint=server.url)
        scope = _write_scope(tmp_path, server)  # type: ignore[arg-type]
        specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
        opts = RunOptions(
            targets=[target],
            scope=scope,
            runs=1,
            evidence_root=tmp_path / "ev",
            run_db=tmp_path / "runs.sqlite",
        )
        outcome = execute_run(opts, [specs])
    reason = outcome.incomplete["ws-live"]
    assert "WebSocketUndecodable: ws-live: a text frame was not UTF-8" in reason
    assert "REDACTED" not in reason
    stored = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "ev").rglob("*.json"))
    assert "WebSocketUndecodable" in stored and "high_entropy" not in stored
    assert server.log.queries == 1  # not retried


# --- second pre-merge audit, LOW 2: a close the server starts is the server's -----------------


@pytest.mark.parametrize("code", [1007, 1009])
async def test_a_close_the_server_starts_with_1007_or_1009_is_not_this_sides(code: int) -> None:
    """The library echoes the server's close: it is not "a frame exceeded" nor "not UTF-8"."""

    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await connection.close(code, f"refused by the server, token {TOKEN}")

    ledger = BudgetLedger(max_requests=100)
    with _query_server(on_query) as server:
        result = await _attempt(_adapter(server), ledger)
    error = result.errors[0]
    assert error.startswith("WebSocketClosed: ws-test: the connection closed mid-turn: received")
    assert "refused by the server" in error and TOKEN not in error  # its reason, scrubbed
    assert "exceeded" not in error and "not UTF-8" not in error
    assert error.endswith(NOT_RETRYABLE_MARK) and result.retries == 0
    assert ledger.spend().requests == 1 and server.log.queries == 1


@pytest.mark.parametrize("code", [1007, 1009])
async def test_a_server_close_before_a_send_is_not_retried_either(code: int) -> None:
    """The server acknowledges the auth frame and closes at once: the session frame's send
    meets the close. It was retried three times, four debited sends for no query
    (verification of the second pre-merge audit)."""

    async def handler(connection: ServerConnection, log: Log) -> None:
        async for raw in connection:
            message = json.loads(raw)
            log.frames.append(message)
            if message.get("type") == "auth":
                await send_json(connection, {"type": "auth_ok"})
                await connection.close(code, "session frame refused")
                return

    ledger = BudgetLedger(max_requests=100)
    with HandlerServer(handler) as server:
        result = await _attempt(_adapter(server), ledger)
    error = result.errors[0]
    assert error.startswith("WebSocketClosed: ws-test: the connection closed")
    assert "session frame refused" in error and error.endswith(NOT_RETRYABLE_MARK)
    assert result.retries == 0 and ledger.spend().requests == 1
    assert server.log.connections == 1 and server.log.queries == 0


@pytest.mark.parametrize(
    ("code", "retryable"), [(1007, False), (1009, False), (1011, True), (1001, True)]
)
async def test_a_send_that_meets_a_server_close_is_classified_as_a_receive_is(
    code: int, retryable: bool
) -> None:
    """The send path, deterministically: the frame's send raises the library's close.

    Through a live server the close can land on the send or on the next receive, depending on
    timing; both go through one classification now.
    """

    from websockets.exceptions import ConnectionClosedError
    from websockets.frames import Close

    class _ClosedConnection:
        async def send(self, _message: str) -> None:
            close = Close(code, "refused")
            raise ConnectionClosedError(close, close, rcvd_then_sent=True)

    with FakeChatServer("echo") as server:
        adapter = _adapter(server)
        with pytest.raises(WebSocketClosed, match="closed while sending") as info:
            await adapter._send_template(
                _ClosedConnection(),  # type: ignore[arg-type]
                {"type": "x"},
                None,
                [],
            )
    assert info.value.retryable is retryable and "refused" in str(info.value)
    assert WebSocketClosed.retryable is True  # the class keeps its default


async def test_a_close_the_server_starts_with_another_code_is_still_retried() -> None:
    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await connection.close(1011, "internal error")

    ledger = BudgetLedger(max_requests=100)
    with _query_server(on_query) as server:
        result = await _attempt(_adapter(server), ledger)
    assert result.errors[0].startswith("WebSocketClosed") and result.retries == 3
    assert not result.errors[0].endswith(NOT_RETRYABLE_MARK)
    assert server.log.queries == 4


async def test_a_frame_over_the_cap_is_still_this_sides_overflow() -> None:
    """This side starts the 1009 close: the overflow, as before (the other direction)."""

    from ildottore.adapters.websocket import WebSocketOverflow

    with FakeChatServer("huge") as server, pytest.raises(WebSocketOverflow, match="exceeded 1024"):
        await _adapter(server, max_frame_bytes=1024).send(ModelRequest(prompt="hi"))


# --- second pre-merge audit, LOW 3: keys in the block are text (A-44's walk) ------------------


@pytest.mark.parametrize(
    ("old", "new", "where", "kind"),
    [
        (
            'text: "{{prompt}}"}',
            'text: "{{prompt}}", opts: {on: true, ~: 1}}',
            "websocket/message/send/opts",
            "a boolean",
        ),
        (
            'type: "new_conversation"}',
            'type: "new_conversation", 5: x}',
            "websocket/session/start",
            "an integer",
        ),
    ],
)
def test_the_loader_refuses_a_key_that_is_not_text(
    tmp_path: Path, old: str, new: str, where: str, kind: str
) -> None:
    """``opts: {on: true, ~: 1}`` went on the wire as ``{"True": true, "None": 1}``."""

    assert old in _BLOCK
    path = _write_target(tmp_path, endpoint=_ENDPOINT, block=_BLOCK.replace(old, new, 1))
    with pytest.raises(ValueError, match="has a key that is not text") as info:
        wiring.load_target(path)
    assert f"{where}: key " in str(info.value) and kind in str(info.value)
    assert "not a string" in str(info.value)
    assert "\n" not in str(info.value)
