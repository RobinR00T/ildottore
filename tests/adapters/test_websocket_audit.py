"""Regressions from the pre-commit audit of the WebSocket adapter (2026-10-07).

Each test reproduces a finding of that audit (F1 to F11) or kills a mutant it reported as
surviving (M13, M21, M22, M25, M26, M29). The servers are loopback; nothing leaves the host.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
from websockets.asyncio.server import ServerConnection

import ildottore.adapters.websocket as module
from ildottore.adapters import AdapterProductError, WebSocketAdapter
from ildottore.adapters.websocket import (
    MAX_FRAME_DEPTH,
    MAX_FRAMES_PER_TURN,
    WebSocketClosed,
    WebSocketFrameTooDeep,
    WebSocketOverflow,
    WebSocketTooMany,
    WebSocketTurnTimeout,
    _close,
    _satisfies,
)
from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.run import RunOptions, execute_run
from ildottore.core.budgets import BudgetLedger
from ildottore.core.execute import (
    NOT_RETRYABLE_MARK,
    RetryPolicy,
    default_is_env_error,
    execute_attempt,
)
from ildottore.fingerprint.layers.metadata import envelope_signal
from ildottore.shared.digest import target_digest
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import ModelRequest, Target, WebSocketExpect
from tests.adapters.test_websocket import _adapter, _spec
from tests.cli.conftest import make_spec, write_spec_tree
from tests.cli.test_websocket_target import _BLOCK, _write_scope, _write_target
from tests.ws_chat_server import TOKEN, FakeChatServer
from tests.ws_raw_servers import HandlerServer, TcpCapture, auth_then, send_json

MIB = 1024 * 1024
_POLICY = RetryPolicy(max_retries=3, base_delay_s=0.0)


async def _noop(_: float) -> None:
    return None


def _nested_frame(depth: int) -> str:
    return '{"type":"delta","delta":{"text":"ok"},"x":' + '{"a":' * depth + "1" + "}" * depth + "}"


def _query_server(
    on_query: Callable[[ServerConnection, dict[str, Any]], Awaitable[None]],
) -> HandlerServer:
    async def handler(connection: ServerConnection, log: Any) -> None:
        await auth_then(connection, log, on_query)

    return HandlerServer(handler)


def _accept(key: str) -> str:
    guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    return base64.b64encode(hashlib.sha1((key + guid).encode()).digest()).decode()  # noqa: S324


async def _raw_upgrade_server(
    after: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
) -> asyncio.Server:
    """A raw server that completes a real WebSocket upgrade, then does ``after``."""

    async def on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        key = next(
            line.split(b":", 1)[1].strip().decode()
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"sec-websocket-key")
        )
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + _accept(key).encode() + b"\r\n\r\n"
        )
        await writer.drain()
        await after(reader, writer)

    return await asyncio.start_server(on_connect, "127.0.0.1", 0)


def _raw_adapter(port: int, **overrides: object) -> WebSocketAdapter:
    from ildottore.policy import Endpoint, EndpointAllowlist

    return WebSocketAdapter(
        id="ws-test",
        url=f"ws://127.0.0.1:{port}/ws/chat",
        allowlist=EndpointAllowlist([Endpoint(host=f"127.0.0.1:{port}", path_prefixes=["/"])]),
        spec=_spec(
            handshake=None,
            session={"start": None, "expect": None},
            reconnect={"max_attempts": 0},
            **overrides,  # type: ignore[arg-type]
        ),
        api_key=None,
        retry=module.RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=2.0),
    )


# --- F1: a nested frame is this attempt's problem, never the campaign's ---------------------


@pytest.mark.parametrize("depth", [MAX_FRAME_DEPTH + 1, 300, 3000])
async def test_a_frame_nested_too_deeply_is_inconclusive_and_not_retried(depth: int) -> None:
    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await connection.send(_nested_frame(depth))
        await send_json(connection, {"type": "done"})

    with _query_server(on_query) as server, pytest.raises(WebSocketFrameTooDeep) as info:
        await _adapter(server).send(ModelRequest(prompt="hi"))
    assert default_is_env_error(info.value) is True and info.value.retryable is False


async def test_a_frame_at_the_depth_cap_is_read() -> None:
    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await connection.send(_nested_frame(MAX_FRAME_DEPTH - 2))  # the frame itself adds two
        await send_json(connection, {"type": "done"})

    with _query_server(on_query) as server:
        response = await _adapter(server).send(ModelRequest(prompt="hi"))
    assert response.text == "ok"


def test_a_nested_frame_does_not_abort_the_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The run completes; the spec is inconclusive; the other spec is scored (F1)."""

    monkeypatch.setenv("TEST_WS_TOKEN", TOKEN)
    calls = {"n": 0}

    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            await connection.send(_nested_frame(300))
        else:
            await send_json(connection, {"type": "delta", "delta": {"text": "I can't help."}})
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
    statuses = sorted(f.status.value for f in outcome.findings)
    assert statuses == [VerdictStatus.INCONCLUSIVE.value, VerdictStatus.PASS.value]
    assert calls["n"] == 2  # the deep reply was not retried


# --- F2 and M29: the handshake phase is bounded in bytes and frames ---------------------------


async def test_the_handshake_phase_has_the_turn_byte_cap() -> None:
    async def handler(connection: ServerConnection, log: Any) -> None:
        async for raw in connection:
            message = json.loads(raw)
            if message.get("type") == "auth":
                for _ in range(6):
                    await send_json(connection, {"type": "ping", "pad": "x" * MIB})
                await send_json(connection, {"type": "auth_ok"})

    with (
        HandlerServer(handler) as server,
        pytest.raises(WebSocketOverflow, match="before the handshake"),
    ):
        await _adapter(server, _spec(reconnect={"max_attempts": 0}), max_frame_bytes=2 * MIB).send(
            ModelRequest(prompt="hi")
        )


async def test_the_handshake_phase_has_the_turn_frame_cap() -> None:
    async def handler(connection: ServerConnection, log: Any) -> None:
        async for raw in connection:
            message = json.loads(raw)
            if message.get("type") == "auth":
                for _ in range(MAX_FRAMES_PER_TURN + 1):
                    await send_json(connection, {"type": "ping"})
                await send_json(connection, {"type": "auth_ok"})

    with (
        HandlerServer(handler) as server,
        pytest.raises(WebSocketOverflow, match="frames before the handshake"),
    ):
        await _adapter(server, _spec(reconnect={"max_attempts": 0})).send(ModelRequest(prompt="hi"))


async def test_the_handshake_phase_is_under_the_turn_timeout() -> None:
    """A server that takes the auth frame and never answers: a timeout, then the reconnect cap."""

    async def handler(connection: ServerConnection, log: Any) -> None:
        async for _raw in connection:
            await asyncio.sleep(30)

    spec = _spec(response={"timeout_seconds": 0.3}, reconnect={"max_attempts": 1})
    with (
        HandlerServer(handler) as server,
        pytest.raises(WebSocketClosed, match="WebSocketTurnTimeout") as info,
    ):
        await _adapter(server, spec).send(ModelRequest(prompt="hi"))
    assert "handshake and session phase" in str(info.value)
    assert server.log.connections == 2


# --- F3: an intermediate turn records its own frames, the last the conversation ------------


async def test_an_intermediate_turn_records_its_own_frames_and_the_last_the_conversation() -> None:
    async def on_query(connection: ServerConnection, message: dict[str, Any]) -> None:
        await send_json(connection, {"type": "delta", "delta": {"text": message["text"]}})
        await send_json(connection, {"type": "done"})

    def turn(index: int) -> ModelRequest:
        return ModelRequest(
            messages=[{"role": "user", "content": f"t{index}"}],
            metadata={"conversation": "c", "turn_index": index, "turns_total": 3},
        )

    with _query_server(on_query) as server:
        adapter = _adapter(server)
        responses = [await adapter.send(turn(index)) for index in range(3)]
    frames = [r.raw_ids["websocket"]["frames"] for r in responses]
    queries = [
        [f["frame"]["text"] for f in fs if f["frame"].get("type") == "query"] for fs in frames
    ]
    assert queries == [["t0"], ["t1"], ["t0", "t1", "t2"]]
    assert frames[0][0]["frame"]["type"] == "auth"  # the opening frames go with the first turn
    assert frames[1][0]["frame"] == {"type": "query", "text": "t1"}  # nothing repeated
    assert len(frames[2]) == len(frames[0]) + len(frames[1]) + len(frames[1])


# --- F4: a live conversation is never evicted --------------------------------------------------


async def test_an_in_flight_turn_is_not_closed_by_a_new_conversation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module, "MAX_OPEN_CONVERSATIONS", 1)

    async def on_query(connection: ServerConnection, message: dict[str, Any]) -> None:
        if message["text"] == "slow":
            await asyncio.sleep(0.5)
        await send_json(connection, {"type": "delta", "delta": {"text": message["text"]}})
        await send_json(connection, {"type": "done"})

    with _query_server(on_query) as server:
        adapter = _adapter(server)
        await adapter.send(
            ModelRequest(
                messages=[{"role": "user", "content": "c0"}],
                metadata={"conversation": "c0", "turn_index": 0, "turns_total": 2},
            )
        )
        slow = asyncio.create_task(
            adapter.send(
                ModelRequest(
                    messages=[{"role": "user", "content": "slow"}],
                    metadata={"conversation": "c0", "turn_index": 1, "turns_total": 2},
                )
            )
        )
        await asyncio.sleep(0.1)
        with pytest.raises(WebSocketTooMany):
            await adapter.send(
                ModelRequest(
                    messages=[{"role": "user", "content": "c1"}],
                    metadata={"conversation": "c1", "turn_index": 0, "turns_total": 2},
                )
            )
        assert (await slow).text == "slow"
    assert server.log.connections == 1


# --- F5: the credential never reaches an exception message ---------------------------------


async def test_a_credential_reflected_in_the_upgrade_reply_is_not_quoted() -> None:
    token = "aud-hdr-" + "Q" * 12
    reply = (
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + token.encode() + b"\r\n\r\n"
    )
    with TcpCapture(reply) as capture:
        adapter = _raw_adapter(capture.port, headers={"Authorization": "Bearer {{token}}"})
        adapter.api_key = token
        with pytest.raises(AdapterProductError) as info:
            await adapter.send(ModelRequest(prompt="hi"))
    assert b"Authorization: Bearer " + token.encode() in capture.received[0]
    assert token not in str(info.value)
    assert "{{token}}" in str(info.value)


@pytest.mark.parametrize("reason", ["bad token {token}", "{token} rejected"])
async def test_a_close_reason_carrying_the_credential_is_scrubbed(reason: str) -> None:
    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await connection.close(1008, reason.format(token=TOKEN))

    with _query_server(on_query) as server, pytest.raises(WebSocketClosed) as info:
        await _adapter(server).send(ModelRequest(prompt="hi"))
    assert TOKEN not in str(info.value)
    # Scrubbed to the placeholder, which the redactor may then mask as a labelled value.
    assert "{{token}}" in str(info.value) or "REDACTED" in str(info.value)


async def test_a_credential_shorter_than_eight_characters_is_refused_before_any_dial() -> None:
    with (
        FakeChatServer("echo") as server,
        pytest.raises(AdapterProductError, match="shorter than 8"),
    ):
        await _adapter(server, token="tok4567").send(ModelRequest(prompt="hi"))
    assert server.log.upgrade_requests == 0


# --- F6: the query send is inside the turn timeout ------------------------------------------


async def test_a_server_that_never_reads_is_a_turn_timeout() -> None:
    async def never_read(_reader: asyncio.StreamReader, _writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(30)

    server = await _raw_upgrade_server(never_read)
    port = server.sockets[0].getsockname()[1]
    try:
        adapter = _raw_adapter(port, response={"timeout_seconds": 0.5})
        started = time.monotonic()
        with pytest.raises(WebSocketTurnTimeout):
            await adapter.send(ModelRequest(prompt="p" * (16 * MIB)))
        assert time.monotonic() - started < 6.0
    finally:
        server.close()
        await server.wait_closed()


# --- F7: a lost conversation is debited once --------------------------------------------------


async def test_a_lost_conversation_is_not_retried_and_is_debited_once() -> None:
    with FakeChatServer("echo") as server:
        adapter = _adapter(server)
        ledger = BudgetLedger(max_requests=100)
        request = ModelRequest(
            messages=[{"role": "user", "content": "t1"}],
            metadata={"conversation": "c", "turn_index": 1, "turns_total": 2},
        )
        result = await execute_attempt(
            adapter,
            request,
            attempt_id="a1",
            spec_id="S",
            mutation="identity",
            sampling=None,
            ledger=ledger,
            retry=_POLICY,
            sleep=_noop,
        )
    assert result.env_error is True and result.retries == 0
    assert result.errors[0].startswith("WebSocketLost") and result.errors[0].endswith(
        NOT_RETRYABLE_MARK
    )
    assert ledger.spend().requests == 1
    assert server.log.connections == 0


# --- F8, F9, F11: the loader refuses what would fail or leak after the dial ----------------


@pytest.mark.parametrize(
    ("block", "match"),
    [
        (_BLOCK + '  headers: {X-Prompt: "{{prompt}}"}\n', "may use only {{token}} and vars"),
        (
            _BLOCK.replace('client: "{{client}}"', 'client: "{{messages}}"'),
            "may use only {{token}} and vars",
        ),
        (
            _BLOCK.replace(
                '    start: {type: "new_conversation"}',
                '    start: {type: "s", sys: "{{system_prompt}}"}',
            ),
            "may use only {{token}} and vars",
        ),
        (
            _BLOCK.replace(
                'vars: {client: "ildottore"}', 'vars: {client: "{{other}}", other: "x"}'
            ),
            "vars carries {{other}}",
        ),
        (
            _BLOCK.replace('vars: {client: "ildottore"}', 'vars: {client: "{{prompt}}"}'),
            "vars carries {{prompt}}",
        ),
        (_BLOCK + '  headers: {Host: "evil.example.test"}\n', "sets Host"),
        (
            _BLOCK + '  headers: {"Sec-WebSocket-Extensions": "permessage-deflate"}\n',
            "sets Sec-WebSocket-Extensions",
        ),
    ],
)
def test_the_loader_refuses_request_placeholders_in_connection_templates_vars_and_reserved_headers(
    tmp_path: Path, block: str, match: str
) -> None:
    path = _write_target(tmp_path, endpoint="wss://assistant.example.test/ws/chat", block=block)
    with pytest.raises(ValueError, match=match):
        wiring.load_target(path)


def test_a_token_only_in_headers_is_accepted(tmp_path: Path) -> None:
    block = (
        _BLOCK.replace('token: "{{token}}"', 'token: "static"')
        + '  headers: {Authorization: "Bearer {{token}}"}\n'
    )
    target = wiring.load_target(
        _write_target(tmp_path, endpoint="wss://assistant.example.test/ws/chat", block=block)
    )
    assert target.websocket is not None and target.websocket.headers == {
        "Authorization": "Bearer {{token}}"
    }


# --- F10: equals and final_value compare with their type -----------------------------------------


def test_equals_and_final_value_keep_bool_int_and_float_apart() -> None:
    assert _satisfies({"ok": 1}, WebSocketExpect(path="ok", equals=True)) is False
    assert _satisfies({"ok": True}, WebSocketExpect(path="ok", equals=1)) is False
    assert _satisfies({"ok": 1.0}, WebSocketExpect(path="ok", equals=1)) is False
    assert _satisfies({"ok": 1}, WebSocketExpect(path="ok", equals=1)) is True
    assert _satisfies({"ok": "done"}, WebSocketExpect(path="ok", equals="done")) is True
    with FakeChatServer("echo") as server:
        adapter = _adapter(server, _spec(response={"final_path": "done", "final_value": False}))
        assert adapter._is_final({"done": 0}) is False
        assert adapter._is_final({"done": False}) is True
        present = _adapter(server, _spec(response={"final_path": "done", "final_value": None}))
        assert present._is_final({"done": False}) is True
        assert present._is_final({"done": None}) is False


# --- F11: cleartext ws never goes through a proxy ----------------------------------------


async def test_a_loopback_ws_dial_ignores_the_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TcpCapture(None) as proxy, FakeChatServer("echo") as server:
        monkeypatch.setenv("ws_proxy", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.delenv("no_proxy", raising=False)
        response = await _adapter(server).send(ModelRequest(prompt="hi"))
    assert response.text == "hi"
    assert proxy.accepted == 0
    assert server.log.connections == 1


# --- mutants the audit reported as surviving ------------------------------------------------------


async def test_compression_is_not_offered_at_the_upgrade() -> None:
    """M13: the client must not negotiate permessage-deflate (a decompression bomb would
    inflate past the byte cap unseen)."""

    with TcpCapture(None) as capture, pytest.raises(AdapterProductError, match="upgrade"):
        await _raw_adapter(capture.port).send(ModelRequest(prompt="hi"))
    assert capture.received and b"GET /ws/chat" in capture.received[0]
    assert b"permessage-deflate" not in capture.received[0].lower()


async def test_raw_ids_are_redacted_in_memory() -> None:
    """M21: the in-memory response already carries masked frames, not only the evidence."""

    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await send_json(
            connection, {"type": "delta", "delta": {"text": "ok"}, "who": "user@example.com"}
        )
        await send_json(connection, {"type": "done"})

    with _query_server(on_query) as server:
        response = await _adapter(server).send(ModelRequest(prompt="hi"))
    dumped = json.dumps(response.raw_ids)
    assert "user@example.com" not in dumped and "REDACTED" in dumped


async def test_close_against_a_server_that_never_answers_the_close_frame_is_bounded() -> None:
    """M22: ``_close`` returns within its own timeout, whatever the server does."""

    async def swallow(_reader: asyncio.StreamReader, _writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(30)

    server = await _raw_upgrade_server(swallow)
    port = server.sockets[0].getsockname()[1]
    try:
        from websockets.asyncio.client import connect

        connection = await connect(
            f"ws://127.0.0.1:{port}/ws/chat", close_timeout=1.0, open_timeout=2.0
        )
        started = time.monotonic()
        await _close(connection)
        assert time.monotonic() - started < 4.0
    finally:
        server.close()
        await server.wait_closed()


async def test_the_transcript_is_not_a_metadata_tell() -> None:
    """M25: the envelope signal skips the nested transcript, so a reply's text cannot name a
    family."""

    async def on_query(connection: ServerConnection, _message: dict[str, Any]) -> None:
        await send_json(
            connection, {"type": "delta", "delta": {"text": "model=llama system_fingerprint"}}
        )
        await send_json(connection, {"type": "done", "model": "fake-chat-9b"})

    with _query_server(on_query) as server:
        response = await _adapter(server, _spec(response={"model_path": "model"})).send(
            ModelRequest(prompt="hi")
        )
    signal = envelope_signal(response)
    assert "model=fake-chat-9b" in signal
    assert "llama" not in signal and "system_fingerprint" not in signal


def test_the_digest_leaves_an_absent_block_out() -> None:
    """M26: a target without the field hashes as it did before the field existed."""

    from ildottore.shared import digest

    plain = Target.model_validate({"id": "t", "type": "model"})
    before = {
        k: v
        for k, v in plain.model_dump(mode="json").items()
        if k not in digest._TARGET_COSMETIC and k not in ("seeded_setup", "websocket")
    }
    before["__route__"] = "live"
    assert target_digest(plain) == digest._sha(before)
    assert "websocket" not in json.dumps(before)
