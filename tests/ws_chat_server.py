"""A loopback JSON-over-WebSocket chat server for the WebSocket adapter tests.

No network leaves the host (the session guard in ``tests/conftest.py`` allows loopback). The
server runs on its own thread and event loop, so both async adapter tests and the synchronous
CLI paths (``asyncio.run`` inside ``fingerprint_target`` and ``execute_run``) can dial it.

Its wire shape is the one ``examples/target.websocket.yaml`` declares: an ``auth`` frame
answered by ``auth_ok``/``auth_failed``, an optional ``new_conversation`` frame, and a ``query``
frame answered by ``delta`` frames (with a ``ping`` between them) and a ``done`` frame. The
``behaviour`` picks what a query gets: the text back (``echo``, the vulnerable target), a
refusal (``hardened``), a compliant answer (``comply``), an error frame, a stall, a close
mid-turn, a flood, an oversized frame, a binary frame, a non-JSON frame, a reply with tool
calls, or a model name in the envelope.
"""

from __future__ import annotations

import asyncio
import http
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from websockets.asyncio.server import Request, Response, ServerConnection, serve

__all__ = ["COMPLIANCE", "REFUSAL", "TOKEN", "FakeChatServer", "ServerLog"]

#: The credential the server accepts (long enough for the redactor to register it too).
TOKEN = "ws-secret-token-0123456789"
REFUSAL = "I'm sorry, I can't help with that."
COMPLIANCE = "Sure, here's the restricted content you asked for."


@dataclass
class ServerLog:
    """What the server saw: counted from its own thread, read after the client returns."""

    connections: int = 0
    closed: int = 0
    queries: int = 0
    upgrade_requests: int = 0
    frames: list[dict[str, Any]] = field(default_factory=list)
    queries_per_connection: list[int] = field(default_factory=list)


class FakeChatServer:
    """``with FakeChatServer("echo") as server: ... server.url ...``."""

    def __init__(
        self,
        behaviour: str = "echo",
        *,
        token: str = TOKEN,
        upgrade_status: int | None = None,
        redirect_to: str | None = None,
        path: str = "/ws/chat",
    ) -> None:
        self.behaviour = behaviour
        self.token = token
        self.upgrade_status = upgrade_status
        self.redirect_to = redirect_to
        self.path = path
        self.log = ServerLog()
        self.port = 0
        self._ready = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._thread = threading.Thread(target=self._run, name="fake-chat-server", daemon=True)

    # --- lifecycle ---------------------------------------------------------------------

    def __enter__(self) -> FakeChatServer:
        self._thread.start()
        if not self._ready.wait(10):  # pragma: no cover - a stuck server
            raise RuntimeError("the fake chat server did not start")
        return self

    def __exit__(self, *_: object) -> None:
        assert self._loop is not None and self._stop is not None
        self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(10)

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}{self.path}"

    def _run(self) -> None:
        asyncio.run(self._main())

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        async with serve(
            self._handler, "127.0.0.1", 0, process_request=self._process_request, max_size=2**23
        ) as server:
            self.port = server.sockets[0].getsockname()[1]
            self._ready.set()
            await self._stop.wait()

    # --- the upgrade -------------------------------------------------------------------

    def _process_request(self, connection: ServerConnection, request: Request) -> Response | None:
        self.log.upgrade_requests += 1
        if self.redirect_to is not None:
            response = connection.respond(http.HTTPStatus.FOUND, "moved")
            response.headers["Location"] = self.redirect_to
            return response
        if self.upgrade_status is not None:
            return connection.respond(http.HTTPStatus(self.upgrade_status), "no")
        return None

    # --- frames ------------------------------------------------------------------------

    async def _handler(self, connection: ServerConnection) -> None:
        self.log.connections += 1
        queries = 0
        try:
            if self.behaviour == "refuse_first" and self.log.connections == 1:
                return  # closes the socket before any handshake reply
            async for raw in connection:
                if isinstance(raw, bytes):  # pragma: no cover - the adapter sends text
                    continue
                message = json.loads(raw)
                self.log.frames.append(message)
                kind = message.get("type")
                if kind == "auth":
                    ok = message.get("token") == self.token
                    await self._send(connection, {"type": "auth_ok" if ok else "auth_failed"})
                    if self.behaviour == "echo_token":
                        note = f"welcome, {message.get('token')}"
                        await self._send(connection, {"type": "ping", "note": note})
                elif kind == "new_conversation":
                    await self._send(connection, {"type": "session", "id": "s-1"})
                elif kind == "query":
                    queries += 1
                    self.log.queries += 1
                    await self._answer(connection, message)
        finally:
            self.log.closed += 1
            self.log.queries_per_connection.append(queries)

    async def _send(self, connection: ServerConnection, frame: dict[str, Any]) -> None:
        await connection.send(json.dumps(frame))

    async def _answer(self, connection: ServerConnection, message: dict[str, Any]) -> None:
        text = str(message.get("text", ""))
        send = self._send
        actions: dict[str, Callable[[], Any]] = {
            "echo": lambda: self._stream(connection, text),
            "hardened": lambda: self._stream(connection, REFUSAL),
            "comply": lambda: self._stream(connection, COMPLIANCE),
            "echo_token": lambda: self._stream(connection, text),
            "refuse_first": lambda: self._stream(connection, text),
            "error": lambda: send(
                connection,
                {"type": "error", "error": {"message": f"rate limited; token {self.token}"}},
            ),
            "stall": lambda: send(connection, {"type": "delta", "delta": {"text": "part"}}),
            "close_mid_turn": lambda: self._close_mid_turn(connection),
            "flood": lambda: self._flood(connection),
            "long_turn": lambda: self._long_turn(connection),
            "huge": lambda: send(
                connection, {"type": "delta", "delta": {"text": "x" * (128 * 1024)}}
            ),
            "binary": lambda: connection.send(b"\x00\x01"),
            "not_json": lambda: connection.send("not json at all"),
            "not_object": lambda: connection.send("[1, 2, 3]"),
            "no_text": lambda: send(connection, {"type": "done"}),
            "tool_calls": lambda: self._with_tool_calls(connection, text),
            "model": lambda: self._with_model(connection, text),
        }
        await actions[self.behaviour]()

    async def _stream(self, connection: ServerConnection, text: str) -> None:
        third = max(1, len(text) // 3)
        chunks = [text[:third], text[third : 2 * third], text[2 * third :]]
        await self._send(connection, {"type": "delta", "delta": {"text": chunks[0]}})
        await self._send(connection, {"type": "ping"})
        await self._send(connection, {"type": "delta", "delta": {"text": chunks[1]}})
        await self._send(connection, {"type": "typing"})
        await self._send(connection, {"type": "delta", "delta": {"text": chunks[2]}})
        await self._send(
            connection, {"type": "done", "usage": {"total_tokens": 7 + len(text) // 4}}
        )

    async def _close_mid_turn(self, connection: ServerConnection) -> None:
        await self._send(connection, {"type": "delta", "delta": {"text": "half an ans"}})
        await connection.close()

    async def _flood(self, connection: ServerConnection) -> None:
        for _ in range(4200):
            await self._send(connection, {"type": "ping"})

    async def _long_turn(self, connection: ServerConnection) -> None:
        for _ in range(5):  # 5 MiB of text in 1 MiB frames: over the turn cap, under the frame cap
            await self._send(connection, {"type": "delta", "delta": {"text": "y" * (1024 * 1024)}})
        await self._send(connection, {"type": "done"})

    async def _with_tool_calls(self, connection: ServerConnection, text: str) -> None:
        await self._send(connection, {"type": "delta", "delta": {"text": text}})
        await self._send(
            connection,
            {
                "type": "done",
                "tool_calls": [{"name": "send_email", "arguments": {"to": "x@example.test"}}],
            },
        )

    async def _with_model(self, connection: ServerConnection, text: str) -> None:
        await self._send(connection, {"type": "delta", "delta": {"text": text}})
        await self._send(connection, {"type": "done", "model": "fake-chat-9b", "id": "r-42"})
