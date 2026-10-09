"""Loopback servers with a custom handler, for the WebSocket adapter's audit regressions.

Adapted from the reproductions the pre-commit audit of the adapter wrote (2026-10-07).
:class:`HandlerServer` is a WebSocket server driven by ``handler(connection, log)``;
:class:`TcpCapture` is a raw TCP server that records what it receives and answers with fixed
bytes, for upgrade replies no WebSocket library would produce. Nothing leaves the host.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from websockets.asyncio.server import ServerConnection, serve

__all__ = ["HandlerServer", "Log", "TcpCapture", "auth_then", "send_json"]

Handler = Callable[[ServerConnection, "Log"], Awaitable[None]]


@dataclass
class Log:
    """What the server saw, counted on its own thread and read after the client returns."""

    connections: int = 0
    queries: int = 0
    frames: list[Any] = field(default_factory=list)
    closed: int = 0


class HandlerServer:
    """``with HandlerServer(handler) as server: ... server.url ...``."""

    def __init__(self, handler: Handler, *, path: str = "/ws/chat") -> None:
        self.handler = handler
        self.path = path
        self.log = Log()
        self.port = 0
        self._ready = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._thread = threading.Thread(target=self._run, name="handler-server", daemon=True)

    def __enter__(self) -> HandlerServer:
        self._thread.start()
        if not self._ready.wait(10):  # pragma: no cover - a stuck server
            raise RuntimeError("the handler server did not start")
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
        async with serve(self._handle, "127.0.0.1", 0, max_size=2**24) as server:
            self.port = server.sockets[0].getsockname()[1]
            self._ready.set()
            await self._stop.wait()

    async def _handle(self, connection: ServerConnection) -> None:
        self.log.connections += 1
        try:
            await self.handler(connection, self.log)
        finally:
            self.log.closed += 1


async def send_json(connection: ServerConnection, frame: Any) -> None:
    await connection.send(json.dumps(frame))


async def auth_then(
    connection: ServerConnection,
    log: Log,
    on_query: Callable[[ServerConnection, dict[str, Any]], Awaitable[None]],
) -> None:
    """The example's handshake (``auth`` to ``auth_ok``, ``new_conversation`` to ``session``),
    then ``on_query`` for each query frame."""

    async for raw in connection:
        message = json.loads(raw)
        log.frames.append(message)
        kind = message.get("type")
        if kind == "auth":
            await send_json(connection, {"type": "auth_ok"})
        elif kind == "new_conversation":
            await send_json(connection, {"type": "session", "id": "s-1"})
        elif kind == "query":
            log.queries += 1
            await on_query(connection, message)


class TcpCapture:
    """A raw loopback TCP server: records each connection's first bytes, answers ``reply``."""

    def __init__(self, reply: bytes | None = None, *, hold_open: bool = False) -> None:
        self.reply = reply
        self.hold_open = hold_open
        self.accepted = 0
        self.received: list[bytes] = []
        self.port = 0
        self._ready = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._thread = threading.Thread(target=self._run, name="tcp-capture", daemon=True)

    def __enter__(self) -> TcpCapture:
        self._thread.start()
        if not self._ready.wait(10):  # pragma: no cover - a stuck server
            raise RuntimeError("the tcp capture server did not start")
        return self

    def __exit__(self, *_: object) -> None:
        assert self._loop is not None and self._stop is not None
        self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(10)

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}/ws/chat"

    def _run(self) -> None:
        asyncio.run(self._main())

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        server = await asyncio.start_server(self._on_connect, "127.0.0.1", 0)
        self.port = server.sockets[0].getsockname()[1]
        self._ready.set()
        async with server:
            await self._stop.wait()

    async def _on_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.accepted += 1
        try:
            data = await asyncio.wait_for(reader.read(65536), 2.0)
        except TimeoutError:  # pragma: no cover - a client that sends nothing
            data = b""
        self.received.append(data)
        if self.reply is not None:
            writer.write(self.reply)
            await writer.drain()
        if self.hold_open:
            await asyncio.sleep(30)
        writer.close()
