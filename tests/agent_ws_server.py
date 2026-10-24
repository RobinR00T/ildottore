"""A loopback fake of a deployed agent over a WebSocket, for the guard's tests (no network).

Its wire shape is the one ``examples/target.agent.yaml`` declares: an ``auth`` frame answered
by ``auth_ok`` (naming the tenant) or an error frame with a ``code``; a ``query`` frame answered
by ``progress`` frames (the tool in use), ``answer`` chunks and a chunk with ``final: true``. The
script of each test picks the handshake reply and the frames a query gets; the server counts what
it saw. ``jwt`` builds an unsigned token whose payload the guard reads.
"""

from __future__ import annotations

import base64
import contextlib
import json
from collections.abc import Callable
from typing import Any

from websockets.asyncio.server import ServerConnection
from websockets.exceptions import ConnectionClosed

from tests.ws_raw_servers import HandlerServer, Log, send_json

__all__ = ["AGENT_BLOCK", "TENANT", "agent_server", "jwt"]

#: The tenant the profiles configure (a placeholder, as in the example).
TENANT = "tenant-0001"

#: The example's wire shape, with a guard the tests narrow per case (``ws://`` on loopback).
AGENT_BLOCK: dict[str, Any] = {
    "headers": {"Authorization": "Bearer {{token}}", "Origin": "https://assistant.example.test"},
    "vars": {"tenant": TENANT},
    "handshake": {
        "send": {"type": "auth", "token": "{{token}}", "tenant": "{{tenant}}"},
        "expect": {"path": "type", "equals": "auth_ok"},
    },
    "message": {"send": {"type": "query", "text": "{{prompt}}"}},
    "response": {
        "text_path": "text",
        "final_path": "final",
        "final_value": True,
        "error_path": "code",
        "timeout_seconds": 2.0,
    },
    "reconnect": {"max_attempts": 0},
    "guard": {
        "endpoint": {"scheme": "ws", "path": "/ws"},
        "auth": {
            "code_path": "code",
            "failure_codes": ["UNAUTHORIZED", "TOKEN_EXPIRED"],
            "cooldown_seconds": 120,
        },
        "token": {
            "tenant": "{{tenant}}",
            "tenant_claims": ["tenant_id", "org_id"],
            "reply_tenant_path": "tenant_id",
            "min_lifetime_seconds": 30,
        },
        "stop_on_tools": {"path": "tool", "names": ["write_record", "run_workflow"]},
    },
}


def jwt(claims: dict[str, Any]) -> str:
    """An unsigned JWT carrying ``claims`` (the guard reads, never verifies, the payload)."""

    def part(value: dict[str, Any]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{part({'alg': 'none', 'typ': 'JWT'})}.{part(claims)}.c2lnbmF0dXJlLXBsYWNlaG9sZGVy"


def _answer(text: str) -> list[dict[str, Any]]:
    return [
        {"type": "progress", "tool": "search_docs", "message": "looking"},
        {"type": "answer", "text": text[: len(text) // 2]},
        {"type": "answer", "text": text[len(text) // 2 :], "final": True},
    ]


def agent_server(
    *,
    auth_reply: dict[str, Any] | str | None = "ok",
    on_query: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
) -> HandlerServer:
    """A :class:`HandlerServer` at ``/ws`` scripted as a deployed agent.

    ``auth_reply``: ``"ok"`` answers ``auth_ok`` naming :data:`TENANT`; a mapping is sent as the
    reply; ``"close"`` closes before replying; ``"silent"`` never replies. ``on_query`` maps the
    query frame to the frames sent back (by default a progress frame and the text in two chunks).
    """

    script = on_query or (lambda message: _answer(f"echo: {message.get('text')}"))

    async def handler(connection: ServerConnection, log: Log) -> None:
        with contextlib.suppress(ConnectionClosed):
            async for raw in connection:
                message = json.loads(raw)
                log.frames.append(message)
                kind = message.get("type")
                if kind == "auth":
                    if auth_reply == "close":
                        await connection.close(1008, "policy")
                        return
                    if auth_reply == "silent":
                        continue
                    reply = (
                        {"type": "auth_ok", "tenant_id": TENANT}
                        if auth_reply == "ok"
                        else auth_reply
                    )
                    await send_json(connection, reply)
                elif kind == "query":
                    log.queries += 1
                    for frame in script(message):
                        await send_json(connection, frame)

    return HandlerServer(handler, path="/ws")
