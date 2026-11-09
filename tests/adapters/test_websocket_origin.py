"""The WebSocket handshake probe: does the endpoint upgrade for a cross-site ``Origin``? (u04 A-133)

Cross-site WebSocket hijacking (CWE-1385): a browser attaches the user's cookies to a WebSocket
upgrade from any page and applies no same-origin policy to the socket, so an endpoint that does
not check the ``Origin`` lets any site open the chat as the user. The adapter, asked for the probe
by the runner's metadata, opens two upgrades (the page's own ``Origin``, then a cross-site one under
``.invalid``), holds each briefly, sends no frame, and renders what the server did with each.

Against the loopback chat server only (``tests/ws_chat_server.py``): one that checks the ``Origin``
at the upgrade, one that checks it after and closes with 1008, and one that does not check it.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ildottore.adapters.base import EndpointNotAllowed, RetryConfig
from ildottore.adapters.websocket import (
    WebSocketAdapter,
    WebSocketClosed,
    WebSocketProbeUntestable,
    origin_of,
)
from ildottore.core.execute import default_is_env_error
from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.shared.models import Capabilities, ModelRequest, WebSocketSpec
from ildottore.shared.probes import CROSS_SITE_ORIGIN, PROBE, WEBSOCKET_ORIGIN_PROBE
from tests.ws_chat_server import TOKEN, FakeChatServer

_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=2.0)
_HOLD = 0.3
_PROBE = ModelRequest(
    prompt="(WebSocket handshake probe)", metadata={PROBE: WEBSOCKET_ORIGIN_PROBE}
)

_BLOCK: dict[str, object] = {
    "handshake": {
        "send": {"type": "auth", "token": "{{token}}"},
        "expect": {"path": "type", "equals": "auth_ok"},
    },
    "message": {"send": {"type": "query", "text": "{{prompt}}"}},
    "response": {"text_path": "delta.text", "final_path": "type", "final_value": "done"},
}


def _spec(**extra: object) -> WebSocketSpec:
    return WebSocketSpec.model_validate({**_BLOCK, **extra})


def _adapter(
    server: FakeChatServer, spec: WebSocketSpec | None = None, *, prefix: str = "/ws/chat"
) -> WebSocketAdapter:
    allowlist = EndpointAllowlist(
        [Endpoint(host=f"127.0.0.1:{server.port}", path_prefixes=[prefix])]
    )
    return WebSocketAdapter(
        id="ws-origin",
        url=server.url,
        allowlist=allowlist,
        spec=spec if spec is not None else _spec(),
        api_key=TOKEN,
        declared=Capabilities(websocket_origin=True),
        retry=_FAST,
        origin_hold_s=_HOLD,
    )


def _control(server: FakeChatServer) -> str:
    return f"http://127.0.0.1:{server.port}"


# --- the three servers --------------------------------------------------------------------


async def test_a_server_that_checks_the_origin_refuses_the_cross_site_upgrade() -> None:
    with FakeChatServer("echo", allowed_origins=frozenset()) as server:
        server.allowed_origins = frozenset({_control(server)})  # the port is known once it runs
        response = await _adapter(server).send(_PROBE)

    assert response.text.splitlines() == [
        "WebSocket Origin probe: two upgrades, no frame sent",
        f"control origin {_control(server)}: accepted (HTTP 101, held open {_HOLD:g}s)",
        f"cross-site origin {CROSS_SITE_ORIGIN}: refused (HTTP 403)",
    ]
    assert server.log.origins == [_control(server), CROSS_SITE_ORIGIN]
    # No frame on either upgrade: no handshake template, no session start, no query.
    assert server.log.frames == []
    assert server.log.queries == 0
    assert response.raw_ids["websocket"]["origin_probe"] == [
        {"origin": _control(server), "outcome": "accepted", "status": 101},
        {"origin": CROSS_SITE_ORIGIN, "outcome": "refused", "status": 403},
    ]


async def test_a_server_that_checks_after_the_upgrade_reads_as_refusing() -> None:
    with FakeChatServer("echo", origin_check="after") as server:
        server.allowed_origins = frozenset({_control(server)})
        response = await _adapter(server).send(_PROBE)

    assert response.text.splitlines()[2] == (
        f"cross-site origin {CROSS_SITE_ORIGIN}: closed by the server after the upgrade "
        "(close code 1008)"
    )
    assert server.log.frames == []


async def test_a_server_that_does_not_check_the_origin_accepts_the_cross_site_upgrade() -> None:
    with FakeChatServer("echo") as server:
        response = await _adapter(server).send(_PROBE)

    assert response.text.splitlines()[2] == (
        f"cross-site origin {CROSS_SITE_ORIGIN}: accepted (HTTP 101, held open {_HOLD:g}s)"
    )
    assert server.log.upgrade_requests == 2
    assert server.log.frames == []


# --- the control -------------------------------------------------------------------------


async def test_a_refused_control_is_untestable_not_a_verdict() -> None:
    only = frozenset({"https://chat.example.com"})
    with (
        FakeChatServer("echo", allowed_origins=only) as server,
        pytest.raises(WebSocketProbeUntestable) as refused,
    ):
        await _adapter(server).send(_PROBE)

    assert "set websocket.origin" in str(refused.value)
    assert refused.value.retryable is False
    assert default_is_env_error(refused.value)
    # The cross-site upgrade is never tried once the control says nothing can be compared.
    assert server.log.origins == [_control(server)]


async def test_the_declared_origin_is_the_control_and_replaces_a_header_origin() -> None:
    page = "https://chat.example.com"
    spec = _spec(origin=page, headers={"Origin": "https://header.example.com"})
    with FakeChatServer("echo", allowed_origins=frozenset({page})) as server:
        response = await _adapter(server, spec).send(_PROBE)

    assert server.log.origins == [page, CROSS_SITE_ORIGIN]
    assert f"control origin {page}: accepted" in response.text
    assert "refused (HTTP 403)" in response.text


# --- the charter -------------------------------------------------------------------------


async def test_an_off_allowlist_endpoint_opens_no_upgrade() -> None:
    with FakeChatServer("echo") as server, pytest.raises(EndpointNotAllowed):
        await _adapter(server, prefix="/elsewhere").send(_PROBE)
    assert server.log.upgrade_requests == 0


async def test_a_busy_server_is_an_environment_error_the_runner_retries() -> None:
    with (
        FakeChatServer("echo", upgrade_status=503) as server,
        pytest.raises(WebSocketClosed) as busy,
    ):
        await _adapter(server).send(_PROBE)
    assert busy.value.retryable is True
    assert "HTTP 503" in str(busy.value)


async def test_a_request_without_the_probe_mark_is_an_ordinary_query() -> None:
    with FakeChatServer("echo") as server:
        response = await _adapter(server).send(ModelRequest(prompt="hello"))
    assert response.text == "hello"
    assert server.log.origins == [None]


# --- the origin ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("ws://127.0.0.1:8765/ws/chat", "http://127.0.0.1:8765"),
        ("wss://chat.example.com/socket", "https://chat.example.com"),
        ("wss://chat.example.com:443/socket", "https://chat.example.com"),
        ("ws://chat.example.com:80/socket", "http://chat.example.com"),
        ("wss://chat.example.com:8443/socket", "https://chat.example.com:8443"),
        ("ws://[::1]:9000/ws", "http://[::1]:9000"),
    ],
)
def test_the_derived_origin_is_the_endpoint_host_as_a_page(url: str, origin: str) -> None:
    assert origin_of(url) == origin


@pytest.mark.parametrize(
    "origin",
    [
        "https://chat.example.com/",
        "https://chat.example.com/app",
        "https://user@chat.example.com",
        "ftp://chat.example.com",
        "chat.example.com",
        "https://chat.example.com?x=1",
    ],
)
def test_a_declared_origin_must_be_an_origin(origin: str) -> None:
    with pytest.raises(ValidationError, match="origin must be a scheme"):
        _spec(origin=origin)
