"""A target reply larger than the cap is refused unread (audit 2026-10-03, SEC-07)."""

from __future__ import annotations

import gzip
import json
import tracemalloc
import zlib
from collections.abc import AsyncIterator

import httpx
import pytest

from ildottore.adapters import MCPAdapter, RetryConfig
from ildottore.adapters.base import (
    MAX_RESPONSE_BYTES,
    AdapterEnvError,
    ResponseTooLarge,
    ResponseUndecodable,
)
from ildottore.adapters.openai import OpenAIAdapter
from ildottore.policy import Endpoint, EndpointAllowlist
from ildottore.shared.models import ModelRequest


def _adapter(body: bytes) -> OpenAIAdapter:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    return OpenAIAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])]),
        api_key="k",
        model="m",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


async def test_a_reply_over_the_cap_is_an_environment_failure_not_a_verdict() -> None:
    oversized = b'{"choices":[{"message":{"content":"' + b"A" * (MAX_RESPONSE_BYTES + 1) + b'"}}]}'
    with pytest.raises(AdapterEnvError, match="exceeded"):
        await _adapter(oversized).send(ModelRequest(prompt="hi"))


async def test_a_normal_reply_still_parses() -> None:
    body = b'{"choices":[{"message":{"content":"hello"}}]}'
    response = await _adapter(body).send(ModelRequest(prompt="hi"))
    assert response.text == "hello"


# --- compressed replies are decoded inside the cap (audit leftovers, 2026-10-04) ---------


def _streamed(body: bytes, chunk: int = 65536) -> AsyncIterator[bytes]:
    async def gen() -> AsyncIterator[bytes]:
        for i in range(0, len(body), chunk):
            yield body[i : i + chunk]

    return gen()


def _encoded_adapter(
    body: bytes, encoding: str, chunk: int = 65536
) -> tuple[OpenAIAdapter, list[int]]:
    sends: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sends.append(1)
        return httpx.Response(
            200,
            content=_streamed(body, chunk),
            headers={"content-type": "application/json", "content-encoding": encoding},
        )

    adapter = OpenAIAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])]),
        api_key="k",
        model="m",
        retry=RetryConfig(max_retries=2, backoff_base_s=0.0, backoff_cap_s=0.0),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    return adapter, sends


_HELLO = b'{"choices":[{"message":{"content":"hello"}}]}'


@pytest.mark.parametrize(
    ("encoding", "body"),
    [
        ("gzip", gzip.compress(_HELLO)),
        ("x-gzip", gzip.compress(_HELLO)),
        ("deflate", zlib.compress(_HELLO)),
        ("deflate", zlib.compress(_HELLO)[2:-4]),  # raw deflate, as some servers send it
        ("identity", _HELLO),
    ],
)
async def test_a_compressed_reply_still_parses(encoding: str, body: bytes) -> None:
    adapter, _ = _encoded_adapter(body, encoding)
    assert (await adapter.send(ModelRequest(prompt="hi"))).text == "hello"


@pytest.mark.parametrize("chunk", [65536, 1_000_000])
async def test_a_compression_bomb_is_refused_without_inflating_it(chunk: int) -> None:
    """A 200 KB gzip reply made httpx allocate about 150 MB (460 MB in one 1 MB chunk) before
    the 4 MiB cap could look at it: httpx inflated each network chunk whole."""

    bomb = gzip.compress(b"\0" * (200 * 1024 * 1024), compresslevel=9)
    adapter, sends = _encoded_adapter(bomb, "gzip", chunk)
    tracemalloc.start()
    try:
        with pytest.raises(ResponseTooLarge):
            await adapter.send(ModelRequest(prompt="hi"))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 4 * MAX_RESPONSE_BYTES, f"peak {peak / 1e6:.0f} MB"
    assert sends == [1], "not retried: it would come back the same size"


async def test_an_endless_stream_of_empty_compressed_blocks_is_capped() -> None:
    """Decoded size stays at zero; the compressed bytes are capped too."""

    compressor = zlib.compressobj(9, zlib.DEFLATED, 31)
    head = compressor.compress(b"") + compressor.flush(zlib.Z_FULL_FLUSH)
    block = compressor.flush(zlib.Z_FULL_FLUSH) or b"\x00\x00\x00\xff\xff"
    adapter, _ = _encoded_adapter(head + block * (MAX_RESPONSE_BYTES // len(block) + 10), "gzip")
    with pytest.raises(ResponseTooLarge):
        await adapter.send(ModelRequest(prompt="hi"))


@pytest.mark.parametrize(
    ("encoding", "body"),
    [
        ("br", b"\x8b\x02\x80hello\x03"),
        ("gzip, br", gzip.compress(_HELLO)),
        ("gzip", b"\x1f\x8b\x08\x00not really gzip at all"),
        ("gzip", gzip.compress(_HELLO)[:-12]),  # truncated
    ],
)
async def test_an_undecodable_reply_is_an_environment_failure_sent_once(
    encoding: str, body: bytes
) -> None:
    """httpx's DecodingError is not a TransportError, so it escaped every adapter's handler."""

    adapter, sends = _encoded_adapter(body, encoding)
    with pytest.raises(ResponseUndecodable):
        await adapter.send(ModelRequest(prompt="hi"))
    assert sends == [1]


async def test_the_mcp_adapter_reads_a_gzip_reply() -> None:
    """It rebuilt the decoded body under its `Content-Encoding: gzip` header, and httpx failed
    to decode it a second time."""

    from tests.adapters.test_mcp import _URL, _allow, _handler

    plain = _handler(poisoned=False)

    def gzipped(request: httpx.Request) -> httpx.Response:
        response = plain(request)  # type: ignore[operator]
        headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}
        headers["content-encoding"] = "gzip"
        return httpx.Response(
            response.status_code,
            headers=headers,
            content=_streamed(gzip.compress(response.content)),
        )

    adapter = MCPAdapter(
        id="mcp-test",
        base_url=_URL,
        allowlist=_allow(),
        retry=RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=5.0),
        client=httpx.AsyncClient(transport=httpx.MockTransport(gzipped)),
    )
    response = await adapter.send(ModelRequest(prompt="list"))
    assert "read_file" in response.text


async def test_the_adapters_ask_only_for_encodings_they_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Left to httpx, Accept-Encoding grows `br` and `zstd` when brotli or zstandard is
    importable, and every reply in those encodings would be refused as undecodable. httpx's
    default is set to what it becomes with both installed, or the test could not fail here."""

    monkeypatch.setattr(httpx._client, "ACCEPT_ENCODING", "gzip, deflate, br, zstd")

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("accept-encoding", ""))
        return httpx.Response(200, content=_HELLO, headers={"content-type": "application/json"})

    adapter = OpenAIAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])]),
        api_key="k",
        model="m",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    await adapter.send(ModelRequest(prompt="hi"))
    assert seen == ["gzip, deflate"]


async def test_an_error_status_is_classified_by_its_status_not_its_body() -> None:
    """A 401 whose body could not be decoded became an inconclusive "undecodable"."""

    from ildottore.adapters.base import AdapterProductError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401, content=_streamed(b"\x8b\x02\x80no"), headers={"content-encoding": "br"}
        )

    adapter = OpenAIAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])]),
        api_key="k",
        model="m",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(AdapterProductError, match="HTTP 401"):
        await adapter.send(ModelRequest(prompt="hi"))


async def test_an_error_status_over_the_cap_is_classified_by_its_status() -> None:
    """A 401 with a body over 4 MiB was `ResponseTooLarge`, an inconclusive attempt, where a short
    401 stops the run; and the `-sV` probe pass, which lets a refused reply fail only its probe,
    then let `dottore fingerprint` exit 0 on a target refusing the credential (delta audit of
    OD-23). Read no further than the cap, as before."""

    from ildottore.adapters.base import AdapterProductError

    sent: list[int] = []
    pulled: list[int] = []
    chunk = 65536

    async def huge() -> AsyncIterator[bytes]:
        for _ in range(16 * MAX_RESPONSE_BYTES // chunk):  # 64 MiB, finite: a regression fails
            pulled.append(chunk)
            yield b"x" * chunk

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(1)
        return httpx.Response(401, content=huge())

    adapter = OpenAIAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])]),
        api_key="k",
        model="m",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(AdapterProductError, match="HTTP 401"):
        await adapter.send(ModelRequest(prompt="hi"))
    assert sent == [1]
    # The cap still stops the read: the body is sixteen times the cap.
    assert sum(pulled) <= MAX_RESPONSE_BYTES + 2 * chunk


async def test_mcp_classifies_an_error_status_over_the_cap_by_its_status() -> None:
    """The MCP adapter reads through the same `read_capped`: a 403 with a body over the cap is
    the 403, not an inconclusive "too large" (pre-merge audit of PR #68)."""

    from ildottore.adapters.base import AdapterProductError
    from tests.adapters.test_mcp import _URL, _allow

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=_streamed(b"x" * (MAX_RESPONSE_BYTES + 65536)))

    adapter = MCPAdapter(
        id="mcp-test",
        base_url=_URL,
        allowlist=_allow(),
        retry=RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=5.0),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(AdapterProductError, match="HTTP 403"):
        await adapter.send(ModelRequest(prompt="list"))


async def test_mcp_asks_for_decodable_encodings_and_skips_notification_replies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reply to `notifications/initialized` was buffered whole by `client.post`, outside
    the cap and inflated by httpx."""

    monkeypatch.setattr(httpx._client, "ACCEPT_ENCODING", "gzip, deflate, br, zstd")

    from tests.adapters.test_mcp import _URL, _allow, _handler

    plain = _handler(poisoned=False)
    pulled = 0
    encodings: set[str] = set()

    async def endless() -> AsyncIterator[bytes]:
        nonlocal pulled
        for _ in range(64):
            pulled += 1
            yield b"x" * (1024 * 1024)

    def handle(request: httpx.Request) -> httpx.Response:
        encodings.add(request.headers.get("accept-encoding", ""))
        body = json.loads(request.content)
        if body.get("method") == "notifications/initialized":
            return httpx.Response(200, content=endless())
        return plain(request)  # type: ignore[operator,no-any-return]

    adapter = MCPAdapter(
        id="mcp-test",
        base_url=_URL,
        allowlist=_allow(),
        retry=RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=5.0),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )
    response = await adapter.send(ModelRequest(prompt="list"))
    assert "read_file" in response.text
    assert pulled == 0
    assert encodings == {"gzip, deflate"}
