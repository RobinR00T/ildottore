"""MCP adapter: scan a Model Context Protocol server as a target (ADR-0002).

An MCP server is a **tool provider**, not a chat model, so "scanning" it means inspecting the
surface it advertises to a host LLM: the tool / resource / prompt metadata. The genuine,
current threat is **tool-metadata poisoning** ("line jumping"): imperative instructions hidden
in a tool's ``description`` that hijack any agent that wires the server in. This adapter
surfaces that metadata so the ordinary evaluators can judge it.

Safe-by-design (contract §8, docs/02): discovery is **read-only**. The adapter performs the
JSON-RPC ``initialize`` handshake and lists ``tools`` / ``resources`` / ``prompts`` over the
MCP **Streamable HTTP** transport, and never calls a tool (``tools/call``), invoking a
target's tools could cause a real side effect, so it is out of scope here.

The allowlist gate is enforced **before every** request (S3 default-deny, unbypassable): a
URL not authorized by the scope issues zero HTTP calls. Auth is header-only (``Bearer``),
mirroring the REST adapter (contract §9). Server ids are redacted before they persist.

``send`` ignores the attack prompt: MCP is not chat, so it returns the server's catalogue as
a deterministic :class:`ModelResponse` (the tool descriptions in ``text``, the server info in
``raw_ids``). That rendering matches the shape an ``MCP-*`` spec's golden fixtures replay, so
an over-the-wire scan and its offline golden are evaluated by the identical evaluator.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, ClassVar

import httpx

from ildottore.adapters.base import (
    ACCEPT_ENCODING,
    MAX_RESPONSE_BYTES,
    AdapterEnvError,
    AdapterProductError,
    EndpointNotAllowed,
    ResponseTooDeep,
    ResponseTooLarge,
    RetryConfig,
    read_capped,
)
from ildottore.policy import EndpointAllowlist
from ildottore.redactor import Redactor
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse
from ildottore.shared.nesting import NestedTooDeeply, bounded_loads
from ildottore.shared.wellformed import well_formed_json

__all__ = ["MCPAdapter"]

# JSON-RPC "method not found", the server simply lacks that capability (e.g. no prompts);
# treat as an empty list, not a product defect.
_METHOD_NOT_FOUND = -32601

# Statuses that mean "try again later" (transient / env), mirrors BaseAdapter.
_RETRYABLE_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})

# A recent MCP protocol revision to offer in the initialize handshake. The server echoes the
# version it actually speaks; we record that, we do not require this exact one.
_PROTOCOL_VERSION = "2025-06-18"


#: What a stdio MCP server under test inherits from the scanner, and nothing else. It used to
#: inherit the whole environment, every other target's API key included, which handed the
#: system being scanned the scanner's credentials (audit 2026-10-03, SEC-08). A server that
#: needs a variable gets it on its authorized command line (``env NAME=value server ...``),
#: where the operator can see it and the scope has to name it.
_STDIO_ENV_PASSTHROUGH: tuple[str, ...] = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
)


def _stdio_environment() -> dict[str, str]:
    return {name: os.environ[name] for name in _STDIO_ENV_PASSTHROUGH if name in os.environ}


@dataclass
class MCPAdapter:
    """A read-only MCP-server discovery target (implements ``TargetAdapter``)."""

    #: It never calls a tool, so a reply carries no tool calls: a seeded spec judged on its
    #: tool trace is not sent through it (OD-18 B).
    returns_tool_calls: ClassVar[bool] = False

    id: str
    base_url: str  # the FULL MCP endpoint URL (origin + path, e.g. http://host:3000/mcp)
    allowlist: EndpointAllowlist
    api_key: str | None = None
    model: str | None = None  # unused (MCP has no model id); kept for factory symmetry
    redactor: Redactor = field(default_factory=Redactor)
    retry: RetryConfig = field(default_factory=RetryConfig)
    client: httpx.AsyncClient | None = None
    protocol_version: str = _PROTOCOL_VERSION

    # stdio transport (a local MCP server launched as a subprocess). Off unless transport is
    # "stdio". Spawning is gated: the exact command line must appear in authorized_commands
    # (the scope target's declared `commands`), so nothing is ever launched without explicit
    # authorization (S3 extended to the local transport). Discovery is still read-only.
    transport: str = "http"  # "http" | "stdio"
    command: tuple[str, ...] = ()
    authorized_commands: tuple[str, ...] = ()

    _rpc_id: int = field(default=0, init=False)
    _cached: ModelResponse | None = field(default=None, init=False)

    def capabilities(self) -> Capabilities:
        """An MCP server is a tool provider (so ``tools``-gated specs apply)."""

        return Capabilities(tools=True)

    async def send(self, request: ModelRequest) -> ModelResponse:
        """Return the server's advertised catalogue (read-only discovery).

        The attack ``request`` is not sent to the server: MCP exposes no chat surface. The
        catalogue is cached per adapter instance so repeated specs/turns do not re-handshake
        and every attempt sees the identical (reproducible) surface.
        """

        if self._cached is not None:
            return self._cached

        if self.transport == "stdio":
            self._cached = await self._discover_stdio()
            return self._cached

        self._check_allowlist()  # BEFORE any egress, unbypassable (S3).
        owns_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=self.retry.timeout_s)
        try:
            server_info, session_id = await self._initialize(client)
            await self._notify_initialized(client, session_id)
            tools = await self._list(client, "tools/list", "tools", session_id)
            resources = await self._list(client, "resources/list", "resources", session_id)
            prompts = await self._list(client, "prompts/list", "prompts", session_id)
        finally:
            if owns_client:
                await client.aclose()

        self._cached = self._render(server_info, tools, resources, prompts)
        return self._cached

    # --- allowlist gate --------------------------------------------------------

    def _check_allowlist(self) -> None:
        """Refuse an off-allowlist endpoint before any egress (contract §4 KEEP)."""

        if not self.allowlist.is_allowed(self.base_url):
            raise EndpointNotAllowed(self.base_url)

    # --- JSON-RPC over Streamable HTTP -----------------------------------------

    async def _initialize(self, client: httpx.AsyncClient) -> tuple[dict[str, Any], str | None]:
        """Perform the ``initialize`` handshake; return (serverInfo, session id)."""

        result, response = await self._rpc(
            client,
            "initialize",
            {
                "protocolVersion": self.protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "ildottore", "version": "0.0.1"},
            },
            session_id=None,
        )
        if not isinstance(result, dict):
            raise AdapterProductError(f"{self.id}: initialize returned no result object")
        raw_info = result.get("serverInfo")
        server_info: dict[str, Any] = dict(raw_info) if isinstance(raw_info, dict) else {}
        protocol = result.get("protocolVersion")
        if isinstance(protocol, str):
            server_info["protocolVersion"] = protocol
        session_id = response.headers.get("mcp-session-id")
        return server_info, session_id

    async def _notify_initialized(self, client: httpx.AsyncClient, session_id: str | None) -> None:
        """Send the ``notifications/initialized`` notification (no response expected)."""

        self._check_allowlist()
        headers = self._headers(session_id)
        body = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        try:
            # Streamed and never read: the reply to a notification is ignored, and `client.post`
            # buffered it whole, uncapped and decompressed by httpx (a 4 MiB cap everywhere
            # else, and none on this one call).
            async with client.stream(
                "POST",
                self.base_url,
                json=body,
                headers=headers,
                timeout=self.retry.timeout_s,
                follow_redirects=False,
            ):
                pass
        except (httpx.TimeoutException, httpx.TransportError):
            # A lost notification is non-fatal: the list calls below will surface a real fault.
            return

    async def _list(
        self, client: httpx.AsyncClient, method: str, key: str, session_id: str | None
    ) -> list[dict[str, Any]]:
        """Call a ``*/list`` method; return its items, or ``[]`` if unsupported."""

        result, _ = await self._rpc(client, method, {}, session_id=session_id, allow_missing=True)
        if result is None:
            return []
        items = result.get(key) if isinstance(result, dict) else None
        if not isinstance(items, list):
            return []
        return [i for i in items if isinstance(i, dict)]

    async def _rpc(
        self,
        client: httpx.AsyncClient,
        method: str,
        params: dict[str, Any],
        *,
        session_id: str | None,
        allow_missing: bool = False,
    ) -> tuple[dict[str, Any] | None, httpx.Response]:
        """Issue one JSON-RPC request, retrying transient failures; return (result, response).

        ``allow_missing`` maps a JSON-RPC ``method not found`` to ``(None, response)`` so an
        absent capability (e.g. no ``prompts``) is empty, not an error.
        """

        self._check_allowlist()  # defense-in-depth: gate every request.
        self._rpc_id += 1
        body = {"jsonrpc": "2.0", "id": self._rpc_id, "method": method, "params": params}
        headers = self._headers(session_id)
        response = await self._post_with_retries(client, body, headers)

        if not response.is_success:
            raise AdapterProductError(
                f"{self.id}: MCP {method} returned non-retryable HTTP {response.status_code}"
            )
        payload = self._decode(response, method)
        if isinstance(payload, dict) and "error" in payload:
            error = payload["error"] if isinstance(payload["error"], dict) else {}
            if allow_missing and error.get("code") == _METHOD_NOT_FOUND:
                return None, response
            raise AdapterProductError(f"{self.id}: MCP {method} error: {error}")
        result = payload.get("result") if isinstance(payload, dict) else None
        return (result if isinstance(result, dict) else None), response

    async def _post_with_retries(
        self, client: httpx.AsyncClient, body: dict[str, Any], headers: dict[str, str]
    ) -> httpx.Response:
        """POST ``body`` with capped-backoff retries on transient failures (env → skip)."""

        last = ""
        attempts = self.retry.max_retries + 1
        for attempt in range(attempts):
            try:
                async with client.stream(
                    "POST",
                    self.base_url,
                    json=body,
                    headers=headers,
                    timeout=self.retry.timeout_s,
                    follow_redirects=False,
                ) as streamed:
                    if streamed.status_code in _RETRYABLE_STATUS:
                        last = f"HTTP {streamed.status_code}"
                        raw: bytes | None = None
                    else:
                        # Same ceiling as the model adapters (SEC-07), checked while reading:
                        # an advertised tool list larger than this is not metadata to evaluate.
                        raw = await read_capped(streamed, f"{self.id}: MCP response")
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last = f"{type(exc).__name__}: {exc}"
                await self._maybe_backoff(attempt, attempts)
                continue
            if raw is None:
                await self._maybe_backoff(attempt, attempts)
                continue
            # `raw` is already decoded: rebuilt under its `Content-Encoding: gzip` header, httpx
            # decoded it a second time and failed with a DecodingError nothing caught.
            kept = [
                (name, value)
                for name, value in streamed.headers.multi_items()
                if name.lower() not in ("content-encoding", "content-length")
            ]
            return httpx.Response(
                streamed.status_code,
                headers=kept,
                content=raw,
                request=streamed.request,
            )
        raise AdapterEnvError(f"{self.id}: exhausted {attempts} attempt(s) to MCP endpoint: {last}")

    async def _maybe_backoff(self, attempt: int, attempts: int) -> None:
        if attempt < attempts - 1:
            await asyncio.sleep(self.retry.backoff_for(attempt))

    def _headers(self, session_id: str | None) -> dict[str, str]:
        headers = {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "accept-encoding": ACCEPT_ENCODING,
        }
        if session_id:
            headers["mcp-session-id"] = session_id
        if self.api_key is not None:
            headers["authorization"] = f"Bearer {self.api_key}"
        return headers

    def _decode(self, response: httpx.Response, method: str) -> Any:
        """Decode a JSON-RPC reply that is either JSON or a Streamable-HTTP SSE event.

        A lone surrogate in it is read as U+FFFD, as where every adapter parses a reply (A-47).
        An SSE stream is decoded as text first, so a raw byte of one is U+FFFD already there.
        """

        ctype = response.headers.get("content-type", "")
        if "text/event-stream" in ctype:
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    return self._parse(line[len("data:") :].strip(), f"MCP {method} SSE data")
            raise AdapterProductError(f"{self.id}: MCP {method} SSE carried no data event")
        return self._parse(response.content, f"MCP {method} response")

    def _parse(self, text: str | bytes, what: str) -> Any:
        """Parse a reply: not JSON is a product defect, nested too deeply is not evaluated.

        ``json.loads`` raised ``RecursionError`` on a reply nested past its stack, which the
        ``except ValueError`` here let through, and the runner aborted the campaign (2026-10-07).
        A lone surrogate in what parses reads as U+FFFD (A-47).
        """

        try:
            return well_formed_json(bounded_loads(text))
        except NestedTooDeeply as exc:
            raise ResponseTooDeep(f"{self.id}: {what} is {exc}; not evaluated") from exc
        except ValueError as exc:
            raise AdapterProductError(f"{self.id}: {what} was not valid JSON: {exc}") from exc

    # --- stdio transport (local subprocess, newline-delimited JSON-RPC) --------

    async def _discover_stdio(self) -> ModelResponse:
        """Discover a local MCP server launched over stdio. Gated + read-only.

        The exact command line must be authorized by the scope (``authorized_commands``); an
        unauthorized command spawns **zero** processes. stdin/stdout carry newline-delimited
        JSON-RPC (stdout is JSON only; server logs go to stderr).
        """

        cmd = tuple(self.command)
        if not cmd:
            raise AdapterProductError(f"{self.id}: stdio transport requires a command")
        joined = " ".join(cmd)
        if joined not in self.authorized_commands:
            # Not authorized by the scope: refuse before spawning anything (S3 default-deny).
            raise EndpointNotAllowed(f"stdio://{joined}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=_stdio_environment(),
            # A reply line may be as long as a reply over HTTP. The default was 64 KiB, and a
            # server listing 300 ordinary tools (148 KB on one line) stopped the campaign on the
            # ValueError `readline` raises past it (pre-commit audit, 2026-10-07).
            limit=MAX_RESPONSE_BYTES,
        )
        try:
            init = await self._stdio_rpc(
                proc,
                "initialize",
                {
                    "protocolVersion": self.protocol_version,
                    "capabilities": {},
                    "clientInfo": {"name": "ildottore", "version": "0.0.1"},
                },
            )
            if not isinstance(init, dict):
                raise AdapterProductError(f"{self.id}: stdio initialize returned no result")
            raw_info = init.get("serverInfo")
            server_info: dict[str, Any] = dict(raw_info) if isinstance(raw_info, dict) else {}
            protocol = init.get("protocolVersion")
            if isinstance(protocol, str):
                server_info["protocolVersion"] = protocol
            await self._stdio_notify(proc, "notifications/initialized")
            tools = await self._stdio_list(proc, "tools/list", "tools")
            resources = await self._stdio_list(proc, "resources/list", "resources")
            prompts = await self._stdio_list(proc, "prompts/list", "prompts")
        finally:
            await self._stdio_close(proc)

        return self._render(server_info, tools, resources, prompts)

    async def _stdio_list(
        self, proc: asyncio.subprocess.Process, method: str, key: str
    ) -> list[dict[str, Any]]:
        result = await self._stdio_rpc(proc, method, {}, allow_missing=True)
        items = result.get(key) if isinstance(result, dict) else None
        if not isinstance(items, list):
            return []
        return [i for i in items if isinstance(i, dict)]

    async def _stdio_notify(self, proc: asyncio.subprocess.Process, method: str) -> None:
        if proc.stdin is None:
            return
        line = json.dumps({"jsonrpc": "2.0", "method": method, "params": {}}) + "\n"
        proc.stdin.write(line.encode())
        await proc.stdin.drain()

    async def _stdio_rpc(
        self,
        proc: asyncio.subprocess.Process,
        method: str,
        params: dict[str, Any],
        *,
        allow_missing: bool = False,
    ) -> dict[str, Any] | None:
        """Send one JSON-RPC request over stdin, read the matching reply from stdout."""

        if proc.stdin is None or proc.stdout is None:
            raise AdapterEnvError(f"{self.id}: stdio pipes unavailable for {method}")
        self._rpc_id += 1
        req_id = self._rpc_id
        payload = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        proc.stdin.write((payload + "\n").encode())
        await proc.stdin.drain()

        # Read lines until the reply with our id arrives (skip notifications / other traffic).
        # What one request reads is capped as a whole, not only per line: 63 lines of 4 MiB
        # before the reply took 80 s and 419 MB per attempt and still passed (delta audit).
        read = 0
        for _ in range(64):
            try:
                raw = await asyncio.wait_for(proc.stdout.readline(), timeout=self.retry.timeout_s)
            except TimeoutError as exc:
                raise AdapterEnvError(f"{self.id}: stdio {method} timed out") from exc
            except ValueError as exc:  # `readline` past the limit above
                raise ResponseTooLarge(
                    f"{self.id}: stdio output for {method} has a line that exceeded "
                    f"{MAX_RESPONSE_BYTES} bytes; not read further"
                ) from exc
            if not raw:
                raise AdapterEnvError(f"{self.id}: stdio stream closed during {method}")
            # Only the newline that ends the line is not counted: stripping every trailing
            # `\r` too let lines of carriage returns through as empty (pre-merge audit).
            read += len(raw) - (1 if raw.endswith(b"\n") else 0)
            if read > MAX_RESPONSE_BYTES:
                raise ResponseTooLarge(
                    f"{self.id}: stdio output for {method} exceeded {MAX_RESPONSE_BYTES} "
                    "bytes; not read further"
                )
            try:
                # `surrogatepass`, the error handler `json.loads` decodes an HTTP reply's bytes
                # with: strict decoding skipped a line holding the raw bytes of half a character
                # as stray output, and the call timed out (pre-commit audit, A-47).
                msg = well_formed_json(bounded_loads(raw.decode("utf-8", "surrogatepass").strip()))
            except NestedTooDeeply as exc:
                # Refused at once, before the `except ValueError` below would skip it as a stray
                # line and leave the adapter waiting for a reply until the timeout.
                raise ResponseTooDeep(
                    f"{self.id}: stdio output for {method} is {exc}; not evaluated"
                ) from exc
            except ValueError:
                continue  # non-JSON line on stdout: skip (should not happen per spec)
            if not isinstance(msg, dict) or msg.get("id") != req_id:
                continue
            if "error" in msg:
                error = msg["error"] if isinstance(msg["error"], dict) else {}
                if allow_missing and error.get("code") == _METHOD_NOT_FOUND:
                    return None
                raise AdapterProductError(f"{self.id}: MCP {method} error: {error}")
            result = msg.get("result")
            return result if isinstance(result, dict) else None
        raise AdapterEnvError(f"{self.id}: no stdio reply to {method} after 64 messages")

    async def _stdio_close(self, proc: asyncio.subprocess.Process) -> None:
        """Terminate the subprocess, escalating to kill if it does not exit promptly."""

        if proc.returncode is not None:
            return
        try:
            proc.terminate()
        except ProcessLookupError:  # pragma: no cover - already gone
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except TimeoutError:  # pragma: no cover - stubborn child
            proc.kill()

    # --- rendering -------------------------------------------------------------

    def _render(
        self,
        server_info: dict[str, Any],
        tools: list[dict[str, Any]],
        resources: list[dict[str, Any]],
        prompts: list[dict[str, Any]],
    ) -> ModelResponse:
        """Render the advertised catalogue into a deterministic :class:`ModelResponse`.

        Tool / resource / prompt descriptions land in ``text`` (the instruction surface a
        metadata-poisoning evaluator inspects); the server identity lands in ``raw_ids``
        (redacted). No tool is ever called, so ``tool_calls`` stays empty.
        """

        lines: list[str] = []
        name = str(server_info.get("name", "unknown"))
        version = str(server_info.get("version", "?"))
        proto = str(server_info.get("protocolVersion", "?"))
        lines.append(f"MCP server: {name} v{version} (protocol {proto})")

        lines.append(f"Tools ({len(tools)}):")
        for tool in tools:
            lines.append(f"- {tool.get('name', '?')}: {tool.get('description', '')}".rstrip())
        lines.append(f"Resources ({len(resources)}):")
        for res in resources:
            label = res.get("name") or res.get("uri") or "?"
            lines.append(f"- {label}: {res.get('description', '')}".rstrip())
        lines.append(f"Prompts ({len(prompts)}):")
        for prompt in prompts:
            lines.append(f"- {prompt.get('name', '?')}: {prompt.get('description', '')}".rstrip())

        raw_ids: dict[str, Any] = {"mcp_server": name, "mcp_version": version, "protocol": proto}
        return ModelResponse(
            text="\n".join(lines),
            tool_calls=[],
            logprobs=None,
            finish_reason="mcp_discovery",
            raw_ids=self.redactor.redact(raw_ids),
            # Discovery bills no model tokens. Saying so lets the token ledger release the send's
            # reservation; without a token field it kept about 514 tokens per MCP attempt.
            usage={
                "tools": len(tools),
                "resources": len(resources),
                "prompts": len(prompts),
                "total_tokens": 0,
            },
        )
