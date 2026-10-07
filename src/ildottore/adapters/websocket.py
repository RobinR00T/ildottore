"""Generic WebSocket chat adapter (ADR-0002): a template-driven client for a chat endpoint
that speaks JSON frames over a socket.

Many deployed assistants expose their chat only over a WebSocket with streaming, and no two
agree on a wire shape. The target file declares it (``websocket:``, a
:class:`~ildottore.shared.models.WebSocketSpec`): the first frame after the socket opens (the
handshake, usually the credential), the frame that carries a query, how the streamed reply is
read back (the path to each text fragment, the frame that ends the turn, the frame types to
discard, the error path), a session-start frame and a reconnect cap. The adapter adds no
provider knowledge of its own.

Safety is the same charter as the HTTP adapters (``docs/02`` S3, S6): the scope's allowlist is
checked **before** the socket is dialled (an off-allowlist URL opens zero connections), an HTTP
redirect at the upgrade is never followed (the scope authorized one URL), the credential is
inserted in memory at send time and recorded in evidence as its placeholder (``{{token}}``),
every frame sent and received is kept in ``raw_ids["websocket"]["frames"]`` so the evidence
store files it redacted, and a turn is bounded in time, bytes and frames.

One connection per conversation: a single-turn attempt opens, queries and closes; a multi-turn
attempt keeps its connection across turns (the runner's ``conversation`` metadata names it) and
closes it after the last turn. Concurrent specs therefore never interleave on one socket, and
one query is in flight per connection (``session.one_query_in_flight``, the only policy built).
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar, Final

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidStatus, InvalidURI

from ildottore.adapters.base import (
    MAX_RESPONSE_BYTES,
    AdapterEnvError,
    AdapterProductError,
    EndpointNotAllowed,
    ResponseTooLarge,
    RetryConfig,
    redact_ids,
)
from ildottore.adapters.rest import get_path
from ildottore.policy import EndpointAllowlist
from ildottore.redactor import Redactor
from ildottore.shared.models import (
    Capabilities,
    JsonDict,
    ModelRequest,
    ModelResponse,
    WebSocketExpect,
    WebSocketSpec,
)

__all__ = [
    "MAX_FRAMES_PER_TURN",
    "MAX_OPEN_CONVERSATIONS",
    "MESSAGES",
    "PLACEHOLDER",
    "PROMPT",
    "RESERVED",
    "SYSTEM_PROMPT",
    "TOKEN",
    "WebSocketAdapter",
    "WebSocketClosed",
    "WebSocketServerError",
    "WebSocketTurnOverflow",
    "WebSocketTurnTimeout",
    "placeholders",
    "render",
]

#: A ``{{name}}`` marker in a template string.
PLACEHOLDER: Final = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
#: The credential ``auth_ref`` resolves to. Inserted in memory at send time, never recorded.
TOKEN: Final = "token"  # noqa: S105 - a placeholder NAME, not a credential
#: The attack text of this turn (the request's ``prompt``, else its last user message).
PROMPT: Final = "prompt"
#: The request's system prompt, or an empty string.
SYSTEM_PROMPT: Final = "system_prompt"
#: The whole message history as a JSON list, for a stateless server.
MESSAGES: Final = "messages"
#: The placeholders every template may use; anything else must be declared under ``vars``.
RESERVED: Final = frozenset({TOKEN, PROMPT, SYSTEM_PROMPT, MESSAGES})
#: Frames read in one turn before the turn is abandoned: a server that streams forever is
#: bounded by this as well as by the timeout, and so is the transcript the evidence keeps.
MAX_FRAMES_PER_TURN: Final = 4096
#: Conversations whose connection is held at once. The runner's concurrency bounds it in
#: practice; this is the ceiling in case something keeps a conversation open.
MAX_OPEN_CONVERSATIONS: Final = 16
#: Shortest credential scrubbed by value from recorded frames (the redactor registers 8+).
_MIN_SCRUB_LEN: Final = 4
#: Upgrade statuses that mean "try again later", as for the HTTP adapters.
_RETRYABLE_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})
#: How long a close handshake may take before the socket is abandoned.
_CLOSE_TIMEOUT_S: Final = 2.0
#: Close code websockets sends when a frame is larger than ``max_size``.
_MESSAGE_TOO_BIG: Final = 1009


class WebSocketClosed(AdapterEnvError):
    """The connection could not be opened, or closed before the turn ended (env, retried)."""

    is_env_error = True


class WebSocketTurnTimeout(AdapterEnvError):
    """No final frame within ``response.timeout_seconds`` (env, inconclusive, retried)."""

    is_env_error = True


class WebSocketServerError(AdapterEnvError):
    """The server answered the turn with an error frame (env, inconclusive, retried)."""

    is_env_error = True


class WebSocketTurnOverflow(ResponseTooLarge):
    """A turn over the byte cap or the frame cap: inconclusive and not retried."""


def placeholders(value: object) -> set[str]:
    """Every ``{{name}}`` in the string leaves (and keys) of ``value``, recursively."""

    found: set[str] = set()
    if isinstance(value, str):
        found.update(PLACEHOLDER.findall(value))
    elif isinstance(value, Mapping):
        for key, item in value.items():
            found.update(placeholders(key))
            found.update(placeholders(item))
    elif isinstance(value, list):
        for item in value:
            found.update(placeholders(item))
    return found


def render(value: Any, values: Mapping[str, object]) -> Any:
    """``value`` with every ``{{name}}`` replaced from ``values``, recursively.

    A string that is exactly one placeholder becomes the value itself, whatever its type (so
    ``"{{messages}}"`` becomes the list); a placeholder inside a longer string is spliced in as
    text (a non-string value as JSON). An unknown name is refused: the loader checks every
    template against the declared names before anything is sent, so reaching this is a defect.
    """

    if isinstance(value, str):
        whole = PLACEHOLDER.fullmatch(value)
        if whole is not None:
            return _lookup(values, whole.group(1))
        return PLACEHOLDER.sub(lambda m: _as_text(_lookup(values, m.group(1))), value)
    if isinstance(value, Mapping):
        return {str(render(key, values)): render(item, values) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, values) for item in value]
    return value


def _lookup(values: Mapping[str, object], name: str) -> object:
    if name not in values:
        raise AdapterProductError(f"template placeholder {{{{{name}}}}} has no value")
    return values[name]


def _as_text(value: object) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


def _scrub(value: Any, secret: str | None) -> Any:
    """``value`` with every occurrence of ``secret`` in its strings and keys replaced.

    A server that echoes the credential (in an acknowledgement, in an error) would otherwise
    put it into the recorded transcript; the redactor masks a registered credential of 8+
    characters by value anyway, this closes the shorter ones too.
    """

    if not secret or len(secret) < _MIN_SCRUB_LEN:
        return value
    marker = "{{" + TOKEN + "}}"
    if isinstance(value, str):
        return value.replace(secret, marker)
    if isinstance(value, Mapping):
        return {str(_scrub(key, secret)): _scrub(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub(item, secret) for item in value]
    return value


def _satisfies(frame: Mapping[str, Any], expect: WebSocketExpect) -> bool:
    value = get_path(frame, expect.path)
    if expect.equals is None:
        return value is not None
    return bool(value == expect.equals)


class _NoRedirects(connect):
    """``websockets.connect`` with HTTP redirects at the upgrade never followed.

    The library follows 3xx redirects, to another origin included, up to ten hops. The scope
    authorized one URL and the gate ran against it, so a redirect is a refusal here: the
    original status comes back as the upgrade error and the connection is not re-dialled.
    """

    def process_redirect(self, exc: Exception) -> Exception | str:
        return exc


@dataclass
class _Conversation:
    """One open connection, the transcript it has produced and its one-query lock."""

    connection: ClientConnection
    frames: list[JsonDict]
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class WebSocketAdapter:
    """A JSON-over-WebSocket chat target (implements ``TargetAdapter``)."""

    #: No ``{{tools}}`` placeholder exists: a deployed chat has its own tools (OD-18 B).
    carries_tool_definitions: ClassVar[bool] = False

    id: str
    #: The full ``ws(s)://host/path`` URL: what the gate authorizes and what is dialled.
    url: str
    allowlist: EndpointAllowlist
    spec: WebSocketSpec
    api_key: str | None = None
    model: str | None = None  # unused (the file's `model` is not on the wire); factory symmetry
    #: What the target file declares (contract §4 KEEP: static, never probed here).
    declared: Capabilities = field(default_factory=Capabilities)
    redactor: Redactor = field(default_factory=Redactor)
    #: ``timeout_s`` bounds the opening handshake; ``backoff_for`` spaces reconnects.
    retry: RetryConfig = field(default_factory=RetryConfig)
    #: Largest single frame accepted (the library closes the connection past it).
    max_frame_bytes: int = MAX_RESPONSE_BYTES

    _conversations: dict[str, _Conversation] = field(default_factory=dict, init=False)

    # --- traits the runner and the plan read -------------------------------------------

    @property
    def returns_tool_calls(self) -> bool:
        """True only when ``response.tool_calls_path`` is declared (OD-18 B)."""

        return self.spec.response.tool_calls_path is not None

    @property
    def carries_system_prompt(self) -> bool:
        """True when a template carries ``{{system_prompt}}``, where a memory seed goes."""

        return SYSTEM_PROMPT in self._placeholders()

    def capabilities(self) -> Capabilities:
        return self.declared

    def _placeholders(self) -> set[str]:
        spec = self.spec
        handshake = spec.handshake.send if spec.handshake is not None else {}
        return placeholders([handshake, spec.message.send, spec.session.start, spec.headers])

    # --- the gate ------------------------------------------------------------------------

    def _check_allowlist(self) -> None:
        """Refuse an off-allowlist URL before the socket is dialled (contract §4 KEEP)."""

        if not self.allowlist.is_allowed(self.url):
            raise EndpointNotAllowed(self.url)

    # --- send ----------------------------------------------------------------------------

    async def send(self, request: ModelRequest) -> ModelResponse:
        """Send one turn and read the streamed reply back as a :class:`ModelResponse`.

        A request with no ``conversation`` in its metadata is a single-turn attempt: it opens
        its own connection and closes it. A multi-turn request keeps one connection for the
        conversation (opened on turn 0, closed after the last turn); a later turn whose
        connection is gone is an environment error, not a silent restart of the session.
        """

        self._check_allowlist()  # BEFORE any socket is opened: unbypassable.
        key, turn_index, last_turn = _conversation_of(request)
        if key is None:
            conversation = await self._open()
            try:
                return await self._turn(conversation, request)
            finally:
                await _close(conversation.connection)

        held = self._conversations.get(key)
        if held is None:
            if turn_index > 0:
                raise WebSocketClosed(
                    f"{self.id}: turn {turn_index} of conversation {key!r} has no open "
                    "connection, so the earlier turns' context is gone; nothing was sent"
                )
            held = await self._open()
            await self._adopt(key, held)
        conversation = held
        try:
            async with conversation.lock:
                response = await self._turn(conversation, request)
        except BaseException:
            await self._drop(key)
            raise
        if last_turn:
            await self._drop(key)
        return response

    async def aclose(self) -> None:
        """Close every connection still held for a conversation."""

        for key in list(self._conversations):
            await self._drop(key)

    async def _adopt(self, key: str, conversation: _Conversation) -> None:
        while len(self._conversations) >= MAX_OPEN_CONVERSATIONS:
            oldest = next(iter(self._conversations))
            await self._drop(oldest)
        self._conversations[key] = conversation

    async def _drop(self, key: str) -> None:
        conversation = self._conversations.pop(key, None)
        if conversation is not None:
            await _close(conversation.connection)

    # --- opening a connection ------------------------------------------------------------

    async def _open(self) -> _Conversation:
        """Dial, handshake and start the session, retrying a failed open up to the cap.

        A failure before the query is sent (DNS, refused, a 503 at the upgrade, a close during
        the handshake, no handshake reply in time) is retried ``reconnect.max_attempts`` more
        times with the base backoff. A refused upgrade (any other 4xx, a redirect), a handshake
        reply that does not satisfy ``expect`` and a malformed frame are product defects and
        are not retried. Once a query is on the wire nothing here resends it: a close mid-turn
        is an environment error the runner retries, debited like every send.
        """

        attempts = self.spec.reconnect.max_attempts + 1
        last = ""
        for attempt in range(attempts):
            self._check_allowlist()  # defense in depth: the gate decides every dial.
            frames: list[JsonDict] = []
            connection: ClientConnection | None = None
            try:
                connection = await self._connect()
                await self._handshake(connection, frames)
                await self._start_session(connection, frames)
                return _Conversation(connection, frames)
            except AdapterEnvError as exc:
                last = f"{type(exc).__name__}: {exc}"
                if connection is not None:
                    await _close(connection)
                if attempt < attempts - 1:
                    await asyncio.sleep(self.retry.backoff_for(attempt))
            except BaseException:
                if connection is not None:
                    await _close(connection)
                raise
        raise WebSocketClosed(
            f"{self.id}: exhausted {attempts} attempt(s) to open {self.url}: {last}"
        )

    async def _connect(self) -> ClientConnection:
        headers = render(self.spec.headers, self._values(None))
        try:
            return await _NoRedirects(
                self.url,
                additional_headers=headers or None,
                open_timeout=self.retry.timeout_s,
                close_timeout=_CLOSE_TIMEOUT_S,
                max_size=self.max_frame_bytes,
                compression=None,  # a decompression bomb has no cap the byte cap can see
                user_agent_header="ildottore",
            )
        except InvalidStatus as exc:
            status = exc.response.status_code
            if status in _RETRYABLE_STATUS:
                raise WebSocketClosed(
                    f"{self.id}: the server answered the upgrade with HTTP {status}"
                ) from exc
            redirect = (
                " (a redirect is not followed: the scope authorized this URL)"
                if (300 <= status < 400)
                else ""
            )
            raise AdapterProductError(
                f"{self.id}: the server refused the WebSocket upgrade with HTTP {status}{redirect}"
            ) from exc
        except InvalidURI as exc:  # pragma: no cover - the gate already parsed a host and path
            raise AdapterProductError(f"{self.id}: not a WebSocket URL: {exc}") from exc
        except InvalidHandshake as exc:
            raise AdapterProductError(
                f"{self.id}: the endpoint did not complete a WebSocket upgrade: {exc}"
            ) from exc
        except (OSError, TimeoutError) as exc:
            raise WebSocketClosed(
                f"{self.id}: could not connect: {type(exc).__name__}: {exc}"
            ) from exc

    async def _handshake(self, connection: ClientConnection, frames: list[JsonDict]) -> None:
        handshake = self.spec.handshake
        if handshake is None:
            return
        await self._send_template(connection, handshake.send, None, frames)
        if handshake.expect is not None:
            await self._expect(connection, handshake.expect, frames, "handshake")

    async def _start_session(self, connection: ClientConnection, frames: list[JsonDict]) -> None:
        session = self.spec.session
        if session.start is None:
            return
        await self._send_template(connection, session.start, None, frames)
        if session.expect is not None:
            await self._expect(connection, session.expect, frames, "session")

    async def _expect(
        self,
        connection: ClientConnection,
        expect: WebSocketExpect,
        frames: list[JsonDict],
        what: str,
    ) -> None:
        """Read the first frame that is not ignored and check ``expect`` against it."""

        try:
            async with asyncio.timeout(self.spec.response.timeout_seconds):
                for _ in range(MAX_FRAMES_PER_TURN):
                    frame, _size = await self._recv_frame(connection, frames)
                    if self._ignored(frame):
                        continue
                    if not _satisfies(frame, expect):
                        raise AdapterProductError(
                            f"{self.id}: the {what} reply did not satisfy expect "
                            f"({expect.path!r} == {expect.equals!r})"
                        )
                    return
        except TimeoutError as exc:
            raise WebSocketTurnTimeout(
                f"{self.id}: no {what} reply within {self.spec.response.timeout_seconds}s"
            ) from exc
        raise WebSocketTurnOverflow(
            f"{self.id}: more than {MAX_FRAMES_PER_TURN} frames before the {what} reply"
        )

    # --- one turn ------------------------------------------------------------------------

    async def _turn(self, conversation: _Conversation, request: ModelRequest) -> ModelResponse:
        connection, frames = conversation.connection, conversation.frames
        reading = self.spec.response
        await self._send_template(connection, self.spec.message.send, request, frames)

        parts: list[str] = []
        calls: list[JsonDict] = []
        usage: JsonDict | None = None
        ids: dict[str, Any] = {}
        final: JsonDict | None = None
        total = 0
        try:
            async with asyncio.timeout(reading.timeout_seconds):
                for _ in range(MAX_FRAMES_PER_TURN):
                    frame, size = await self._recv_frame(connection, frames)
                    total += size
                    if total > MAX_RESPONSE_BYTES:
                        raise WebSocketTurnOverflow(
                            f"{self.id}: the turn exceeded {MAX_RESPONSE_BYTES} bytes; "
                            "not read further"
                        )
                    if self._ignored(frame):
                        continue
                    if reading.error_path is not None:
                        error = get_path(frame, reading.error_path)
                        if error is not None:
                            raise WebSocketServerError(
                                f"{self.id}: the server answered with an error frame "
                                f"({reading.error_path}: {self._shown(error)})"
                            )
                    fragment = get_path(frame, reading.text_path)
                    if isinstance(fragment, str):
                        parts.append(fragment)
                    if reading.tool_calls_path is not None:
                        raw_calls = get_path(frame, reading.tool_calls_path)
                        if isinstance(raw_calls, list):
                            calls.extend(dict(c) for c in raw_calls if isinstance(c, Mapping))
                    if reading.usage_path is not None:
                        raw_usage = get_path(frame, reading.usage_path)
                        if isinstance(raw_usage, Mapping):
                            usage = dict(raw_usage)
                    if reading.model_path is not None:
                        model = get_path(frame, reading.model_path)
                        if isinstance(model, str):
                            ids["model"] = model
                    if reading.id_path is not None:
                        reply_id = get_path(frame, reading.id_path)
                        if reply_id is not None:
                            ids["id"] = reply_id
                    if self._is_final(frame):
                        final = frame
                        break
                else:
                    raise WebSocketTurnOverflow(
                        f"{self.id}: more than {MAX_FRAMES_PER_TURN} frames in one turn"
                    )
        except TimeoutError as exc:
            raise WebSocketTurnTimeout(
                f"{self.id}: no final frame ({reading.final_path}) within "
                f"{reading.timeout_seconds}s"
            ) from exc

        if not parts:
            raise AdapterProductError(
                f"{self.id}: no frame of the turn carried text at path {reading.text_path!r}"
            )
        finish = get_path(final, reading.final_path) if final is not None else None
        ids["websocket"] = {"frames": [dict(f) for f in frames]}
        return ModelResponse(
            text="".join(parts),
            tool_calls=calls,
            logprobs=None,  # no WebSocket chat exposes logprobs; never fabricated (ADR-0005)
            finish_reason=finish if isinstance(finish, str) else "final",
            raw_ids=redact_ids(self.redactor, ids),
            usage=usage,
        )

    # --- frames --------------------------------------------------------------------------

    async def _send_template(
        self,
        connection: ClientConnection,
        template: JsonDict,
        request: ModelRequest | None,
        frames: list[JsonDict],
    ) -> None:
        """Render ``template`` twice: with the credential for the wire, as its placeholder
        for the record."""

        values = self._values(request)
        wire = render(template, values)
        recorded = render(template, {**values, TOKEN: "{{" + TOKEN + "}}"})
        try:
            await connection.send(json.dumps(wire))
        except ConnectionClosed as exc:
            raise WebSocketClosed(f"{self.id}: the connection closed while sending: {exc}") from exc
        frames.append({"direction": "sent", "frame": recorded})

    async def _recv_frame(
        self, connection: ClientConnection, frames: list[JsonDict]
    ) -> tuple[JsonDict, int]:
        """One JSON object frame, recorded with the credential scrubbed; its size in bytes."""

        try:
            raw = await connection.recv()
        except ConnectionClosed as exc:
            sent = exc.sent
            if sent is not None and sent.code == _MESSAGE_TOO_BIG:
                raise WebSocketTurnOverflow(
                    f"{self.id}: a frame exceeded {self.max_frame_bytes} bytes; not read further"
                ) from exc
            raise WebSocketClosed(f"{self.id}: the connection closed mid-turn: {exc}") from exc
        if isinstance(raw, bytes):
            raise AdapterProductError(
                f"{self.id}: received a binary frame; this adapter reads JSON text frames"
            )
        try:
            frame = json.loads(raw)
        except ValueError as exc:
            raise AdapterProductError(f"{self.id}: a frame was not valid JSON: {exc}") from exc
        if not isinstance(frame, dict):
            raise AdapterProductError(f"{self.id}: a frame was not a JSON object")
        frames.append({"direction": "received", "frame": _scrub(frame, self.api_key)})
        return frame, len(raw.encode("utf-8"))

    def _ignored(self, frame: Mapping[str, Any]) -> bool:
        kind = get_path(frame, self.spec.response.type_path)
        return isinstance(kind, str) and kind in self.spec.response.ignore_types

    def _is_final(self, frame: Mapping[str, Any]) -> bool:
        reading = self.spec.response
        value = get_path(frame, reading.final_path)
        if reading.final_value is None:
            return value is not None
        return bool(value == reading.final_value)

    def _shown(self, error: object) -> str:
        """An error frame's content for an error message: redacted, scrubbed and short."""

        text = self.redactor.redact_text(_as_text(_scrub(error, self.api_key)))
        return text if len(text) <= 200 else text[:200] + "..."

    def _values(self, request: ModelRequest | None) -> dict[str, object]:
        """The placeholder values of one send (``vars`` first, the reserved names over them)."""

        values: dict[str, object] = dict(self.spec.vars)
        if request is not None:
            prompt = _prompt_text(request)
            values[PROMPT] = prompt
            values[SYSTEM_PROMPT] = request.system_prompt or ""
            values[MESSAGES] = (
                [dict(m) for m in request.messages]
                if request.messages
                else [{"role": "user", "content": prompt}]
            )
        if self.api_key is not None:
            values[TOKEN] = self.api_key
        elif TOKEN in self._placeholders():
            raise AdapterProductError(
                f"{self.id}: a template uses {{{{token}}}} and no credential is resolved; set "
                "the variable auth_ref names"
            )
        return values


def _prompt_text(request: ModelRequest) -> str:
    """The attack text of this turn: the explicit prompt, else the last user message."""

    if request.prompt is not None:
        return request.prompt
    for message in reversed(request.messages or []):
        if message.get("role") == "user":
            content = message.get("content")
            return content if isinstance(content, str) else _as_text(content)
    return ""


def _conversation_of(request: ModelRequest) -> tuple[str | None, int, bool]:
    """``(conversation key, turn index, is this the last turn)`` from the runner's metadata."""

    metadata = request.metadata or {}
    key = metadata.get("conversation")
    if not isinstance(key, str) or not key:
        return None, 0, True
    turn_raw = metadata.get("turn_index")
    turn_index = turn_raw if isinstance(turn_raw, int) and not isinstance(turn_raw, bool) else 0
    total = metadata.get("turns_total")
    last = isinstance(total, int) and not isinstance(total, bool) and turn_index + 1 >= total
    return key, turn_index, last


async def _close(connection: ClientConnection) -> None:
    """Close ``connection`` without letting a dead socket raise or hang the caller."""

    try:
        async with asyncio.timeout(_CLOSE_TIMEOUT_S + 1.0):
            await connection.close()
    except (ConnectionClosed, OSError, TimeoutError):
        return
