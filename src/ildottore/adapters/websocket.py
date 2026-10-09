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
A live conversation is never evicted: past :data:`MAX_OPEN_CONVERSATIONS` a new one is refused.

The pre-commit audit (2026-10-07) found and this module now closes: a frame nested past what
the evidence store can serialize aborted the campaign (bounded at :data:`MAX_FRAME_DEPTH`); the
handshake phase had no byte cap (it has the turn's); the whole transcript was copied into
every turn's record (an intermediate turn now records its own frames, the last turn the
conversation's); eviction closed live conversations; the credential reached exception text (a
single helper scrubs and redacts every message that quotes the wire, and a credential shorter
than 8 characters, which the redactor cannot mask by value, is refused before any dial); the
query send and the handshake sat outside the turn timeout; a lost conversation was retried and
debited three times for nothing; and ``equals``/``final_value`` read ``1``, ``1.0`` and ``true``
as one value.

The pre-merge audit (2026-10-09) found and this module now closes: a frame was parsed with a
plain ``json.loads``, so half a character escaped in it reached the evidence store and aborted
the campaign (frames now go through ``bounded_loads`` and ``well_formed_json`` as every reply
does, A-47); a tool call's JSON-text arguments were not measured (``check_argument_nesting``);
a text frame that is not UTF-8 (close code 1007) was retried; and a socket that failed to open
was dialled again inside one send even when the runner owns the retries.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar, Final, Literal

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidStatus, InvalidURI

from ildottore.adapters.base import (
    MAX_RESPONSE_BYTES,
    AdapterEnvError,
    AdapterProductError,
    EndpointNotAllowed,
    ResponseTooDeep,
    ResponseTooLarge,
    ResponseUndecodable,
    RetryConfig,
    redact_ids,
)
from ildottore.adapters.rest import get_path
from ildottore.policy import EndpointAllowlist
from ildottore.redactor import Redactor
from ildottore.shared.config_errors import quoted
from ildottore.shared.models import (
    Capabilities,
    JsonDict,
    ModelRequest,
    ModelResponse,
    WebSocketExpect,
    WebSocketSpec,
)
from ildottore.shared.nesting import NestedTooDeeply, bounded_loads
from ildottore.shared.toolcalls import check_argument_nesting
from ildottore.shared.wellformed import well_formed_json

__all__ = [
    "CONNECTION_PLACEHOLDERS",
    "MAX_FRAMES_PER_TURN",
    "MAX_FRAME_DEPTH",
    "MAX_OPEN_CONVERSATIONS",
    "MESSAGES",
    "MIN_CREDENTIAL_LEN",
    "PLACEHOLDER",
    "PROMPT",
    "RESERVED",
    "RESERVED_HEADERS",
    "SYSTEM_PROMPT",
    "TOKEN",
    "WebSocketAdapter",
    "WebSocketClosed",
    "WebSocketFrameTooDeep",
    "WebSocketLost",
    "WebSocketOverflow",
    "WebSocketServerError",
    "WebSocketTooMany",
    "WebSocketTurnTimeout",
    "WebSocketUndecodable",
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
#: The placeholders a template rendered with no request (headers, handshake, session start)
#: may use: the credential, and ``vars``. A request placeholder there failed after the socket
#: was open (pre-commit audit, F8); the loader refuses it.
CONNECTION_PLACEHOLDERS: Final = frozenset({TOKEN})
#: Upgrade headers the operator may not set: the library writes them, and a second ``Host``
#: went on the wire next to the library's (pre-commit audit, F11).
RESERVED_HEADERS: Final = frozenset(
    {
        "host",
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
        "sec-websocket-protocol",
        "sec-websocket-accept",
    }
)
#: Frames read in one turn before the turn is abandoned: a server that streams forever is
#: bounded by this as well as by the timeout, and so is the transcript the evidence keeps.
MAX_FRAMES_PER_TURN: Final = 4096
#: Nesting a received frame may have. The whole frame is filed in the attempt's ``raw_ids``, a
#: few levels down, and the evidence store serializes the attempt with pydantic, which refuses
#: a value nested 255 levels; ``_scrub`` below walks the frame by recursion too (Python stops at
#: 1000 frames). A frame past either aborted the campaign instead of this attempt (pre-commit
#: audit, F1). The parse itself is ``shared.nesting.bounded_loads``, which refuses a text nested
#: past 100 levels before ``json.loads`` sees it (that one recurses only past some 116,000 on
#: 3.14 and some 10,000 on 3.12), so this tighter bound is checked on the parsed frame.
MAX_FRAME_DEPTH: Final = 64
#: Conversations whose connection is held at once. A live conversation is never evicted (it
#: used to be, closing a socket mid-turn: pre-commit audit, F4): past this, a new conversation
#: is refused as an environment error. The runner's concurrency keeps it far below.
MAX_OPEN_CONVERSATIONS: Final = 256
#: Shortest credential accepted. The redactor masks a registered credential by value only from
#: 8 characters, and a shorter one echoed in a close reason reached the evidence (pre-commit
#: audit, F5); the adapter refuses it before any dial.
MIN_CREDENTIAL_LEN: Final = 8
#: Upgrade statuses that mean "try again later", as for the HTTP adapters.
_RETRYABLE_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})
#: How long a close handshake may take before the socket is abandoned.
_CLOSE_TIMEOUT_S: Final = 2.0
#: Close code websockets sends when a frame is larger than ``max_size``.
_MESSAGE_TOO_BIG: Final = 1009
#: Close code websockets sends when a text frame is not UTF-8 (raw ``ED A0 80``, half a
#: character, included): the same frame would come back on a retry.
_INVALID_PAYLOAD: Final = 1007


# The class names below reach the CLI's error line and the stored evidence, which the redactor
# reads: a name its high-entropy rule masks is unreadable there, as four were until the second
# pre-merge audit of PR #87 (`WebSocketFrameUndecodable` printed as a high_entropy mask).
# `tests/adapters/test_websocket_premerge.py` checks every exported one survives `redact_text`.


class WebSocketClosed(AdapterEnvError):
    """The connection could not be opened, or closed before the turn ended (env, retried).

    Not retried when the server closed it with 1007 or 1009, saying what was sent was invalid
    or too large: it would refuse the same query again.
    """

    is_env_error = True
    retryable = True


class WebSocketTurnTimeout(AdapterEnvError):
    """No final frame within ``response.timeout_seconds`` (env, inconclusive, retried)."""

    is_env_error = True


class WebSocketServerError(AdapterEnvError):
    """The server answered the turn with an error frame (env, inconclusive, retried)."""

    is_env_error = True


class WebSocketOverflow(ResponseTooLarge):
    """A turn over the byte cap or the frame cap: inconclusive and not retried."""


class WebSocketFrameTooDeep(ResponseTooDeep):
    """A frame nested past :data:`MAX_FRAME_DEPTH`, or a tool call in it whose JSON-text
    arguments nest past :data:`~ildottore.shared.nesting.MAX_DEPTH`: inconclusive and not
    retried, as a reply nested too deeply is on every other adapter."""


class WebSocketUndecodable(ResponseUndecodable):
    """A text frame that is not UTF-8, which the library refuses by closing the connection
    (1007): inconclusive and not retried. Retried, the same frame came back three more times,
    each one debited (pre-merge audit of PR #87)."""


class WebSocketLost(WebSocketClosed):
    """A later turn whose connection is gone: inconclusive, and not retried.

    Retried, it was sent again three times and debited each time for a query that could never
    go out (pre-commit audit, F7).
    """

    retryable = False


class WebSocketTooMany(WebSocketClosed):
    """More than :data:`MAX_OPEN_CONVERSATIONS` held at once: this one is refused, not retried."""

    retryable = False


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

    A server that echoes the credential (in an acknowledgement, in an error, in a close
    reason) would otherwise put it into the recorded transcript or an error message; the
    redactor masks a registered credential by value as well, this does not depend on it.
    """

    if not secret:
        return value
    marker = "{{" + TOKEN + "}}"
    if isinstance(value, str):
        return value.replace(secret, marker)
    if isinstance(value, Mapping):
        return {str(_scrub(key, secret)): _scrub(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub(item, secret) for item in value]
    return value


def _same(value: object, expected: object) -> bool:
    """Equality that keeps ``1``, ``1.0`` and ``true`` apart (pre-commit audit, F10)."""

    return type(value) is type(expected) and bool(value == expected)


def _satisfies(frame: Mapping[str, Any], expect: WebSocketExpect) -> bool:
    value = get_path(frame, expect.path)
    if expect.equals is None:
        return value is not None
    return _same(value, expect.equals)


def _depth(value: object) -> int:
    """Nesting depth of a parsed frame, measured without recursion."""

    deepest = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, dict):
            deepest = max(deepest, level)
            stack.extend((child, level + 1) for child in item.values())
        elif isinstance(item, list):
            deepest = max(deepest, level)
            stack.extend((child, level + 1) for child in item)
    return deepest


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
    """One open connection, the transcript it has produced and its one-query lock.

    ``reported`` is how many frames an earlier turn's record already carries: an intermediate
    turn records only its own frames, the last turn the whole conversation (the conversation
    engine stores one attempt per conversation, from the final turn's response). Copying the
    whole transcript into every turn was quadratic (pre-commit audit, F3).
    """

    connection: ClientConnection
    frames: list[JsonDict]
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    reported: int = 0


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
        self._check_credential()
        key, turn_index, last_turn = _conversation_of(request)
        if key is None:
            conversation = await self._open()
            try:
                return await self._turn(conversation, request, whole=True)
            finally:
                await _close(conversation.connection)

        held = self._conversations.get(key)
        if held is None:
            if turn_index > 0:
                raise WebSocketLost(
                    f"{self.id}: turn {turn_index} of conversation {key!r} has no open "
                    "connection, so the earlier turns' context is gone; nothing was sent"
                )
            if len(self._conversations) >= MAX_OPEN_CONVERSATIONS:
                raise WebSocketTooMany(
                    f"{self.id}: {MAX_OPEN_CONVERSATIONS} conversations are open already; "
                    f"conversation {key!r} was not started"
                )
            held = await self._open()
            self._conversations[key] = held
        conversation = held
        try:
            async with conversation.lock:
                response = await self._turn(conversation, request, whole=last_turn)
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

    def _check_credential(self) -> None:
        """Refuse a credential the redactor could not mask by value, before any dial."""

        if self.api_key is not None and len(self.api_key) < MIN_CREDENTIAL_LEN:
            raise AdapterProductError(
                f"{self.id}: the credential is shorter than {MIN_CREDENTIAL_LEN} characters, "
                "which the redactor cannot mask by value; nothing was sent"
            )

    async def _drop(self, key: str) -> None:
        conversation = self._conversations.pop(key, None)
        if conversation is not None:
            await _close(conversation.connection)

    # --- opening a connection ------------------------------------------------------------

    async def _open(self) -> _Conversation:
        """Dial, handshake and start the session, retrying a failed open up to the cap.

        A failure before the query is sent (DNS, refused, a 503 at the upgrade, a close during
        the handshake, no handshake reply in time) is dialled again up to
        ``reconnect.max_attempts`` more times with the base backoff, and never more often than
        this adapter's own ``retry.max_retries``: a campaign builds every live adapter with no
        retries of its own (``NO_ADAPTER_RETRIES``), so there each dial is one send the runner
        paces, debits and retries. Re-dialled here, a socket that failed to open was dialled up
        to ``max_attempts + 1`` times per debited request: 8 dials for 4 debits with
        ``max_attempts: 1`` under the runner's retries (pre-merge audit of PR #87). A refused
        upgrade (any other 4xx, a redirect), a handshake reply that does not satisfy ``expect``
        and a malformed frame are product defects and are not retried. Once a query is on the
        wire nothing here resends it: a close mid-turn is an environment error the runner
        retries, debited like every send. The handshake and session phase (sends and replies)
        runs under ``response.timeout_seconds``, as a turn does, and under the turn's byte and
        frame caps.
        """

        attempts = max(0, min(self.spec.reconnect.max_attempts, self.retry.max_retries)) + 1
        timeout = self.spec.response.timeout_seconds
        last = ""
        for attempt in range(attempts):
            self._check_allowlist()  # defense in depth: the gate decides every dial.
            frames: list[JsonDict] = []
            connection: ClientConnection | None = None
            try:
                connection = await self._connect()
                try:
                    async with asyncio.timeout(timeout):
                        await self._handshake(connection, frames)
                        await self._start_session(connection, frames)
                except TimeoutError as exc:
                    raise WebSocketTurnTimeout(
                        f"{self.id}: the handshake and session phase did not complete within "
                        f"{timeout}s"
                    ) from exc
                return _Conversation(connection, frames)
            except AdapterEnvError as exc:
                if connection is not None:
                    await _close(connection)
                if getattr(exc, "retryable", True) is False:
                    raise  # an overflow in the handshake phase repeats; not re-dialled
                last = f"{type(exc).__name__}: {exc}"
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
        # Cleartext ws is loopback-only and never goes through a proxy (the environment's
        # proxy would see the handshake token in the clear, on a host the scope did not
        # authorize); wss honours the proxy environment as the HTTP adapters do, TLS end to
        # end (pre-commit audit, F11).
        proxy: Literal[True] | None = None if self.url.lower().startswith("ws:") else True
        try:
            return await _NoRedirects(
                self.url,
                additional_headers=headers or None,
                open_timeout=self.retry.timeout_s,
                close_timeout=_CLOSE_TIMEOUT_S,
                max_size=self.max_frame_bytes,
                compression=None,  # a decompression bomb has no cap the byte cap can see
                user_agent_header="ildottore",
                proxy=proxy,
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
                f"{self.id}: the endpoint did not complete a WebSocket upgrade: "
                f"{self._safe(str(exc))}"
            ) from exc
        except (OSError, TimeoutError) as exc:
            raise WebSocketClosed(
                f"{self.id}: could not connect: {type(exc).__name__}: {self._safe(str(exc))}"
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
        """Read the first frame that is not ignored and check ``expect`` against it.

        Bounded in frames and bytes like a turn (it had no byte cap: pre-commit audit, F2);
        the caller bounds it in time.
        """

        total = 0
        for _ in range(MAX_FRAMES_PER_TURN):
            frame, size = await self._recv_frame(connection, frames)
            total += size
            if total > MAX_RESPONSE_BYTES:
                raise WebSocketOverflow(
                    f"{self.id}: more than {MAX_RESPONSE_BYTES} bytes before the {what} reply; "
                    "not read further"
                )
            if self._ignored(frame):
                continue
            if not _satisfies(frame, expect):
                raise AdapterProductError(
                    f"{self.id}: the {what} reply did not satisfy expect "
                    f"({quoted(expect.path)} == {quoted(expect.equals)})"
                )
            return
        raise WebSocketOverflow(
            f"{self.id}: more than {MAX_FRAMES_PER_TURN} frames before the {what} reply"
        )

    # --- one turn ------------------------------------------------------------------------

    async def _turn(
        self, conversation: _Conversation, request: ModelRequest, *, whole: bool
    ) -> ModelResponse:
        """Send one query and read the turn; ``whole`` records the conversation's transcript.

        The query send is inside the turn timeout (a server that never reads blocked a large
        send with no bound of the adapter's own: pre-commit audit, F6).
        """

        connection, frames = conversation.connection, conversation.frames
        reading = self.spec.response
        start = conversation.reported

        parts: list[str] = []
        calls: list[JsonDict] = []
        usage: JsonDict | None = None
        ids: dict[str, Any] = {}
        final: JsonDict | None = None
        total = 0
        try:
            async with asyncio.timeout(reading.timeout_seconds):
                await self._send_template(connection, self.spec.message.send, request, frames)
                for _ in range(MAX_FRAMES_PER_TURN):
                    frame, size = await self._recv_frame(connection, frames)
                    total += size
                    if total > MAX_RESPONSE_BYTES:
                        raise WebSocketOverflow(
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
                                f"({quoted(reading.error_path)}: {self._shown(error)})"
                            )
                    fragment = get_path(frame, reading.text_path)
                    if isinstance(fragment, str):
                        parts.append(fragment)
                    if reading.tool_calls_path is not None:
                        raw_calls = get_path(frame, reading.tool_calls_path)
                        if isinstance(raw_calls, list):
                            calls.extend(
                                self._tool_call(c) for c in raw_calls if isinstance(c, Mapping)
                            )
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
                    raise WebSocketOverflow(
                        f"{self.id}: more than {MAX_FRAMES_PER_TURN} frames in one turn"
                    )
        except TimeoutError as exc:
            raise WebSocketTurnTimeout(
                f"{self.id}: no final frame ({quoted(reading.final_path)}) within "
                f"{reading.timeout_seconds}s"
            ) from exc

        if not parts:
            raise AdapterProductError(
                f"{self.id}: no frame of the turn carried text at path {quoted(reading.text_path)}"
            )
        finish = get_path(final, reading.final_path) if final is not None else None
        recorded = frames if whole else frames[start:]
        conversation.reported = len(frames)
        ids["websocket"] = {"frames": [dict(f) for f in recorded]}
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
            raise WebSocketClosed(
                f"{self.id}: the connection closed while sending: {self._safe(str(exc))}"
            ) from exc
        frames.append({"direction": "sent", "frame": recorded})

    async def _recv_frame(
        self, connection: ClientConnection, frames: list[JsonDict]
    ) -> tuple[JsonDict, int]:
        """One JSON object frame, recorded with the credential scrubbed; its size in bytes."""

        try:
            raw = await connection.recv()
        except ConnectionClosed as exc:
            sent, received = exc.sent, exc.rcvd
            # The library echoes a close it receives, so a sent 1009 or 1007 is this side's
            # refusal only when it was not an echo of the server's (second pre-merge audit of
            # PR #87: a server's 1009 read as "a frame exceeded ...", its reason dropped).
            ours = sent is not None and not exc.rcvd_then_sent
            if ours and sent is not None and sent.code == _MESSAGE_TOO_BIG:
                raise WebSocketOverflow(
                    f"{self.id}: a frame exceeded {self.max_frame_bytes} bytes; not read further"
                ) from exc
            if ours and sent is not None and sent.code == _INVALID_PAYLOAD:
                raise WebSocketUndecodable(
                    f"{self.id}: a text frame was not UTF-8 and the connection was closed (1007); "
                    "not evaluated"
                ) from exc
            # The close reason is the server's text: scrubbed and redacted before it is
            # quoted (a credential in it reached attempt.error: pre-commit audit, F5).
            closed = WebSocketClosed(
                f"{self.id}: the connection closed mid-turn: {self._safe(str(exc))}"
            )
            if (
                received is not None
                and exc.rcvd_then_sent
                and received.code in (_MESSAGE_TOO_BIG, _INVALID_PAYLOAD)
            ):
                closed.retryable = False  # the server refused what was sent; it would again
            raise closed from exc
        if isinstance(raw, bytes):
            raise AdapterProductError(
                f"{self.id}: received a binary frame; this adapter reads JSON text frames"
            )
        too_deep = WebSocketFrameTooDeep(
            f"{self.id}: a frame is nested deeper than {MAX_FRAME_DEPTH} levels; not evaluated"
        )
        try:
            # Parsed as every other adapter parses a reply: the nesting measured before the
            # parse, and half a character (a lone surrogate escaped in a string) read as U+FFFD,
            # since no UTF-8 writer downstream takes it (A-47; pre-merge audit of PR #87: a
            # plain json.loads let one such frame abort the campaign).
            frame = well_formed_json(bounded_loads(raw))
        except NestedTooDeeply as exc:
            raise too_deep from exc
        except ValueError as exc:
            raise AdapterProductError(
                f"{self.id}: a frame was not valid JSON: {self._safe(str(exc))}"
            ) from exc
        if not isinstance(frame, dict):
            raise AdapterProductError(f"{self.id}: a frame was not a JSON object")
        if _depth(frame) > MAX_FRAME_DEPTH:
            raise too_deep
        frames.append({"direction": "received", "frame": _scrub(frame, self.api_key)})
        return frame, len(raw.encode("utf-8"))

    def _tool_call(self, call: Mapping[str, Any]) -> JsonDict:
        """A tool call read from a frame, refused when its JSON-text arguments nest too deeply.

        The frame's own parse never opens arguments carried as a JSON string; the evaluators
        and the in-band tool loop do (``shared.toolcalls.call_arguments``), so they are measured
        here, as the base adapter measures them (pre-merge audit of PR #87).
        """

        try:
            check_argument_nesting(call)
        except NestedTooDeeply as exc:
            raise WebSocketFrameTooDeep(
                f"{self.id}: a frame has a tool call whose arguments are {exc}; not evaluated"
            ) from exc
        return dict(call)

    def _ignored(self, frame: Mapping[str, Any]) -> bool:
        kind = get_path(frame, self.spec.response.type_path)
        return isinstance(kind, str) and kind in self.spec.response.ignore_types

    def _is_final(self, frame: Mapping[str, Any]) -> bool:
        reading = self.spec.response
        value = get_path(frame, reading.final_path)
        if reading.final_value is None:
            return value is not None
        return _same(value, reading.final_value)

    def _safe(self, text: str) -> str:
        """Text from the wire for an error message: the credential scrubbed, then redacted."""

        return self.redactor.redact_text(str(_scrub(text, self.api_key)))

    def _shown(self, error: object) -> str:
        """An error frame's content for an error message: scrubbed, redacted and short."""

        text = self._safe(_as_text(error))
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
