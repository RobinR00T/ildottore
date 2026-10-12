"""Shared adapter plumbing (u04, contract §5 step 1).

Everything provider-agnostic lives here so each concrete adapter (``openai``,
``anthropic``, ``rest``) stays thin (ADR-0002 - own the bytes, don't normalize):

* **Allowlist gate** - every egress is checked against u01's default-deny
  :class:`~ildottore.policy.EndpointAllowlist` **before** the ``httpx`` call is
  issued (contract §4 KEEP: unbypassable by subclasses). Out-of-scope host or
  off-prefix path raises :class:`EndpointNotAllowed`; **zero** requests leave.
* **Retry / timeout / backoff** - transient statuses (429/502/503/504) and
  transport/timeout errors are retried with capped exponential backoff, then the
  attempt is *skipped* by re-raising as :class:`AdapterEnvError` (env, per
  ``AGENTS.md §2``). A 200 body the adapter cannot read (not JSON, not an object, not the
  provider's shape) is :class:`ResponseMalformed`, and one nested too deeply to evaluate
  :class:`ResponseTooDeep`: environment failures of that attempt, not retried (OD-21; a
  campaign none of whose first replies can be read still stops, u08 A-74). A non-retryable
  4xx is a **product defect** (:class:`AdapterStatusError`, never masked as a flake). A lone
  surrogate in a body is read as U+FFFD where it is parsed (:mod:`ildottore.shared.wellformed`,
  A-47).
* **Logprob mapping** - :func:`map_logprobs` folds a provider-neutral token list
  into :class:`~ildottore.shared.models.TokenLogprob` (ADR-0005 / OD-1).
* **Redaction** - raw request/response ids are redacted through u01's redactor
  before they land on :class:`~ildottore.shared.models.ModelResponse.raw_ids`.

Capabilities are **static per adapter+config** (declared, not probed at send
time - contract §4 KEEP; live probing is u09 fingerprint).
"""

from __future__ import annotations

import asyncio
import functools
import json
import re
import zlib
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, Final, cast

import httpx

from ildottore.policy import EndpointAllowlist
from ildottore.redactor import (
    TRANSCRIPT_FRAMES,
    TRANSCRIPT_PROTOCOL_PATHS,
    Redactor,
    mask_split,
    redact_split,
    registered_secrets,
    withhold_open_ends,
)
from ildottore.shared.logprobs import readable_logprob
from ildottore.shared.models import (
    Capabilities,
    ModelRequest,
    ModelResponse,
    TokenLogprob,
)
from ildottore.shared.nesting import NestedTooDeeply, bounded_loads
from ildottore.shared.provider_filter import INPUT_FILTER_REFUSED
from ildottore.shared.toolcalls import check_argument_nesting
from ildottore.shared.wellformed import well_formed_json

__all__ = [
    "ACCEPT_ENCODING",
    "FILTER_REFUSED",
    "UNREADABLE_EXCERPT_BYTES",
    "AdapterEnvError",
    "AdapterError",
    "AdapterProductError",
    "AdapterStatusError",
    "BaseAdapter",
    "EndpointNotAllowed",
    "ProviderFilterBlock",
    "ResponseMalformed",
    "ResponseTooDeep",
    "ResponseTooLarge",
    "ResponseUndecodable",
    "RetryConfig",
    "SamplingRefused",
    "azure_prompt_filter",
    "map_logprobs",
    "read_capped",
    "redact_ids",
    "reply_excerpt",
    "sampling_params_named",
]

# HTTP statuses that mean "try again later" (transient / env, not a defect).
_RETRYABLE_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})

#: Largest response body read from a target, in bytes (4 MiB). A model reply is orders of
#: magnitude smaller; anything above this is refused unread past the cap (SEC-07).
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class AdapterError(Exception):
    """Base class for every u04 adapter error."""


class EndpointNotAllowed(AdapterError):
    """The requested URL is not on the scope allowlist (S3 default-deny).

    Raised **before** any network call - the request never leaves the process.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        super().__init__(f"endpoint not allowed by scope: {url!r}")


class AdapterEnvError(AdapterError):
    """A transient / environment failure (rate limit, 5xx, timeout, transport).

    Per ``AGENTS.md §2`` the runner treats this as **retry/skip**, not a product
    defect. Raised only after the retry budget is exhausted.
    """


class ResponseTooLarge(AdapterEnvError):
    """A reply over :data:`MAX_RESPONSE_BYTES`: an environment failure that is NOT retried.

    It would come back the same size on every retry, and the runner's retry policy used to
    send it three more times although the docstring said it was not retried (review of
    PR #32). ``retryable = False`` is the structural marker ``core.execute`` reads, and
    ``is_env_error`` says explicitly what the class name no longer does: ``core.execute`` falls
    back to an ``...EnvError`` name suffix, and without the marker this subclass would have
    been taken for a product defect and halted the campaign.
    """

    is_env_error = True
    retryable = False


class ResponseUndecodable(AdapterEnvError):
    """A reply whose ``Content-Encoding`` cannot be decoded: unsupported, stacked or corrupt.

    The reply cannot be evaluated, so the attempt is inconclusive, and it would come back the
    same on a retry. Before, httpx's own ``DecodingError`` escaped every adapter's handler
    (it is not a ``TransportError``), and the MCP adapter rebuilt an already decoded body
    under its ``gzip`` header and failed to decode it a second time.
    """

    is_env_error = True
    retryable = False


class ResponseTooDeep(AdapterEnvError):
    """A reply nested deeper than :data:`~ildottore.shared.nesting.MAX_DEPTH`: not evaluated.

    ``json.loads`` raises ``RecursionError`` on a body nested past its stack, which escaped the
    ``except ValueError`` below, and the runner aborted the whole campaign on one 400 KB reply
    of ``[``. A body it parses could abort it too: 300 levels (about 600 bytes) overflowed
    pydantic's serializer when the evidence was written (2026-10-07). Like a reply over the
    size cap, it is an environment failure of this attempt, which is inconclusive and is not
    retried; so, since OD-21, is a body that is not JSON at all (:class:`ResponseMalformed`).
    """

    is_env_error = True
    retryable = False


class ResponseMalformed(AdapterEnvError):
    """A success reply the adapter cannot read as one: not evaluated, and not retried (OD-21).

    Not JSON (brackets that do not balance, an integer of more than 4,300 digits, bytes that are
    not text included), not a JSON object, or not the shape the provider or the template
    declares (OpenAI's ``choices[0].message.content``, Anthropic's ``content`` array, a REST
    template's ``text_path``, a WebSocket frame that is binary, not JSON or not an object, or a
    turn with no text, no tool call and no filter's stop, an MCP reply that is not JSON-RPC). It
    was an :class:`AdapterProductError`, and the runner stopped the whole campaign on the first one:
    one hostile ``<html>`` reply ended a scan after 1 request. Decided 2026-10-11 under the
    owner's delegation (best practice), revisable, as #65 decided for a reply nested too deeply:
    the attempt is inconclusive and the campaign goes on. A wrong endpoint answers every request
    this way, so the runner reads ``malformed_reply`` and stops a campaign whose first replies
    all are unreadable, or which reads none of 20 in a row later (``core.execute``, u08 A-74).

    It carries what the attempt keeps for review (pre-merge audit of ``598f0858``, HIGH 1): an
    ``excerpt`` of the body, at most :data:`UNREADABLE_EXCERPT_BYTES` of UTF-8 through the
    adapter's redactor (:func:`reply_excerpt`), the body's ``size`` in bytes, and the adapter's
    ``advice`` on what to check, worded for the adapter and for how it was built (a target file
    declares no REST template, so it is not told to check one: LOW 2).
    """

    is_env_error = True
    #: The same request gets the same reply: sent once within a run (a resume sends it again,
    #: since the target may have been fixed: ``shared.unreadable.UNREADABLE_MARK``).
    retryable = False
    #: The structural marker the runner's stop reads (``core.execute.is_unreadable_reply``).
    malformed_reply = True

    def __init__(
        self,
        message: str,
        *,
        excerpt: str | None = None,
        size: int | None = None,
        advice: str | None = None,
    ) -> None:
        super().__init__(message)
        self.excerpt = excerpt
        self.size = size
        self.advice = advice

    def __reduce__(self) -> tuple[Any, ...]:
        """Rebuild with what it keeps (the default reduction passes the message alone)."""

        rebuild = functools.partial(
            type(self), excerpt=self.excerpt, size=self.size, advice=self.advice
        )
        return (rebuild, self.args)

    def with_reply(
        self, body: bytes | str, redactor: Redactor, advice: str | None
    ) -> ResponseMalformed:
        """This error, with the excerpt, the size and the advice it lacks filled in."""

        if self.excerpt is None:
            self.excerpt, self.size = reply_excerpt(body, redactor)
        if self.advice is None:
            self.advice = advice
        return self


#: The most of an unreadable reply an attempt keeps for review, in bytes of UTF-8 (4 KiB).
UNREADABLE_EXCERPT_BYTES = 4096


#: A character a token of the redactor's rules can be made of: a key shape that crosses the read
#: cut is cut before rather than read in part, when what lies before the cut is this short.
_TOKEN_CHAR = re.compile(r"[\w+/=.:@-]")
_SHORT_TOKEN_HEAD = 256


def _clean_cut(text: str, cut: int) -> int:
    """Where to cut ``text``, at or before ``cut``, so nothing that could be a credential crosses.

    A registered credential that crosses ``cut`` (whatever characters it holds) is left out
    whole, and so is a token of key characters whose part before the cut is short: read in part,
    neither is recognised, and up to 15 leading characters of a registered credential reached
    the excerpt (verification of 07aa0b3a, LOW 1). A longer token's head is long enough for the
    redactor's own rules.
    """

    if cut >= len(text):
        return len(text)
    start = cut
    if _TOKEN_CHAR.match(text, cut):
        head = cut
        while head > 0 and _TOKEN_CHAR.match(text, head - 1):
            head -= 1
        if cut - head <= _SHORT_TOKEN_HEAD:
            start = head
    for secret in registered_secrets():
        end = cut + len(secret) - 1
        found = text.find(secret, max(0, cut - len(secret) + 1), end)
        while found != -1 and found < cut:
            start = min(start, found)
            found = text.find(secret, found + 1, end)
    return start


#: The fields of a streamed event that are its protocol's, not the reply's: an event's type and
#: kind, and what OpenAI's and Anthropic's chunks and Ollama's lines repeat in every event.
_STREAM_PROTOCOL_PATHS: Final = (
    *("type", "event", "object", "id", "model", "created", "created_at"),
    *("system_fingerprint", "done", "done_reason"),
)
#: What ends a line of an event stream: CRLF, LF or CR, and nothing else (WHATWG HTML, "Server-sent
#: events", 9.2.6). ``str.splitlines`` also ends one at U+2028 or U+0085, which JSON may hold raw.
_SSE_LINE_BREAK: Final = re.compile(r"\r\n|\r|\n")
_NDJSON_LINE_BREAK: Final = re.compile(r"\r?\n")
_SSE_DATA: Final = "data"
_BOM: Final = "\ufeff"


def _lines(text: str, breaks: re.Pattern[str]) -> list[list[str]]:
    """``text`` as ``[line, ending]`` pairs, the last ending empty when the text has none."""

    out: list[list[str]] = []
    cursor = 0
    for match in breaks.finditer(text):
        out.append([text[cursor : match.start()], match.group(0)])
        cursor = match.end()
    if cursor < len(text):
        out.append([text[cursor:], ""])
    return out


def _event(data: str) -> tuple[str, Any]:
    """An event's data as a frame: JSON that is an object or an array as it parses, a JSON string
    as the text it holds, anything else (a bare delta, a number, ``[DONE]``) as the text it is."""

    try:
        value = well_formed_json(bounded_loads(data))
    except ValueError:
        return "text", data
    if isinstance(value, (dict, list)):
        return "json", value
    return ("string", value) if isinstance(value, str) else ("text", data)


def _stream_window() -> tuple[int, int]:
    """``(window, settled)``: how much of a streamed body the excerpt's masking reads, and from
    where in it a stream's last piece may be the head of more (third pre-merge audit, LOW 4).

    The excerpt reads at most ``extent`` characters of the body it is given (twice what it keeps,
    then a margin for a registered credential or a short key-shaped token crossing that cut,
    :func:`reply_excerpt`). A window of four times that leaves the excerpt reading well inside
    the rewritten part even where masks shorten it, and nothing past the window is read: a 4 MiB
    stream of tiny events cost up to 12.8 s and costs what 37 KiB does. A stream cut by the
    window may run on past it, so the part of each stream whose last piece lies past half the
    window that may be a secret's head (a run of key characters, a registered credential's
    beginning) is left out (:func:`ildottore.redactor.withhold_open_ends`): no span crossing the
    cut is shown in part. One that ended in the first half is read as complete.
    """

    longest = max((len(secret) for secret in registered_secrets()), default=0)
    extent = 2 * UNREADABLE_EXCERPT_BYTES + 4 * max(longest, _SHORT_TOKEN_HEAD)
    return 4 * extent, 2 * extent


def _head(text: str, window: int) -> tuple[str, bool]:
    """``text``, or its head up to the last line end at or before ``window``, and whether cut."""

    if len(text) <= window:
        return text, False
    cut = max(text.rfind("\n", 0, window), text.rfind("\r", 0, window)) + 1
    return text[:cut], True


#: A unit of a stream as read: the lines it comes from, its kind and its frame.
_Unit = tuple[list[int], str, Any]


def _written(kind: str, value: Any, original: str) -> str:
    """A unit's data as written again: JSON as the target wrote it, compact when it was so and
    not ``\\u``-escaped (second pre-merge audit, MEDIUM 1)."""

    if kind == "text":
        return cast("str", value)
    compact = False
    try:
        before = json.loads(original)
        compact = original.strip() in (
            json.dumps(before, separators=(",", ":"), ensure_ascii=False),
            json.dumps(before, separators=(",", ":")),
        )
    except ValueError:
        compact = False
    return json.dumps(value, ensure_ascii=False, separators=(",", ":") if compact else None)


def _masked_units(
    redactor: Redactor, units: list[_Unit], *, cut: bool, settled: int, offsets: list[int]
) -> list[Any] | None:
    """Each unit's frame with the stream's content masked across the units as a transcript's is
    (A-77), its open tails left out when ``cut``, or None when no frame changes."""

    transcript = {
        TRANSCRIPT_FRAMES: [{"direction": "received", "frame": frame} for _, _, frame in units],
        TRANSCRIPT_PROTOCOL_PATHS: list(_STREAM_PROTOCOL_PATHS),
    }
    masked = mask_split(redactor, transcript)
    if cut:
        after = next(
            (i for i, (lines, _, _) in enumerate(units) if offsets[lines[0]] >= settled),
            len(units),
        )
        masked = withhold_open_ends(masked, after=after)
    if masked is transcript:
        return None
    frames = cast("dict[str, list[dict[str, Any]]]", masked)[TRANSCRIPT_FRAMES]
    return [frame["frame"] for frame in frames]


def _offsets(lines: list[list[str]]) -> list[int]:
    """Where each line starts in the text it was cut from."""

    out, at = [], 0
    for line, ending in lines:
        out.append(at)
        at += len(line) + len(ending)
    return out


def _sse_masked(text: str, redactor: Redactor) -> str | None:
    """``text``, a server-sent event stream, with its events' content masked across the events
    as a WebSocket transcript's is (A-77), or None when it is no such stream or holds nothing to
    mask.

    A reply streamed as events when no stream was asked for is not JSON, so it was quoted as it
    came, each delta redacted alone, and a key or a registered credential in 3-character deltas
    was rebuilt from the excerpt (pre-merge audit of c4bd2012, MEDIUM 3). Read as the format says
    (second pre-merge audit, MEDIUM 2): a line ends at CRLF, LF or CR only, a blank line ends an
    event, a line starting with a colon is a comment, the field is what comes before the first
    colon and one space after it is dropped, and an event's ``data`` lines are joined by LF. An
    event's data is an object or an array when it parses as one, and is then masked field by
    field across the events; an event of several ``data`` lines that make no object or array
    joined is read line by line (a page of ``data:`` lines with no blank line between them, which
    the format reads as one event), each line as its own unit; any other data is the text it
    holds, of one stream (a JSON string decoded). One reading: the line-by-line one used to run
    only when the format's masked nothing, so one masked event kept a block's key in clear (third
    pre-merge audit, LOW 3). Only the head the excerpt can read is read (:func:`_stream_window`).
    A masked unit is written again on one ``data`` line (a text holding LF, on as many), every
    other line as it came; the text returned is that head.
    """

    window, settled = _stream_window()
    head, cut = _head(text, window)
    lines = _lines(head, _SSE_LINE_BREAK)
    events: list[list[int]] = []
    current: list[int] = []
    for index, (line, _) in enumerate(lines):
        line = line.removeprefix(_BOM) if index == 0 else line
        if not line:
            if current:
                events.append(current)
                current = []
        elif not line.startswith(":") and line.partition(":")[0] == _SSE_DATA:
            current.append(index)
    if current:
        events.append(current)

    def value(index: int) -> str:
        field = lines[index][0].removeprefix(_BOM) if index == 0 else lines[index][0]
        data = field.partition(":")[2]
        return data[1:] if data.startswith(" ") else data

    units: list[_Unit] = []
    for event in events:
        values = [value(index) for index in event]
        kind, frame = _event("\n".join(values))
        if kind != "json" and len(event) > 1:
            units.extend(
                ([index], *_event(data)) for index, data in zip(event, values, strict=True)
            )
        else:
            units.append((event, kind, frame))
    if len(units) < 2:
        return None
    offsets = _offsets(lines)
    masked = _masked_units(redactor, units, cut=cut, settled=settled, offsets=offsets)
    if masked is None:
        return None
    for (event, kind, before), after in zip(units, masked, strict=True):
        if after == before:
            continue
        first, ending = event[0], lines[event[0]][1] or "\n"
        prefix = _BOM if first == 0 and lines[0][0].startswith(_BOM) else ""
        original = "\n".join(value(index) for index in event)
        written = _written(kind, after, original).split("\n")
        lines[first] = [
            prefix + ending.join(f"{_SSE_DATA}: {piece}" for piece in written),
            lines[first][1],
        ]
        for index in event[1:]:
            lines[index] = ["", ""]
    return "".join(line + ending for line, ending in lines)


def _stream_line(value: Any) -> bool:
    """Whether a JSON line is a piece of a streamed reply in a shape known to stream: Ollama's
    (``done`` beside a ``message`` or a ``response``) or an OpenAI chunk (``object``
    ``chat.completion.chunk``, or ``choices`` holding a ``delta``)."""

    if not isinstance(value, dict):
        return False
    if "done" in value and ("message" in value or "response" in value):
        return True
    if value.get("object") == "chat.completion.chunk":
        return True
    choices = value.get("choices")
    return isinstance(choices, list) and any(
        isinstance(choice, dict) and "delta" in choice for choice in choices
    )


def _ndjson_masked(text: str, redactor: Redactor) -> str | None:
    """``text``, a reply streamed as JSON lines in a shape known to stream (:func:`_stream_line`:
    Ollama's, OpenAI's chunks), with its lines' content masked across them as an event stream's
    is, or None when it is not that or holds nothing to mask.

    Any other body of JSON lines is a list of records (a log), masked string by string as every
    list of records is: read as a stream, the fields of 181 of 217 clean logs were joined across
    the records and masked, and the excerpt was not `main`'s (third pre-merge audit, LOW 2). Only
    the head the excerpt can read is read (:func:`_stream_window`); lines not masked are kept as
    they came.
    """

    window, settled = _stream_window()
    head, cut = _head(text, window)
    lines = _lines(head, _NDJSON_LINE_BREAK)
    units: list[_Unit] = []
    for index, (line, _) in enumerate(lines):
        if not line.strip():
            continue
        kind, value = _event(line.strip())
        if kind != "json" or not _stream_line(value):
            return None
        units.append(([index], kind, value))
    if len(units) < 2:
        return None
    masked = _masked_units(redactor, units, cut=cut, settled=settled, offsets=_offsets(lines))
    if masked is None:
        return None
    for (event, kind, before), after in zip(units, masked, strict=True):
        if after != before:
            lines[event[0]][0] = _written(kind, after, lines[event[0]][0])
    return "".join(line + ending for line, ending in lines)


def _split_masked(body: bytes | str, redactor: Redactor) -> bytes | str:
    """``body``, or, when it holds a reply kept in pieces, the same written again with them
    masked as the text they make (:func:`ildottore.redactor.mask_split`, A-77).

    A WebSocket turn with no text is quoted as its frames, a reply in the wrong shape as its
    body, and a reply streamed as server-sent events as its events: a secret streamed in deltas,
    or kept as tokens, was redacted piece by piece and rebuilt from the excerpt (audit of main
    de122e26, HIGH 1; pre-merge audit of c4bd2012, MEDIUM 3). A JSON body's logprob lists are
    masked, and so is an event stream's content across its events (:func:`_sse_masked`); a body
    that is neither, or holds no such piece, is returned as it is, so its excerpt is byte for
    byte what it was.
    """

    try:
        parsed = well_formed_json(bounded_loads(body))
    except ValueError:
        text = body if isinstance(body, str) else bytes(body).decode("utf-8", "replace")
        streamed = _sse_masked(text, redactor) if _SSE_DATA in text else None
        if streamed is None:
            streamed = _ndjson_masked(text, redactor)
        return body if streamed is None else streamed
    masked = mask_split(redactor, parsed)
    # Written as the target wrote it, not ``\u``-escaped: the excerpt's own redaction reads the
    # text outside any stream next, and a number grouped by a no-break space escaped is no phone
    # and no card to the rules (second pre-merge audit of the branch, MEDIUM 1).
    return body if masked is parsed else json.dumps(masked, ensure_ascii=False)


def reply_excerpt(body: bytes | str, redactor: Redactor) -> tuple[str, int]:
    """``(excerpt, size)``: the start of ``body`` for review, redacted, and its size in bytes.

    Read over twice what is kept, cut where no credential and no short key-shaped token crosses
    (:func:`_clean_cut`), redacted, then cut to :data:`UNREADABLE_EXCERPT_BYTES`, so a credential
    is masked whole before the last cut takes part of its mask; bytes that are not UTF-8 read as
    U+FFFD, and no cut splits a character. A JSON body holding a value split over the items of
    a list is read with it masked (:func:`_split_masked`); the size is the body's as it came.
    """

    size = len(body.encode("utf-8", "replace") if isinstance(body, str) else bytes(body))
    body = _split_masked(body, redactor)
    data = body.encode("utf-8", "replace") if isinstance(body, str) else bytes(body)
    cut = min(len(data), 2 * UNREADABLE_EXCERPT_BYTES)
    while 0 < cut < len(data) and data[cut] & 0xC0 == 0x80:  # not inside a character
        cut -= 1
    longest = max((len(secret) for secret in registered_secrets()), default=0)
    head = data[:cut].decode("utf-8", "replace")
    window = head + data[cut : cut + 4 * max(longest, _SHORT_TOKEN_HEAD)].decode("utf-8", "replace")
    kept = window[: _clean_cut(window, len(head))]
    shown = redactor.redact_text(kept).encode("utf-8")[:UNREADABLE_EXCERPT_BYTES]
    return shown.decode("utf-8", "ignore"), size


class AdapterProductError(AdapterError):
    """A real product defect: the target refused the request in its own shape (a non-retryable
    4xx, a JSON-RPC error, a handshake reply that does not satisfy ``expect``) or the
    configuration cannot be sent (a placeholder with no value). A success body the adapter
    cannot read is :class:`ResponseMalformed`, an environment failure, since OD-21.

    Per ``AGENTS.md §2`` this is a hard **FAIL** - never masked as a flake.
    """


class AdapterStatusError(AdapterProductError):
    """A non-retryable HTTP status (a 4xx, or a status the retries do not cover): a product error.

    It is still one everywhere it was (the attack phase stops on it, as before). The subclass
    only carries the status, so the composition root can tell a request the endpoint refused
    from the rest: the fingerprint's profile-only probe treats a 4xx to it as a failed probe
    (u09 §7 A-67), since Azure OpenAI's prompt filter answers a blocked prompt with HTTP 400 and
    the error code ``content_filter``, and stopped ``-sV`` on the guardrail layer's benign
    request (pre-merge audit of ``cd413c0``).
    """

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code

    def __reduce__(self) -> tuple[Any, ...]:
        """Rebuild with the status: the default reduction passed the message alone, and
        ``copy.copy`` and ``pickle.loads`` raised ``TypeError`` on the keyword it lacked."""

        return (functools.partial(type(self), status_code=self.status_code), self.args)


class ProviderFilterBlock(AdapterProductError):
    """The provider's own input filter refused the prompt before the model saw it (OD-41).

    Recognised only in the shapes a provider documents (:func:`azure_prompt_filter`, and
    Gemini's ``promptFeedback.blockReason`` in ``adapters.rest``), never from any 4xx: every
    other refusal stays an :class:`AdapterStatusError`. ``status_code`` is the status the refusal
    came with (400 for Azure's, 200 for Gemini's body), ``code`` the provider's own code for it.

    Still an :class:`AdapterProductError`, so whatever is not taught about it treats it as
    before: the fingerprint pass stops on it, except on the guardrail layer's benign probe
    (``cli.wiring.refused_request``, u09 A-67), and the judge evaluator reads it as an unusable
    judge. The attack phase reads the ``blocked_by_provider_filter`` marker instead: the attempt
    is recorded as blocked, not sent again, and the campaign goes on (``core.execute``, u08
    A-69). Before OD-41 it stopped the campaign at the first one, exit 3 after one request.
    """

    #: The structural marker ``core.execute`` reads, as it reads ``is_env_error``.
    blocked_by_provider_filter = True
    #: The same prompt is refused the same way.
    retryable = False

    def __init__(self, message: str, *, status_code: int, code: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code

    def __reduce__(self) -> tuple[Any, ...]:
        """Rebuild with the status and the code (as :class:`AdapterStatusError` does)."""

        rebuild = functools.partial(type(self), status_code=self.status_code, code=self.code)
        return (rebuild, self.args)


#: Azure OpenAI's error code for a prompt its content filter refused.
_AZURE_FILTER_CODE = "content_filter"
#: A filter category name as Azure writes one (``hate``, ``jailbreak``, ``self_harm``): a key
#: of another shape is not written into the attempt, and at most eight are.
_CATEGORY = re.compile(r"[a-z][a-z_]{0,39}")
_MAX_CATEGORIES = 8


def azure_prompt_filter(status_code: int, raw: bytes) -> str | None:
    """What Azure OpenAI's prompt filter says it refused, or ``None`` for any other reply.

    The shape, sourced (OD-41): Microsoft Learn, "Content filtering for Microsoft Foundry Models
    (classic)", section "Content filtering scenarios" (learn.microsoft.com/en-us/azure/
    foundry-classic/foundry-models/concepts/content-filter, read 2026-10-10): "Prompts that are
    classified at a filtered category and severity level return an HTTP 400 error", and
    "Scenario 3: Inappropriate input prompt" gives the body ``{"error": {"message": ..., "type":
    null, "param": "prompt", "code": "content_filter", "status": 400}}``. The "Guardrail
    annotations" page reads ``error.innererror`` beside that code; the Azure OpenAI REST
    reference (2024-10-21) names its code, ``innerErrorCode``: ``ResponsibleAIPolicyViolation``,
    "The prompt violated one of more content filter rules". The body Azure sends, with
    ``innererror.content_filter_result`` per category, is the one in
    ``tests/cli/test_input_filter_probe.py`` (pre-merge audit of ``cd413c0``).

    Recognised: status 400 and ``error.code`` exactly ``content_filter``; ``innererror`` is
    optional, as in Scenario 3. Returned: the categories ``innererror.content_filter_result``
    (or ``content_filter_results``) marks ``filtered: true``. ``innererror.code`` is read and
    not written: the redactor's entropy rule masks ``ResponsibleAIPolicyViolation``, and the
    attempt would read ``«REDACTED:high_entropy:...»`` as if a secret had been in it. Nothing of
    the provider's own message is written either.
    """

    if status_code != 400:
        return None
    try:
        payload = bounded_loads(raw)
    except ValueError:
        return None
    error = payload.get("error") if isinstance(payload, Mapping) else None
    if not isinstance(error, Mapping) or error.get("code") != _AZURE_FILTER_CODE:
        return None
    inner = error.get("innererror")
    results: object = None
    if isinstance(inner, Mapping):
        results = inner.get("content_filter_result", inner.get("content_filter_results"))
    filtered = sorted(
        str(name)
        for name, verdict in (results.items() if isinstance(results, Mapping) else ())
        if isinstance(name, str)
        and _CATEGORY.fullmatch(name)
        and isinstance(verdict, Mapping)
        and verdict.get("filtered") is True
    )[:_MAX_CATEGORIES]
    detail = f"error code {_AZURE_FILTER_CODE}"
    return detail + (f"; filtered: {', '.join(filtered)}" if filtered else "")


#: What every :class:`ProviderFilterBlock` message says, after where the refusal came from. The
#: same words as an input-side block read from a reply (``shared.provider_filter``, OD-42).
FILTER_REFUSED = INPUT_FILTER_REFUSED


class SamplingRefused(AdapterProductError):
    """A 400 whose error names, as a parameter, a sampling field the request sent (u12 A-68).

    Not retried, as no 4xx is: the same request is refused the same way. It is a product error,
    so the campaign stops at the first one (the ``--judge`` model's too: the evaluator re-raises
    it), now in words that name the fix: a model that takes no ``temperature`` or ``top_p``
    (Anthropic's API reference lists Opus 4.7 and later, Sonnet 5, and the Fable and Mythos 5
    families) needs ``sampling: false`` under the target file's ``capabilities``. Before, the
    error said only ``non-retryable HTTP 400``. The target's own error text is not quoted, only
    which of the parameters it names (:func:`sampling_params_named`).
    """


#: The request fields a model can refuse as sampling, as an error body names them.
_SAMPLING_PARAMS: tuple[str, ...] = ("temperature", "top_p", "top_k")

#: A parameter name as an error names a parameter, not as a word of a quoted prompt: a token
#: between backticks or quotes, or the first word of the message.
_QUOTED = r"[`'\"]{name}[`'\"]"
_LEADING = r"^\s*{name}(?![\w.])"


def sampling_params_named(raw: bytes) -> list[str]:
    """The sampling parameters a 400's JSON error names as parameters (u12 A-68).

    Named means: ``error.param`` is the name (its last dotted part, so ``body.temperature``
    counts), or ``error.message`` holds it as a quoted token (`` `temperature` ``,
    ``'top_p'``, ``"top_k"``) or starts with it (``temperature is not supported``, ``top_k:
    unexpected parameter``), case-insensitively. A word of a quoted prompt (``Flagged: 'the
    temperature of the room'``) or part of a longer identifier (``my_temperature_override``)
    is not. The caller fires only on a name the request actually sent.
    """

    try:
        payload = bounded_loads(raw)
    except ValueError:
        return []
    error = payload.get("error") if isinstance(payload, Mapping) else None
    if not isinstance(error, Mapping):
        return []
    param = error.get("param")
    message = error.get("message")
    named: list[str] = []
    for name in _SAMPLING_PARAMS:
        by_param = isinstance(param, str) and param.strip().lower().rsplit(".", 1)[-1] == name
        by_message = isinstance(message, str) and any(
            re.search(pattern.format(name=name), message, re.IGNORECASE)
            for pattern in (_QUOTED, _LEADING)
        )
        if by_param or by_message:
            named.append(name)
    return named


#: The ``Content-Encoding`` values :func:`read_capped` decodes itself, with the ``wbits`` zlib
#: needs: 47 detects a gzip or a zlib header; raw deflate is tried when "deflate" has neither.
_DECODED_ENCODINGS: dict[str, int] = {"gzip": 47, "x-gzip": 47, "deflate": 47}

#: The ``Accept-Encoding`` every adapter sends: exactly what :func:`read_capped` decodes. Left to
#: httpx, the header grows ``br`` and ``zstd`` whenever ``brotli`` or ``zstandard`` happens to
#: be importable, and a server that took the offer would have every reply refused as
#: undecodable: every attempt inconclusive, a silent false negative (pre-commit audit of the
#: leftovers, 2026-10-04).
ACCEPT_ENCODING = "gzip, deflate"

#: The raw id that carries the model name the provider echoes; redacted without the entropy rule.
_MODEL_ID = "model"


async def read_capped(response: httpx.Response, label: str) -> bytes:
    """Read a streamed body, refusing one larger than :data:`MAX_RESPONSE_BYTES`.

    The single cap for every adapter that reads a target over the wire. The check runs per
    chunk, so an oversized body is abandoned mid-stream instead of being buffered whole and
    measured afterwards, which is what the MCP adapter did (review of PR #32).

    The body is read RAW and decoded here, never more than one byte past the cap. httpx
    decompressed each network chunk (up to 64 KiB read) whole before the cap could look at it,
    so a 200 KB gzip reply allocated about 150 MB on its way to being refused. The compressed
    bytes are capped too, so an endless stream of empty deflate blocks ends.

    An error status whose body cannot be decoded, or is over the cap, returns an empty body: the
    status is what classifies that reply, and a 401 must not turn into an inconclusive
    "undecodable" or "too large". The size half was missing before PR #68: a 401 with a 5 MB
    body was an inconclusive attempt where a short one stops the run, and once the ``-sV``
    probe pass let a refused reply fail only its probe, ``dottore fingerprint`` exited 0 on it
    (delta audit of OD-23).
    """

    try:
        return await _read_decoded(response, label)
    except (ResponseUndecodable, ResponseTooLarge):
        if response.is_success:
            raise
        return b""


async def _read_decoded(response: httpx.Response, label: str) -> bytes:
    """:func:`read_capped` without the error-status leniency."""

    def too_large() -> ResponseTooLarge:
        return ResponseTooLarge(f"{label} exceeded {MAX_RESPONSE_BYTES} bytes; not read further")

    if response.is_stream_consumed:
        # A transport that handed over a body httpx had already read and decoded (a test
        # double built with `content=`): there is no raw stream left, only the result.
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise too_large()
        return response.content

    encoding = response.headers.get("content-encoding", "").strip().lower()
    if encoding in ("", "identity"):
        decoder = None
    elif encoding in _DECODED_ENCODINGS:
        decoder = zlib.decompressobj(_DECODED_ENCODINGS[encoding])
    else:
        raise ResponseUndecodable(f"{label} uses Content-Encoding {encoding!r}, not decoded")

    chunks: list[bytes] = []
    size = 0
    raw_size = 0
    first = True
    async for raw in response.aiter_raw():
        raw_size += len(raw)
        if raw_size > MAX_RESPONSE_BYTES:
            raise too_large()
        if decoder is None:
            pieces = [raw]
        else:
            if first and encoding == "deflate" and raw and raw[0] & 0x0F != 8:
                decoder = zlib.decompressobj(-zlib.MAX_WBITS)  # raw deflate, no zlib header
            pieces = _inflate(decoder, raw, MAX_RESPONSE_BYTES + 1 - size, label)
        first = False
        for piece in pieces:
            size += len(piece)
            if size > MAX_RESPONSE_BYTES:
                raise too_large()
            chunks.append(piece)
    if decoder is not None:
        try:
            chunks.append(decoder.flush())
        except zlib.error as exc:
            raise ResponseUndecodable(f"{label}: corrupt {encoding} body ({exc})") from exc
        if not decoder.eof and raw_size:
            raise ResponseUndecodable(f"{label}: truncated {encoding} body")
    return b"".join(chunks)


def _inflate(decoder: Any, data: bytes, room: int, label: str) -> list[bytes]:
    """Decompress ``data`` without producing more than ``room`` bytes (one past the cap)."""

    pieces: list[bytes] = []
    try:
        while data and room > 0:
            piece = decoder.decompress(data, room)
            pieces.append(piece)
            room -= len(piece)
            data = decoder.unconsumed_tail
    except zlib.error as exc:
        raise ResponseUndecodable(f"{label}: corrupt compressed body ({exc})") from exc
    return pieces


@dataclass(frozen=True)
class RetryConfig:
    """Retry / timeout / backoff policy (contract §5 step 1).

    ``max_retries`` counts *additional* attempts after the first try. Backoff is
    capped exponential: ``min(base * 2**n, cap)`` seconds. ``sleep`` is injectable
    so tests never actually wait.
    """

    max_retries: int = 2
    backoff_base_s: float = 0.05
    backoff_cap_s: float = 2.0
    timeout_s: float = 30.0

    def backoff_for(self, attempt: int) -> float:
        """Backoff delay before retry ``attempt`` (0-indexed), capped."""

        return min(self.backoff_base_s * (2.0**attempt), self.backoff_cap_s)


class _UnreadableLogprob(Exception):
    """A logprob figure ``readable_logprob`` refuses (u04 §7, A-39): what holds it is not read.

    Not only a number no model produces: a string that spells one, a bool, anything that is not a
    JSON number. Caught where it is raised, so no message names it; it is named so the redactor
    would keep the name if one did (``_ImpossibleFigure`` read as a high-entropy mask, u01 A-63).
    """


def _figure(value: object) -> float:
    """``value`` as a logprob (:func:`~ildottore.shared.logprobs.readable_logprob`), or raise."""

    figure = readable_logprob(value)
    if figure is None:
        raise _UnreadableLogprob
    return figure


def _coerce_top(raw_top: object) -> list[tuple[str, float]] | None:
    """Normalize a provider ``top_logprobs`` blob into ``[(token, logprob), …]``.

    Accepts either a list of ``{"token": str, "logprob": float}`` entries
    (OpenAI shape) or a ``{token: logprob}`` mapping. Returns ``None`` when
    nothing usable is present (ADR-0005: no fabricated alternatives). A null
    alternative is skipped in both shapes, and a blob of neither shape is no
    alternatives (a number or a bool there raised ``TypeError``). One alternative
    whose figure no model produces, whether or not it names a token, makes them all
    ``None`` (u04 §7, A-39), not the whole block: no alternative is ever scored, so
    the token's own figure still is.
    """

    pairs: list[tuple[str, float]] = []
    try:
        if isinstance(raw_top, Mapping):
            for map_token, map_logprob in raw_top.items():
                if map_logprob is not None:
                    pairs.append((str(map_token), _figure(map_logprob)))
        elif isinstance(raw_top, Sequence) and not isinstance(raw_top, str):
            for entry in raw_top:
                if isinstance(entry, Mapping):
                    token = entry.get("token")
                    logprob = entry.get("logprob")
                    if logprob is None:
                        continue
                    figure = _figure(logprob)  # before the token, as in `map_logprobs`
                    if token is not None:
                        pairs.append((str(token), figure))
    except _UnreadableLogprob:
        return None
    return pairs or None


def map_logprobs(
    entries: Sequence[Mapping[str, Any]] | None,
) -> list[TokenLogprob] | None:
    """Map a provider-neutral token list into :class:`TokenLogprob` (ADR-0005).

    Each entry is ``{"token": str, "logprob": float, "top_logprobs"?: …}``.
    Returns ``None`` (not ``[]``) when ``entries`` is ``None`` - so
    ``logprob_membership`` returns ``inconclusive: capability_unavailable``
    (contract §4 KEEP, ADR-0005). An empty-but-present list stays ``[]``.

    A block in which any entry's own figure is one no model produces, whether or not
    the entry names its token, is ``None`` too, as if the reply carried no block
    (u04 §7, A-39): the attempt and every evaluator of its text go on, and nothing
    is scored from the rest of the block. Such a figure among a token's
    alternatives drops only those alternatives (:func:`_coerce_top`).
    """

    if entries is None:
        return None
    out: list[TokenLogprob] = []
    try:
        for entry in entries:
            token = entry.get("token")
            logprob = entry.get("logprob")
            if logprob is None:
                # A present-but-broken entry is a product-shape problem; skip it here
                # and let the adapter's response validation decide. Being lenient
                # keeps a single stray null from nuking an otherwise-valid list.
                continue
            # Read before the token is: skipping an entry with no token first let its
            # impossible figure pass unseen and the rest be scored (delta audit, L2).
            figure = _figure(logprob)
            if token is None:
                continue
            out.append(
                TokenLogprob(
                    token=str(token),
                    logprob=figure,
                    top=_coerce_top(entry.get("top_logprobs")),
                )
            )
    except _UnreadableLogprob:
        # The whole block, not the entry (OD-24): the readable rest scored alone is not the
        # reply's figure, and confident tokens around one positive figure read as "likely
        # memorized". Before, ``float()`` raised here and stopped the command (exit 1 or 3).
        # Only an entry's own figure gets here; `_coerce_top` keeps its alternatives' to itself.
        return None
    return out


def redact_ids(redactor: Redactor, ids: Mapping[str, Any]) -> dict[str, Any]:
    """Redactor-mask provider request/response ids before they persist.

    The ``model`` echo, when it is a string, is a model name, not an opaque id: it skips the
    entropy rule (patterns and known credentials still apply). Mixed-case names such as
    ``meta-llama/Meta-Llama-3-8B-Instruct`` were masked as high-entropy before the
    fingerprint's metadata layer could read them (audit of the fingerprint). A value split over
    the items of a list (a WebSocket transcript's deltas) is masked as the text it makes
    (:func:`ildottore.redactor.redact_split`, A-77). This is in memory only: the evidence store,
    the run store and the reports apply their own full redactor to everything they keep. Shared
    by the HTTP adapters and the WebSocket one.
    """

    model = ids.get(_MODEL_ID)
    if not isinstance(model, str):  # a nested value gets the full redactor
        return cast("dict[str, Any]", redact_split(redactor, dict(ids)))
    rest = {key: value for key, value in ids.items() if key != _MODEL_ID}
    redacted = cast("dict[str, Any]", redact_split(redactor, rest))
    redacted[_MODEL_ID] = redactor.without_entropy().redact_text(model)
    return {key: redacted[key] for key in ids}


@dataclass
class BaseAdapter(ABC):
    """Common send loop shared by every concrete adapter.

    Subclasses provide the provider name, capability declaration and the two pure
    functions that build the wire request and parse the wire response. The base
    owns the allowlist gate, retry loop, error classification and redaction so no
    subclass can bypass them (contract §4 KEEP).
    """

    id: str
    base_url: str
    allowlist: EndpointAllowlist
    api_key: str | None = None
    model: str | None = None
    retry: RetryConfig = field(default_factory=RetryConfig)
    redactor: Redactor = field(default_factory=Redactor)
    client: httpx.AsyncClient | None = None
    #: The path the OPERATOR declared in ``target.endpoint``, when it differs from the
    #: provider default. ``_full_url`` was ``base_url + _endpoint_path`` with a hardcoded
    #: path, so a gateway-hosted model had its path silently discarded:
    #: ``https://x.openai.azure.com/openai/deployments/gpt4o/chat/completions`` went on the
    #: wire as ``https://x.openai.azure.com/v1/chat/completions``. Azure OpenAI, LiteLLM and
    #: every corporate gateway host the API under a prefix, so the declared path is data, not
    #: decoration: the scope allowlist is built from it and the request has to match.
    path_override: str | None = None

    # --- provider hooks (subclass contract) -----------------------------------

    @property
    @abstractmethod
    def _endpoint_path(self) -> str:
        """Provider path appended to ``base_url`` (e.g. ``/v1/chat/completions``)."""

    @abstractmethod
    def capabilities(self) -> Capabilities:
        """Static, declared capabilities for this adapter+config (contract §4)."""

    @abstractmethod
    def _build_request(self, request: ModelRequest) -> tuple[dict[str, Any], dict[str, str]]:
        """Return ``(json_body, headers)`` for the wire call. Pure, no I/O."""

    @abstractmethod
    def _parse_response(self, payload: Mapping[str, Any]) -> ModelResponse:
        """Turn a parsed JSON success body into a :class:`ModelResponse`. Pure.

        Raise :class:`ResponseMalformed` on a malformed / unexpected shape (OD-21).
        """

    @property
    def unreadable_advice(self) -> str:
        """What to check when this target's replies cannot be read (OD-21, u08 A-74)."""

        return "check the target's endpoint and provider"

    #: True for an adapter whose replies may be a JSON array (a REST template rooted at an index).
    @property
    def reads_array_body(self) -> bool:
        return False

    def _parse_array_response(self, payload: list[Any]) -> ModelResponse:
        """Parse a success body that is a JSON array (only where :attr:`reads_array_body`)."""

        raise ResponseMalformed(
            f"{self.id}: success response JSON was not an object; not evaluated"
        )

    def _checked(self, parsed: ModelResponse, label: str) -> ModelResponse:
        """``parsed``, its tool calls' JSON-text arguments measured for nesting.

        OpenAI carries a call's arguments as a JSON string, which the reply's parse never opened:
        the evaluators and the in-band tool loop do, so it is measured here.
        """

        for call in parsed.tool_calls:
            try:
                check_argument_nesting(call)
            except NestedTooDeeply as exc:
                raise ResponseTooDeep(
                    f"{label} has a tool call whose arguments are {exc}; not evaluated"
                ) from exc
        return parsed

    def _unreadable(self, message: str, body: bytes | str) -> ResponseMalformed:
        """A :class:`ResponseMalformed` with an excerpt of ``body`` and this adapter's advice."""

        return ResponseMalformed(message).with_reply(body, self.redactor, self.unreadable_advice)

    def _prompt_blocked(self, payload: Mapping[str, Any]) -> tuple[str, str] | None:
        """``(code, detail)`` when a success body says the provider's filter refused the prompt.

        ``None`` here: an OpenAI or Anthropic success body is a reply. The REST adapter reads
        Gemini's prompt block (OD-41), which comes back as a success body with no candidate.
        """

        return None

    # --- wire mechanics --------------------------------------------------------

    @property
    def _request_path(self) -> str:
        """The path this adapter will actually request: declared first, provider default."""

        return self.path_override or self._endpoint_path

    def _full_url(self) -> str:
        """Compose the absolute endpoint URL (base + the path that will be requested)."""

        return self.base_url.rstrip("/") + self._request_path

    def _redact_ids(self, ids: Mapping[str, Any]) -> dict[str, Any]:
        """Redactor-mask provider request/response ids before they persist (:func:`redact_ids`)."""

        return redact_ids(self.redactor, ids)

    def _check_allowlist(self, url: str) -> None:
        """Refuse an off-allowlist URL **before** any egress (contract §4 KEEP)."""

        if not self.allowlist.is_allowed(url):
            raise EndpointNotAllowed(url)

    async def send(self, request: ModelRequest) -> ModelResponse:
        """Send ``request`` to the target, honoring the allowlist + retry policy.

        Order is load-bearing: the allowlist gate runs first, so a refused URL
        issues **zero** ``httpx`` calls (contract §7). Transient failures retry
        with backoff then surface as :class:`AdapterEnvError` (env → skip); a
        success body it cannot read raises :class:`ResponseMalformed` (env, not retried).
        """

        url = self._full_url()
        self._check_allowlist(url)  # BEFORE httpx - unbypassable.

        body, headers = self._build_request(request)
        owns_client = self.client is None
        client = self.client or httpx.AsyncClient(timeout=self.retry.timeout_s)
        try:
            return await self._send_with_retries(client, url, body, headers)
        finally:
            if owns_client:
                await client.aclose()

    async def _send_with_retries(
        self,
        client: httpx.AsyncClient,
        url: str,
        body: dict[str, Any],
        headers: dict[str, str],
    ) -> ModelResponse:
        """Retry transient failures with capped backoff; classify the rest."""

        last_env_detail = ""
        attempts = self.retry.max_retries + 1
        for attempt in range(attempts):
            try:
                # follow_redirects=False per call, defense-in-depth: even if an injected
                # client enabled redirects, a 3xx to an off-allowlist host is NOT followed
                # (the allowlist gate runs once, before the loop, audit low).
                async with client.stream(
                    "POST",
                    url,
                    json=body,
                    headers={**headers, "accept-encoding": ACCEPT_ENCODING},
                    timeout=self.retry.timeout_s,
                    follow_redirects=False,
                ) as response:
                    if response.status_code in _RETRYABLE_STATUS:
                        last_env_detail = f"HTTP {response.status_code}"
                        retry_now = True
                    else:
                        retry_now = False
                        raw = await self._read_capped(response)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_env_detail = f"{type(exc).__name__}: {exc}"
                await self._maybe_backoff(attempt, attempts)
                continue

            if retry_now:
                await self._maybe_backoff(attempt, attempts)
                continue

            return self._handle_final_response(response, raw, body=body)

        raise AdapterEnvError(
            f"{self.id}: exhausted {attempts} attempt(s) to {self._request_path}: "
            f"{last_env_detail or 'transient failure'}"
        )

    async def _maybe_backoff(self, attempt: int, attempts: int) -> None:
        """Sleep before the next retry, unless this was the last attempt."""

        if attempt < attempts - 1:
            await asyncio.sleep(self.retry.backoff_for(attempt))

    async def _read_capped(self, response: httpx.Response) -> bytes:
        """Read the body, refusing one larger than :data:`MAX_RESPONSE_BYTES`.

        The body used to be read whole, with no limit: three 60 MB replies cost 1.5 GB of
        memory, 72 s and 180 MB of evidence, and the run still exited 0 (audit 2026-10-03,
        SEC-07). A target that answers with more than any model reply needs is not a finding
        to evaluate; it is an environment failure for this attempt, which is inconclusive and
        is not retried. The cap also bounds the input every spec regex runs over.
        """

        return await read_capped(response, f"{self.id}: response from {self._request_path}")

    #: True for an adapter that puts sampling on the wire (OpenAI, Anthropic), whose 400 naming
    #: a sampling parameter it sent is a :class:`SamplingRefused` (u12 A-68).
    sends_sampling: ClassVar[bool] = False

    def _handle_final_response(
        self, response: httpx.Response, raw: bytes, *, body: Mapping[str, Any] | None = None
    ) -> ModelResponse:
        """Classify a non-retryable response: 2xx → parse (unreadable: env), else product defect."""

        if response.is_success:
            label = f"{self.id}: response from {self._request_path}"
            try:
                # Half a character (a lone surrogate) parses, and then no UTF-8 writer
                # takes it: the evidence store aborted the campaign on one (A-47).
                payload = well_formed_json(bounded_loads(raw))
            except NestedTooDeeply as exc:
                raise ResponseTooDeep(f"{label} is {exc}; not evaluated") from exc
            except ValueError as exc:  # non-JSON success body = malformed (OD-21)
                raise self._unreadable(
                    f"{self.id}: success response was not valid JSON: {exc}; not evaluated", raw
                ) from exc
            if isinstance(payload, list) and self.reads_array_body:
                # A template rooted at an index (Hugging Face's `0.generated_text`) reads an array
                # (pre-merge audit of 598f0858, LOW 2); no provider's prompt block is an array.
                try:
                    return self._checked(self._parse_array_response(payload), label)
                except ResponseMalformed as exc:
                    exc.with_reply(raw, self.redactor, self.unreadable_advice)
                    raise
            if not isinstance(payload, Mapping):
                raise self._unreadable(
                    f"{self.id}: success response JSON was not an object; not evaluated", raw
                )
            blocked = self._prompt_blocked(payload)
            if blocked is not None:
                code, detail = blocked
                raise ProviderFilterBlock(
                    f"{label}: {FILTER_REFUSED} ({detail})",
                    status_code=response.status_code,
                    code=code,
                )
            try:
                parsed = self._parse_response(payload)
            except ResponseMalformed as exc:  # not the provider's shape: keep the body too
                exc.with_reply(raw, self.redactor, self.unreadable_advice)
                raise
            return self._checked(parsed, label)

        # The provider's input filter refused the prompt (OD-41): the attempt is blocked, not a
        # defect. Read first: its 400 names the prompt, never a sampling parameter.
        filtered = azure_prompt_filter(response.status_code, raw)
        if filtered is not None:
            raise ProviderFilterBlock(
                f"{self.id}: non-retryable HTTP {response.status_code} from "
                f"{self._request_path}: {FILTER_REFUSED} ({filtered})",
                status_code=response.status_code,
                code=_AZURE_FILTER_CODE,
            )
        # A non-retryable 4xx (auth, bad request) is a product/config defect -
        # not something a retry will fix, and not to be masked as a flake.
        # Only a parameter the request sent: an error naming top_k, which no adapter sends, or a
        # moderation 400 quoting "the temperature of the room" is not this (pre-merge audit).
        sent = [name for name in _SAMPLING_PARAMS if body is not None and name in body]
        named = sampling_params_named(raw) if response.status_code == 400 else []
        refused = [name for name in named if name in sent]
        if self.sends_sampling and refused:
            raise SamplingRefused(
                f"{self.id}: non-retryable HTTP 400 from {self._request_path}: the target "
                f"refused the request's {' and '.join(refused)}. If the model takes no "
                "temperature or top_p, set `sampling: false` under capabilities in the target "
                f"file of {self.id}: the scanner then sends neither, and its replies are not "
                "temperature-0 deterministic. A value it refuses comes from the spec, the "
                "target file's sampling_defaults or the judge"
            )
        raise AdapterStatusError(
            f"{self.id}: non-retryable HTTP {response.status_code} from {self._request_path}",
            status_code=response.status_code,
        )
