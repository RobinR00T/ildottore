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
  ``AGENTS.md §2``). A malformed 200 body is a **product defect** →
  :class:`AdapterProductError` (never masked as a flake); one nested too deeply to evaluate
  is :class:`ResponseTooDeep`, an environment failure that is not retried. A lone surrogate in
  a body is read as U+FFFD where it is parsed (:mod:`ildottore.shared.wellformed`, A-47).
* **Logprob mapping** - :func:`map_logprobs` folds a provider-neutral token list
  into :class:`~ildottore.shared.models.TokenLogprob` (ADR-0005 / OD-1).
* **Redaction** - raw request/response ids are redacted through u01's redactor
  before they land on :class:`~ildottore.shared.models.ModelResponse.raw_ids`.

Capabilities are **static per adapter+config** (declared, not probed at send
time - contract §4 KEEP; live probing is u09 fingerprint).
"""

from __future__ import annotations

import asyncio
import re
import zlib
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, cast

import httpx

from ildottore.policy import EndpointAllowlist
from ildottore.redactor import Redactor
from ildottore.shared.logprobs import readable_logprob
from ildottore.shared.models import (
    Capabilities,
    ModelRequest,
    ModelResponse,
    TokenLogprob,
)
from ildottore.shared.nesting import NestedTooDeeply, bounded_loads
from ildottore.shared.toolcalls import check_argument_nesting
from ildottore.shared.wellformed import well_formed_json

__all__ = [
    "ACCEPT_ENCODING",
    "AdapterEnvError",
    "AdapterError",
    "AdapterProductError",
    "BaseAdapter",
    "EndpointNotAllowed",
    "ResponseTooDeep",
    "ResponseTooLarge",
    "ResponseUndecodable",
    "RetryConfig",
    "SamplingRefused",
    "map_logprobs",
    "read_capped",
    "redact_ids",
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
    retried; a body that is not JSON at all is still a product defect.
    """

    is_env_error = True
    retryable = False


class AdapterProductError(AdapterError):
    """A real product defect (e.g. a malformed / unparseable success response).

    Per ``AGENTS.md §2`` this is a hard **FAIL** - never masked as a flake.
    """


class SamplingRefused(AdapterProductError):
    """A 400 whose error names a sampling parameter the request sent (u12 A-68).

    Not retried, as no 4xx is: the same request is refused the same way. It is a product error,
    so the campaign stops at the first one, now in words that name the fix: a model that takes
    no ``temperature`` or ``top_p`` (Anthropic's API reference lists Opus 4.7 and later, Sonnet 5
    and the Fable models) needs ``sampling: false`` under the target file's ``capabilities``.
    Before, the error said only ``non-retryable HTTP 400``. The target's own error text is not
    quoted, only which of the parameters it names.
    """


#: The request fields a model can refuse as sampling, as an error body names them.
_SAMPLING_PARAMS: tuple[str, ...] = ("temperature", "top_p", "top_k")


def _sampling_params_named(raw: bytes) -> list[str]:
    """The sampling parameters a 400's JSON error names (``error.message``, ``error.param``)."""

    try:
        payload = bounded_loads(raw)
    except ValueError:
        return []
    error = payload.get("error") if isinstance(payload, Mapping) else None
    if not isinstance(error, Mapping):
        return []
    text = " ".join(
        value for value in (error.get("message"), error.get("param")) if isinstance(value, str)
    ).lower()
    return [name for name in _SAMPLING_PARAMS if re.search(rf"\b{name}\b", text)]


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


class _ImpossibleFigure(Exception):
    """A logprob figure no model produces (u04 §7, A-39): what holds it is not read."""


def _figure(value: object) -> float:
    """``value`` as a logprob (:func:`~ildottore.shared.logprobs.readable_logprob`), or raise."""

    figure = readable_logprob(value)
    if figure is None:
        raise _ImpossibleFigure
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
    except _ImpossibleFigure:
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
    except _ImpossibleFigure:
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
    fingerprint's metadata layer could read them (audit of the fingerprint). This is in
    memory only: the evidence store, the run store and the reports apply their own full
    redactor to everything they keep. Shared by the HTTP adapters and the WebSocket one.
    """

    model = ids.get(_MODEL_ID)
    if not isinstance(model, str):  # a nested value gets the full redactor
        return cast("dict[str, Any]", redactor.redact(dict(ids)))
    rest = {key: value for key, value in ids.items() if key != _MODEL_ID}
    redacted = cast("dict[str, Any]", redactor.redact(rest))
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

        Raise :class:`AdapterProductError` on a malformed / unexpected shape.
        """

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
        malformed success body raises :class:`AdapterProductError` (defect).
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
        """Classify a non-retryable response: 2xx → parse, else product defect."""

        if response.is_success:
            label = f"{self.id}: response from {self._request_path}"
            try:
                # Half a character (a lone surrogate) parses, and then no UTF-8 writer
                # takes it: the evidence store aborted the campaign on one (A-47).
                payload = well_formed_json(bounded_loads(raw))
            except NestedTooDeeply as exc:
                raise ResponseTooDeep(f"{label} is {exc}; not evaluated") from exc
            except ValueError as exc:  # non-JSON success body = malformed
                raise AdapterProductError(
                    f"{self.id}: success response was not valid JSON: {exc}"
                ) from exc
            if not isinstance(payload, Mapping):
                raise AdapterProductError(f"{self.id}: success response JSON was not an object")
            parsed = self._parse_response(payload)
            # OpenAI carries a call's arguments as a JSON string, which the parse above never
            # opened: the evaluators and the in-band tool loop do, so it is measured here.
            for call in parsed.tool_calls:
                try:
                    check_argument_nesting(call)
                except NestedTooDeeply as exc:
                    raise ResponseTooDeep(
                        f"{label} has a tool call whose arguments are {exc}; not evaluated"
                    ) from exc
            return parsed

        # A non-retryable 4xx (auth, bad request) is a product/config defect -
        # not something a retry will fix, and not to be masked as a flake.
        sent = [name for name in ("temperature", "top_p") if body is not None and name in body]
        named = _sampling_params_named(raw) if response.status_code == 400 else []
        if self.sends_sampling and sent and named:
            raise SamplingRefused(
                f"{self.id}: non-retryable HTTP 400 from {self._request_path}: the target "
                f"refused the request's sampling (its error names {', '.join(named)}; the request "
                f"sent {' and '.join(sent)}). A model that takes no temperature or top_p needs "
                "`sampling: false` under capabilities in its target file; the scanner then sends "
                "neither, and its replies are not temperature-0 deterministic"
            )
        raise AdapterProductError(
            f"{self.id}: non-retryable HTTP {response.status_code} from {self._request_path}"
        )
