"""Shared adapter plumbing (u04, contract §5 step 1).

Everything provider-agnostic lives here so each concrete adapter (``openai``,
``anthropic``, ``rest``) stays thin (ADR-0002 — own the bytes, don't normalize):

* **Allowlist gate** — every egress is checked against u01's default-deny
  :class:`~ildottore.policy.EndpointAllowlist` **before** the ``httpx`` call is
  issued (contract §4 KEEP: unbypassable by subclasses). Out-of-scope host or
  off-prefix path raises :class:`EndpointNotAllowed`; **zero** requests leave.
* **Retry / timeout / backoff** — transient statuses (429/502/503/504) and
  transport/timeout errors are retried with capped exponential backoff, then the
  attempt is *skipped* by re-raising as :class:`AdapterEnvError` (env, per
  ``AGENTS.md §2``). A malformed 200 body is a **product defect** →
  :class:`AdapterProductError` (never masked as a flake).
* **Logprob mapping** — :func:`map_logprobs` folds a provider-neutral token list
  into :class:`~ildottore.shared.models.TokenLogprob` (ADR-0005 / OD-1).
* **Redaction** — raw request/response ids are redacted through u01's redactor
  before they land on :class:`~ildottore.shared.models.ModelResponse.raw_ids`.

Capabilities are **static per adapter+config** (declared, not probed at send
time — contract §4 KEEP; live probing is u09 fingerprint).
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

import httpx

from ildottore.policy import EndpointAllowlist
from ildottore.redactor import Redactor
from ildottore.shared.models import (
    Capabilities,
    ModelRequest,
    ModelResponse,
    TokenLogprob,
)

__all__ = [
    "AdapterEnvError",
    "AdapterError",
    "AdapterProductError",
    "BaseAdapter",
    "EndpointNotAllowed",
    "RetryConfig",
    "map_logprobs",
]

# HTTP statuses that mean "try again later" (transient / env, not a defect).
_RETRYABLE_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})


class AdapterError(Exception):
    """Base class for every u04 adapter error."""


class EndpointNotAllowed(AdapterError):
    """The requested URL is not on the scope allowlist (S3 default-deny).

    Raised **before** any network call — the request never leaves the process.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        super().__init__(f"endpoint not allowed by scope: {url!r}")


class AdapterEnvError(AdapterError):
    """A transient / environment failure (rate limit, 5xx, timeout, transport).

    Per ``AGENTS.md §2`` the runner treats this as **retry/skip**, not a product
    defect. Raised only after the retry budget is exhausted.
    """


class AdapterProductError(AdapterError):
    """A real product defect (e.g. a malformed / unparseable success response).

    Per ``AGENTS.md §2`` this is a hard **FAIL** — never masked as a flake.
    """


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


def _coerce_top(
    raw_top: Sequence[Any] | Mapping[str, Any] | None,
) -> list[tuple[str, float]] | None:
    """Normalize a provider ``top_logprobs`` blob into ``[(token, logprob), …]``.

    Accepts either a list of ``{"token": str, "logprob": float}`` entries
    (OpenAI shape) or a ``{token: logprob}`` mapping. Returns ``None`` when
    nothing usable is present (ADR-0005: no fabricated alternatives).
    """

    if raw_top is None:
        return None
    pairs: list[tuple[str, float]] = []
    if isinstance(raw_top, Mapping):
        for map_token, map_logprob in raw_top.items():
            pairs.append((str(map_token), float(map_logprob)))
        return pairs or None
    for entry in raw_top:
        if isinstance(entry, Mapping):
            token = entry.get("token")
            logprob = entry.get("logprob")
            if token is None or logprob is None:
                continue
            pairs.append((str(token), float(logprob)))
    return pairs or None


def map_logprobs(
    entries: Sequence[Mapping[str, Any]] | None,
) -> list[TokenLogprob] | None:
    """Map a provider-neutral token list into :class:`TokenLogprob` (ADR-0005).

    Each entry is ``{"token": str, "logprob": float, "top_logprobs"?: …}``.
    Returns ``None`` (not ``[]``) when ``entries`` is ``None`` — so
    ``logprob_membership`` returns ``inconclusive: capability_unavailable``
    (contract §4 KEEP, ADR-0005). An empty-but-present list stays ``[]``.
    """

    if entries is None:
        return None
    out: list[TokenLogprob] = []
    for entry in entries:
        token = entry.get("token")
        logprob = entry.get("logprob")
        if token is None or logprob is None:
            # A present-but-broken entry is a product-shape problem; skip it here
            # and let the adapter's response validation decide. Being lenient
            # keeps a single stray null from nuking an otherwise-valid list.
            continue
        raw_top = entry.get("top_logprobs")
        out.append(
            TokenLogprob(
                token=str(token),
                logprob=float(logprob),
                top=_coerce_top(raw_top),
            )
        )
    return out


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

    def _full_url(self) -> str:
        """Compose the absolute endpoint URL (base + provider path)."""

        return self.base_url.rstrip("/") + self._endpoint_path

    def _redact_ids(self, ids: Mapping[str, Any]) -> dict[str, Any]:
        """Redactor-mask provider request/response ids before they persist."""

        return cast("dict[str, Any]", self.redactor.redact(dict(ids)))

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
        self._check_allowlist(url)  # BEFORE httpx — unbypassable.

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
                response = await client.post(
                    url, json=body, headers=headers, timeout=self.retry.timeout_s
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_env_detail = f"{type(exc).__name__}: {exc}"
                await self._maybe_backoff(attempt, attempts)
                continue

            if response.status_code in _RETRYABLE_STATUS:
                last_env_detail = f"HTTP {response.status_code}"
                await self._maybe_backoff(attempt, attempts)
                continue

            return self._handle_final_response(response)

        raise AdapterEnvError(
            f"{self.id}: exhausted {attempts} attempt(s) to {self._endpoint_path}: "
            f"{last_env_detail or 'transient failure'}"
        )

    async def _maybe_backoff(self, attempt: int, attempts: int) -> None:
        """Sleep before the next retry, unless this was the last attempt."""

        if attempt < attempts - 1:
            await asyncio.sleep(self.retry.backoff_for(attempt))

    def _handle_final_response(self, response: httpx.Response) -> ModelResponse:
        """Classify a non-retryable response: 2xx → parse, else product defect."""

        if response.is_success:
            try:
                payload = response.json()
            except ValueError as exc:  # non-JSON success body = malformed
                raise AdapterProductError(
                    f"{self.id}: success response was not valid JSON: {exc}"
                ) from exc
            if not isinstance(payload, Mapping):
                raise AdapterProductError(f"{self.id}: success response JSON was not an object")
            return self._parse_response(payload)

        # A non-retryable 4xx (auth, bad request) is a product/config defect —
        # not something a retry will fix, and not to be masked as a flake.
        raise AdapterProductError(
            f"{self.id}: non-retryable HTTP {response.status_code} from {self._endpoint_path}"
        )
