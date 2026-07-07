"""Generic REST adapter over ``httpx`` (u04, contract §5 step 4).

The long-tail escape hatch (ADR-0002): a declarative request/response template
maps a provider-neutral :class:`~ildottore.shared.models.ModelRequest` onto an
arbitrary JSON REST endpoint and pulls the answer back out with a small dotted
JSON-path extractor (list indices supported, e.g. ``choices.0.text``).

Defaults are deliberately conservative: ``logprobs=None`` and ``seed=False``
(contract §5 step 4) — the long tail rarely exposes either, and we never
fabricate them. Auth is **header-only** in MVP-1 to shrink the secret-leak
surface (contract §9); query/body-templated tokens are deferred pending sign-off.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ildottore.adapters.base import AdapterProductError, BaseAdapter
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse

__all__ = ["RestAdapter", "RestTemplate"]


def _get_path(payload: Any, path: str) -> Any:
    """Resolve a dotted path (``a.b.0.c``) into a nested JSON payload.

    Integer-looking segments index into sequences. Returns ``None`` if any
    segment is missing rather than raising, so a missing optional field (e.g.
    ``finish_reason``) is simply absent.
    """

    current: Any = payload
    for segment in path.split("."):
        if current is None:
            return None
        if segment.lstrip("-").isdigit():
            if not isinstance(current, Sequence) or isinstance(current, (str, bytes)):
                return None
            idx = int(segment)
            if -len(current) <= idx < len(current):
                current = current[idx]
            else:
                return None
        elif isinstance(current, Mapping):
            current = current.get(segment)
        else:
            return None
    return current


@dataclass(frozen=True)
class RestTemplate:
    """Declarative request/response mapping for a generic REST endpoint.

    * ``path`` — endpoint path appended to ``base_url``.
    * ``prompt_field`` — dotted location in the request body to inject the prompt
      (default ``prompt``). System prompt goes to ``system_field`` if set.
    * ``text_path`` — dotted path to the answer text in the response.
    * ``finish_path`` / ``id_path`` / ``usage_path`` — optional response paths.
    * ``static_body`` — fields merged into every request (e.g. ``model``).
    * ``static_headers`` — headers merged into every request.
    """

    path: str = "/"
    prompt_field: str = "prompt"
    system_field: str | None = None
    text_path: str = "text"
    finish_path: str | None = None
    id_path: str | None = None
    usage_path: str | None = None
    static_body: Mapping[str, Any] = field(default_factory=dict)
    static_headers: Mapping[str, str] = field(default_factory=dict)


@dataclass
class RestAdapter(BaseAdapter):
    """Template-driven generic REST target (long-tail; ADR-0002)."""

    template: RestTemplate = field(default_factory=RestTemplate)
    # Capabilities are driven entirely by config (contract §5 step 4). Defaults
    # are the conservative long-tail baseline: nothing declared present.
    tools_enabled: bool = False
    rag_enabled: bool = False
    memory_enabled: bool = False
    streaming_enabled: bool = False
    seed_enabled: bool = False
    logprobs_enabled: bool = False
    multi_identity_enabled: bool = False
    multimodal_enabled: bool = False

    @property
    def _endpoint_path(self) -> str:
        return self.template.path

    def capabilities(self) -> Capabilities:
        return Capabilities(
            tools=self.tools_enabled,
            rag=self.rag_enabled,
            memory=self.memory_enabled,
            streaming=self.streaming_enabled,
            seed=self.seed_enabled,
            logprobs=self.logprobs_enabled,
            multi_identity=self.multi_identity_enabled,
            multimodal=self.multimodal_enabled,
        )

    def _prompt_text(self, request: ModelRequest) -> str:
        """Pick the prompt text to inject (explicit ``prompt`` wins)."""

        if request.prompt is not None:
            return request.prompt
        if request.messages:
            last = request.messages[-1]
            content = last.get("content") if isinstance(last, Mapping) else None
            if isinstance(content, str):
                return content
        return ""

    def _build_request(self, request: ModelRequest) -> tuple[dict[str, Any], dict[str, str]]:
        body: dict[str, Any] = dict(self.template.static_body)
        body[self.template.prompt_field] = self._prompt_text(request)
        if self.template.system_field is not None and request.system_prompt is not None:
            body[self.template.system_field] = request.system_prompt

        headers: dict[str, str] = {"content-type": "application/json"}
        headers.update(self.template.static_headers)
        # Header-only auth injection (MVP-1, contract §9).
        if self.api_key is not None:
            headers["authorization"] = f"Bearer {self.api_key}"
        return body, headers

    def _parse_response(self, payload: Mapping[str, Any]) -> ModelResponse:
        text = _get_path(payload, self.template.text_path)
        if text is None:
            raise AdapterProductError(
                f"{self.id}: response missing text at path {self.template.text_path!r}"
            )
        if not isinstance(text, str):
            raise AdapterProductError(f"{self.id}: response text is not a string")

        finish_reason = None
        if self.template.finish_path is not None:
            candidate = _get_path(payload, self.template.finish_path)
            if isinstance(candidate, str):
                finish_reason = candidate

        ids: dict[str, Any] = {}
        if self.template.id_path is not None:
            id_value = _get_path(payload, self.template.id_path)
            if id_value is not None:
                ids["id"] = id_value

        usage = None
        if self.template.usage_path is not None:
            usage_value = _get_path(payload, self.template.usage_path)
            if isinstance(usage_value, Mapping):
                usage = dict(usage_value)

        return ModelResponse(
            text=text,
            tool_calls=[],
            # Long tail: no logprobs by default (contract §5 step 4).
            logprobs=None,
            finish_reason=finish_reason,
            raw_ids=self._redact_ids(ids),
            usage=usage,
        )
