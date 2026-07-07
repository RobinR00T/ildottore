"""Anthropic Messages API adapter over ``httpx`` (u04, contract §5 step 3).

Thin by design (ADR-0002). The Messages API places the system prompt in a
top-level ``system`` field (not a message role) — we honor that placement
verbatim and preserve the provider ``stop_reason`` vocabulary
(``end_turn``/``max_tokens``/``stop_sequence``/``tool_use``) rather than
translating it.

**OD-1 (ADR-0005):** the public Messages API exposes no usable per-token
logprobs in MVP-1, so this adapter declares ``Capabilities.logprobs = False`` and
returns ``ModelResponse.logprobs = None`` — which drives
``logprob_membership`` to ``inconclusive: capability_unavailable``. Revisit for
MVP-2 if Anthropic ships per-token logprobs.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ildottore.adapters.base import AdapterProductError, BaseAdapter
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse

__all__ = ["AnthropicAdapter"]

_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MAX_TOKENS = 1024


@dataclass
class AnthropicAdapter(BaseAdapter):
    """Anthropic Messages API target.

    ``logprobs`` is fixed ``False`` (OD-1); the remaining capabilities are
    declared and config-overridable (contract §4 KEEP).
    """

    tools_enabled: bool = True
    streaming_enabled: bool = True
    rag_enabled: bool = False
    memory_enabled: bool = False
    multi_identity_enabled: bool = False
    multimodal_enabled: bool = True
    anthropic_version: str = _ANTHROPIC_VERSION

    @property
    def _endpoint_path(self) -> str:
        return "/v1/messages"

    def capabilities(self) -> Capabilities:
        return Capabilities(
            tools=self.tools_enabled,
            rag=self.rag_enabled,
            memory=self.memory_enabled,
            streaming=self.streaming_enabled,
            # Messages API has no per-request `seed`; do not fake determinism.
            seed=False,
            # OD-1: no usable per-token logprobs in MVP-1.
            logprobs=False,
            multi_identity=self.multi_identity_enabled,
            multimodal=self.multimodal_enabled,
        )

    def _build_messages(self, request: ModelRequest) -> list[dict[str, Any]]:
        """Assemble the ``messages`` array (system goes in a top-level field)."""

        if request.messages is not None:
            return [dict(m) for m in request.messages]
        if request.prompt is not None:
            return [{"role": "user", "content": request.prompt}]
        return []

    def _build_request(self, request: ModelRequest) -> tuple[dict[str, Any], dict[str, str]]:
        sampling = request.sampling
        max_tokens = _DEFAULT_MAX_TOKENS
        if sampling is not None and sampling.max_tokens is not None:
            max_tokens = sampling.max_tokens

        body: dict[str, Any] = {
            "model": self.model,
            "messages": self._build_messages(request),
            "max_tokens": max_tokens,
        }
        # System-prompt placement verbatim: Anthropic top-level `system` field.
        if request.system_prompt is not None:
            body["system"] = request.system_prompt
        if request.tools is not None:
            body["tools"] = [dict(t) for t in request.tools]
        if sampling is not None:
            if sampling.temperature is not None:
                body["temperature"] = sampling.temperature
            if sampling.top_p is not None:
                body["top_p"] = sampling.top_p
            # No `seed` field on the Messages API (seed=False capability).

        headers = {
            "content-type": "application/json",
            "anthropic-version": self.anthropic_version,
        }
        if self.api_key is not None:
            headers["x-api-key"] = self.api_key
        return body, headers

    def _parse_response(self, payload: Mapping[str, Any]) -> ModelResponse:
        content = payload.get("content")
        if not isinstance(content, list):
            raise AdapterProductError(f"{self.id}: response has no content array")

        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in content:
            if not isinstance(block, Mapping):
                continue
            block_type = block.get("type")
            if block_type == "text":
                part = block.get("text")
                if isinstance(part, str):
                    text_parts.append(part)
            elif block_type == "tool_use":
                tool_calls.append(dict(block))

        # `stop_reason` vocabulary preserved verbatim (no translation).
        stop_reason = payload.get("stop_reason")

        usage_raw = payload.get("usage")
        usage = dict(usage_raw) if isinstance(usage_raw, Mapping) else None

        ids: dict[str, Any] = {}
        if "id" in payload:
            ids["id"] = payload["id"]
        if "model" in payload:
            ids["model"] = payload["model"]

        return ModelResponse(
            text="".join(text_parts),
            tool_calls=tool_calls,
            # OD-1: Anthropic exposes no usable per-token logprobs → None.
            logprobs=None,
            finish_reason=stop_reason if isinstance(stop_reason, str) else None,
            raw_ids=self._redact_ids(ids),
            usage=usage,
        )
