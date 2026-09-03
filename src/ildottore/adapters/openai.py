"""OpenAI chat/completions adapter over ``httpx`` (u04, contract §5 step 2).

Thin by design (ADR-0002): we build the ``/v1/chat/completions`` request
ourselves — system-prompt placement, message roles and pinned sampling params
(``temperature``/``top_p``/``seed``) are preserved verbatim; no SDK, no
normalization. Token logprobs (``logprobs.content[].logprob`` + ``top_logprobs``)
map into the common :class:`~ildottore.shared.models.TokenLogprob` (ADR-0005).
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ildottore.adapters.base import AdapterProductError, BaseAdapter, map_logprobs
from ildottore.shared.media import render_media_part
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse

__all__ = ["OpenAIAdapter"]


@dataclass
class OpenAIAdapter(BaseAdapter):
    """OpenAI-compatible chat/completions target.

    Capabilities are **declared** (contract §4 KEEP): tools/streaming/seed/
    logprobs default true for a first-party OpenAI endpoint, but every flag is
    overridable per config so an OpenAI-compatible gateway can turn them off.
    """

    tools_enabled: bool = True
    streaming_enabled: bool = True
    seed_enabled: bool = True
    logprobs_enabled: bool = True
    rag_enabled: bool = False
    memory_enabled: bool = False
    multi_identity_enabled: bool = False
    multimodal_enabled: bool = False

    @property
    def _endpoint_path(self) -> str:
        return "/v1/chat/completions"

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

    def _build_messages(self, request: ModelRequest) -> list[dict[str, Any]]:
        """Assemble the OpenAI ``messages`` array, system-prompt first (verbatim).

        A single-turn request with ``media`` sends a multimodal user turn: a ``content`` array of
        one ``text`` part plus one ``image_url`` part per rendered image (data URL). Multi-turn
        transcripts (``messages``) are passed through unchanged (multimodal multi-turn is a future
        seam).
        """

        messages: list[dict[str, Any]] = []
        if request.system_prompt is not None:
            messages.append({"role": "system", "content": request.system_prompt})
        if request.messages is not None:
            messages.extend(dict(m) for m in request.messages)
        elif request.media:
            messages.append({"role": "user", "content": self._multimodal_content(request)})
        elif request.prompt is not None:
            messages.append({"role": "user", "content": request.prompt})
        return messages

    @staticmethod
    def _multimodal_content(request: ModelRequest) -> list[dict[str, Any]]:
        """Build the OpenAI multimodal ``content`` array (text + one image_url per media part)."""

        content: list[dict[str, Any]] = [{"type": "text", "text": request.prompt or ""}]
        for part in request.media or []:
            mime, raw = render_media_part(part)
            data_url = f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"
            content.append({"type": "image_url", "image_url": {"url": data_url}})
        return content

    def _build_request(self, request: ModelRequest) -> tuple[dict[str, Any], dict[str, str]]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": self._build_messages(request),
        }
        if request.tools is not None:
            body["tools"] = [dict(t) for t in request.tools]

        sampling = request.sampling
        if sampling is not None:
            if sampling.temperature is not None:
                body["temperature"] = sampling.temperature
            if sampling.top_p is not None:
                body["top_p"] = sampling.top_p
            if sampling.max_tokens is not None:
                body["max_tokens"] = sampling.max_tokens
            # Only forward a seed when this adapter declares seed support; never
            # fabricate one (contract §4 KEEP).
            if sampling.seed is not None and self.seed_enabled:
                body["seed"] = sampling.seed

        if self.logprobs_enabled:
            body["logprobs"] = True

        headers = {"content-type": "application/json"}
        if self.api_key is not None:
            headers["authorization"] = f"Bearer {self.api_key}"
        return body, headers

    def _parse_response(self, payload: Mapping[str, Any]) -> ModelResponse:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise AdapterProductError(f"{self.id}: response has no choices")
        first = choices[0]
        if not isinstance(first, Mapping):
            raise AdapterProductError(f"{self.id}: choice is not an object")

        message = first.get("message")
        if not isinstance(message, Mapping):
            raise AdapterProductError(f"{self.id}: choice has no message object")
        text = message.get("content")
        if text is None:
            text = ""
        if not isinstance(text, str):
            raise AdapterProductError(f"{self.id}: message content is not a string")

        tool_calls: list[dict[str, Any]] = []
        raw_tool_calls = message.get("tool_calls")
        if isinstance(raw_tool_calls, list):
            tool_calls = [dict(tc) for tc in raw_tool_calls if isinstance(tc, Mapping)]

        finish_reason = first.get("finish_reason")
        logprobs = self._extract_logprobs(first) if self.logprobs_enabled else None

        usage_raw = payload.get("usage")
        usage = dict(usage_raw) if isinstance(usage_raw, Mapping) else None

        ids: dict[str, Any] = {}
        if "id" in payload:
            ids["id"] = payload["id"]
        if "system_fingerprint" in payload:
            ids["system_fingerprint"] = payload["system_fingerprint"]
        if "model" in payload:
            ids["model"] = payload["model"]

        return ModelResponse(
            text=text,
            tool_calls=tool_calls,
            logprobs=logprobs,
            finish_reason=finish_reason if isinstance(finish_reason, str) else None,
            raw_ids=self._redact_ids(ids),
            usage=usage,
        )

    def _extract_logprobs(self, choice: Mapping[str, Any]) -> list[Any] | None:
        """Fold ``choice.logprobs.content[]`` into the common TokenLogprob shape.

        Returns ``None`` when the provider omitted logprobs entirely (ADR-0005) —
        distinct from an empty list.
        """

        logprobs_obj = choice.get("logprobs")
        if not isinstance(logprobs_obj, Mapping):
            return None
        content = logprobs_obj.get("content")
        if not isinstance(content, list):
            return None
        entries: list[dict[str, Any]] = [dict(c) for c in content if isinstance(c, Mapping)]
        return map_logprobs(entries)
