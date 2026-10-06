"""Anthropic Messages API adapter over ``httpx`` (u04, contract §5 step 3).

Thin by design (ADR-0002). The Messages API places the system prompt in a
top-level ``system`` field (not a message role) - we honor that placement
verbatim and preserve the provider ``stop_reason`` vocabulary
(``end_turn``/``max_tokens``/``stop_sequence``/``tool_use``) rather than
translating it.

**OD-1 (ADR-0005):** the public Messages API exposes no usable per-token
logprobs in MVP-1, so this adapter declares ``Capabilities.logprobs = False`` and
returns ``ModelResponse.logprobs = None`` - which drives
``logprob_membership`` to ``inconclusive: capability_unavailable``. Revisit for
MVP-2 if Anthropic ships per-token logprobs.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ildottore.adapters.base import AdapterProductError, BaseAdapter
from ildottore.shared.media import MediaError, render_media_part
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

    @property
    def carries_tool_definitions(self) -> bool:
        """True when this endpoint takes tools: the in-band setup's are translated (OD-18)."""

        return self.tools_enabled

    #: The whole history goes on the wire, so a memory seed reaches the model (OD-18).
    carries_history = True

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
        """Assemble the ``messages`` array (system goes in a top-level field).

        The Messages API accepts only ``role`` + ``content`` on a text turn and rejects
        unknown fields (HTTP 400). A multi-turn transcript from the conversation engine may
        carry provider-foreign keys (e.g. an OpenAI-shaped ``tool_calls``), so each message
        is projected to the Anthropic-valid shape here (ADR-0002: the adapter owns the wire
        shape). Tool-use history mapping to Anthropic content blocks is a future seam.
        """

        if request.messages is not None:
            return self._project_history(request.messages)
        if request.media:
            return [{"role": "user", "content": self._multimodal_content(request)}]
        if request.prompt is not None:
            return [{"role": "user", "content": request.prompt}]
        return []

    @staticmethod
    def _multimodal_content(request: ModelRequest) -> list[dict[str, Any]]:
        """Build the Anthropic multimodal ``content`` array (text + one image block per part).

        The Messages API accepts image input but not audio, so an audio carrier is refused here
        (defense-in-depth: the planner already skips an ``audio`` spec on this adapter, which does
        not declare the capability) rather than sent as a malformed image block the API would 400.
        """

        content: list[dict[str, Any]] = [{"type": "text", "text": request.prompt or ""}]
        for part in request.media or []:
            mime, raw = render_media_part(part)
            if not mime.startswith("image/"):
                raise MediaError(
                    f"Anthropic Messages API does not accept {mime!r} media (image only)"
                )
            content.append(
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": mime,
                        "data": base64.b64encode(raw).decode("ascii"),
                    },
                }
            )
        return content

    @staticmethod
    def _project_tool(tool: Mapping[str, Any]) -> dict[str, Any]:
        """A provider-neutral tool as a Messages API tool (``input_schema``); one already in
        that shape passes through unchanged."""

        if "input_schema" in tool:
            return dict(tool)
        return {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "input_schema": tool.get("parameters", {"type": "object", "properties": {}}),
        }

    @classmethod
    def _project_history(cls, messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """The history in the Messages API shape, tool turns included (OD-18).

        A provider-neutral assistant turn with ``tool_calls`` (``id``, ``name``, ``arguments``)
        becomes ``text`` and ``tool_use`` blocks; the ``tool`` turns after it become one user
        turn of ``tool_result`` blocks, as the API requires. Any other turn is projected to
        ``role`` + ``content`` as before (an OpenAI-shaped ``tool_calls`` is still dropped).
        """

        projected: list[dict[str, Any]] = []
        for message in messages:
            role = message.get("role")
            calls = message.get("tool_calls")
            if role == "tool":
                block = {
                    "type": "tool_result",
                    "tool_use_id": message.get("tool_call_id", ""),
                    "content": message.get("content", ""),
                }
                last = projected[-1] if projected else None
                if (
                    last is not None
                    and last["role"] == "user"
                    and isinstance(last["content"], list)
                ):
                    last["content"].append(block)
                else:
                    projected.append({"role": "user", "content": [block]})
            elif (
                role == "assistant"
                and isinstance(calls, list)
                and calls
                and all(
                    isinstance(c, Mapping) and "function" not in c and "arguments" in c
                    for c in calls
                )
            ):
                text = message.get("content")
                blocks: list[dict[str, Any]] = []
                if isinstance(text, str) and text.strip():  # the API rejects a blank text block
                    blocks.append({"type": "text", "text": text})
                blocks.extend(
                    {
                        "type": "tool_use",
                        "id": call.get("id", ""),
                        "name": call.get("name", ""),
                        "input": dict(call.get("arguments") or {}),
                    }
                    for call in calls
                )
                projected.append({"role": "assistant", "content": blocks})
            else:
                projected.append(cls._project_message(message))
        return projected

    @staticmethod
    def _project_message(message: Mapping[str, Any]) -> dict[str, Any]:
        """Keep only the Messages-API-valid fields of one turn (``role`` + ``content``).

        An empty content (e.g. a threaded assistant turn that was pure tool-use, whose text
        is "") is replaced with a placeholder: the Messages API rejects an empty-string
        content, which would otherwise 400 the whole multi-turn conversation (audit M13).
        """

        role = message.get("role", "user")
        content = message.get("content", "")
        if isinstance(content, str) and content == "":
            content = "[non-text turn]"
        return {"role": role, "content": content}

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
            body["tools"] = [self._project_tool(t) for t in request.tools]
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
