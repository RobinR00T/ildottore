"""OpenAI chat/completions adapter over ``httpx`` (u04, contract §5 step 2).

Thin by design (ADR-0002): we build the ``/v1/chat/completions`` request
ourselves - system-prompt placement, message roles and pinned sampling params
(``temperature``/``top_p``/``seed``) are preserved verbatim; no SDK, no
normalization. Token logprobs (``logprobs.content[].logprob`` + ``top_logprobs``)
map into the common :class:`~ildottore.shared.models.TokenLogprob` (ADR-0005).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar

from ildottore.adapters.base import AdapterProductError, BaseAdapter, map_logprobs
from ildottore.shared.media import render_media_part
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse, Sampling

__all__ = ["OpenAIAdapter", "sent_sampling"]


def sent_sampling(
    sampling: Sampling, *, sampling_enabled: bool = True, seed_enabled: bool = True
) -> Sampling:
    """The sampling a chat/completions request carries, from what it was asked to carry.

    One function for the wire and for the record, as the Anthropic adapter's (u12 A-66). Without
    ``seed_enabled`` no ``seed`` goes out; without ``sampling_enabled`` (a target file's
    ``capabilities.sampling: false``, u12 A-68) neither ``temperature`` nor ``top_p`` does, for a
    model that refuses them (a reasoning model behind an OpenAI-compatible endpoint, or a Claude
    model behind a gateway): it then samples at its own default, so its replies are not
    temperature-0 deterministic.
    """

    drop = [
        name
        for name in (("temperature", "top_p") if not sampling_enabled else ())
        + (("seed",) if not seed_enabled else ())
        if getattr(sampling, name) is not None
    ]
    return sampling.model_copy(update=dict.fromkeys(drop)) if drop else sampling


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
    audio_enabled: bool = False
    #: False when the target file says ``sampling: false`` (u12 A-68): no temperature, no top_p.
    sampling_enabled: bool = True
    #: A 400 that names a sampling parameter is refused in words that name the capability.
    sends_sampling: ClassVar[bool] = True

    @property
    def _endpoint_path(self) -> str:
        return "/v1/chat/completions"

    @property
    def carries_tool_definitions(self) -> bool:
        """True when this endpoint takes tools: the in-band setup's are translated (OD-18)."""

        return self.tools_enabled

    #: The system prompt goes on the wire, so a memory seed reaches the model (OD-18).
    carries_system_prompt = True

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
            audio=self.audio_enabled,
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
            messages.extend(self._project_message(m) for m in request.messages)
        elif request.media:
            messages.append({"role": "user", "content": self._multimodal_content(request)})
        elif request.prompt is not None:
            messages.append({"role": "user", "content": request.prompt})
        return messages

    @staticmethod
    def _multimodal_content(request: ModelRequest) -> list[dict[str, Any]]:
        """Build the OpenAI multimodal ``content`` array (text + one block per media part).

        An image part becomes an ``image_url`` data-URL block; an audio part becomes an
        ``input_audio`` block (base64 + format), the shape the audio-capable chat models accept.
        """

        content: list[dict[str, Any]] = [{"type": "text", "text": request.prompt or ""}]
        for part in request.media or []:
            mime, raw = render_media_part(part)
            b64 = base64.b64encode(raw).decode("ascii")
            if mime.startswith("audio/"):
                audio_format = mime.split("/", 1)[1]  # "audio/wav" -> "wav"
                content.append(
                    {"type": "input_audio", "input_audio": {"data": b64, "format": audio_format}}
                )
            else:
                content.append(
                    {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}}
                )
        return content

    @staticmethod
    def _project_tool(tool: Mapping[str, Any]) -> dict[str, Any]:
        """A provider-neutral tool (``name``, ``description``, ``parameters``) as a function.

        One already in the OpenAI shape (it has a ``type``) passes through unchanged.
        """

        if "type" in tool:
            return dict(tool)
        return {
            "type": "function",
            "function": {
                "name": tool.get("name", ""),
                "description": tool.get("description", ""),
                "parameters": tool.get("parameters", {"type": "object", "properties": {}}),
            },
        }

    @staticmethod
    def _project_message(message: Mapping[str, Any]) -> dict[str, Any]:
        """One history turn in the OpenAI shape.

        The in-band tool loop (OD-18) writes provider-neutral turns: an assistant turn whose
        ``tool_calls`` carry ``id``, ``name`` and ``arguments``, and ``tool`` turns with the
        result. Those become OpenAI ``function`` calls (arguments as a JSON string) and ``tool``
        messages; any other turn passes through as before.
        """

        turn = dict(message)
        calls = turn.get("tool_calls")
        if turn.get("role") == "assistant" and isinstance(calls, list):
            turn["tool_calls"] = [
                call
                if "function" in call
                else {
                    "id": call.get("id", ""),
                    "type": "function",
                    "function": {
                        "name": call.get("name", ""),
                        "arguments": json.dumps(call.get("arguments", {}), sort_keys=True),
                    },
                }
                for call in (dict(c) for c in calls if isinstance(c, Mapping))
            ]
        if turn.get("role") == "tool":
            return {
                "role": "tool",
                "tool_call_id": turn.get("tool_call_id", ""),
                "content": turn.get("content", ""),
            }
        return turn

    def _build_request(self, request: ModelRequest) -> tuple[dict[str, Any], dict[str, str]]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": self._build_messages(request),
        }
        if request.tools is not None:
            body["tools"] = [self._project_tool(t) for t in request.tools]

        sampling = request.sampling
        if sampling is not None:
            # Only forward a seed when this adapter declares seed support; never fabricate one
            # (contract §4 KEEP); and no temperature or top_p to a model that takes none (A-68).
            sampling = sent_sampling(
                sampling, sampling_enabled=self.sampling_enabled, seed_enabled=self.seed_enabled
            )
            if sampling.temperature is not None:
                body["temperature"] = sampling.temperature
            if sampling.top_p is not None:
                body["top_p"] = sampling.top_p
            if sampling.max_tokens is not None:
                body["max_tokens"] = sampling.max_tokens
            if sampling.seed is not None:
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

        Returns ``None`` when the provider omitted logprobs entirely (ADR-0005),
        distinct from an empty list, and when an entry's own figure is one no model
        produces (:func:`~ildottore.adapters.base.map_logprobs`, u04 §7 A-39).
        """

        logprobs_obj = choice.get("logprobs")
        if not isinstance(logprobs_obj, Mapping):
            return None
        content = logprobs_obj.get("content")
        if not isinstance(content, list):
            return None
        entries: list[dict[str, Any]] = [dict(c) for c in content if isinstance(c, Mapping)]
        return map_logprobs(entries)
