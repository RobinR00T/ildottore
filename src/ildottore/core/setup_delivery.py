"""A spec's setup delivered in-band to a bare model endpoint (OD-18, ADR-0009 option A).

A spec declares the scene its attack needs: documents a retriever returned, tools the agent can
call (with what each returns), a planted prior session. Nothing used to send any of it, so 32
of the 75 specs went out as a user turn that referred to a document, a tool or a memory the
target did not have. Against a **bare model** (a target of ``type: model``) the scene can be
built in the request itself, which measures how the model handles untrusted content in its
context; it does not test a deployed application's own retrieval or tools, and the evidence
says so (``setup_delivery: in_band``). A deployed application waits for option B.

Pure: no I/O, no clock. The conversation engine (:mod:`ildottore.core.conversation`) sends.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Final

from ildottore.shared.enums import TargetType
from ildottore.shared.models import AttackSpec, JsonDict, Target

__all__ = [
    "IN_BAND",
    "MAX_TOOL_ROUNDS",
    "InBandSetup",
    "delivers_in_band",
    "in_band_setup",
]

#: The value of ``setup_delivery`` in the request metadata of an attempt built here.
IN_BAND: Final = "in_band"
#: Tool rounds after a turn: the model calls, the runner answers, the model continues. Each
#: round is one more send under the budget; four lets a chain (read, stage, send) play out.
MAX_TOOL_ROUNDS: Final = 4
#: The assistant turn after a planted user turn, so the attack is never a second user turn in
#: a row (some Messages APIs merge or refuse two).
SEED_ACK: Final = "Understood."
#: What a tool returns when the spec declares nothing for it.
DEFAULT_TOOL_RESULT: Final = "OK"
#: Accepts any arguments: the specs declare tool names and behaviour, not schemas.
_ANY_ARGUMENTS: Final[JsonDict] = {"type": "object", "properties": {}, "additionalProperties": True}


@dataclass(frozen=True)
class InBandSetup:
    """What a spec's setup becomes on the wire, ready for the conversation engine."""

    #: Prior turns (the memory seed), sent before the first attacker turn.
    preamble: list[JsonDict] = field(default_factory=list)
    #: Prepended to the first attacker turn: the retrieved documents.
    context: str = ""
    #: Provider-neutral tool definitions (``name``, ``description``, ``parameters``).
    tools: list[JsonDict] = field(default_factory=list)
    #: The answer to a call of each tool, by name.
    results: dict[str, str] = field(default_factory=dict)

    def tool_result(self, name: str) -> str:
        """The spec's ``returns`` for ``name``, or :data:`DEFAULT_TOOL_RESULT`."""

        return self.results.get(name, DEFAULT_TOOL_RESULT)


def delivers_in_band(spec: AttackSpec, target: Target) -> bool:
    """True when ``spec`` has a scene to build and ``target`` is a bare model endpoint."""

    setup = spec.setup
    if setup is None or target.type is not TargetType.MODEL:
        return False
    return bool(setup.documents or setup.tools or setup.memory_seed)


def in_band_setup(spec: AttackSpec) -> InBandSetup:
    """Build the in-band scene of ``spec`` (``{{run_id}}`` is already bound by the runner)."""

    setup = spec.setup
    if setup is None:
        return InBandSetup()
    return InBandSetup(
        preamble=_preamble(setup.memory_seed or []),
        context=_context(setup.documents or []),
        tools=[_definition(tool) for tool in setup.tools or [] if _name(tool)],
        results={
            _name(tool): _as_text(tool["returns"])
            for tool in setup.tools or []
            if _name(tool) and tool.get("returns") is not None
        },
    )


def _preamble(seed: list[JsonDict]) -> list[JsonDict]:
    turns: list[JsonDict] = []
    for entry in seed:
        content = entry.get("content")
        if not isinstance(content, str) or not content:
            continue
        role = "assistant" if entry.get("role") == "assistant" else "user"
        turns.append({"role": role, "content": content})
    # The history opens with a user turn (the Messages API requires it): a seed's leading
    # assistant entries are dropped, and a trailing user turn gets the acknowledgement.
    while turns and turns[0]["role"] == "assistant":
        turns.pop(0)
    if turns and turns[-1]["role"] == "user":
        turns.append({"role": "assistant", "content": SEED_ACK})
    return turns


def _context(documents: list[JsonDict]) -> str:
    blocks: list[str] = []
    for document in documents:
        body = document.get("content_template") or document.get("content")
        if not isinstance(body, str) or not body:
            continue
        name = document.get("id") or document.get("name") or f"doc-{len(blocks) + 1}"
        blocks.append(f"[document {name}]\n{body.strip()}\n[/document]")
    if not blocks:
        return ""
    return "Context retrieved from the knowledge base:\n\n" + "\n\n".join(blocks) + "\n\n"


def _definition(tool: JsonDict) -> JsonDict:
    name = _name(tool)
    description = tool.get("description")
    return {
        "name": name,
        "description": description
        if isinstance(description, str) and description
        else (f"The {name} tool."),
        "parameters": dict(_ANY_ARGUMENTS),
    }


def _name(tool: JsonDict) -> str:
    name = tool.get("name")
    return name if isinstance(name, str) else ""


def _as_text(value: object) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)
