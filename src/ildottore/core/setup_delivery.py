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
    "MAX_CALLS_PER_ROUND",
    "MAX_ROUND_ARGUMENT_BYTES",
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
#: How a memory seed opens the system prompt: what a memory feature keeps from earlier sessions.
MEMORY_HEADER: Final = "Saved memory from earlier sessions:"
#: Calls answered in one round. A reply with more is not answered (the round ends): one reply
#: of 20,000 calls grew each request by megabytes and spent the campaign's token ceiling in
#: four sends (pre-merge audit of #50).
MAX_CALLS_PER_ROUND: Final = 16
#: The arguments one answered round may carry, in bytes of JSON. A reply of 16 calls with 4 MB
#: of arguments, answered, grew each request past 16 MB and sent 374 MB in one attempt (delta
#: audit of #50): a round over this is not answered, so the history stays small.
MAX_ROUND_ARGUMENT_BYTES: Final = 64 * 1024
#: What a tool returns when the spec declares nothing for it.
DEFAULT_TOOL_RESULT: Final = "OK"
#: Accepts any arguments: the specs declare tool names and behaviour, not schemas.
_ANY_ARGUMENTS: Final[JsonDict] = {"type": "object", "properties": {}, "additionalProperties": True}


@dataclass(frozen=True)
class InBandSetup:
    """What a spec's setup becomes on the wire, ready for the conversation engine."""

    #: The memory seed, as saved memory from earlier sessions (appended to the system prompt).
    memory: str = ""
    #: Prepended to the first attacker turn: the retrieved documents.
    context: str = ""
    #: Provider-neutral tool definitions (``name``, ``description``, ``parameters``).
    tools: list[JsonDict] = field(default_factory=list)
    #: The answer to a call of each tool, by name.
    results: dict[str, str] = field(default_factory=dict)

    def tool_result(self, name: str) -> str:
        """The spec's ``returns`` for ``name``, or :data:`DEFAULT_TOOL_RESULT`."""

        return self.results.get(name, DEFAULT_TOOL_RESULT)

    def declares(self, name: str) -> bool:
        """True when ``name`` is one of the scene's tools."""

        return any(tool["name"] == name for tool in self.tools)

    def system_prompt(self, spec_prompt: str | None) -> str | None:
        """The spec's system prompt with the saved memory after it, when there is any."""

        if not self.memory:
            return spec_prompt
        return f"{spec_prompt}\n\n{self.memory}" if spec_prompt else self.memory


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
        memory=_memory(setup.memory_seed or []),
        context=_context(setup.documents or []),
        tools=[_definition(tool) for tool in setup.tools or [] if _name(tool)],
        results={
            _name(tool): _as_text(tool["returns"])
            for tool in setup.tools or []
            if _name(tool) and tool.get("returns") is not None
        },
    )


def _memory(seed: list[JsonDict]) -> str:
    """The seed as saved memory from earlier sessions, one line an entry.

    Not as turns of this chat: a model repeating "the previous user's" note from its own history
    leaks nothing across a session, and obeying a tag "the user" asked for in the same chat is
    not a poisoned memory, so DL-XSESSION-001 and MEM-POISON-001 measured something else
    (pre-merge audit of #50). A memory feature keeps earlier sessions in the system context;
    each entry says which session it came from (``session``, else ``an earlier session``).
    """

    lines = []
    for entry in seed:
        content = entry.get("content")
        if not isinstance(content, str) or not content.strip():
            continue
        session = entry.get("session")
        where = session if isinstance(session, str) and session else "an earlier session"
        role = entry.get("role") if entry.get("role") in ("user", "assistant") else "user"
        lines.append(f"- [{where}, {role}] {content.strip()}")
    return MEMORY_HEADER + "\n" + "\n".join(lines) if lines else ""


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
