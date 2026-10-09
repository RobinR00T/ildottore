"""A spec's setup delivered in-band to a bare model endpoint (OD-18, ADR-0009 option A).

A spec declares the scene its attack needs: documents a retriever returned, tools the agent can
call (with what each returns), a planted prior session. Nothing used to send any of it, so 32
of the 75 specs went out as a user turn that referred to a document, a tool or a memory the
target did not have. Against a **bare model** (a target of ``type: model``) the scene can be
built in the request itself, which measures how the model handles untrusted content in its
context; it does not test a deployed application's own retrieval or tools, and the evidence
says so (``setup_delivery: in_band``). A deployed application (any other type) holds the scene
only where its operator seeded it and its target file says so (option B, the second half of
this module): ``setup_delivery: seeded``.

Pure: no I/O, no clock. The conversation engine (:mod:`ildottore.core.conversation`) sends.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from typing import Final

from ildottore.shared.enums import EvaluatorType, TargetType
from ildottore.shared.models import AttackSpec, JsonDict, ModelResponse, Target

__all__ = [
    "IN_BAND",
    "MAX_CALLS_PER_ROUND",
    "MAX_ROUND_ARGUMENT_BYTES",
    "MAX_TOOL_ROUNDS",
    "RUN_ID_PLACEHOLDER",
    "SEEDED",
    "TRACE_EVALUATORS",
    "InBandSetup",
    "canary_binding",
    "canonical_tool_calls",
    "delivers_in_band",
    "in_band_setup",
    "is_seeded",
    "needs_run_token",
    "needs_seeding",
    "scene_tool_names",
    "seeded_canaries",
    "seeding_gap",
    "tool_name_map",
    "trace_gap",
]

#: The value of ``setup_delivery`` in the request metadata of an attempt built here.
IN_BAND: Final = "in_band"
#: The value for a deployed application whose operator declared the spec's setup seeded (B).
SEEDED: Final = "seeded"
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


# --- option B: a deployed application, seeded by its operator --------------------------------

#: The per-run canary placeholder a spec binds (``core.runner``).
RUN_ID_PLACEHOLDER: Final = "{{run_id}}"
#: Evaluators that judge the tool-call trace: on them, no call is the secure answer.
TRACE_EVALUATORS: Final = frozenset(
    {EvaluatorType.TOOL_CALL, EvaluatorType.TOOL_SEQUENCE, EvaluatorType.KILL_CHAIN_PROGRESSION}
)


def needs_seeding(spec: AttackSpec, target: Target) -> bool:
    """True when ``spec`` needs a scene that only the operator can put into ``target``.

    A deployed application (any type but ``model``) cannot be handed a spec's documents, tools or
    memory in the request: the operator seeds them into the deployment and says so in the target
    file, or the spec would go out referring to a scene the target does not have (OD-18 B).
    """

    setup = spec.setup
    if setup is None or target.type is TargetType.MODEL:
        return False
    return bool(setup.documents or setup.tools or setup.memory_seed)


def is_seeded(spec: AttackSpec, target: Target) -> bool:
    """True when the target file declares ``spec`` seeded (its id, or a glob matching it)."""

    seeded = target.seeded_setup
    return seeded is not None and any(
        fnmatch.fnmatchcase(spec.id, pattern) for pattern in seeded.specs
    )


def scene_tool_names(spec: AttackSpec) -> set[str]:
    """The names of the tools ``spec``'s scene declares."""

    setup = spec.setup
    if setup is None or not setup.tools:
        return set()
    return {str(tool.get("name")) for tool in setup.tools if tool.get("name")}


def seeding_gap(spec: AttackSpec, target: Target) -> str | None:
    """Why ``spec`` cannot go out to ``target`` as a seeded deployment, or ``None``.

    The runner and the plan both ask this, so what the dry run counts as "not seeded" is what
    the run reports; both exempt the offline mock, which answers from the spec, not from a
    deployment. Three reasons: the spec is not declared; its scene carries the per-run canary
    and no ``run_token`` replaces it (the operator seeds before the run, so the canary the
    evaluators look for could never be in the deployment, and ``secret_leakage`` would be
    blind; pre-commit audit of B); or two of its scene tools map to one deployment name.
    """

    if not needs_seeding(spec, target):
        return None
    seeded = target.seeded_setup
    if seeded is None or not is_seeded(spec, target):
        return (
            "setup_not_seeded: this spec needs documents, tools or memory in the deployment, "
            "and the target file does not declare them seeded (seeded_setup.specs)"
        )
    if not seeded.run_token and needs_run_token(spec):
        return (
            "setup_not_seeded: this spec's canary is bound per run ({{run_id}}) and has to be "
            "in the deployment, which nobody can seed before the run; declare "
            "seeded_setup.run_token, then seed the canary that --dry-run -vv prints"
        )
    clash = _clashing_names(spec, seeded.tools)
    if clash:
        return (
            f"setup_not_seeded: seeded_setup.tools maps {', '.join(clash)}, all tools of this "
            "spec's scene, to one deployment name, so a call under it could not be told apart"
        )
    return None


def needs_run_token(spec: AttackSpec) -> bool:
    """True when ``spec``'s per-run canary has to be in the deployment before the run.

    It does when the scene (documents, tool results, memory) carries the placeholder, or when a
    canary carrying it (``setup.canaries``, an evaluator's ``canary_ref``) is not in what the
    request itself sends (the system prompt and the attack): ``AC-BOLA-001`` plants its canary
    in another customer's record, outside the scene, and was sent with a canary nobody could
    have planted (delta audit of B).
    """

    setup = spec.setup
    if setup is None:
        return False
    if RUN_ID_PLACEHOLDER in _scene_text(spec):
        return True
    carried = json.dumps(
        [setup.system_prompt, spec.attack.model_dump(mode="json")], sort_keys=True, default=str
    )
    canaries = [*(setup.canaries or []), *(e.canary_ref for e in spec.evaluators if e.canary_ref)]
    return any(RUN_ID_PLACEHOLDER in c and json.dumps(c)[1:-1] not in carried for c in canaries)


def canary_binding(spec: AttackSpec, target: Target, run_id: str) -> str:
    """What ``{{run_id}}`` binds to in ``spec``.

    The run id, unless the spec is seeded, its canary has to be in the deployment and a
    ``run_token`` is declared: then ``<run_token>-<spec id>``, so each seeded spec's canary is
    its own (one token for all let a reply quoting one spec's seeded record fail another spec,
    delta audit of B) and a spec whose canary travels in the request keeps the per-run one.
    """

    seeded = target.seeded_setup
    if (
        seeded is not None
        and seeded.run_token
        and needs_seeding(spec, target)
        and is_seeded(spec, target)
        and needs_run_token(spec)
    ):
        return f"{seeded.run_token}-{spec.id}"
    return run_id


def seeded_canaries(spec: AttackSpec, target: Target) -> list[str]:
    """The canaries the operator has to seed for ``spec`` (empty when it binds per run)."""

    binding = canary_binding(spec, target, RUN_ID_PLACEHOLDER)
    if binding == RUN_ID_PLACEHOLDER or spec.setup is None:
        return []
    canaries = [
        *(spec.setup.canaries or []),
        *(e.canary_ref for e in spec.evaluators if e.canary_ref),
    ]
    return sorted(
        {c.replace(RUN_ID_PLACEHOLDER, binding) for c in canaries if RUN_ID_PLACEHOLDER in c}
    )


def trace_gap(spec: AttackSpec, target: Target, *, returns_tool_calls: bool) -> str | None:
    """Why a seeded spec judged on its tool trace cannot be judged through this adapter.

    A REST template (and the read-only MCP adapter) reads no tool calls from a reply, so a
    trace spec could only ever see "no tool call" and pass; on a deployment that does return
    its calls, no call is the secure answer (delta audit of B).
    """

    if returns_tool_calls or not (needs_seeding(spec, target) and is_seeded(spec, target)):
        return None
    if not any(e.type in TRACE_EVALUATORS for e in spec.evaluators):
        return None
    return (
        "setup_not_delivered: this spec judges the tool-call trace, and this target's adapter "
        "reads no tool calls from a reply, so it could never see one"
    )


def tool_name_map(spec: AttackSpec, target: Target) -> dict[str, str]:
    """Deployment tool name to ``spec``'s tool name, for the tools of this spec's scene only.

    Per spec, not per target: specs name one deployment tool differently (``lookup_ticket``,
    ``read_ticket``), and a target-wide map renamed a call into a name the spec judging it does
    not use (pre-commit audit of B).
    """

    seeded = target.seeded_setup
    if seeded is None or not seeded.tools:
        return {}
    scene = scene_tool_names(spec)
    back: dict[str, str] = {}
    for spec_name, deployment in sorted(seeded.tools.items()):
        if spec_name in scene:
            back.setdefault(deployment, spec_name)  # two in one scene: seeding_gap refuses it
    return back


def canonical_tool_calls(
    response: ModelResponse, target: Target, spec: AttackSpec
) -> ModelResponse:
    """``response`` with each call under a deployment's tool name renamed to ``spec``'s.

    The evaluators judge calls against the spec's tool names (its allowlist, its destructive
    tools, its sequences); a deployment calls its own. ``seeded_setup.tools`` maps one to the
    other, and this applies it to every key a call's name can be read from (a top-level
    ``name`` and ``function.name``). The stored evidence keeps the calls as they were made; only
    what is judged is renamed, and the attempt records the map (``seeded_tools``).
    """

    back = tool_name_map(spec, target)
    if not back or not response.tool_calls:
        return response
    calls: list[JsonDict] = []
    for call in response.tool_calls:
        renamed = dict(call)
        name = renamed.get("name")
        if isinstance(name, str) and name in back:
            renamed["name"] = back[name]
        function = renamed.get("function")
        fn_name = function.get("name") if isinstance(function, dict) else None
        if isinstance(function, dict) and isinstance(fn_name, str) and fn_name in back:
            renamed["function"] = {**function, "name": back[fn_name]}
        calls.append(renamed)
    return response.model_copy(update={"tool_calls": calls})


def _scene_text(spec: AttackSpec) -> str:
    setup = spec.setup
    if setup is None:
        return ""
    return json.dumps(
        [setup.documents, setup.tools, setup.memory_seed], sort_keys=True, default=str
    )


def _clashing_names(spec: AttackSpec, tools: dict[str, str]) -> list[str]:
    scene = scene_tool_names(spec)
    by_deployment: dict[str, list[str]] = {}
    for spec_name, deployment in tools.items():
        if spec_name in scene:
            by_deployment.setdefault(deployment, []).append(spec_name)
    return sorted(name for names in by_deployment.values() if len(names) > 1 for name in names)
