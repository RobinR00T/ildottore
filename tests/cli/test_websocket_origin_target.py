"""``AC-WS-ORIGIN-001`` through the composition root (u04 A-133, OD-75).

The capability follows the provider (a ``provider: websocket`` target has ``websocket_origin``, a
live target of any other provider may not declare it, an offline mock only when it replays the
fixtures), the plan skips the spec everywhere else, the runner marks its request as the probe,
and a real campaign against the loopback chat server fails one that upgrades a cross-site
``Origin`` and passes one that refuses it, with no frame sent to either.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ildottore.cli import fleet as fleet_mod
from ildottore.cli import wiring
from ildottore.cli.run import RunOptions, execute_run
from ildottore.core.planner import build_plan
from ildottore.core.runner import _build_request
from ildottore.registry import load_paths
from ildottore.shared.digest import target_digest
from ildottore.shared.enums import RequiresCapability, VerdictStatus
from ildottore.shared.models import AttackSpec, Target
from ildottore.shared.package_data import BATTERY
from ildottore.shared.probes import CROSS_SITE_ORIGIN, PROBE, WEBSOCKET_ORIGIN_PROBE
from tests.ws_chat_server import TOKEN, FakeChatServer

SPEC = "AC-WS-ORIGIN-001"
_SPEC_FILE = BATTERY / "attacks" / f"{SPEC}.yaml"

_BLOCK = """websocket:
  handshake:
    send: {type: "auth", token: "{{token}}"}
    expect: {path: "type", equals: "auth_ok"}
  message:
    send: {type: "query", text: "{{prompt}}"}
  response:
    text_path: "delta.text"
    final_path: "type"
    final_value: "done"
    timeout_seconds: 5
"""


def _battery() -> list[AttackSpec]:
    result = load_paths([BATTERY / "attacks"])
    return [spec for pack in result.packs for spec in pack.specs]


def _the_spec() -> AttackSpec:
    (spec,) = [s for s in _battery() if s.id == SPEC]
    return spec


def _selected(target: Target) -> set[str]:
    plan = build_plan(_battery(), None, target.capabilities, target_id=target.id, plan_ref="p")
    return {s.spec_id for s in plan.selected}


def _file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "target.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def _ws_target(tmp_path: Path, endpoint: str, extra: str = "") -> Path:
    return _file(
        tmp_path,
        f'id: ws-live\ntype: chatbot\nprovider: websocket\nendpoint: "{endpoint}"\n'
        f'auth_ref: "env://TEST_WS_TOKEN"\n{extra}{_BLOCK}',
    )


def _scope(tmp_path: Path, server: FakeChatServer) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        'version: "1.0"\ntargets:\n  - id: ws-live\n'
        f'    base_url: "{server.url}"\n    endpoints:\n'
        f'      - host: "127.0.0.1:{server.port}"\n        path_prefixes: ["/ws/chat"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://TEST_WS_TOKEN"\n',
        encoding="utf-8",
    )
    return path


# --- the capability and the plan -----------------------------------------------------------


def test_the_spec_requires_a_websocket_endpoint() -> None:
    assert _the_spec().requires == [RequiresCapability.WEBSOCKET_ORIGIN]


def test_a_websocket_target_has_the_capability_and_plans_the_spec(tmp_path: Path) -> None:
    target = wiring.load_target(_ws_target(tmp_path, "wss://chat.example.test/ws/chat"))
    assert target.capabilities.websocket_origin is True
    assert SPEC in _selected(target)


def test_any_other_target_skips_the_spec() -> None:
    target = wiring.load_target(Path(__file__).parents[2] / "examples" / "target.mcp.yaml")
    plan = build_plan(_battery(), None, target.capabilities, target_id=target.id, plan_ref="p")
    (skip,) = [s for s in plan.skipped if s.spec_id == SPEC]
    assert skip.reason == "capability_unavailable: target does not declare websocket_origin"


def test_a_websocket_target_cannot_declare_it_false(tmp_path: Path) -> None:
    path = _ws_target(
        tmp_path, "wss://chat.example.test/ws/chat", "capabilities:\n  websocket_origin: false\n"
    )
    with pytest.raises(ValueError, match="declares websocket_origin false"):
        wiring.load_target(path)


def test_a_live_target_of_another_provider_cannot_declare_it(tmp_path: Path) -> None:
    path = _file(
        tmp_path,
        'id: chat\ntype: chatbot\nprovider: openai\nendpoint: "https://api.example/v1/chat"\n'
        "capabilities:\n  websocket_origin: true\n",
    )
    with pytest.raises(ValueError, match="only the WebSocket adapter probes an upgrade"):
        wiring.load_target(path)


@pytest.mark.parametrize("scenario", ["vulnerable", "hardened"])
def test_a_mock_that_replays_the_fixtures_may_declare_it(tmp_path: Path, scenario: str) -> None:
    path = _file(
        tmp_path,
        f"id: m\ntype: chatbot\nmock_scenario: {scenario}\n"
        "capabilities:\n  websocket_origin: true\n",
    )
    assert SPEC in _selected(wiring.load_target(path))


@pytest.mark.parametrize(
    "scenario", ["mock_scenario: bare\n", "mock_scenario: comprehending\n", ""]
)
def test_a_mock_that_replays_no_fixtures_cannot_declare_it(tmp_path: Path, scenario: str) -> None:
    """A canned reply holds no probe: the spec's oracle would fail it (OD-16)."""

    path = _file(
        tmp_path, f"id: m\ntype: chatbot\n{scenario}capabilities:\n  websocket_origin: true\n"
    )
    with pytest.raises(ValueError, match="replays no fixtures"):
        wiring.load_target(path)


def test_a_fleet_entry_cannot_declare_it(tmp_path: Path) -> None:
    path = tmp_path / "fleet.yaml"
    path.write_text(
        'version: "1"\ntargets:\n  - id: chat\n    provider: openai\n    model: gpt-test\n'
        "    endpoint: https://api.example/v1/chat\n"
        "    capabilities: { websocket_origin: true }\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="websocket_origin"):
        fleet_mod.load_fleet(path)


def test_the_capability_and_an_absent_origin_leave_the_digest_as_it_was(tmp_path: Path) -> None:
    """A run stored before the field and the capability existed still resumes."""

    target = wiring.load_target(_ws_target(tmp_path, "wss://chat.example.test/ws/chat"))
    assert target.websocket is not None and target.websocket.origin is None
    before = target.model_copy(
        update={"capabilities": target.capabilities.model_copy(update={"websocket_origin": False})}
    )
    assert target_digest(target) == target_digest(before)
    with_origin = target.model_copy(
        update={
            "websocket": target.websocket.model_copy(update={"origin": "https://chat.example.test"})
        }
    )
    assert target_digest(with_origin) != target_digest(target)


# --- the runner's mark ---------------------------------------------------------------------


def test_the_runner_marks_the_request_as_the_probe() -> None:
    request = _build_request(_the_spec(), "(probe)")
    assert request.metadata == {PROBE: WEBSOCKET_ORIGIN_PROBE}


def test_no_other_battery_spec_is_marked() -> None:
    marked = [
        spec.id
        for spec in _battery()
        if (_build_request(spec, "x").metadata or {}).get(PROBE) is not None
    ]
    assert marked == [SPEC]


# --- a real campaign against the loopback server -------------------------------------------


def _run(tmp_path: Path, server: FakeChatServer) -> VerdictStatus:
    specs = tmp_path / "specs"
    specs.mkdir()
    shutil.copy(_SPEC_FILE, specs / _SPEC_FILE.name)
    options = RunOptions(
        targets=[_ws_target(tmp_path, server.url)],
        scope=_scope(tmp_path, server),
        runs=1,
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
    )
    outcome = execute_run(options, [specs])
    (finding,) = outcome.findings
    return finding.status


def test_an_endpoint_that_upgrades_a_cross_site_origin_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_WS_TOKEN", TOKEN)
    with FakeChatServer("echo") as server:
        status = _run(tmp_path, server)
    assert status is VerdictStatus.FAIL
    assert server.log.origins[-1] == CROSS_SITE_ORIGIN
    assert server.log.frames == []


def test_an_endpoint_that_refuses_a_cross_site_origin_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_WS_TOKEN", TOKEN)
    with FakeChatServer("echo", allowed_origins=frozenset()) as server:
        server.allowed_origins = frozenset({f"http://127.0.0.1:{server.port}"})
        status = _run(tmp_path, server)
    assert status is VerdictStatus.PASS
    assert server.log.frames == []


def test_an_endpoint_that_refuses_its_own_page_is_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_WS_TOKEN", TOKEN)
    with FakeChatServer("echo", allowed_origins=frozenset({"https://elsewhere.test"})) as server:
        status = _run(tmp_path, server)
    assert status is VerdictStatus.INCONCLUSIVE
    assert CROSS_SITE_ORIGIN not in server.log.origins
