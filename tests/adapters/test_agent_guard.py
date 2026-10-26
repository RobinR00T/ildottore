"""The WebSocket guard (``websocket.guard``, ``adapters/agent_guard.py``): the credential checked
before it is sent, the first authentication failure stopping the run with a cooldown kept across
processes, pacing across processes, a reported tool closing the connection, and a lower byte cap.

Every test that dials uses the loopback :class:`tests.agent_ws_server` fake; nothing leaves the
host. A refusal is proven by the server's own count of connections and queries, and the state
file is read back to prove it never holds the credential.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ildottore.adapters import RetryConfig, WebSocketAdapter
from ildottore.adapters.agent_guard import (
    STATE_DIR_ENV,
    AgentAuthRefused,
    AgentGuardState,
    AgentPacingStop,
    AgentTenantMismatch,
    AgentToolStop,
    GuardStop,
    check_token,
    guard_state_dir,
    reported_tools,
    token_claims,
)
from ildottore.adapters.websocket import WebSocketOverflow
from ildottore.core.execute import default_is_env_error
from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.redactor import Redactor
from ildottore.shared.models import ModelRequest, WebSocketGuard, WebSocketSpec
from tests.agent_ws_server import AGENT_BLOCK, TENANT, agent_server, jwt
from tests.ws_raw_servers import HandlerServer

_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=2.0)
_NOW = 1_800_000_000.0


class _Clock:
    """A wall clock the test moves by hand."""

    def __init__(self, now: float = _NOW) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _token(**claims: Any) -> str:
    return jwt({"tenant_id": TENANT, "exp": _NOW + 3600, "sub": "operator", **claims})


def _spec(**guard: Any) -> WebSocketSpec:
    raw: dict[str, Any] = json.loads(json.dumps(AGENT_BLOCK))
    for key, value in guard.items():
        if value is None:
            raw["guard"].pop(key, None)
        else:
            raw["guard"][key] = value
    return WebSocketSpec.model_validate(raw)


def _adapter(
    server: HandlerServer,
    spec: WebSocketSpec | None = None,
    *,
    token: str | None = None,
    clock: _Clock | None = None,
    state: Path,
    **extra: Any,
) -> WebSocketAdapter:
    allowlist = EndpointAllowlist(
        [Endpoint(host=f"127.0.0.1:{server.port}", path_prefixes=["/ws"])]
    )
    return WebSocketAdapter(
        id="agent-test",
        url=server.url,
        allowlist=allowlist,
        spec=spec if spec is not None else _spec(),
        api_key=token if token is not None else _token(),
        retry=_FAST,
        guard_state_dir=state,
        clock=clock if clock is not None else _Clock(),
        **extra,
    )


def _state_files(state: Path) -> list[Path]:
    return sorted((state / "guard").glob("*.json"))


# --- the block ------------------------------------------------------------------------------


def test_failure_codes_and_code_path_go_together() -> None:
    with pytest.raises(ValidationError, match="go together"):
        WebSocketGuard.model_validate({"auth": {"failure_codes": ["UNAUTHORIZED"]}})
    with pytest.raises(ValidationError, match="go together"):
        WebSocketGuard.model_validate({"auth": {"code_path": "code"}})


def test_the_endpoint_path_is_absolute_and_the_scheme_one_of_the_two_transports() -> None:
    with pytest.raises(ValidationError):
        WebSocketGuard.model_validate({"endpoint": {"path": "ws"}})
    with pytest.raises(ValidationError):
        WebSocketGuard.model_validate({"endpoint": {"scheme": "ftp"}})
    # https is a rest.guard's scheme (u04 A-98); under websocket.guard the loader refuses it.
    assert WebSocketGuard.model_validate({"endpoint": {"scheme": "https"}}).endpoint is not None


def test_the_state_directory_follows_the_variable_then_xdg_then_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(STATE_DIR_ENV, str(tmp_path / "explicit"))
    assert guard_state_dir() == tmp_path / "explicit"
    monkeypatch.delenv(STATE_DIR_ENV)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert guard_state_dir() == tmp_path / "xdg" / "ildottore"
    monkeypatch.delenv("XDG_STATE_HOME")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert guard_state_dir() == tmp_path / "home" / ".local" / "state" / "ildottore"


# --- the credential, before it is sent ------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "not-a-jwt-at-all",
        "a.b",
        "a.!!!.c",
        "a." + "W10" + ".c",  # a payload that is a JSON list
        "a." + "x" * 20000 + ".c",
    ],
)
def test_anything_but_a_jwt_with_an_object_payload_has_no_claims(token: str) -> None:
    assert token_claims(token) is None


def _check(token: str, *, tenant: str = TENANT, claims: list[str] | None = None) -> None:
    check_token(
        "agent-test",
        token,
        tenant=tenant,
        tenant_claims=claims or ["tenant_id", "org_id"],
        min_lifetime_s=30,
        now=_NOW,
    )


def test_a_jwt_for_the_tenant_with_life_left_passes() -> None:
    _check(_token())
    # The first claim the token carries is the one compared.
    _check(jwt({"org_id": TENANT, "exp": _NOW + 60}))


@pytest.mark.parametrize(
    ("token", "error", "reason"),
    [
        ("plain-credential-0123456789", AgentTenantMismatch, "not a JWT"),
        (jwt({"exp": _NOW + 3600}), AgentTenantMismatch, "none of the tenant claims"),
        (_token(tenant_id="tenant-9999"), AgentTenantMismatch, "not the one"),
        (jwt({"tenant_id": TENANT}), AgentTenantMismatch, "no exp"),
        (jwt({"tenant_id": TENANT, "exp": True}), AgentTenantMismatch, "no exp"),
        (_token(exp=_NOW + 10), AgentAuthRefused, "expires in 10s"),
        (_token(exp=_NOW - 5), AgentAuthRefused, "has expired"),
    ],
)
def test_a_credential_the_guard_refuses_and_why(
    token: str, error: type[GuardStop], reason: str
) -> None:
    with pytest.raises(error, match=reason) as caught:
        _check(token)
    # The message names the claim, never a value: no tenant, no token.
    assert TENANT not in str(caught.value) and "tenant-9999" not in str(caught.value)
    assert token not in str(caught.value)


def test_a_guard_stop_halts_the_campaign_and_survives_the_redactor() -> None:
    """Not an environment error (nothing retries it), and its class names reach the evidence
    readable (the redactor's high-entropy rule masked four names once: PR #87)."""

    for cls in (GuardStop, AgentAuthRefused, AgentTenantMismatch, AgentPacingStop, AgentToolStop):
        assert default_is_env_error(cls("x")) is False
        assert Redactor().redact_text(cls.__name__) == cls.__name__


# --- the state, across processes ------------------------------------------------------------


def _state(tmp_path: Path, clock: _Clock, **guard: Any) -> AgentGuardState:
    return AgentGuardState(
        "agent-test",
        "wss://assistant.example.test/ws",
        WebSocketGuard.model_validate(guard),
        tmp_path,
        clock,
    )


def test_a_refused_credential_is_remembered_by_digest_never_by_value(tmp_path: Path) -> None:
    clock = _Clock()
    state = _state(tmp_path, clock, auth={"cooldown_seconds": 0})
    token = _token()
    state.admit(token)
    state.record_auth_failure(token, refused=True)
    # Another process (another object over the same file) refuses it too.
    other = _state(tmp_path, clock, auth={"cooldown_seconds": 0})
    with pytest.raises(AgentAuthRefused, match="refused this credential before"):
        other.admit(token)
    other.admit(_token(sub="another-operator"))  # a fresh credential passes

    (path,) = _state_files(tmp_path)
    assert token not in path.read_text(encoding="utf-8")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    # One file per endpoint, named by its digest: the directory does not list the host.
    assert "example" not in path.name


def test_the_refused_digests_are_bounded(tmp_path: Path) -> None:
    state = _state(tmp_path, _Clock(), auth={"cooldown_seconds": 0})
    for index in range(40):
        state.record_auth_failure(_token(sub=f"op-{index}"), refused=True)
    (path,) = _state_files(tmp_path)
    assert len(json.loads(path.read_text(encoding="utf-8"))["refused_credentials"]) == 32


def test_the_cooldown_holds_every_process_then_lifts(tmp_path: Path) -> None:
    clock = _Clock()
    state = _state(tmp_path, clock, auth={"cooldown_seconds": 120})
    state.record_auth_failure(_token(), refused=False)
    clock.now += 60
    with pytest.raises(AgentPacingStop, match="60s more"):
        _state(tmp_path, clock, auth={"cooldown_seconds": 120}).admit(_token())
    clock.now += 61
    state.admit(_token())  # not refused outright: the same credential may try again


def test_pacing_spaces_queries_and_caps_the_hour_across_processes(tmp_path: Path) -> None:
    clock = _Clock()
    pacing = {"min_interval_seconds": 15, "max_per_hour": 3}
    first, second = _state(tmp_path, clock, pacing=pacing), _state(tmp_path, clock, pacing=pacing)
    assert first.reserve() == 0.0
    assert second.reserve() == 15.0  # the other process's slot counts
    assert first.reserve() == 30.0
    with pytest.raises(AgentPacingStop, match="3 queries in the last hour"):
        second.reserve()
    # The refusal reserved nothing; an hour after the first slot one frees again.
    clock.now += 3601
    assert second.reserve() == 0.0


def test_a_torn_state_file_starts_over(tmp_path: Path) -> None:
    clock = _Clock()
    state = _state(tmp_path, clock, pacing={"min_interval_seconds": 5})
    state.path.parent.mkdir(parents=True)
    state.path.write_text("{not json", encoding="utf-8")
    assert state.reserve() == 0.0
    state.path.write_text('["a list"]', encoding="utf-8")
    assert state.reserve() == 0.0


def test_no_pacing_block_reserves_nothing(tmp_path: Path) -> None:
    state = _state(tmp_path, _Clock())
    assert state.reserve() == 0.0
    assert _state_files(tmp_path) == []


def test_reported_tools_reads_one_name_or_a_list() -> None:
    assert reported_tools({"tool": "a"}, "tool") == ["a"]
    assert reported_tools({"step": {"tools": ["a", 3, "b"]}}, "step.tools") == ["a", "b"]
    assert reported_tools({"tool": {"name": "a"}}, "tool") == []


# --- the adapter, against the loopback agent ------------------------------------------------


async def test_a_guarded_turn_reads_the_answer_and_paces_it(tmp_path: Path) -> None:
    waits: list[float] = []

    async def pause(seconds: float) -> None:
        waits.append(seconds)

    spec = _spec(pacing={"min_interval_seconds": 10})
    with agent_server() as server:
        adapter = _adapter(server, spec, state=tmp_path, pause=pause)
        first = await adapter.send(ModelRequest(prompt="hello"))
        second = await adapter.send(ModelRequest(prompt="again"))
    assert first.text == "echo: hello" and second.text == "echo: again"
    assert waits == [10.0]  # the first went at once; the second waited out the interval
    assert server.log.queries == 2
    auth = server.log.frames[0]
    assert auth["type"] == "auth" and auth["tenant"] == TENANT


async def test_a_401_at_the_upgrade_stops_and_refuses_the_credential(tmp_path: Path) -> None:
    from tests.ws_chat_server import FakeChatServer

    with FakeChatServer(upgrade_status=401, path="/ws") as server:
        allowlist = EndpointAllowlist(
            [Endpoint(host=f"127.0.0.1:{server.port}", path_prefixes=["/ws"])]
        )
        adapter = WebSocketAdapter(
            id="agent-test",
            url=server.url,
            allowlist=allowlist,
            spec=_spec(),
            api_key=_token(),
            retry=_FAST,
            guard_state_dir=tmp_path,
            clock=_Clock(),
        )
        with pytest.raises(AgentAuthRefused, match="HTTP 401 at the upgrade"):
            await adapter.send(ModelRequest(prompt="hi"))
        with pytest.raises(AgentAuthRefused, match="refused this credential before"):
            await adapter.send(ModelRequest(prompt="hi"))
    assert server.log.upgrade_requests == 1  # the second send dialled nothing


async def test_an_auth_error_code_in_the_handshake_reply_stops(tmp_path: Path) -> None:
    reply = {"type": "error", "code": "UNAUTHORIZED", "message": "bad token"}
    with agent_server(auth_reply=reply) as server:
        adapter = _adapter(server, state=tmp_path)
        with pytest.raises(AgentAuthRefused, match="error code 'UNAUTHORIZED'") as caught:
            await adapter.send(ModelRequest(prompt="hi"))
        with pytest.raises(AgentAuthRefused, match="refused this credential before"):
            await adapter.send(ModelRequest(prompt="hi"))
    assert default_is_env_error(caught.value) is False
    assert server.log.connections == 1 and server.log.queries == 0


async def test_a_reply_that_does_not_satisfy_expect_is_an_auth_failure(tmp_path: Path) -> None:
    with agent_server(auth_reply={"type": "welcome"}) as server:
        adapter = _adapter(server, _spec(auth={"cooldown_seconds": 5}), state=tmp_path)
        with pytest.raises(AgentAuthRefused, match="did not satisfy expect"):
            await adapter.send(ModelRequest(prompt="hi"))
    assert server.log.queries == 0


@pytest.mark.parametrize("auth_reply", ["close", "silent"])
async def test_no_handshake_reply_starts_the_cooldown_without_refusing_the_token(
    tmp_path: Path, auth_reply: str
) -> None:
    clock = _Clock()
    with agent_server(auth_reply=auth_reply) as server:
        spec = _spec()
        if auth_reply == "silent":
            raw = spec.model_dump(mode="json")
            raw["response"]["timeout_seconds"] = 0.3
            spec = WebSocketSpec.model_validate(raw)
        adapter = _adapter(server, spec, state=tmp_path, clock=clock)
        with pytest.raises(AgentAuthRefused, match="handshake reply"):
            await adapter.send(ModelRequest(prompt="hi"))
        with pytest.raises(AgentPacingStop, match="guard waits"):
            await adapter.send(ModelRequest(prompt="hi"))
        assert server.log.connections == 1
        clock.now += 121
        # The cooldown over, the same credential dials again (it was not refused outright).
        with pytest.raises(AgentAuthRefused):
            await adapter.send(ModelRequest(prompt="hi"))
        assert server.log.connections == 2


async def test_a_reply_naming_another_tenant_stops_before_any_query(tmp_path: Path) -> None:
    with agent_server(auth_reply={"type": "auth_ok", "tenant_id": "tenant-9999"}) as server:
        adapter = _adapter(server, state=tmp_path)
        with pytest.raises(AgentTenantMismatch, match="before any query") as caught:
            await adapter.send(ModelRequest(prompt="hi"))
    assert server.log.queries == 0
    assert "tenant-9999" not in str(caught.value)


async def test_a_token_for_another_tenant_is_never_sent(tmp_path: Path) -> None:
    with agent_server() as server:
        adapter = _adapter(server, token=_token(tenant_id="tenant-9999"), state=tmp_path)
        with pytest.raises(AgentTenantMismatch):
            await adapter.send(ModelRequest(prompt="hi"))
    assert server.log.connections == 0


async def test_an_endpoint_off_the_guard_path_dials_nothing(tmp_path: Path) -> None:
    with agent_server() as server:
        adapter = _adapter(
            server, _spec(endpoint={"scheme": "ws", "path": "/ws/v2"}), state=tmp_path
        )
        with pytest.raises(GuardStop, match="scheme and path"):
            await adapter.send(ModelRequest(prompt="hi"))
    assert server.log.connections == 0


async def test_a_listed_tool_closes_the_connection(tmp_path: Path) -> None:
    def script(_message: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"type": "progress", "tool": "search_docs"},
            {"type": "progress", "tool": "write_record"},
            {"type": "answer", "text": "done", "final": True},
        ]

    with agent_server(on_query=script) as server:
        adapter = _adapter(server, state=tmp_path)
        with pytest.raises(AgentToolStop, match="'write_record'") as caught:
            await adapter.send(ModelRequest(prompt="hi"))
    assert server.log.closed == 1
    assert default_is_env_error(caught.value) is False


async def test_a_listed_tool_in_an_ignored_frame_still_stops(tmp_path: Path) -> None:
    raw = json.loads(json.dumps(AGENT_BLOCK))
    raw["response"]["ignore_types"] = ["progress"]
    with agent_server(on_query=lambda _m: [{"type": "progress", "tool": "run_workflow"}]) as server:
        adapter = _adapter(server, WebSocketSpec.model_validate(raw), state=tmp_path)
        with pytest.raises(AgentToolStop, match="'run_workflow'"):
            await adapter.send(ModelRequest(prompt="hi"))


async def test_an_auth_error_mid_turn_stops_the_run(tmp_path: Path) -> None:
    with agent_server(on_query=lambda _m: [{"type": "error", "code": "TOKEN_EXPIRED"}]) as server:
        adapter = _adapter(server, state=tmp_path)
        with pytest.raises(AgentAuthRefused, match="'TOKEN_EXPIRED'"):
            await adapter.send(ModelRequest(prompt="hi"))


async def test_the_guard_lowers_the_byte_cap_of_a_turn(tmp_path: Path) -> None:
    long = [{"type": "answer", "text": "x" * 400}, {"type": "answer", "text": "y", "final": True}]
    with agent_server(on_query=lambda _m: long) as server:
        adapter = _adapter(server, _spec(max_response_bytes=300), state=tmp_path)
        with pytest.raises(WebSocketOverflow, match="exceeded 300 bytes"):
            await adapter.send(ModelRequest(prompt="hi"))


async def test_the_hourly_cap_stops_the_run_with_the_queries_it_let_through(
    tmp_path: Path,
) -> None:
    with agent_server() as server:
        adapter = _adapter(server, _spec(pacing={"max_per_hour": 1}), state=tmp_path)
        await adapter.send(ModelRequest(prompt="one"))
        with pytest.raises(AgentPacingStop, match="1 queries in the last hour"):
            await adapter.send(ModelRequest(prompt="two"))
    assert server.log.queries == 1


async def test_the_guard_paths_are_kept_as_protocol_fields(tmp_path: Path) -> None:
    with agent_server() as server:
        adapter = _adapter(server, state=tmp_path)
        reply = await adapter.send(ModelRequest(prompt="hello"))
    transcript = reply.raw_ids["websocket"]
    assert {"code", "tool", "tenant_id"} <= set(transcript["protocol_paths"])
    sent = json.dumps(transcript["frames"])
    assert _token() not in sent and "{{token}}" in sent


async def test_without_a_guard_nothing_is_written(tmp_path: Path) -> None:
    raw = json.loads(json.dumps(AGENT_BLOCK))
    raw.pop("guard")
    with agent_server() as server:
        adapter = _adapter(server, WebSocketSpec.model_validate(raw), state=tmp_path)
        await adapter.send(ModelRequest(prompt="hi"))
    assert not (tmp_path / "guard").exists()
