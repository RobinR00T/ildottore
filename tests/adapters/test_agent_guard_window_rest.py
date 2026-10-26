"""The guard's window (``guard.window``) and the guard on a REST target (``rest.guard``), u04 A-98.

The window is read in its own IANA zone, before a dial and again at the slot a query is paced to;
outside it nothing is sent and the run stops. A REST target takes the WebSocket guard's block and
its checks through the same :class:`~ildottore.adapters.agent_guard.GuardKeeper`: an HTTP 401 or
403, an error code in the body, a reply naming another tenant and a listed tool stop the run, and
every attempt (a retry included) takes a pacing slot. Every REST test answers from ``respx``;
the WebSocket ones dial the loopback fake. Nothing leaves the host.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx
import pytest
import respx
import yaml
from pydantic import ValidationError

from ildottore.adapters import (
    EndpointNotAllowed,
    RestAdapter,
    RestTemplate,
    RetryConfig,
    WebSocketAdapter,
)
from ildottore.adapters.agent_guard import (
    AgentAuthRefused,
    AgentGuardState,
    AgentPacingStop,
    AgentTenantMismatch,
    AgentToolStop,
    AgentWindowStop,
    GuardStop,
    in_window,
    next_opening,
)
from ildottore.adapters.base import ResponseTooLarge
from ildottore.core.execute import default_is_env_error
from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.shared.models import (
    ModelRequest,
    WebSocketGuard,
    WebSocketGuardWindow,
    WebSocketSpec,
)
from tests.agent_ws_server import AGENT_BLOCK, TENANT, agent_server, jwt

_MADRID = ZoneInfo("Europe/Madrid")
_URL = "https://agent.example.test/api/chat"
_FAST = RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0)
_OFFICE = {"timezone": "Europe/Madrid", "days": ["mon-fri"], "start": "09:00", "end": "19:00"}


def _at(year: int, month: int, day: int, hour: int, minute: int = 0) -> float:
    """Epoch seconds of a Madrid wall-clock time."""

    return datetime(year, month, day, hour, minute, tzinfo=_MADRID).timestamp()


#: Friday 15 January 2027, 10:00 in Madrid: inside the office window.
_FRIDAY_10 = _at(2027, 1, 15, 10)


class _Clock:
    def __init__(self, now: float = _FRIDAY_10) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _window(**changes: Any) -> WebSocketGuardWindow:
    return WebSocketGuardWindow.model_validate({**_OFFICE, **changes})


# --- the window block ------------------------------------------------------------------------


def test_a_window_needs_a_zone_the_tz_database_names() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        WebSocketGuardWindow.model_validate({k: v for k, v in _OFFICE.items() if k != "timezone"})
    for zone in ("CET+1", "Mars/Olympus", "../etc/passwd", "local"):
        with pytest.raises(ValidationError, match="not an IANA time zone"):
            _window(timezone=zone)


def test_days_are_names_or_ranges_that_do_not_wrap() -> None:
    assert _window(days=["mon-fri"]).weekdays == frozenset(range(5))
    assert _window(days=["MON", "wed-thu", "sun"]).weekdays == frozenset({0, 2, 3, 6})
    with pytest.raises(ValidationError, match="wraps past sun"):
        _window(days=["fri-mon"])
    for bad in (["funday"], ["mon-tue-wed"], []):
        with pytest.raises(ValidationError):
            _window(days=bad)


def test_times_are_hh_mm_and_24_00_only_ends_the_day() -> None:
    assert _window(start="00:00", end="24:00").end_minutes == 1440
    with pytest.raises(ValidationError, match="HH:MM"):
        _window(start="24:00")
    with pytest.raises(ValidationError, match="HH:MM"):
        _window(start="9:00")
    with pytest.raises(ValidationError, match="the same time"):
        _window(start="10:00", end="10:00")


def test_an_unquoted_time_yaml_read_as_minutes_is_refused_with_the_fix() -> None:
    raw = yaml.safe_load("timezone: UTC\ndays: [mon]\nstart: '09:00'\nend: 19:00\n")
    assert raw["end"] == 1140  # YAML 1.1 sexagesimal
    with pytest.raises(ValidationError, match="write the time quoted"):
        WebSocketGuardWindow.model_validate(raw)


def test_a_guard_without_a_window_has_none() -> None:
    assert WebSocketGuard.model_validate({}).window is None


# --- reading the clock -------------------------------------------------------------------------


def test_the_window_is_read_in_its_own_zone() -> None:
    window = _window()
    assert in_window(window, _at(2027, 1, 15, 9))  # start inclusive
    assert not in_window(window, _at(2027, 1, 15, 19))  # end exclusive
    assert not in_window(window, _at(2027, 1, 15, 8, 59))
    assert not in_window(window, _at(2027, 1, 16, 12))  # Saturday
    # 08:30 UTC is 09:30 in Madrid in winter: inside, whatever the host's zone.
    utc = datetime(2027, 1, 15, 8, 30, tzinfo=ZoneInfo("UTC")).timestamp()
    assert in_window(window, utc)
    assert not in_window(_window(timezone="UTC"), _at(2027, 1, 15, 9, 30))


def test_a_window_across_midnight_closes_the_next_morning() -> None:
    nights = _window(days=["fri"], start="22:00", end="06:00")
    assert in_window(nights, _at(2027, 1, 15, 23))  # Friday night
    assert in_window(nights, _at(2027, 1, 16, 5, 59))  # Saturday morning, Friday's night
    assert not in_window(nights, _at(2027, 1, 16, 6))
    assert not in_window(nights, _at(2027, 1, 16, 23))  # Saturday is not listed
    assert not in_window(nights, _at(2027, 1, 15, 5))  # Thursday's night was not listed


def test_the_next_opening_skips_unlisted_days() -> None:
    window = _window()
    assert next_opening(window, _at(2027, 1, 15, 8)) == datetime(2027, 1, 15, 9, tzinfo=_MADRID)
    # Friday evening: the next opening is Monday morning.
    opening = next_opening(window, _at(2027, 1, 15, 20))
    assert opening == datetime(2027, 1, 18, 9, tzinfo=_MADRID)
    # Inside the window, the next opening is the next day's.
    assert next_opening(window, _FRIDAY_10).date().isoformat() == "2027-01-18"


def test_the_window_follows_a_daylight_saving_change() -> None:
    # Madrid moves to summer time on 28 March 2027: 09:00 is then 07:00 UTC, not 08:00.
    window = _window(days=["mon-sun"])
    summer_0730_utc = datetime(2027, 3, 29, 7, 30, tzinfo=ZoneInfo("UTC")).timestamp()
    winter_0730_utc = datetime(2027, 3, 26, 7, 30, tzinfo=ZoneInfo("UTC")).timestamp()
    assert in_window(window, summer_0730_utc)
    assert not in_window(window, winter_0730_utc)


# --- the state refuses outside the window ------------------------------------------------------


def _state(tmp_path: Path, clock: _Clock, **guard: Any) -> AgentGuardState:
    return AgentGuardState(
        "agent-test", _URL, WebSocketGuard.model_validate(guard), tmp_path, clock
    )


def test_outside_the_window_nothing_is_admitted_and_the_message_says_when(
    tmp_path: Path,
) -> None:
    clock = _Clock(_at(2027, 1, 16, 12))  # Saturday noon
    state = _state(tmp_path, clock, window=_OFFICE)
    with pytest.raises(AgentWindowStop) as caught:
        state.admit(None)
    message = str(caught.value)
    assert "outside guard.window (mon-fri 09:00-19:00 Europe/Madrid)" in message
    assert "it is sat 12:00 there" in message and "opens mon 2027-01-18 09:00" in message
    assert "nothing was sent" in message
    assert default_is_env_error(caught.value) is False  # the run stops; nothing retries it
    with pytest.raises(AgentWindowStop):
        state.reserve()
    assert not (tmp_path / "guard").exists()  # refused before the state file is touched


def test_a_slot_paced_past_the_end_of_the_window_is_not_taken(tmp_path: Path) -> None:
    clock = _Clock(_at(2027, 1, 15, 18, 59))
    pacing = {"min_interval_seconds": 120}
    state = _state(tmp_path, clock, window=_OFFICE, pacing=pacing)
    assert state.reserve() == 0.0
    # The next slot falls at 19:01, after the window closes: refused, and not recorded.
    with pytest.raises(AgentWindowStop, match="opens mon 2027-01-18 09:00"):
        state.reserve()
    recorded = json.loads(state.path.read_text(encoding="utf-8"))["sent"]
    assert len(recorded) == 1


# --- the WebSocket adapter with a window -----------------------------------------------------


def _ws_spec(**guard: Any) -> WebSocketSpec:
    raw: dict[str, Any] = json.loads(json.dumps(AGENT_BLOCK))
    raw["guard"].update(guard)
    return WebSocketSpec.model_validate(raw)


def _ws_token(now: float) -> str:
    return jwt({"tenant_id": TENANT, "exp": now + 3600, "sub": "operator"})


async def test_a_websocket_target_outside_its_window_dials_nothing(tmp_path: Path) -> None:
    clock = _Clock(_at(2027, 1, 15, 20))
    with agent_server() as server:
        adapter = WebSocketAdapter(
            id="agent-test",
            url=server.url,
            allowlist=EndpointAllowlist(
                [Endpoint(host=f"127.0.0.1:{server.port}", path_prefixes=["/ws"])]
            ),
            spec=_ws_spec(window=_OFFICE),
            api_key=_ws_token(_at(2027, 1, 18, 9, 30)),  # alive on Monday too
            retry=_FAST,
            guard_state_dir=tmp_path,
            clock=clock,
        )
        with pytest.raises(AgentWindowStop):
            await adapter.send(ModelRequest(prompt="hi"))
        assert server.log.connections == 0
        clock.now = _at(2027, 1, 18, 9, 30)  # Monday morning: open
        reply = await adapter.send(ModelRequest(prompt="hi"))
    assert reply.text == "echo: hi"


# --- the REST adapter with a guard -------------------------------------------------------------


def _rest_guard(**changes: Any) -> WebSocketGuard:
    raw: dict[str, Any] = {
        "endpoint": {"scheme": "https", "path": "/api/chat"},
        "auth": {"code_path": "code", "failure_codes": ["UNAUTHORIZED"], "cooldown_seconds": 300},
        "token": {
            "tenant": TENANT,
            "tenant_claims": ["tenant_id"],
            "reply_tenant_path": "tenant_id",
        },
        "stop_on_tools": {"path": "tool", "names": ["write_record"]},
    }
    for key, value in changes.items():
        if value is None:
            raw.pop(key, None)
        else:
            raw[key] = value
    return WebSocketGuard.model_validate(raw)


def _rest(
    tmp_path: Path,
    guard: WebSocketGuard | None = None,
    *,
    clock: _Clock | None = None,
    token: str | None = None,
    retry: RetryConfig = _FAST,
    host: str = "agent.example.test",
    **extra: Any,
) -> RestAdapter:
    clock = clock if clock is not None else _Clock()
    return RestAdapter(
        id="agent-rest",
        base_url="https://agent.example.test",
        allowlist=EndpointAllowlist([Endpoint(host=host, path_prefixes=["/api"])]),
        api_key=token if token is not None else _ws_token(clock.now),
        template=RestTemplate(path="/api/chat", prompt_field="message", text_path="answer"),
        retry=retry,
        guard=guard if guard is not None else _rest_guard(),
        guard_state_dir=tmp_path,
        clock=clock,
        **extra,
    )


def _ok(text: str = "fine", **extra: Any) -> httpx.Response:
    return httpx.Response(200, json={"answer": text, "tenant_id": TENANT, **extra})


@respx.mock
async def test_a_guarded_rest_reply_is_read_as_before(tmp_path: Path) -> None:
    route = respx.post(_URL).mock(return_value=_ok("hello back"))
    reply = await _rest(tmp_path).send(ModelRequest(prompt="hello"))
    assert reply.text == "hello back" and route.call_count == 1


@pytest.mark.parametrize("status", [401, 403])
@respx.mock
async def test_a_401_or_403_stops_the_run_and_refuses_the_credential(
    tmp_path: Path, status: int
) -> None:
    route = respx.post(_URL).mock(return_value=httpx.Response(status, json={"error": "no"}))
    clock = _Clock()
    token = _ws_token(clock.now)
    with pytest.raises(AgentAuthRefused, match=f"HTTP {status}"):
        await _rest(tmp_path, clock=clock, token=token).send(ModelRequest(prompt="hi"))
    # The next run, the same credential: refused before anything goes out.
    with pytest.raises(AgentAuthRefused, match="refused this credential before"):
        await _rest(tmp_path, clock=clock, token=token).send(ModelRequest(prompt="hi"))
    assert route.call_count == 1
    assert token not in (tmp_path / "guard").joinpath(
        next(p.name for p in (tmp_path / "guard").iterdir())
    ).read_text(encoding="utf-8")


@respx.mock
async def test_an_error_code_in_the_body_is_an_auth_failure_with_a_cooldown(
    tmp_path: Path,
) -> None:
    route = respx.post(_URL).mock(return_value=httpx.Response(400, json={"code": "UNAUTHORIZED"}))
    clock = _Clock()
    with pytest.raises(AgentAuthRefused, match="'UNAUTHORIZED'"):
        await _rest(tmp_path, clock=clock).send(ModelRequest(prompt="hi"))
    # A fresh credential still waits out the cooldown.
    fresh = jwt({"tenant_id": TENANT, "exp": clock.now + 7200, "sub": "other"})
    with pytest.raises(AgentPacingStop, match="cooldown_seconds"):
        await _rest(tmp_path, clock=clock, token=fresh).send(ModelRequest(prompt="hi"))
    assert route.call_count == 1


@respx.mock
async def test_a_token_for_another_tenant_is_never_sent(tmp_path: Path) -> None:
    route = respx.post(_URL).mock(return_value=_ok())
    token = jwt({"tenant_id": "tenant-9999", "exp": _FRIDAY_10 + 3600})
    with pytest.raises(AgentTenantMismatch):
        await _rest(tmp_path, token=token).send(ModelRequest(prompt="hi"))
    assert route.call_count == 0


@respx.mock
async def test_a_reply_naming_another_tenant_stops_and_is_not_read(tmp_path: Path) -> None:
    respx.post(_URL).mock(return_value=_ok(tenant_id="tenant-9999"))
    with pytest.raises(AgentTenantMismatch, match="the reply is not read"):
        await _rest(tmp_path).send(ModelRequest(prompt="hi"))


@respx.mock
async def test_a_listed_tool_stops_the_run_after_that_reply(tmp_path: Path) -> None:
    respx.post(_URL).mock(return_value=_ok(tool="write_record"))
    with pytest.raises(AgentToolStop, match=r"'write_record'.*the run stops after this reply"):
        await _rest(tmp_path).send(ModelRequest(prompt="hi"))
    # A tool the block does not list is read as any reply.
    respx.post(_URL).mock(return_value=_ok("ok", tool="search_docs"))
    assert (await _rest(tmp_path).send(ModelRequest(prompt="hi"))).text == "ok"


@respx.mock
async def test_the_guard_lowers_the_byte_cap_of_a_reply(tmp_path: Path) -> None:
    respx.post(_URL).mock(return_value=_ok("x" * 400))
    with pytest.raises(ResponseTooLarge, match="exceeded 300 bytes"):
        await _rest(tmp_path, _rest_guard(max_response_bytes=300)).send(ModelRequest(prompt="hi"))


@respx.mock
async def test_every_attempt_a_retry_included_takes_a_pacing_slot(tmp_path: Path) -> None:
    waits: list[float] = []

    async def pause(seconds: float) -> None:
        waits.append(seconds)

    respx.post(_URL).mock(side_effect=[httpx.Response(429), _ok("after the retry")])
    adapter = _rest(
        tmp_path,
        _rest_guard(pacing={"min_interval_seconds": 10}),
        retry=RetryConfig(max_retries=2, backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=1.0),
        pause=pause,
    )
    reply = await adapter.send(ModelRequest(prompt="hi"))
    assert reply.text == "after the retry"
    assert waits == [10.0]  # the first attempt went at once; the retry waited its slot


@respx.mock
async def test_the_hourly_cap_stops_a_rest_run(tmp_path: Path) -> None:
    route = respx.post(_URL).mock(return_value=_ok())
    adapter = _rest(tmp_path, _rest_guard(pacing={"max_per_hour": 1}))
    await adapter.send(ModelRequest(prompt="one"))
    with pytest.raises(AgentPacingStop, match="1 queries in the last hour"):
        await adapter.send(ModelRequest(prompt="two"))
    assert route.call_count == 1


@respx.mock
async def test_a_rest_target_outside_its_window_sends_nothing(tmp_path: Path) -> None:
    route = respx.post(_URL).mock(return_value=_ok())
    clock = _Clock(_at(2027, 1, 16, 12))
    with pytest.raises(AgentWindowStop, match="opens mon 2027-01-18 09:00"):
        await _rest(tmp_path, _rest_guard(window=_OFFICE), clock=clock).send(
            ModelRequest(prompt="hi")
        )
    assert route.call_count == 0


@respx.mock
async def test_an_endpoint_off_the_guard_path_sends_nothing(tmp_path: Path) -> None:
    route = respx.post(_URL).mock(return_value=_ok())
    guard = _rest_guard(endpoint={"scheme": "https", "path": "/api/v2/chat"})
    with pytest.raises(GuardStop, match="scheme and path"):
        await _rest(tmp_path, guard).send(ModelRequest(prompt="hi"))
    assert route.call_count == 0


@respx.mock
async def test_an_off_allowlist_url_reaches_neither_the_state_nor_the_network(
    tmp_path: Path,
) -> None:
    route = respx.post(_URL).mock(return_value=_ok())
    with pytest.raises(EndpointNotAllowed):
        await _rest(tmp_path, host="other.example.test").send(ModelRequest(prompt="hi"))
    assert route.call_count == 0 and not (tmp_path / "guard").exists()


@respx.mock
async def test_without_a_guard_a_rest_target_writes_no_state(tmp_path: Path) -> None:
    respx.post(_URL).mock(return_value=httpx.Response(401, json={"error": "no"}))
    adapter = RestAdapter(
        id="plain-rest",
        base_url="https://agent.example.test",
        allowlist=EndpointAllowlist([Endpoint(host="agent.example.test", path_prefixes=["/api"])]),
        api_key="tok-fake-000000000000000000",
        template=RestTemplate(path="/api/chat", prompt_field="message", text_path="answer"),
        retry=_FAST,
        guard_state_dir=tmp_path,
    )
    with pytest.raises(Exception) as caught:
        await adapter.send(ModelRequest(prompt="hi"))
    assert not isinstance(caught.value, GuardStop)
    assert not (tmp_path / "guard").exists()
