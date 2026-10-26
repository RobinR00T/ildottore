"""``rest.guard``, ``guard.window`` and profiles by name, through the loader and the CLI (u04 A-98).

The loader reads a REST target's ``rest`` block with the WebSocket guard's rules; the digest
leaves it out; the dry run names the guard and its window and says when a run started now would
send nothing. ``-t name`` and ``--scope name`` read ``name.yaml`` from the profile directories
(``ILDOTTORE_TARGETS_DIR``, ``ILDOTTORE_SCOPES_DIR``; the root ``conftest`` points both at an
empty temporary directory per test). Nothing leaves the host: the REST campaign answers from
``respx``.
"""

from __future__ import annotations

import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from zoneinfo import ZoneInfo

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from ildottore.cli import run as run_mod
from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.cli.exit_codes import ExitCode
from ildottore.policy import authorize_target
from ildottore.shared.digest import target_digest
from tests.agent_ws_server import AGENT_BLOCK, TENANT, jwt

from .conftest import make_spec, write_spec_tree

_REPO = Path(__file__).resolve().parent.parent.parent
_EXAMPLE_TARGET = _REPO / "examples" / "target.agent-rest.yaml"
_EXAMPLE_SCOPE = _REPO / "examples" / "scope.agent-rest.yaml"
_MADRID = ZoneInfo("Europe/Madrid")
_URL = "https://assistant.example.test/api/chat"


def _at(year: int, month: int, day: int, hour: int, minute: int = 0) -> float:
    return datetime(year, month, day, hour, minute, tzinfo=_MADRID).timestamp()


def _example() -> dict[str, Any]:
    raw = yaml.safe_load(_EXAMPLE_TARGET.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


def _write(tmp_path: Path, raw: dict[str, Any], name: str = "target.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return path


# --- the example and the loader -------------------------------------------------------------


def test_the_rest_example_loads_and_its_scope_authorizes_it() -> None:
    target = wiring.load_target(_EXAMPLE_TARGET)
    assert target.rest is not None and target.rest.guard is not None
    guard = target.rest.guard
    assert guard.window is not None and guard.window.timezone == "Europe/Madrid"
    assert guard.window.weekdays == frozenset(range(5))
    scope = wiring.build_scope(_EXAMPLE_SCOPE)
    endpoint = wiring.scope_endpoint_of(scope, target)
    assert endpoint == _URL
    assert authorize_target(scope, target.id, endpoint).allowed


def test_the_rest_guard_reaches_the_adapter() -> None:
    from ildottore.adapters import RestAdapter
    from ildottore.policy import EndpointAllowlist
    from ildottore.policy.scope import Endpoint

    target = wiring.load_target(_EXAMPLE_TARGET)
    allowlist = EndpointAllowlist(
        [Endpoint(host="assistant.example.test:443", path_prefixes=["/api/chat"])]
    )
    adapter = wiring.build_real_adapter(target, allowlist, api_key=_token())
    assert isinstance(adapter, RestAdapter) and target.rest is not None
    assert adapter.guard == target.rest.guard


def _with_guard(**changes: Any) -> dict[str, Any]:
    raw = _example()
    for key, value in changes.items():
        if value is None:
            raw["rest"]["guard"].pop(key, None)
        else:
            raw["rest"]["guard"][key] = value
    return raw


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (_with_guard(endpoint={"scheme": "wss"}), "rest.guard.endpoint.scheme"),
        (_with_guard(endpoint={"path": "/api/admin"}), "path is not the one"),
        (
            _with_guard(token={"tenant": "{{tenant}}", "tenant_claims": ["tenant_id"]}),
            "a rest target has no vars",
        ),
        (
            _with_guard(window={"days": ["mon"], "start": "09:00", "end": "17:00"}),
            "timezone",
        ),
        (
            _with_guard(
                window={
                    "timezone": "Nowhere/City",
                    "days": ["mon"],
                    "start": "09:00",
                    "end": "17:00",
                }
            ),
            "not an IANA time zone",
        ),
        ({**_example(), "provider": "openai", "model": "m"}, "rest"),
        ({**_example(), "rest": ["not", "a", "mapping"]}, "rest"),
        ({**_example(), "rest": {"guard": {}, "extra": 1}}, "rest"),
    ],
)
def test_the_loader_refuses_a_rest_block_the_file_cannot_keep(
    tmp_path: Path, raw: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        wiring.load_target(_write(tmp_path, raw))


def test_a_websocket_guard_with_an_http_scheme_is_refused(tmp_path: Path) -> None:
    block: dict[str, Any] = yaml.safe_load(yaml.safe_dump(AGENT_BLOCK))
    block["guard"]["endpoint"] = {"scheme": "https", "path": "/ws"}
    raw = {
        "id": "agent-live",
        "type": "agent",
        "provider": "websocket",
        "endpoint": "ws://127.0.0.1:9/ws",
        "auth_ref": "env://TEST_AGENT_JWT",
        "websocket": block,
    }
    with pytest.raises(ValueError, match=r"websocket\.guard\.endpoint\.scheme"):
        wiring.load_target(_write(tmp_path, raw))


def test_the_rest_guard_is_not_part_of_the_target_digest(tmp_path: Path) -> None:
    guarded = wiring.load_target(_write(tmp_path, _example(), "a.yaml"))
    eased = wiring.load_target(
        _write(tmp_path, _with_guard(window=None, pacing={"max_per_hour": 5}), "b.yaml")
    )
    plain_raw = _example()
    plain_raw.pop("rest")
    plain = wiring.load_target(_write(tmp_path, plain_raw, "c.yaml"))
    assert target_digest(guarded) == target_digest(eased) == target_digest(plain)
    # The endpoint is still in it.
    moved = wiring.load_target(
        _write(tmp_path, {**plain_raw, "endpoint": "https://other.example.test/api/chat"}, "d.yaml")
    )
    assert target_digest(moved) != target_digest(plain)


# --- the dry run --------------------------------------------------------------------------------


def test_the_guard_line_names_the_window_and_when_it_opens() -> None:
    target = wiring.load_target(_EXAMPLE_TARGET)
    inside = run_mod._guard_line(target, 10, now=_at(2027, 1, 15, 10))
    assert inside is not None
    assert "window mon-fri 09:00-19:00 Europe/Madrid" in inside
    assert "outside the window" not in inside
    assert "stops on 3 tool name(s)" in inside and "200000 bytes per reply" in inside
    outside = run_mod._guard_line(target, 10, now=_at(2027, 1, 16, 12))
    assert outside is not None
    assert (
        "outside the window now: a run started now sends nothing; it opens mon 2027-01-18 09:00"
    ) in outside


def test_the_worked_example_dry_run_prints_the_rest_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """examples/README.md, Scenario L, prints this plan (sends nothing); the clock is a Saturday."""

    monkeypatch.setattr(run_mod, "time", SimpleNamespace(time=lambda: _at(2027, 1, 16, 12)))
    result = CliRunner().invoke(
        app,
        ["run", "--dry-run", "--quick", "-t", str(_EXAMPLE_TARGET), "--scope", str(_EXAMPLE_SCOPE)],
    )
    assert result.exit_code == 0, result.output
    assert f"target:  agent-rest-staging (agent) authorized at {_URL}" in result.output
    assert (
        "  guard:   auth failure stops the run, 300s cooldown; token tenant checked, at least 30s "
        "of life; 20s between queries, at most 30/hour (across processes); this plan's 125 "
        "requests pass the hourly cap: the run stops there, resume it later; window mon-fri "
        "09:00-19:00 Europe/Madrid; outside the window now: a run started now sends nothing; it "
        "opens mon 2027-01-18 09:00; stops on 3 tool name(s); 200000 bytes per reply"
    ) in result.output


# --- a guarded REST campaign ------------------------------------------------------------------


def _token(**claims: Any) -> str:
    return jwt({"tenant_id": TENANT, "exp": int(time.time()) + 3600, **claims})


def _campaign_files(tmp_path: Path, **guard: Any) -> tuple[Path, Path]:
    raw = _with_guard(window=None, pacing=None, **guard)
    raw["rest"]["guard"]["token"]["tenant"] = TENANT
    raw["auth_ref"] = "env://TEST_AGENT_JWT"
    target = _write(tmp_path, raw)
    scope_raw = yaml.safe_load(_EXAMPLE_SCOPE.read_text(encoding="utf-8"))
    scope_raw["targets"][0]["identities"][0]["auth_ref"] = "env://TEST_AGENT_JWT"
    scope = _write(tmp_path, scope_raw, "scope.yaml")
    return target, scope


def _run(tmp_path: Path, target: str, scope: str, specs: Path, *extra: str) -> Any:
    return CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            target,
            "--scope",
            scope,
            "--spec-path",
            str(specs),
            "--runs",
            "1",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            *extra,
        ],
    )


@respx.mock
def test_a_401_stops_the_rest_run_and_the_next_run_sends_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_AGENT_JWT", _token())
    route = respx.post(_URL).mock(return_value=httpx.Response(401, json={"error": "no"}))
    target, scope = _campaign_files(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001"), make_spec("PI-DIRECT-002")])
    first = _run(tmp_path, str(target), str(scope), specs)
    second = _run(tmp_path, str(target), str(scope), specs)
    assert first.exit_code == ExitCode.ERROR, first.output
    assert "authentication failed (HTTP 401)" in first.output
    assert second.exit_code == ExitCode.ERROR, second.output
    assert "refused this credential before" in second.output
    assert route.call_count == 1


@respx.mock
def test_a_listed_tool_stops_the_rest_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_AGENT_JWT", _token())
    route = respx.post(_URL).mock(
        return_value=httpx.Response(200, json={"text": "done", "tool": "send_message"})
    )
    target, scope = _campaign_files(tmp_path)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001"), make_spec("PI-DIRECT-002")])
    result = _run(tmp_path, str(target), str(scope), specs)
    assert result.exit_code == ExitCode.ERROR, result.output
    assert "'send_message', which guard.stop_on_tools lists" in result.output
    assert route.call_count == 1


# --- profiles by name ---------------------------------------------------------------------------


def test_a_bare_name_reads_the_profile_and_a_path_reads_as_before(
    tmp_path: Path, profile_dirs_in_tmp: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets, scopes = profile_dirs_in_tmp
    targets.mkdir()
    shutil.copy(_EXAMPLE_TARGET, targets / "staging.yaml")
    monkeypatch.chdir(tmp_path)
    assert wiring.resolve_profile(Path("staging"), "target") == targets / "staging.yaml"
    # A path, a suffix, or a name with a separator: read as written, never looked up.
    for written in ("staging.yaml", "./sub/staging", str(_EXAMPLE_TARGET)):
        assert wiring.resolve_profile(Path(written), "target") == Path(written)
    # The scope directory is its own.
    with pytest.raises(ValueError, match=r"no scope file or profile named 'staging'"):
        wiring.resolve_profile(Path("staging"), "scope")
    assert str(scopes) in _refusal(Path("staging"), "scope")


def _refusal(arg: Path, kind: str) -> str:
    with pytest.raises(ValueError) as caught:
        wiring.resolve_profile(arg, kind)
    return str(caught.value)


def test_an_ambiguous_or_missing_profile_is_refused_and_says_why(
    tmp_path: Path, profile_dirs_in_tmp: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets, _ = profile_dirs_in_tmp
    targets.mkdir()
    monkeypatch.chdir(tmp_path)
    missing = _refusal(Path("prod"), "target")
    assert "no target file or profile named 'prod'" in missing
    assert str(targets / "prod.yaml") in missing and "ILDOTTORE_TARGETS_DIR" in missing
    (targets / "prod.yaml").write_text("id: x\n", encoding="utf-8")
    (targets / "prod.yml").write_text("id: x\n", encoding="utf-8")
    assert "is both" in _refusal(Path("prod"), "target")
    (targets / "prod.yml").unlink()
    (tmp_path / "prod").write_text("id: y\n", encoding="utf-8")
    assert "both a file here and the profile" in _refusal(Path("prod"), "target")
    # A directory here of the same name is not a file: the profile is read.
    (tmp_path / "prod").unlink()
    (tmp_path / "prod").mkdir()
    assert wiring.resolve_profile(Path("prod"), "target") == targets / "prod.yaml"


def test_the_default_profile_directory_is_under_the_home_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ILDOTTORE_TARGETS_DIR")
    monkeypatch.setenv("HOME", str(tmp_path))
    assert wiring.profile_dir("target") == tmp_path / ".config" / "ildottore" / "targets"
    monkeypatch.setenv("ILDOTTORE_SCOPES_DIR", "~/elsewhere")
    assert wiring.profile_dir("scope") == Path(os.path.expanduser("~/elsewhere"))


def test_run_and_fingerprint_take_profiles_by_name(
    tmp_path: Path, profile_dirs_in_tmp: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets, scopes = profile_dirs_in_tmp
    targets.mkdir()
    scopes.mkdir()
    shutil.copy(_EXAMPLE_TARGET, targets / "staging.yaml")
    shutil.copy(_EXAMPLE_SCOPE, scopes / "staging.yaml")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_mod, "time", SimpleNamespace(time=lambda: _at(2027, 1, 15, 10)))
    result = CliRunner().invoke(
        app, ["run", "--dry-run", "--quick", "-t", "staging", "--scope", "staging"]
    )
    assert result.exit_code == 0, result.output
    assert "agent-rest-staging (agent) authorized at" in result.output
    missing = CliRunner().invoke(app, ["run", "--dry-run", "-t", "nope", "--scope", "staging"])
    assert missing.exit_code == ExitCode.ERROR
    assert "no target file or profile named 'nope'" in missing.output
    judge = CliRunner().invoke(
        app, ["run", "--dry-run", "-t", "staging", "--scope", "staging", "--judge", "nope"]
    )
    assert judge.exit_code == ExitCode.ERROR and "named 'nope'" in judge.output
    fingerprint = CliRunner().invoke(app, ["fingerprint", "nope", "--offline"])
    assert fingerprint.exit_code == ExitCode.ERROR
    assert "no target file or profile named 'nope'" in fingerprint.output
    fleet_judge = CliRunner().invoke(
        app,
        [
            "fleet",
            str(_REPO / "examples" / "fleet.example.yaml"),
            "--out",
            str(tmp_path / "fleet"),
            "--judge",
            "nope",
        ],
    )
    assert fleet_judge.exit_code == ExitCode.ERROR and "named 'nope'" in fleet_judge.output
