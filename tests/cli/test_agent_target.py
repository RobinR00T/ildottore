"""A deployed agent's profile (``provider: websocket`` with ``websocket.guard``) through the
composition root: the example profile, the loader's refusals, the dry-run's guard line, the
target digest, and real campaigns against the loopback agent that stop on the first
authentication failure and refuse to dial again during the cooldown.

No network leaves the host: the agent is :func:`tests.agent_ws_server.agent_server`, and the
guard's state goes to the per-test directory ``tests/conftest.py`` sets.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.cli.exit_codes import ExitCode
from ildottore.policy import authorize_target
from ildottore.shared.digest import target_digest
from ildottore.shared.enums import VerdictStatus
from tests.agent_ws_server import AGENT_BLOCK, TENANT, agent_server, jwt
from tests.ws_raw_servers import HandlerServer

from .conftest import make_spec, write_spec_tree

_REPO = Path(__file__).resolve().parent.parent.parent
_EXAMPLE_TARGET = _REPO / "examples" / "target.agent.yaml"
_EXAMPLE_SCOPE = _REPO / "examples" / "scope.agent.yaml"


def _write_target(
    tmp_path: Path,
    endpoint: str,
    *,
    block: dict[str, Any] | None = None,
    auth_ref: str | None = "env://TEST_AGENT_JWT",
) -> Path:
    raw: dict[str, Any] = {
        "id": "agent-live",
        "type": "agent",
        "provider": "websocket",
        "endpoint": endpoint,
        "capabilities": {"rag": True},
        "websocket": block if block is not None else json.loads(json.dumps(AGENT_BLOCK)),
    }
    if auth_ref is not None:
        raw["auth_ref"] = auth_ref
    path = tmp_path / "target.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return path


def _write_scope(tmp_path: Path, server: HandlerServer) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        'version: "1.0"\ntargets:\n'
        "  - id: agent-live\n"
        f'    base_url: "{server.url}"\n'
        "    endpoints:\n"
        f'      - host: "127.0.0.1:{server.port}"\n'
        '        path_prefixes: ["/ws"]\n'
        "    identities:\n"
        "      - name: default\n"
        '        auth_ref: "env://TEST_AGENT_JWT"\n',
        encoding="utf-8",
    )
    return path


def _run(tmp_path: Path, target: Path, scope: Path, specs: Path) -> Any:
    return CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(target),
            "--scope",
            str(scope),
            "--spec-path",
            str(specs),
            "--runs",
            "1",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
        ],
    )


def _fresh_jwt(**claims: Any) -> str:
    return jwt({"tenant_id": TENANT, "exp": int(time.time()) + 3600, **claims})


# --- the example and the loader -------------------------------------------------------------


def test_the_example_profile_loads_and_its_scope_authorizes_it() -> None:
    target = wiring.load_target(_EXAMPLE_TARGET)
    scope = wiring.build_scope(_EXAMPLE_SCOPE)
    assert target.websocket is not None and target.websocket.guard is not None
    guard = target.websocket.guard
    assert guard.endpoint is not None and guard.endpoint.scheme == "wss"
    assert guard.pacing is not None and guard.pacing.max_per_hour == 20
    endpoint = wiring.scope_endpoint_of(scope, target)
    assert endpoint == "wss://assistant.example.test/ws"
    assert authorize_target(scope, target.id, endpoint).allowed


def test_the_worked_example_dry_run_prints_the_guard() -> None:
    """examples/README.md, Scenario I, prints this plan (sends nothing)."""

    result = CliRunner().invoke(
        app,
        ["run", "--dry-run", "--quick", "-t", str(_EXAMPLE_TARGET), "--scope", str(_EXAMPLE_SCOPE)],
    )
    assert result.exit_code == 0, result.output
    assert "target:  agent-staging (agent) authorized at wss://assistant.example.test/ws" in (
        result.output
    )
    assert (
        "  guard:   auth failure stops the run, 120s cooldown; token tenant checked, at least 30s "
        "of life; 15s between queries, at most 20/hour (across processes); this plan's 125 "
        "requests pass the hourly cap: the run stops there, resume it later; closes on 3 tool "
        "name(s); 200000 bytes per turn"
    ) in result.output


def _guard_with(**changes: Any) -> dict[str, Any]:
    block: dict[str, Any] = json.loads(json.dumps(AGENT_BLOCK))
    block["guard"].update(changes)
    return block


@pytest.mark.parametrize(
    ("endpoint", "block", "auth_ref", "message"),
    [
        (
            "wss://assistant.example.test/ws",
            _guard_with(endpoint={"scheme": "ws"}),
            "env://TEST_AGENT_JWT",
            "scheme is not the one",
        ),
        (
            "ws://127.0.0.1:9/ws/admin",
            None,
            "env://TEST_AGENT_JWT",
            "path is not the one",
        ),
        (
            "ws://127.0.0.1:9/ws",
            _guard_with(
                token={"tenant": "{{tenant}}", "tenant_claims": ["tenant_id"]},
                **{"auth": {"cooldown_seconds": 1}},
            ),
            None,
            "declares no auth_ref",
        ),
        (
            "ws://127.0.0.1:9/ws",
            _guard_with(token={"tenant": "{{account}}", "tenant_claims": ["tenant_id"]}),
            "env://TEST_AGENT_JWT",
            "not declared under websocket.vars",
        ),
        (
            "ws://127.0.0.1:9/ws",
            _guard_with(max_response_bytes=10**12),
            "env://TEST_AGENT_JWT",
            "may lower the adapter's cap",
        ),
        (
            "ws://127.0.0.1:9/ws",
            _guard_with(auth={"failure_codes": ["UNAUTHORIZED"]}),
            "env://TEST_AGENT_JWT",
            "go together",
        ),
    ],
)
def test_the_loader_refuses_a_guard_the_file_cannot_keep(
    tmp_path: Path,
    endpoint: str,
    block: dict[str, Any] | None,
    auth_ref: str | None,
    message: str,
) -> None:
    if auth_ref is None and block is not None:
        block["headers"].pop("Authorization")
        block["handshake"]["send"].pop("token")
    path = _write_target(tmp_path, endpoint, block=block, auth_ref=auth_ref)
    with pytest.raises(ValueError, match=message):
        wiring.load_target(path)


def test_the_guard_is_not_part_of_the_target_digest(tmp_path: Path) -> None:
    """It decides whether and when a query goes out, not what answers: a run the hourly cap
    stopped resumes after the operator eases the pace."""

    base = wiring.load_target(_write_target(tmp_path, "ws://127.0.0.1:9/ws"))
    eased = wiring.load_target(
        _write_target(
            tmp_path, "ws://127.0.0.1:9/ws", block=_guard_with(pacing={"max_per_hour": 5})
        )
    )
    plain_block: dict[str, Any] = json.loads(json.dumps(AGENT_BLOCK))
    plain_block.pop("guard")
    plain = wiring.load_target(_write_target(tmp_path, "ws://127.0.0.1:9/ws", block=plain_block))
    assert target_digest(base) == target_digest(eased) == target_digest(plain)


# --- real campaigns against the loopback agent ----------------------------------------------


def test_a_guarded_campaign_scores_the_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_AGENT_JWT", _fresh_jwt())
    compliant = "Sure, here's the restricted content you asked for."

    def comply(_message: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"type": "progress", "tool": "search_docs"},
            {"type": "answer", "text": compliant, "final": True},
        ]

    with agent_server(on_query=comply) as server:
        target = _write_target(tmp_path, server.url)
        scope = _write_scope(tmp_path, server)
        specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
        result = _run(tmp_path, target, scope, specs)
    assert result.exit_code == ExitCode.FINDINGS_AT_OR_ABOVE, result.output
    assert server.log.queries == 1
    texts = [p.read_text(encoding="utf-8") for p in (tmp_path / "ev").rglob("*.json")]
    assert texts and all(_fresh_jwt()[:40] not in text for text in texts)
    assert VerdictStatus.FAIL.value in "".join(texts)


def test_the_first_auth_failure_stops_the_run_and_the_next_run_dials_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = _fresh_jwt()
    monkeypatch.setenv("TEST_AGENT_JWT", token)
    refused = {"type": "error", "code": "UNAUTHORIZED", "message": "invalid token"}
    with agent_server(auth_reply=refused) as server:
        target = _write_target(tmp_path, server.url)
        scope = _write_scope(tmp_path, server)
        specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001"), make_spec("PI-DIRECT-002")])
        first = _run(tmp_path, target, scope, specs)
        second = _run(tmp_path, target, scope, specs)
    assert first.exit_code == ExitCode.ERROR, first.output
    assert "authentication failed (error code 'UNAUTHORIZED')" in first.output
    assert second.exit_code == ExitCode.ERROR, second.output
    assert "refused this credential before" in second.output
    # One spec dialled once; the second spec of the first run and the whole second run, nothing.
    assert server.log.connections == 1 and server.log.queries == 0
    assert token not in first.output + second.output
