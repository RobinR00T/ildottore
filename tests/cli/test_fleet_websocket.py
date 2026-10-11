"""OD-37: ``dottore fleet`` refuses a WebSocket entry instead of writing a file ``run`` refuses.

A fleet entry has no ``websocket:`` block, so a ``ws://`` or ``wss://`` endpoint was written as a
``provider: rest`` target (the provider inferred from a path that is neither ``/chat/completions``
nor ``/messages``), and ``run``, ``fleet --run`` and the printed ``dottore run`` all refused that
file: a ``ws://`` or ``wss://`` endpoint is dialled only by ``provider: websocket``, with a block
declaring its wire shape (PR #87). Decided 2026-10-11 under the owner's delegation (best practice,
revisable): the fleet refuses such an entry, and a ``provider: websocket`` one, before it writes
anything, and points to the hand-written WebSocket target. The judge is held to the same rule.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import fleet as fleet_mod
from ildottore.cli.app import app

_HAND_WRITTEN = "examples/target.websocket.yaml"

_FLEET_HEAD = """version: "1"
targets:
  - id: local-llama
    endpoint: http://localhost:11434/v1/chat/completions
    model: llama3.2:1b
"""


def _fleet(
    *entries: fleet_mod.FleetTarget, judge: fleet_mod.FleetJudge | None = None
) -> fleet_mod.FleetConfig:
    """A fleet of one OpenAI-compatible entry and these, so the refused one is ``targets.1``."""

    head = fleet_mod.FleetTarget(id="local", endpoint="http://localhost:11434/v1/chat/completions")
    return fleet_mod.FleetConfig(targets=[head, *entries], judge=judge)


@pytest.mark.parametrize(
    "endpoint",
    [
        "wss://assistant.example.test/ws/chat",
        "ws://127.0.0.1:8765/ws",
        "WSS://Assistant.Example.test/ws/chat",  # the scheme is read case-insensitively, as run
        "  wss://assistant.example.test/ws/chat",  # and stripped, as run reads the endpoint
    ],
)
@pytest.mark.parametrize("provider", [None, "rest", "openai"])
def test_a_websocket_endpoint_is_refused_before_anything_is_written(
    tmp_path: Path, endpoint: str, provider: str | None
) -> None:
    out = tmp_path / "out"
    entry = fleet_mod.FleetTarget(id="ws-assistant", endpoint=endpoint, provider=provider)
    with pytest.raises(ValueError) as caught:
        fleet_mod.materialize_fleet(_fleet(entry), out)
    message = str(caught.value)
    assert "targets.1.endpoint of 'ws-assistant'" in message, message
    assert "provider websocket" in message and "websocket: block" in message, message
    assert "OD-37" in message and _HAND_WRITTEN in message, message
    assert "examples/scope.websocket.yaml" in message, message
    assert not out.exists(), "a refused fleet writes nothing, not even the directory"


def test_provider_websocket_is_refused_on_any_endpoint(tmp_path: Path) -> None:
    """It wrote a ``provider: websocket`` file with no block, which ``run`` refuses too."""

    out = tmp_path / "out"
    entry = fleet_mod.FleetTarget(
        id="sock", endpoint="https://assistant.example.test/chat", provider="WebSocket"
    )
    with pytest.raises(ValueError) as caught:
        fleet_mod.materialize_fleet(_fleet(entry), out)
    message = str(caught.value)
    assert "targets.1.provider of 'sock' is websocket" in message, message
    assert _HAND_WRITTEN in message, message
    assert not out.exists()


@pytest.mark.parametrize(
    ("endpoint", "provider", "field"),
    [
        ("wss://judge.example.test/ws", None, "endpoint"),
        ("https://judge.example.test/v1/chat/completions", "websocket", "provider"),
    ],
)
def test_a_websocket_judge_is_refused_before_anything_is_written(
    tmp_path: Path, endpoint: str, provider: str | None, field: str
) -> None:
    out = tmp_path / "out"
    judge = fleet_mod.FleetJudge(id="ws-judge", endpoint=endpoint, provider=provider)
    with pytest.raises(ValueError) as caught:
        fleet_mod.materialize_fleet(_fleet(judge=judge), out)
    message = str(caught.value)
    assert f"judge.{field} of 'ws-judge'" in message, message
    assert "OD-37" in message, message
    assert not out.exists()


def test_the_cli_refuses_a_websocket_entry_with_exit_3_and_writes_no_scope(
    tmp_path: Path,
) -> None:
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(
        _FLEET_HEAD + "  - id: ws-assistant\n    endpoint: wss://assistant.example.test/ws/chat\n",
        encoding="utf-8",
    )
    out = tmp_path / "o"
    for extra in ([], ["--run"]):
        result = CliRunner().invoke(app, ["fleet", str(fleet), "--out", str(out), *extra])
        assert result.exit_code == 3, result.output
        assert "targets.1.endpoint of 'ws-assistant'" in result.output, result.output
        assert _HAND_WRITTEN in result.output, result.output
        assert not (out / "scope.yaml").exists()
        assert not (out / "target-ws-assistant.yaml").exists()


def test_an_http_fleet_is_unchanged(tmp_path: Path) -> None:
    """The refusal reads the scheme only: an entry whose path says ``ws`` is still written."""

    entry = fleet_mod.FleetTarget(id="chat", endpoint="https://app.example.test/ws/chat")
    out = fleet_mod.materialize_fleet(_fleet(entry), tmp_path / "out")
    assert [p.name for p in out.target_paths] == ["target-local.yaml", "target-chat.yaml"]
