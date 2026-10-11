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


# --- pre-merge audit of be3f2e71, HIGH 1: a hand-written WebSocket judge given with --judge ------

_WS_JUDGE_BLOCK = (
    "judge:\n"
    "  id: ws-assistant-staging\n"
    "  endpoint: wss://assistant.example.test/ws/chat\n"
    "  api_key_env: ASSISTANT_WS_TOKEN\n"
)


def _ws_judge_fleet(tmp_path: Path) -> tuple[Path, Path]:
    """A fleet whose judge: block declares the example WebSocket target, and that target's file."""

    judge = tmp_path / "ws-judge.yaml"
    root = Path(__file__).resolve().parents[2]
    judge.write_bytes((root / "examples" / "target.websocket.yaml").read_bytes())
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(_FLEET_HEAD + _WS_JUDGE_BLOCK, encoding="utf-8")
    return fleet, judge


def test_a_hand_written_websocket_judge_given_with_judge_is_accepted(tmp_path: Path) -> None:
    """It worked on 6d5f7ae (fleet exit 0, the dry run planned judge requests) and the first
    OD-37 build refused it: the --judge file is what the run reads, checked by ``load_target``
    and held to the block by ``_check_judge``. The block is not written as ``judge.yaml``, a
    file ``run`` would refuse; the hint carries the --judge file."""

    fleet, judge = _ws_judge_fleet(tmp_path)
    out = tmp_path / "o"
    result = CliRunner().invoke(
        app, ["fleet", str(fleet), "--out", str(out), "--judge", str(judge)]
    )
    assert result.exit_code == 0, result.output
    assert not (out / "judge.yaml").exists(), "a judge.yaml run refuses is not written"
    assert "judge:   " not in result.output, result.output
    assert f'--judge "{judge}"' in result.output, result.output

    dry = CliRunner().invoke(
        app,
        [
            "run",
            "--dry-run",
            "--quick",
            "-t",
            str(out / "target-local-llama.yaml"),
            "--scope",
            str(out / "scope.yaml"),
            "--judge",
            str(judge),
        ],
    )
    assert dry.exit_code == 0, dry.output
    assert "request(s) to the --judge model" in dry.output, dry.output


def test_without_judge_a_websocket_judge_block_is_refused_with_advice_that_works(
    tmp_path: Path,
) -> None:
    fleet, _judge = _ws_judge_fleet(tmp_path)
    out = tmp_path / "o"
    result = CliRunner().invoke(app, ["fleet", str(fleet), "--out", str(out)])
    assert result.exit_code == 3, result.output
    assert "judge.endpoint of 'ws-assistant-staging' is a wss:// URL" in result.output
    # A judge cannot be "scanned with dottore run": it is passed with --judge, and this block
    # still authorizes it.
    assert "pass it to dottore fleet with --judge" in result.output, result.output
    assert "scan it with dottore run" not in result.output, result.output
    assert not out.exists()


def test_materialize_takes_the_judge_file_and_writes_no_judge_yaml(tmp_path: Path) -> None:
    from ildottore.cli import wiring

    fleet, judge = _ws_judge_fleet(tmp_path)
    config = fleet_mod.load_fleet(fleet)
    out = fleet_mod.materialize_fleet(config, tmp_path / "out", judge=wiring.load_target(judge))
    assert out.judge_path is None
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == [
        "scope.yaml",
        "target-local-llama.yaml",
    ]
    scope = wiring.build_scope(out.scope_path)
    assert scope.target("ws-assistant-staging") is not None, "the block still authorizes it"
