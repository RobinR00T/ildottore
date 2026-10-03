"""Fleet-config expansion tests: one file declaring many targets -> scope + target files."""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.cli import fleet as fleet_mod
from ildottore.cli import wiring

_FLEET = """
version: "1"
targets:
  - id: openai-gpt4o
    endpoint: https://api.openai.com/v1/chat/completions
    model: gpt-4o
    api_key_env: OPENAI_API_KEY
  - id: local-ollama
    endpoint: http://localhost:11434/v1/chat/completions
    model: llama3.2:1b
  - id: my-app
    provider: rest
    endpoint: https://my-app.example.com/chat
  - id: my-mcp
    kind: mcp
    endpoint: http://localhost:3000/mcp
"""


def _write_fleet(tmp_path: Path) -> Path:
    path = tmp_path / "fleet.yaml"
    path.write_text(_FLEET, encoding="utf-8")
    return path


def test_infer_provider_from_endpoint() -> None:
    # The path is the strongest signal: /chat/completions is OpenAI-compatible anywhere
    # (OpenAI, Ollama, vLLM, LM Studio, …), /messages is Anthropic.
    assert fleet_mod.infer_provider("https://api.openai.com/v1/chat/completions") == "openai"
    assert fleet_mod.infer_provider("http://localhost:11434/v1/chat/completions") == "openai"
    assert fleet_mod.infer_provider("https://api.anthropic.com/v1/messages") == "anthropic"
    assert fleet_mod.infer_provider("https://my-app.example.com/chat") == "rest"


def test_materialize_writes_scope_and_targets_including_mcp(tmp_path: Path) -> None:
    cfg = fleet_mod.load_fleet(_write_fleet(tmp_path))
    out = fleet_mod.materialize_fleet(cfg, tmp_path / "fleet-out")

    # All four targets are scannable now: the three llm/URL entries plus the mcp server
    # (routed to the read-only MCP adapter). Nothing is skipped.
    assert len(out.target_paths) == 4
    assert out.skipped == []
    assert out.scope_path.exists()
    assert all(p.exists() for p in out.target_paths)


def test_generated_files_load_in_the_engine(tmp_path: Path) -> None:
    """The generated scope + target files are consumable by the real wiring loaders."""

    cfg = fleet_mod.load_fleet(_write_fleet(tmp_path))
    out = fleet_mod.materialize_fleet(cfg, tmp_path / "fleet-out")

    scope = wiring.build_scope(out.scope_path)
    assert {t.id for t in scope.targets} == {"openai-gpt4o", "local-ollama", "my-app", "my-mcp"}

    by_id = {wiring.load_target(p).id: wiring.load_target(p) for p in out.target_paths}
    # Provider inferred from the endpoint host; api key carried as an env reference (never inline).
    assert by_id["openai-gpt4o"].provider == "openai"
    assert by_id["openai-gpt4o"].auth_ref == "env://OPENAI_API_KEY"
    assert by_id["local-ollama"].provider == "openai"  # /chat/completions -> OpenAI-compatible
    assert by_id["local-ollama"].auth_ref is None  # no key declared
    assert by_id["my-app"].provider == "rest"  # bespoke path -> generic REST adapter
    assert by_id["my-mcp"].provider == "mcp"  # kind: mcp -> read-only MCP adapter
    assert by_id["my-mcp"].type.value == "api"


def test_fleet_with_only_mcp_materializes(tmp_path: Path) -> None:
    """An mcp-only fleet is now valid: the mcp entry routes to the read-only MCP adapter."""

    path = tmp_path / "mcp-only.yaml"
    path.write_text(
        'version: "1"\ntargets:\n  - id: m\n    kind: mcp\n    endpoint: http://localhost:3000/mcp\n',
        encoding="utf-8",
    )
    cfg = fleet_mod.load_fleet(path)
    out = fleet_mod.materialize_fleet(cfg, tmp_path / "out")
    assert len(out.target_paths) == 1
    assert out.skipped == []
    target = wiring.load_target(out.target_paths[0])
    assert target.provider == "mcp"
    assert target.type.value == "api"


def test_load_fleet_rejects_unknown_field(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        'version: "1"\ntargets:\n  - id: x\n    endpoint: http://h/y\n    bogus: 1\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        fleet_mod.load_fleet(path)


# --- audit regressions (2026-09-01) ------------------------------------------


def test_fleet_rejects_yaml_injecting_id() -> None:
    """M1/M2: an id with YAML metacharacters is rejected at validation (never reaches the
    generated scope), so the authorization allowlist cannot be corrupted."""

    with pytest.raises(ValueError):
        fleet_mod.FleetTarget(id='evil", "x": "y', endpoint="http://h/v1/chat/completions")
    with pytest.raises(ValueError):
        fleet_mod.FleetTarget(id="../escape", endpoint="http://h/v1/chat/completions")


def test_fleet_rejects_duplicate_ids(tmp_path: Path) -> None:
    cfg = fleet_mod.FleetConfig(
        version="1",
        targets=[
            fleet_mod.FleetTarget(id="dup", endpoint="http://a/v1/chat/completions"),
            fleet_mod.FleetTarget(id="dup", endpoint="http://b/v1/chat/completions"),
        ],
    )
    with pytest.raises(ValueError, match="duplicate target id"):
        fleet_mod.materialize_fleet(cfg, tmp_path / "out")


def test_generated_scope_is_safe_dumped_and_loads(tmp_path: Path) -> None:
    """The generated scope/target are produced with yaml.safe_dump and load cleanly."""

    cfg = fleet_mod.load_fleet(_write_fleet(tmp_path))
    out = fleet_mod.materialize_fleet(cfg, tmp_path / "fleet-out")
    scope = wiring.build_scope(out.scope_path)
    assert {t.id for t in scope.targets} == {"openai-gpt4o", "local-ollama", "my-app", "my-mcp"}


_JUDGE_FILE = (
    "id: local-judge\n"
    "type: model\n"
    "provider: openai\n"
    'endpoint: "http://localhost:11434/v1/chat/completions"\n'
    'model: "llama3.2:3b"\n'
)
_JUDGE_BLOCK = """
judge:
  id: local-judge
  endpoint: http://localhost:11434/v1/chat/completions
  model: llama3.2:3b
"""


def _fleet_with_judge(tmp_path: Path, block: str = _JUDGE_BLOCK) -> Path:
    path = tmp_path / "fleet-judge.yaml"
    path.write_text(_FLEET + block, encoding="utf-8")
    return path


def test_generated_scope_authorizes_the_declared_judge(tmp_path: Path) -> None:
    """A judge the fleet file declares is authorized in the generated scope.

    Without it, the documented ``fleet --run --judge`` produced a scope the judge was absent
    from: nothing was sent to it (default-deny held), but every ``semantic_judge`` verdict came
    back inconclusive and the run exited 0, the judge silently disabled by the tool's output.
    """

    cfg = fleet_mod.load_fleet(_fleet_with_judge(tmp_path))
    out = fleet_mod.materialize_fleet(cfg, tmp_path / "fleet-judge")

    assert out.judge_path is not None and out.judge_path.name == "judge.yaml"
    judge = wiring.load_target(out.judge_path)
    scope = wiring.build_scope(out.scope_path)
    entry = scope.target("local-judge")
    assert entry is not None, "the judge must be in the generated scope"
    assert entry.endpoints, "and with a real endpoint allowlist, not an empty one"

    # The real gate agrees, and so does the credential allowlist: the only tests that matter.
    from ildottore.policy import authorize_target

    endpoint = wiring.scope_endpoint_of(scope, judge)
    assert authorize_target(scope, judge.id, endpoint).allowed
    wiring.check_target_credential(scope, judge)


def test_a_matching_judge_file_is_accepted(tmp_path: Path) -> None:
    judge_path = tmp_path / "judge.yaml"
    judge_path.write_text(_JUDGE_FILE, encoding="utf-8")
    cfg = fleet_mod.load_fleet(_fleet_with_judge(tmp_path))
    out = fleet_mod.materialize_fleet(
        cfg, tmp_path / "fleet-judge", judge=wiring.load_target(judge_path)
    )
    assert wiring.build_scope(out.scope_path).target("local-judge") is not None


def test_a_judge_file_the_fleet_does_not_declare_is_refused(tmp_path: Path) -> None:
    """SEC-04. The judge file used to authorize itself: its host and its ``auth_ref`` went
    into the generated scope, so it could make the scanner read any environment variable and
    send it, with the targets' replies, to a host no authorization record listed."""

    judge_path = tmp_path / "judge.yaml"
    judge_path.write_text(
        _JUDGE_FILE.replace("localhost:11434", "127.0.0.1:18093")
        + 'auth_ref: "env://AUDIT_UNRELATED_SECRET"\n',
        encoding="utf-8",
    )
    cfg = fleet_mod.load_fleet(_write_fleet(tmp_path))
    with pytest.raises(ValueError, match="does not declare"):
        fleet_mod.materialize_fleet(cfg, tmp_path / "out", judge=wiring.load_target(judge_path))
    assert not (tmp_path / "out" / "scope.yaml").exists(), "nothing is written on refusal"


@pytest.mark.parametrize(
    ("edit", "field"),
    [
        (lambda t: t.replace("localhost:11434", "127.0.0.1:18093"), "endpoint"),
        (lambda t: t + 'auth_ref: "env://AUDIT_UNRELATED_SECRET"\n', "auth_ref"),
        (lambda t: t.replace("id: local-judge", "id: other-judge"), "id"),
    ],
)
def test_a_judge_file_that_differs_from_the_declaration_is_refused(
    tmp_path: Path, edit: object, field: str
) -> None:
    judge_path = tmp_path / "judge.yaml"
    judge_path.write_text(edit(_JUDGE_FILE), encoding="utf-8")  # type: ignore[operator]
    cfg = fleet_mod.load_fleet(_fleet_with_judge(tmp_path))
    with pytest.raises(ValueError, match=field):
        fleet_mod.materialize_fleet(cfg, tmp_path / "out", judge=wiring.load_target(judge_path))


def test_a_judge_that_is_a_fleet_target_is_not_duplicated(tmp_path: Path) -> None:
    block = "\njudge:\n  id: local-ollama\n  endpoint: http://localhost:11434/v1/chat/completions\n"
    cfg = fleet_mod.load_fleet(_fleet_with_judge(tmp_path, block))
    out = fleet_mod.materialize_fleet(cfg, tmp_path / "fleet-dupe")
    scope = wiring.build_scope(out.scope_path)
    assert [t.id for t in scope.targets].count("local-ollama") == 1


def test_a_judge_reusing_a_target_id_with_another_endpoint_is_refused(tmp_path: Path) -> None:
    block = "\njudge:\n  id: local-ollama\n  endpoint: https://judge.example.test/v1/messages\n"
    cfg = fleet_mod.load_fleet(_fleet_with_judge(tmp_path, block))
    with pytest.raises(ValueError, match="own id"):
        fleet_mod.materialize_fleet(cfg, tmp_path / "out")


def test_the_cli_refuses_an_undeclared_judge_and_writes_no_scope(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from ildottore.cli.app import app

    judge_path = tmp_path / "judge.yaml"
    judge_path.write_text(_JUDGE_FILE, encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "fleet",
            str(_write_fleet(tmp_path)),
            "--out",
            str(tmp_path / "o"),
            "--judge",
            str(judge_path),
        ],
    )
    assert result.exit_code == 3, result.output
    assert "judge:" in result.output
    assert not (tmp_path / "o" / "scope.yaml").exists()


def test_the_cli_hint_carries_the_declared_judge(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from ildottore.cli.app import app

    out_dir = tmp_path / "o"
    result = CliRunner().invoke(
        app, ["fleet", str(_fleet_with_judge(tmp_path)), "--out", str(out_dir)]
    )
    assert result.exit_code == 0, result.output
    assert f"judge:   {out_dir / 'judge.yaml'}" in result.output
    assert f'--judge "{out_dir / "judge.yaml"}"' in result.output


# --- SEC-13: the generated scope pins every endpoint to its port -------------------------


def test_the_generated_scope_pins_each_host_to_its_port(tmp_path: Path) -> None:
    """SEC-13. A bare host authorizes every port: a fleet entry for an Ollama on :11434 also
    authorized :2375 (the Docker API) on the same machine."""

    cfg = fleet_mod.load_fleet(_write_fleet(tmp_path))
    out = fleet_mod.materialize_fleet(cfg, tmp_path / "fleet-out")
    scope = wiring.build_scope(out.scope_path)
    hosts = {t.id: t.endpoints[0].host for t in scope.targets}
    assert hosts == {
        "openai-gpt4o": "api.openai.com:443",
        "local-ollama": "localhost:11434",
        "my-app": "my-app.example.com:443",
        "my-mcp": "localhost:3000",
    }

    from ildottore.policy import authorize_target

    assert authorize_target(
        scope, "local-ollama", "http://localhost:11434/v1/chat/completions"
    ).allowed
    assert not authorize_target(
        scope, "local-ollama", "http://localhost:2375/v1/chat/completions"
    ).allowed
    assert authorize_target(
        scope, "openai-gpt4o", "https://api.openai.com/v1/chat/completions"
    ).allowed


def test_an_ipv6_endpoint_is_pinned_and_still_authorized(tmp_path: Path) -> None:
    path = tmp_path / "v6.yaml"
    path.write_text(
        'version: "1"\ntargets:\n  - id: v6\n    endpoint: http://[::1]:8080/v1/chat/completions\n',
        encoding="utf-8",
    )
    out = fleet_mod.materialize_fleet(fleet_mod.load_fleet(path), tmp_path / "o")
    scope = wiring.build_scope(out.scope_path)
    assert scope.targets[0].endpoints[0].host == "[::1]:8080"

    from ildottore.policy import authorize_target

    assert authorize_target(scope, "v6", "http://[::1]:8080/v1/chat/completions").allowed
    assert not authorize_target(scope, "v6", "http://[::1]:9090/v1/chat/completions").allowed
