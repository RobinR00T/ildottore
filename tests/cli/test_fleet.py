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
