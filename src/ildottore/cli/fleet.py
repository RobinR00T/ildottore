"""Fleet config: declare the whole set of LLM targets to validate in one file.

A single ``fleet.yaml`` lists every model/endpoint an operator wants Il Dottore to scan
(hosted APIs by key, a local model, a raw URL, or an MCP server) and expands into the
files the engine already consumes: the authorization ``scope.yaml`` (the non-bypassable
allowlist) plus one ``target.yaml`` per target. Keys are **never** written here: each entry
references an environment variable (``api_key_env``), resolved only at send time (S6).

Shape::

    version: "1"
    targets:
      - id: openai-gpt4o
        provider: openai                 # inferred from the endpoint host if omitted
        endpoint: https://api.openai.com/v1/chat/completions
        model: gpt-4o
        api_key_env: OPENAI_API_KEY
      - id: anthropic-haiku
        endpoint: https://api.anthropic.com/v1/messages
        model: claude-haiku-4-5
        api_key_env: ANTHROPIC_API_KEY
      - id: local-ollama                 # no key needed
        endpoint: http://localhost:11434/v1/chat/completions
        model: llama3.2:1b
      - id: my-app                       # a raw URL (generic REST adapter)
        provider: rest
        endpoint: https://my-app.example.com/chat
      - id: my-mcp                       # a Model Context Protocol server (read-only discovery)
        kind: mcp
        endpoint: http://localhost:3000/mcp

``kind: mcp`` routes to the read-only :class:`~ildottore.adapters.mcp.MCPAdapter`, which
inspects the server's advertised tool / resource / prompt metadata (it never calls a tool).
Point the ``mcp`` suite at such a target for the metadata-poisoning checks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "FleetConfig",
    "FleetTarget",
    "MaterializedFleet",
    "infer_provider",
    "load_fleet",
    "materialize_fleet",
]


class FleetTarget(BaseModel):
    """One target in the fleet (a model endpoint, a URL, or an MCP server)."""

    model_config = ConfigDict(extra="forbid")

    # A safe id: letters/digits/_-. only, so it never injects YAML into the generated scope
    # nor escapes the target-<id>.yaml filename (audit M1/M2).
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    endpoint: str = Field(min_length=1)
    kind: Literal["llm", "mcp"] = "llm"
    provider: str | None = None  # openai | anthropic | rest; inferred from endpoint if None
    model: str | None = None
    api_key_env: str | None = None  # env var NAME (never the key value)
    capabilities: dict[str, bool] = Field(default_factory=dict)


class FleetConfig(BaseModel):
    """The whole fleet an operator wants to validate."""

    model_config = ConfigDict(extra="forbid")

    version: str = "1"
    targets: list[FleetTarget] = Field(min_length=1)


class MaterializedFleet(BaseModel):
    """Result of expanding a fleet into engine files."""

    model_config = ConfigDict(extra="forbid")

    scope_path: Path
    target_paths: list[Path] = Field(default_factory=list)
    skipped: list[tuple[str, str]] = Field(default_factory=list)  # (target id, reason)


def infer_provider(endpoint: str) -> str:
    """Infer the provider (openai | anthropic | rest) from the endpoint.

    The path is the strongest signal: any ``…/chat/completions`` endpoint is OpenAI-compatible
    (OpenAI itself, but also Ollama, vLLM, LM Studio, LiteLLM, …), and ``…/messages`` is the
    Anthropic Messages API. Host names are the fallback. Anything else is the generic REST
    adapter (whose template the operator tunes for a bespoke endpoint)."""

    parts = urlsplit(endpoint)
    host = (parts.hostname or "").lower()
    path = (parts.path or "").lower()
    if path.endswith("/chat/completions"):
        return "openai"
    if path.endswith("/messages") or "anthropic" in host:
        return "anthropic"
    if "openai" in host:
        return "openai"
    return "rest"


def load_fleet(path: str | Path) -> FleetConfig:
    """Parse + validate a ``fleet.yaml`` (no code execution, no network)."""

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"fleet file {path} must be a mapping at top level")
    return FleetConfig.model_validate(raw)


def _endpoint_yaml(entry: FleetTarget) -> tuple[str, str]:
    """Return (host, path) for the scope allowlist from an entry's endpoint."""

    parts = urlsplit(entry.endpoint)
    host = parts.hostname or entry.endpoint
    path = parts.path or "/"
    return host, path


def _target_doc(entry: FleetTarget) -> dict[str, object]:
    """Build a ``target.yaml`` document for a fleet entry (serialized via safe_dump).

    An ``mcp`` entry becomes an ``api`` target routed to the read-only MCP adapter
    (provider ``mcp``, ``tools`` capability true, a server is a tool provider); an
    ``llm``/URL entry keeps its inferred chat provider.
    """

    is_mcp = entry.kind == "mcp"
    provider = entry.provider or ("mcp" if is_mcp else infer_provider(entry.endpoint))
    doc: dict[str, object] = {
        "id": entry.id,
        "type": "api" if is_mcp else "chatbot",
        "provider": provider,
        "endpoint": entry.endpoint,
        "capabilities": {"tools": is_mcp, "rag": False, **entry.capabilities},
    }
    if entry.model:
        doc["model"] = entry.model
    if entry.api_key_env:
        doc["auth_ref"] = f"env://{entry.api_key_env}"
    return doc


def _scope_doc(entries: list[FleetTarget]) -> dict[str, object]:
    """Build the authorization ``scope.yaml`` document (serialized via safe_dump)."""

    targets = []
    for entry in entries:
        host, path = _endpoint_yaml(entry)
        auth = f"env://{entry.api_key_env}" if entry.api_key_env else "env://NONE"
        targets.append(
            {
                "id": entry.id,
                "base_url": entry.endpoint,
                "endpoints": [{"host": host, "path_prefixes": [path]}],
                "identities": [{"name": "default", "auth_ref": auth}],
            }
        )
    return {"version": "1.0", "targets": targets}


def materialize_fleet(config: FleetConfig, out_dir: str | Path) -> MaterializedFleet:
    """Expand ``config`` into a ``scope.yaml`` + one ``target.yaml`` per target.

    Both ``llm`` and ``mcp`` entries are scannable: an ``mcp`` entry routes to the read-only
    MCP adapter (discovery of the server's advertised tool metadata). ``skipped`` is retained
    for forward-compatibility with kinds that have no adapter yet (none today). A fleet with
    **no** targets raises rather than writing an empty (min_length) scope.
    """

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    seen: set[str] = set()
    for target in config.targets:
        if target.id in seen:
            raise ValueError(f"duplicate target id {target.id!r} in fleet")
        seen.add(target.id)

    scannable = list(config.targets)
    skipped: list[tuple[str, str]] = []

    if not scannable:  # pragma: no cover - FleetConfig.targets already enforces min_length=1
        raise ValueError("fleet has no targets to scan")

    scope_path = out / "scope.yaml"
    scope_path.write_text(yaml.safe_dump(_scope_doc(scannable), sort_keys=False), encoding="utf-8")

    target_paths: list[Path] = []
    for entry in scannable:
        target_path = out / f"target-{entry.id}.yaml"  # id is charset-validated (safe filename)
        target_path.write_text(
            yaml.safe_dump(_target_doc(entry), sort_keys=False), encoding="utf-8"
        )
        target_paths.append(target_path)

    return MaterializedFleet(scope_path=scope_path, target_paths=target_paths, skipped=skipped)
