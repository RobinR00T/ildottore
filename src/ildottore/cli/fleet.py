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
    judge:                               # optional: the LLM-as-judge for semantic_judge
      id: local-judge
      endpoint: http://localhost:11434/v1/chat/completions
      model: llama3.2:3b

The judge is declared here, not only in a ``--judge`` file, because this file is the
authorization record the generated scope is built from. A judge file that authorized itself
could name any host and any environment variable, and the scanner would read that credential
and send it there with the targets' replies (audit SEC-04, 2026-10-03).

``kind: mcp`` routes to the read-only :class:`~ildottore.adapters.mcp.MCPAdapter`, which
inspects the server's advertised tool / resource / prompt metadata (it never calls a tool).
Point the ``mcp`` suite at such a target for the metadata-poisoning checks.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Literal
from urllib.parse import SplitResult, urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ildottore import safe_yaml
from ildottore.cli.wiring import shown_auth_ref
from ildottore.shared.config_errors import quoted, validation_problems, yaml_problem
from ildottore.shared.files import MAX_FILE_BYTES, read_text_capped
from ildottore.shared.models import Target

__all__ = [
    "FleetConfig",
    "FleetJudge",
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


class FleetJudge(BaseModel):
    """The LLM-as-judge, declared in the fleet file so that file stays the one authorization.

    ``fleet`` writes it to ``judge.yaml`` next to the targets and authorizes it in the scope.
    A ``--judge`` file is still accepted, but only when it names this same id, endpoint and
    credential: the scope entry is built from this declaration, never from the file.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(
        default="judge", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
    )
    endpoint: str = Field(min_length=1)
    provider: str | None = None  # inferred from the endpoint if None, as for a target
    model: str | None = None
    api_key_env: str | None = None  # env var NAME (never the key value)


class FleetConfig(BaseModel):
    """The whole fleet an operator wants to validate."""

    model_config = ConfigDict(extra="forbid")

    version: str = "1"
    targets: list[FleetTarget] = Field(min_length=1)
    judge: FleetJudge | None = None


class MaterializedFleet(BaseModel):
    """Result of expanding a fleet into engine files."""

    model_config = ConfigDict(extra="forbid")

    scope_path: Path
    target_paths: list[Path] = Field(default_factory=list)
    judge_path: Path | None = None  # judge.yaml, written when the fleet declares a judge
    skipped: list[tuple[str, str]] = Field(default_factory=list)  # (target id, reason)


def _split(endpoint: str) -> SplitResult:
    """``urlsplit`` of the endpoint as a run reads it (stripped), refused quoted up to 300
    characters.

    urllib refuses a host it cannot read (a bracket, a host NFKC turns into a path) with no
    file named, and quoted the whole endpoint for some (pre-merge audit of A-51). Read raw, a
    leading U+00A0 hid the host here and the generated target failed later (delta audit).
    """

    try:
        return urlsplit(endpoint.strip())
    except ValueError as exc:
        raise ValueError(f"endpoint {quoted(endpoint)} is not a URL that can be read") from exc


def infer_provider(endpoint: str) -> str:
    """Infer the provider (openai | anthropic | rest) from the endpoint.

    The path is the strongest signal: any ``…/chat/completions`` endpoint is OpenAI-compatible
    (OpenAI itself, but also Ollama, vLLM, LM Studio, LiteLLM, …), and ``…/messages`` is the
    Anthropic Messages API. Host names are the fallback. Anything else is the generic REST
    adapter (whose template the operator tunes for a bespoke endpoint)."""

    parts = _split(endpoint)
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

    # Neither error quotes the file: an `api_key: <key>` written where `api_key_env` belongs
    # was echoed back by pydantic, and a YAML error escaped as a traceback with exit 1, the code
    # for "findings below the threshold" (fifth audit of the residuals).
    try:
        raw = safe_yaml.safe_load(read_text_capped(path))
    except yaml.YAMLError as exc:
        raise ValueError(f"fleet file {path} is not valid YAML: {yaml_problem(exc)}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"fleet file {path} must be a mapping at top level")
    try:
        return FleetConfig.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(
            f"fleet file {path} failed validation: {validation_problems(exc)}"
        ) from exc


_DEFAULT_PORTS = {"https": 443, "http": 80}


def _scope_endpoint(endpoint: str) -> tuple[str, str]:
    """Return (host, path) for the scope allowlist, with the host pinned to its port.

    The generated scope used to write the bare host name, which the allowlist reads as "any
    port", so a fleet entry for ``localhost:11434`` also authorized ``localhost:2375`` and every
    other port on that machine (audit SEC-13). The port is the URL's own, or the scheme's
    default; an IPv6 literal is bracketed so the allowlist can split it. Schemes with no default
    port (the offline ``mock://``) keep the bare host.
    """

    parts = _split(endpoint)
    path = parts.path or "/"
    host = parts.hostname
    if not host:
        return endpoint, path
    try:
        port = parts.port or _DEFAULT_PORTS.get(parts.scheme.lower())
    except ValueError as exc:
        raise ValueError(f"endpoint {quoted(endpoint)} has an invalid port") from exc
    shown = f"[{host}]" if ":" in host else host
    return (f"{shown}:{port}" if port else shown), path


def _scope_entry(target_id: str, endpoint: str, api_key_env: str | None) -> dict[str, object]:
    """One scope target: its endpoint pinned to host, port and path, and its one credential.

    ``identities`` is required (min 1) and is also the credential allowlist: an entry's own
    ``auth_ref`` must be declared here or resolving it is refused. A keyless entry gets
    ``env://NONE``, a placeholder no environment defines.
    """

    host, path = _scope_endpoint(endpoint)
    auth = f"env://{api_key_env}" if api_key_env else "env://NONE"
    return {
        "id": target_id,
        "base_url": endpoint,
        "endpoints": [{"host": host, "path_prefixes": [path]}],
        "identities": [{"name": "default", "auth_ref": auth}],
    }


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


def _judge_doc(judge: FleetJudge) -> dict[str, object]:
    """Build ``judge.yaml`` from the fleet's declaration (serialized via safe_dump).

    A judge is a model, sampled at temperature 0 so its verdict on the same reply is stable.
    """

    doc: dict[str, object] = {
        "id": judge.id,
        "type": "model",
        "provider": judge.provider or infer_provider(judge.endpoint),
        "endpoint": judge.endpoint,
        "capabilities": {"tools": False, "rag": False},
        "sampling_defaults": {"temperature": 0.0},
    }
    if judge.model:
        doc["model"] = judge.model
    if judge.api_key_env:
        doc["auth_ref"] = f"env://{judge.api_key_env}"
    return doc


def _check_judge(config: FleetConfig, judge: Target | None) -> None:
    """Refuse a ``--judge`` file the fleet does not declare, or one that differs from it.

    The judge used to be authorized from the ``--judge`` file itself: its host went into the
    generated scope and so did its ``auth_ref``. A judge file naming another host and
    ``env://ANY_VARIABLE`` therefore made the scanner read that variable and send it, with the
    targets' replies, to a host no authorization record listed, the very thing the scope's
    credential allowlist exists to prevent (audit SEC-04). The same file passed to ``run`` with
    a scope that did not list the judge was refused.
    """

    declared = config.judge
    if declared is not None:
        for target in config.targets:
            if target.id == declared.id and (
                target.endpoint != declared.endpoint or target.api_key_env != declared.api_key_env
            ):
                raise ValueError(
                    f"the fleet's judge {quoted(declared.id)} has the id of a target with a "
                    "different endpoint or credential; give the judge its own id"
                )
    if judge is None:
        return
    if declared is None:
        raise ValueError(
            f"--judge names {quoted(judge.id)}, which the fleet file does not declare. Add a "
            "`judge:` block to the fleet file with its id, endpoint and api_key_env: the fleet "
            "file is the authorization record, and a judge file cannot authorize itself"
        )
    expected_auth = f"env://{declared.api_key_env}" if declared.api_key_env else None
    mismatches = [
        f"{name} {_shown(name, got)} (the fleet declares {_shown(name, want)})"
        for name, got, want in (
            ("id", judge.id, declared.id),
            ("endpoint", judge.endpoint, declared.endpoint),
            ("auth_ref", judge.auth_ref, expected_auth),
        )
        if got != want
    ]
    if mismatches:
        raise ValueError("--judge does not match the fleet's judge: " + "; ".join(mismatches))


def _shown(field: str, value: str | None) -> str:
    """A judge field as an error may quote it: an ``auth_ref`` literal never (it is a key).

    Anything else is quoted up to 300 characters (clause A-51).
    """

    if field == "auth_ref" and value is not None:
        return shown_auth_ref(value)
    return quoted(value)


def _rendered(doc: dict[str, object]) -> bytes:
    """A generated file's bytes, measured and written as they are (LF line ends everywhere)."""

    return yaml.safe_dump(doc, sort_keys=False).encode("utf-8")


def _scope_doc(config: FleetConfig) -> dict[str, object]:
    """Build the authorization ``scope.yaml`` document (serialized via safe_dump)."""

    targets = [_scope_entry(e.id, e.endpoint, e.api_key_env) for e in config.targets]
    judge = config.judge
    if judge is not None and judge.id not in {e.id for e in config.targets}:
        targets.append(_scope_entry(judge.id, judge.endpoint, judge.api_key_env))
    return {"version": "1.0", "targets": targets}


def _documents(config: FleetConfig) -> Iterator[tuple[str, dict[str, object]]]:
    """Each file :func:`materialize_fleet` writes, by name, built only when it is reached."""

    yield "scope.yaml", _scope_doc(config)
    for entry in config.targets:  # the id is charset-validated (a safe file name)
        yield f"target-{entry.id}.yaml", _target_doc(entry)
    if config.judge is not None:
        yield "judge.yaml", _judge_doc(config.judge)


def materialize_fleet(
    config: FleetConfig, out_dir: str | Path, *, judge: Target | None = None
) -> MaterializedFleet:
    """Expand ``config`` into a ``scope.yaml`` + one ``target.yaml`` per target.

    Both ``llm`` and ``mcp`` entries are scannable: an ``mcp`` entry routes to the read-only
    MCP adapter (discovery of the server's advertised tool metadata). ``skipped`` is retained
    for forward-compatibility with kinds that have no adapter yet (none today). A fleet with
    **no** targets raises rather than writing an empty (min_length) scope.

    A judge declared in the fleet file is authorized in the generated scope and written to
    ``judge.yaml``, so the LLM-as-judge is not silently denied. ``judge`` (a ``--judge`` file,
    when one is given) must match that declaration, or this raises (see :func:`_check_judge`).
    """

    out = Path(out_dir)

    seen: set[str] = set()
    for target in config.targets:
        if target.id in seen:
            raise ValueError(f"duplicate target id {quoted(target.id)} in fleet")
        seen.add(target.id)

    _check_judge(config, judge)

    scannable = list(config.targets)
    skipped: list[tuple[str, str]] = []

    if not scannable:  # pragma: no cover - FleetConfig.targets already enforces min_length=1
        raise ValueError("fleet has no targets to scan")

    # Every refusal of this function runs before it writes anything: a refused judge used to
    # leave an empty --out directory, or an older scope.yaml in an existing one (review of PR
    # #32). That includes the size of each file it writes: the scope repeats every endpoint, so
    # a fleet file of 845,022 bytes wrote a scope of 1,355,024 that `run`, `fleet --run` and the
    # printed command then refused at the read cap (pre-commit audit of A-43). Each is measured
    # and dropped before the next, so one rendered file is held at a time: holding them all took
    # 29 MiB for 60 targets sharing one 500 KB anchor and, computed from those sizes, about 3
    # GiB for a fleet file just under the cap (delta audit). The judge file is measured only
    # when it is the judge the printed command reads, not when ``judge`` (a ``--judge`` file)
    # replaces it. An OS error while writing can still leave the directory part written.
    for name, doc in _documents(config):
        if name == "judge.yaml" and judge is not None:
            continue
        size = len(_rendered(doc))
        if size > MAX_FILE_BYTES:
            advice = "split the fleet" if name == "scope.yaml" else "shorten that entry"
            raise ValueError(
                f"the {name} this fleet would write is {size:,} bytes, over the "
                f"{MAX_FILE_BYTES:,}-byte cap a file is read up to; {advice}"
            )

    out.mkdir(parents=True, exist_ok=True)
    for name, doc in _documents(config):
        (out / name).write_bytes(_rendered(doc))
    scope_path = out / "scope.yaml"
    target_paths = [out / f"target-{entry.id}.yaml" for entry in scannable]
    judge_path = out / "judge.yaml" if config.judge is not None else None

    return MaterializedFleet(
        scope_path=scope_path, target_paths=target_paths, skipped=skipped, judge_path=judge_path
    )
