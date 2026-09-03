"""Composition-smoke (contract §7).

``wiring.build_runner`` returns an engine whose injected components satisfy each
``shared.protocols`` type; no concrete leaks past the root. The wiring module is the
**only** place concretes meet interfaces (contract §4 KEEP).
"""

from __future__ import annotations

from pathlib import Path

from ildottore.cli import wiring
from ildottore.core.runner import CampaignRunner, PolicyGate
from ildottore.shared.enums import TargetType
from ildottore.shared.models import Capabilities, Target
from ildottore.shared.protocols import (
    EvidenceStore,
    Reporter,
    RiskScorer,
    RunStore,
)

from .conftest import make_spec, write_scope, write_target


def _scope(tmp_path: Path):
    return wiring.build_scope(write_scope(tmp_path))


def test_build_runner_returns_wired_campaign_runner(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    specs = [make_spec("PI-DIRECT-001")]
    built = wiring.build_runner(
        scope=scope,
        specs=specs,
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
    )
    assert isinstance(built.runner, CampaignRunner)
    assert isinstance(built.policy, PolicyGate)
    assert built.evidence_root == tmp_path / "ev"


def test_build_judge_adapter_enables_semantic_judge(tmp_path: Path) -> None:
    """--judge builds a scoped over-the-wire adapter and registers semantic_judge."""

    from ildottore.evaluators import build_default_registry as build_eval
    from ildottore.shared.protocols import TargetAdapter

    scope = _scope(tmp_path)
    judge = Target(
        id="mock-target",  # in the scope written by write_scope
        type=TargetType.MODEL,
        capabilities=Capabilities(),
        provider="openai",
        endpoint="http://mock-target/v1/chat/completions",
        model="judge-model",
    )
    adapter = wiring.build_judge_adapter(scope, judge)
    assert isinstance(adapter, TargetAdapter)
    # Without a judge, semantic_judge is absent; with this adapter it is registered.
    assert not build_eval(judge=None, discover=False).has("semantic_judge")
    assert build_eval(judge=adapter, discover=False).has("semantic_judge")


def test_injected_components_satisfy_protocols(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    specs = [make_spec("PI-DIRECT-001")]
    built = wiring.build_runner(
        scope=scope, specs=specs, evidence_root=tmp_path / "ev", run_db=tmp_path / "r.sqlite"
    )
    r = built.runner
    assert isinstance(r._scorer, RiskScorer)  # type: ignore[attr-defined]
    assert isinstance(r._evidence, EvidenceStore)  # type: ignore[attr-defined]
    assert isinstance(r._runs, RunStore)  # type: ignore[attr-defined]


def test_build_reporter_returns_reporter_for_each_format(tmp_path: Path) -> None:
    for fmt in ("json", "html", "sarif", "junit"):
        reporter = wiring.build_reporter(fmt)
        assert isinstance(reporter, Reporter)


def test_permissive_pack_enables_present_categories() -> None:
    specs = [make_spec("PI-1")]
    pack = wiring.build_permissive_pack(specs)
    cats = set(pack.allow_categories)
    assert specs[0].category in cats


def test_load_target_reads_id_type_capabilities(tmp_path: Path) -> None:
    path = write_target(tmp_path, target_id="acme-bot")
    target = wiring.load_target(path)
    assert isinstance(target, Target)
    assert target.id == "acme-bot"
    assert target.type is TargetType.CHATBOT
    assert isinstance(target.capabilities, Capabilities)


def test_load_target_rejects_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    try:
        wiring.load_target(path)
    except ValueError as exc:
        assert "mapping" in str(exc)
    else:  # pragma: no cover - guard
        raise AssertionError("expected ValueError for non-mapping target file")


def test_load_target_rejects_missing_id(tmp_path: Path) -> None:
    path = tmp_path / "noid.yaml"
    path.write_text("type: chatbot\n", encoding="utf-8")
    try:
        wiring.load_target(path)
    except ValueError as exc:
        assert "id" in str(exc)
    else:  # pragma: no cover - guard
        raise AssertionError("expected ValueError for missing id")


def test_load_target_rejects_bad_type(tmp_path: Path) -> None:
    path = tmp_path / "badtype.yaml"
    path.write_text("id: x\ntype: not-a-type\n", encoding="utf-8")
    try:
        wiring.load_target(path)
    except ValueError as exc:
        assert "invalid type" in str(exc)
    else:  # pragma: no cover - guard
        raise AssertionError("expected ValueError for bad type")


def test_deterministic_clock_steps_by_one() -> None:
    clock = wiring.deterministic_clock()
    assert clock() == 1.0
    assert clock() == 2.0
    assert clock() == 3.0


def test_scope_endpoint_maps_target_to_base_url(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    endpoint_for = wiring.scope_endpoint_for(scope)
    target = Target(id="mock-target", type=TargetType.CHATBOT, capabilities=Capabilities())
    assert endpoint_for(target, make_spec("PI-1")) == "mock://mock-target"


def test_scope_endpoint_unknown_target_falls_back_to_id(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    endpoint_for = wiring.scope_endpoint_for(scope)
    stranger = Target(id="not-in-scope", type=TargetType.CHATBOT, capabilities=Capabilities())
    # Falls back to the id, which never parses to an allowlisted host ⇒ default-deny.
    assert endpoint_for(stranger, make_spec("PI-1")) == "not-in-scope"


def test_build_registry_and_fingerprint_engine(tmp_path: Path) -> None:
    reg = wiring.build_registry([tmp_path])  # empty tree parses to an empty registry
    assert reg.list() == []
    engine = wiring.build_fingerprint_engine()
    assert engine is not None


def test_build_real_adapter_routes_mcp_to_mcp_adapter() -> None:
    """A provider=mcp target builds the read-only MCPAdapter with the FULL endpoint URL."""

    from ildottore.adapters import MCPAdapter
    from ildottore.policy import EndpointAllowlist
    from ildottore.policy.scope import Endpoint

    target = Target(
        id="my-mcp",
        type=TargetType.API,
        capabilities=Capabilities(tools=True),
        provider="mcp",
        endpoint="https://mcp.example.com/mcp",
    )
    allowlist = EndpointAllowlist([Endpoint(host="mcp.example.com", path_prefixes=["/mcp"])])
    adapter = wiring.build_real_adapter(target, allowlist, api_key=None)
    assert isinstance(adapter, MCPAdapter)
    # MCP posts to the endpoint path itself, so base_url keeps the full URL (not just origin).
    assert adapter.base_url == "https://mcp.example.com/mcp"


def test_build_identity_probes_one_per_scope_identity() -> None:
    """build_identity_probes yields one adapter per scope identity, carrying its owned canary."""

    from ildottore.core.runner import IdentityProbe
    from ildottore.policy.scope import Endpoint, Identity, Scope, ScopeTarget
    from ildottore.shared.protocols import TargetAdapter

    scope = Scope(
        version="1.0",
        targets=[
            ScopeTarget(
                id="multi",
                base_url="https://api.acme.test/v1/chat/completions",
                endpoints=[Endpoint(host="api.acme.test", path_prefixes=["/v1"])],
                identities=[
                    Identity(name="tenant-a", auth_ref="env://A_KEY"),
                    Identity(name="tenant-b", auth_ref="env://B_KEY", canary="B-CANARY-{{run_id}}"),
                ],
            )
        ],
    )
    target = Target(
        id="multi",
        type=TargetType.MODEL,
        capabilities=Capabilities(multi_identity=True),
        provider="openai",
        endpoint="https://api.acme.test/v1/chat/completions",
    )
    probes = wiring.build_identity_probes(scope, target)
    assert [p.identity_id for p in probes] == ["tenant-a", "tenant-b"]
    assert probes[0].canary is None and probes[1].canary == "B-CANARY-{{run_id}}"
    assert all(isinstance(p, IdentityProbe) for p in probes)
    assert all(isinstance(p.adapter, TargetAdapter) for p in probes)

    # A single-identity target yields no probes (authz_leak stays capability_unavailable).
    solo = scope.model_copy(
        update={
            "targets": [
                scope.targets[0].model_copy(
                    update={"identities": [Identity(name="a", auth_ref="env://A")]}
                )
            ]
        }
    )
    assert wiring.build_identity_probes(solo, target) == []


def test_build_real_adapter_routes_stdio_mcp() -> None:
    """A provider=mcp, transport=stdio target builds an stdio MCPAdapter carrying the argv and
    the scope-authorized command list."""

    from ildottore.adapters import MCPAdapter
    from ildottore.policy import EndpointAllowlist

    target = Target(
        id="local-mcp",
        type=TargetType.API,
        capabilities=Capabilities(tools=True),
        provider="mcp",
        transport="stdio",
        command=["python", "server.py"],
    )
    adapter = wiring.build_real_adapter(
        target,
        EndpointAllowlist([]),
        api_key=None,
        authorized_commands=("python server.py",),
    )
    assert isinstance(adapter, MCPAdapter)
    assert adapter.transport == "stdio"
    assert adapter.command == ("python", "server.py")
    assert adapter.authorized_commands == ("python server.py",)


def test_authorized_api_key_rejects_unscoped_credential(tmp_path: Path) -> None:
    """A target in scope may only use a credential the scope declared for it (audit low)."""

    scope = _scope(tmp_path)  # write_scope declares identity auth_ref env://MOCK_KEY
    ok = Target(
        id="mock-target",
        type=TargetType.MODEL,
        capabilities=Capabilities(),
        auth_ref="env://MOCK_KEY",
    )
    # Authorized credential resolves (value may be None if the env var is unset, no raise).
    wiring._authorized_api_key(scope, ok)
    hostile = ok.model_copy(update={"auth_ref": "env://AWS_SECRET_ACCESS_KEY"})
    import pytest

    with pytest.raises(ValueError, match="not authorized by the"):
        wiring._authorized_api_key(scope, hostile)
