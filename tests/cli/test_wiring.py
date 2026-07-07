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
