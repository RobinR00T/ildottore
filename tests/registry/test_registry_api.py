"""Registry API + property tests (contract §7)."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ildottore.registry import (
    LintCode,
    Registry,
    SpecNotFoundError,
    SuiteNotFoundError,
    load_path,
)


def _good_registry(packs_root: Path) -> Registry:
    result = load_path(packs_root / "good")
    return Registry.from_packs(result.packs)


def test_get_roundtrips_every_listed_spec(packs_root: Path) -> None:
    reg = _good_registry(packs_root)
    for spec in reg.list():
        assert reg.get(spec.id) is spec


def test_get_unknown_raises(packs_root: Path) -> None:
    reg = _good_registry(packs_root)
    with pytest.raises(SpecNotFoundError):
        reg.get("NOPE-000")


def test_resolve_returns_suite_order(packs_root: Path) -> None:
    reg = _good_registry(packs_root)
    resolved = reg.resolve("good-baseline")
    assert [s.id for s in resolved] == ["DL-CANARY-001", "JB-REFUSAL-001"]


def test_resolve_unknown_suite_raises(packs_root: Path) -> None:
    reg = _good_registry(packs_root)
    with pytest.raises(SuiteNotFoundError):
        reg.resolve("no-such-suite")


def test_list_filters_are_correct_subsets(packs_root: Path) -> None:
    reg = _good_registry(packs_root)
    everything = reg.list()
    by_cat = reg.list(category="jailbreak")
    assert {s.id for s in by_cat} == {"JB-REFUSAL-001"}
    assert {s.id for s in by_cat} <= {s.id for s in everything}

    by_owasp = reg.list(owasp="LLM06")
    assert {s.id for s in by_owasp} == {"DL-CANARY-001"}

    by_tag = reg.list(tag="canary")
    assert {s.id for s in by_tag} == {"DL-CANARY-001"}

    by_pack = reg.list(pack="good-pack")
    assert {s.id for s in by_pack} == {"JB-REFUSAL-001", "DL-CANARY-001"}

    assert reg.list(category="jailbreak", owasp="LLM06") == []  # AND semantics


def test_packs_and_suites_accessors(packs_root: Path) -> None:
    reg = _good_registry(packs_root)
    assert [p.id for p in reg.packs()] == ["good-pack"]
    assert [s.id for s in reg.suites()] == ["good-baseline"]
    assert reg.has_suite("good-baseline")
    assert not reg.has_suite("ghost")


def test_collision_recorded_first_wins(packs_root: Path) -> None:
    result = load_path(packs_root / "collision")
    reg = Registry.from_packs(result.packs)
    collisions = reg.collisions
    assert len(collisions) == 1
    assert collisions[0].code is LintCode.ID_COLLISION
    assert collisions[0].spec_id == "COLLIDE-001"
    # First pack (pack-a) keeps ownership.
    assert reg.list(pack="pack-a") and not reg.list(pack="pack-b")


# --- Hypothesis property: get/list/resolve invariants over an arbitrary pack subset ------


def test_property_get_and_list_consistency(packs_root: Path) -> None:
    reg = _good_registry(packs_root)
    all_ids = [s.id for s in reg.list()]

    @given(st.lists(st.sampled_from(all_ids), unique=True))
    def _prop(subset: list[str]) -> None:
        # get(id) round-trips; list() is always the full superset of any id-subset.
        for sid in subset:
            assert reg.get(sid).id == sid
        assert set(subset) <= set(all_ids)

    _prop()
