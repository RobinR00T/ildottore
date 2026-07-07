"""Registry + entry-point discovery tests (contract §7, docs/06 §3).

A stub plugin registered under ``dottore.mutators`` is discovered and validated; a malformed
one raises a clear :class:`MutatorProtocolError` (never a silent skip).
"""

from __future__ import annotations

from importlib.metadata import EntryPoint

import pytest

from ildottore.mutators import (
    MutatorProtocolError,
    MutatorRegistry,
    build_default_registry,
)
from ildottore.mutators import registry as registry_mod
from ildottore.mutators.base import BaseMutator


class GoodPlugin(BaseMutator):
    name = "stub_plugin"
    reversible = False

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        return f"[stub]{text}", {"note": "stub"}


class BadPluginNoName:
    """Does not satisfy the Mutator protocol (no ``name``)."""

    def mutate(self, text: str, seed: str) -> str:
        return text


class BadPluginNotCallable:
    name = "broken"
    mutate = "not-callable"  # type: ignore[assignment]


def _fake_entry_points(mapping: dict[str, type]):
    def _factory(*, group: str):
        assert group == registry_mod.ENTRY_POINT_GROUP
        return [
            EntryPoint(name=name, value="tests.mutators.test_registry:unused", group=group)
            for name in mapping
        ]

    return _factory


def test_default_registry_has_twelve_builtins() -> None:
    reg = build_default_registry(discover=False)
    assert len(reg.names()) == 12
    assert reg.has("identity")


def test_manual_register_and_get() -> None:
    reg = MutatorRegistry()
    reg.register(GoodPlugin(), origin="test")
    assert reg.has("stub_plugin")
    assert reg.get("stub_plugin").mutate("hi", "SPEC:x") == "[stub]hi"


def test_duplicate_name_rejected() -> None:
    reg = MutatorRegistry()
    reg.register(GoodPlugin(), origin="test")
    with pytest.raises(MutatorProtocolError, match="duplicate mutator name"):
        reg.register(GoodPlugin(), origin="test")


def test_duplicate_name_allowed_with_replace() -> None:
    reg = MutatorRegistry()
    reg.register(GoodPlugin(), origin="test")
    reg.register(GoodPlugin(), origin="test", replace=True)
    assert reg.has("stub_plugin")


def test_plugin_discovered_via_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry_mod, "entry_points", _fake_entry_points({"stub": GoodPlugin}))
    monkeypatch.setattr(EntryPoint, "load", lambda self: GoodPlugin, raising=False)
    reg = MutatorRegistry()
    loaded = reg.discover_plugins()
    assert loaded == ["stub_plugin"]
    assert reg.has("stub_plugin")


def test_build_default_registry_discovers_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry_mod, "entry_points", _fake_entry_points({"stub": GoodPlugin}))
    monkeypatch.setattr(EntryPoint, "load", lambda self: GoodPlugin, raising=False)
    reg = build_default_registry(discover=True)
    assert reg.has("stub_plugin")
    assert len(reg.names()) == 13


def test_malformed_plugin_missing_name_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry_mod, "entry_points", _fake_entry_points({"bad": BadPluginNoName}))
    monkeypatch.setattr(EntryPoint, "load", lambda self: BadPluginNoName, raising=False)
    reg = MutatorRegistry()
    with pytest.raises(MutatorProtocolError, match="missing a non-empty str 'name'"):
        reg.discover_plugins()


def test_malformed_plugin_not_callable_mutate_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        registry_mod, "entry_points", _fake_entry_points({"bad": BadPluginNotCallable})
    )
    monkeypatch.setattr(EntryPoint, "load", lambda self: BadPluginNotCallable, raising=False)
    reg = MutatorRegistry()
    with pytest.raises(MutatorProtocolError, match="no callable 'mutate'"):
        reg.discover_plugins()


def test_get_unknown_raises_keyerror() -> None:
    reg = build_default_registry(discover=False)
    with pytest.raises(KeyError):
        reg.get("does_not_exist")


def test_names_are_sorted() -> None:
    reg = build_default_registry(discover=False)
    assert reg.names() == sorted(reg.names())
