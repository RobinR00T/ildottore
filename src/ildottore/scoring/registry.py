"""Scorer discovery (``docs/06 §3`` L3 plugin registration).

The default scorer is always available under the name ``"default"``. Third-party scorers may
register via the ``dottore.scorers`` entry-point group and are validated against the
:class:`~ildottore.shared.protocols.RiskScorer` protocol at load time - an object that does
not satisfy the protocol is rejected with a clear error, never silently skipped (``docs/06``).

Discovery executes no network calls and, beyond importing the registered callable, no side
effects (the safety posture in ``docs/06 §5``). Import is lazy and memoized.
"""

from __future__ import annotations

from importlib import metadata
from typing import cast

from ildottore.scoring.base import DefaultRiskScorer
from ildottore.shared.protocols import RiskScorer

__all__ = ["ENTRY_POINT_GROUP", "get_scorer", "list_scorers", "register_scorer"]

ENTRY_POINT_GROUP = "dottore.scorers"

# name → zero-arg factory producing a RiskScorer. Seeded with the built-in default.
_FACTORIES: dict[str, type[RiskScorer]] = {"default": DefaultRiskScorer}
_loaded_plugins = False


def register_scorer(name: str, factory: type[RiskScorer]) -> None:
    """Register a scorer factory under ``name`` (later ids never silently override).

    A duplicate ``name`` is a hard error (``docs/06 §2`` - id collisions are not silent).
    """
    if name in _FACTORIES:
        raise ValueError(f"scorer id already registered: {name!r}")
    _FACTORIES[name] = factory


def _load_plugins() -> None:
    global _loaded_plugins
    if _loaded_plugins:
        return
    for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
        loaded = ep.load()
        instance = loaded() if isinstance(loaded, type) else loaded
        if not isinstance(instance, RiskScorer):
            raise TypeError(f"entry point {ep.name!r} does not implement the RiskScorer protocol")
        if ep.name not in _FACTORIES:
            _FACTORIES[ep.name] = cast("type[RiskScorer]", loaded)
    _loaded_plugins = True


def list_scorers() -> list[str]:
    """Return the sorted names of all registered scorers (discovering plugins first)."""
    _load_plugins()
    return sorted(_FACTORIES)


def get_scorer(name: str = "default") -> RiskScorer:
    """Instantiate the scorer registered under ``name`` (default: the built-in)."""
    _load_plugins()
    try:
        factory = _FACTORIES[name]
    except KeyError:
        available = ", ".join(sorted(_FACTORIES))
        raise KeyError(f"unknown scorer {name!r}; available: {available}") from None
    return factory()
