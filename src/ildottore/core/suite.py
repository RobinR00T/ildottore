"""Suite → spec-set resolution (u08, contract §5.2).

A **suite** is a named, ordered set of attack specs (a framework preset like
``owasp:llm`` or a hand-authored engagement suite — ``docs/08 §6``). Resolution is
delegated to the injected Spec Registry (u02) via a narrow structural protocol
(:class:`SuiteResolver`) so ``core`` never imports the registry concrete
(contract §3/§8 — interfaces only, composition is u12).

Preset ids carry a colon (``owasp:llm``); the registry stores them verbatim, so
resolution is a straight lookup — this module normalizes the id and surfaces a
typed :class:`SuiteResolutionError` when a suite is unknown, rather than leaking
the registry's ``KeyError`` into the runner. Order is preserved (the registry
returns specs in declared order) because determinism depends on a stable spec
sequence (``docs/01 §5``).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ildottore.shared.models import AttackSpec

__all__ = [
    "SuiteResolutionError",
    "SuiteResolver",
    "resolve_suite",
]


class SuiteResolutionError(KeyError):
    """A suite id could not be resolved to any spec (unknown suite)."""


@runtime_checkable
class SuiteResolver(Protocol):
    """The slice of the Spec Registry (u02) the suite resolver needs.

    Structurally satisfied by :class:`ildottore.registry.Registry` — ``core``
    codes against this Protocol, never the concrete (contract §8).
    """

    def has_suite(self, suite_id: str) -> bool: ...

    def resolve(self, suite_id: str) -> list[AttackSpec]: ...


def resolve_suite(resolver: SuiteResolver, suite_id: str) -> list[AttackSpec]:
    """Resolve ``suite_id`` to its ordered spec set via the registry.

    Raises :class:`SuiteResolutionError` when the suite is unknown **or** resolves
    to zero specs — an empty campaign is almost always an operator error (a typo in
    the suite id or an unloaded pack), so it fails loud rather than running nothing.
    """

    normalized = suite_id.strip()
    if not resolver.has_suite(normalized):
        raise SuiteResolutionError(f"suite {suite_id!r} is not registered")
    specs = resolver.resolve(normalized)
    if not specs:
        raise SuiteResolutionError(
            f"suite {suite_id!r} resolved to zero specs "
            "(all referenced spec ids absent from the registry)"
        )
    return specs
