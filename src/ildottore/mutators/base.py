"""Mutator base: protocol adapter, result shape, and seed derivation (contract §5.1).

A **mutation** is a deterministic, intent-preserving transform of an attack's
*carrier/obfuscation* only (``docs/03 §4``, contract §2). The same
``expected_secure_behavior`` must still apply, so the evaluator/judge contract is
unchanged.

Every built-in strategy is a **pure function** of ``(text, seed)`` — no I/O, no global
state, no wall clock, and no ``random`` without the passed seed (contract §4 KEEP). The
shared runtime seam is :class:`ildottore.shared.protocols.Mutator`
(``name: str`` + ``mutate(text: str, seed: str) -> str``): every strategy here satisfies
it structurally. Alongside the protocol's ``str -> str`` method, strategies expose
:meth:`BaseMutator.mutate_result` which returns a richer :class:`MutationResult` carrying
reversibility/provenance metadata for evidence (contract §6).

Determinism is seeded by ``(spec.id, mutation.name)`` upstream (``docs/01 §3.3``): the
execution engine (u08) passes that composite as the ``seed`` string; the same seed ⇒
byte-identical output on replay. :func:`derive_int_seed` maps the seed string to a stable
integer (BLAKE2b, salted per strategy) for any strategy that needs an RNG.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from random import Random
from typing import runtime_checkable

from ildottore.shared.protocols import Mutator

__all__ = [
    "BaseMutator",
    "MutationResult",
    "Mutator",
    "derive_int_seed",
    "seeded_rng",
]

# Re-export the shared protocol so plugin authors import it from one place; ``runtime_checkable``
# already applies (shared marks it), this keeps the symbol addressable from ``mutators.base``.
runtime_checkable  # noqa: B018 — imported for documentation of protocol-check semantics.


@dataclass(frozen=True, slots=True)
class MutationResult:
    """Output of a mutation with reversibility + provenance metadata (contract §6).

    ``text`` is the transformed carrier. ``provenance`` carries the decode hint for
    reversible encodings (base64/rot13/zero-width) and the confusable/split map otherwise.
    It is data-only and never contains secrets/PII the transform itself introduces (the
    input payload is the operator's, masked downstream by the redactor per ``docs/11 §5``).
    """

    text: str
    strategy: str
    seed: str
    params: dict[str, object] = field(default_factory=dict)
    reversible: bool = False
    provenance: dict[str, object] = field(default_factory=dict)


def derive_int_seed(seed: str, *, salt: str = "") -> int:
    """Derive a stable non-negative 64-bit int from the ``(spec.id, mutation.name)`` seed.

    Deterministic across processes and platforms: uses BLAKE2b (stdlib ``hashlib``), never
    Python's salted ``hash()``. ``salt`` lets a strategy namespace its own stream so two
    strategies fed the same seed string diverge (contract §4 KEEP: no dict-order/global
    coupling).
    """
    digest = hashlib.blake2b(f"{salt}\x00{seed}".encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big")


def seeded_rng(seed: str, *, salt: str = "") -> Random:
    """A ``random.Random`` seeded deterministically from the seed string (+ optional salt)."""
    return Random(derive_int_seed(seed, salt=salt))  # noqa: S311 — not cryptographic; reproducible.


class BaseMutator:
    """Common scaffold for built-in mutators (satisfies :class:`Mutator` structurally).

    Subclasses set the class attribute ``name`` and implement :meth:`_transform`, returning
    ``(text, reversible, provenance)``. :meth:`mutate` returns just the string (the shared
    protocol shape); :meth:`mutate_result` wraps it into a :class:`MutationResult`.
    """

    name: str = ""
    reversible: bool = False

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        """Return the mutated text plus provenance. Overridden by every strategy."""
        raise NotImplementedError

    def mutate(self, text: str, seed: str) -> str:
        """Protocol method: deterministic ``str -> str`` transform (``docs/01 §3``)."""
        transformed, _ = self._transform(text, seed)
        return transformed

    def mutate_result(self, text: str, seed: str) -> MutationResult:
        """Richer transform returning reversibility + provenance for evidence (contract §6)."""
        transformed, provenance = self._transform(text, seed)
        return MutationResult(
            text=transformed,
            strategy=self.name,
            seed=seed,
            params={},
            reversible=self.reversible,
            provenance=provenance,
        )
