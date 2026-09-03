"""``identity`` - the null transform (contract §2).

Returns the input unchanged; ``identity(t) == t`` for all ``t`` (property test, §7).
This is the baseline variant every spec implicitly runs.
"""

from __future__ import annotations

from ildottore.mutators.base import BaseMutator

__all__ = ["IdentityMutator"]


class IdentityMutator(BaseMutator):
    """Returns the carrier unchanged."""

    name = "identity"
    reversible = True

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        return text, {"note": "identity: input returned unchanged"}
