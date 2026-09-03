"""Auth-identity resolution (u01) - single + multi-identity to ``auth_ref`` handles.

Resolves the identities declared on a scope target to their ``auth_ref``
**handles** - never to secret values (S6, contract §5 step 5). A target with ≥2
identities enables cross-tenant / authz specs (``multi_identity``,
``Capabilities.multi_identity``); a single-identity target makes those specs
**skip-eligible**, never an error (contract §7, ``docs/11 §3``).
"""

from __future__ import annotations

from ildottore.policy.errors import IdentityError
from ildottore.policy.scope import Identity, ScopeTarget


class IdentityResolver:
    """Resolves and looks up a scope target's declared identities."""

    def __init__(self, target: ScopeTarget) -> None:
        if not target.identities:
            # Scope validation enforces ≥1; this guards direct construction.
            raise IdentityError(f"target {target.id!r} declares no auth identities")
        self._target = target
        self._by_name: dict[str, Identity] = {i.name: i for i in target.identities}
        if len(self._by_name) != len(target.identities):
            raise IdentityError(f"target {target.id!r} has duplicate identity names")

    @property
    def multi_identity(self) -> bool:
        """True when the target declares ≥2 identities (maps to ``Capabilities``)."""

        return len(self._by_name) >= 2

    def auth_refs(self) -> dict[str, str]:
        """Map each identity ``name`` → its ``auth_ref`` handle (no secret values)."""

        return {name: ident.auth_ref for name, ident in self._by_name.items()}

    def resolve(self, name: str) -> str:
        """Return the ``auth_ref`` for ``name`` or raise :class:`IdentityError`."""

        ident = self._by_name.get(name)
        if ident is None:
            raise IdentityError(f"unknown identity {name!r} for target {self._target.id!r}")
        return ident.auth_ref

    def is_skip_eligible_for_multi_identity(self) -> bool:
        """True when authz/xtenant specs must **skip** (single identity), not error.

        The runner (u08) reads this to record a logged skip rather than a failure
        when a multi-identity spec meets a single-identity scope.
        """

        return not self.multi_identity
