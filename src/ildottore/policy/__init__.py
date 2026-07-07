"""Config, scope authorization, policy packs and the endpoint allowlist (u01).

Public surface: the :class:`~ildottore.policy.packs.PolicyEngine` gate, the
:class:`~ildottore.policy.scope.Scope` authorization record + loader, the
default-deny :class:`~ildottore.policy.allowlist.EndpointAllowlist`, identity
resolution and the typed error family. The central redactor lives at
``ildottore.redactor`` and the app config at ``ildottore.config`` (contract §1).
"""

from __future__ import annotations

from ildottore.policy.allowlist import EndpointAllowlist
from ildottore.policy.errors import (
    ChecksumMismatchError,
    IdentityError,
    NetworkAccessError,
    PolicyError,
    PolicyPackError,
    ScopeError,
)
from ildottore.policy.identities import IdentityResolver
from ildottore.policy.packs import (
    CheckResult,
    PolicyEngine,
    PolicyPack,
    enabled_specs,
    load_pack,
)
from ildottore.policy.scope import (
    Endpoint,
    Identity,
    IntegrityVerifier,
    Scope,
    ScopeTarget,
    Sha256Verifier,
    load_scope,
    scope_hash,
)

__all__ = [
    "CheckResult",
    "ChecksumMismatchError",
    "Endpoint",
    "EndpointAllowlist",
    "Identity",
    "IdentityError",
    "IdentityResolver",
    "IntegrityVerifier",
    "NetworkAccessError",
    "PolicyEngine",
    "PolicyError",
    "PolicyPack",
    "PolicyPackError",
    "Scope",
    "ScopeError",
    "ScopeTarget",
    "Sha256Verifier",
    "enabled_specs",
    "load_pack",
    "load_scope",
    "scope_hash",
]
