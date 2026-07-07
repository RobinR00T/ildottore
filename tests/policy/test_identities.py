"""Identity resolution tests (contract §7 multi-identity)."""

from __future__ import annotations

import pytest

from ildottore.policy.errors import IdentityError
from ildottore.policy.identities import IdentityResolver
from ildottore.policy.scope import Identity, ScopeTarget


def _target(identities: list[Identity]) -> ScopeTarget:
    return ScopeTarget(
        id="acme",
        base_url="https://api.acme.test",
        endpoints=[],
        identities=identities,
    )


def test_single_identity_resolves() -> None:
    r = IdentityResolver(_target([Identity(name="primary", auth_ref="vault://p")]))
    assert r.multi_identity is False
    assert r.auth_refs() == {"primary": "vault://p"}
    assert r.resolve("primary") == "vault://p"
    assert r.is_skip_eligible_for_multi_identity() is True


def test_multi_identity_resolves_both() -> None:
    r = IdentityResolver(
        _target(
            [
                Identity(name="a", auth_ref="vault://a"),
                Identity(name="b", auth_ref="vault://b"),
            ]
        )
    )
    assert r.multi_identity is True
    assert r.auth_refs() == {"a": "vault://a", "b": "vault://b"}
    assert r.resolve("a") == "vault://a"
    assert r.resolve("b") == "vault://b"
    assert r.is_skip_eligible_for_multi_identity() is False


def test_unknown_identity_raises() -> None:
    r = IdentityResolver(_target([Identity(name="a", auth_ref="vault://a")]))
    with pytest.raises(IdentityError):
        r.resolve("ghost")


def test_duplicate_names_raise() -> None:
    with pytest.raises(IdentityError):
        IdentityResolver(
            _target(
                [
                    Identity(name="dup", auth_ref="vault://1"),
                    Identity(name="dup", auth_ref="vault://2"),
                ]
            )
        )


def test_auth_refs_never_expose_values_only_handles() -> None:
    r = IdentityResolver(_target([Identity(name="a", auth_ref="vault://acme/a")]))
    # All values are references (scheme://...), never inline secret material.
    for ref in r.auth_refs().values():
        assert "://" in ref
