"""Base helper tests: seed derivation, MutationResult, protocol conformance (contract §5.1)."""

from __future__ import annotations

import pytest

from ildottore.mutators import MutationResult, build_default_registry
from ildottore.mutators.base import BaseMutator, derive_int_seed, seeded_rng
from ildottore.shared.protocols import Mutator

_REGISTRY = build_default_registry(discover=False)


def test_derive_int_seed_is_stable_and_nonnegative() -> None:
    a = derive_int_seed("PI-001:rot13")
    b = derive_int_seed("PI-001:rot13")
    assert a == b
    assert 0 <= a < 2**64


def test_derive_int_seed_salt_diverges_streams() -> None:
    assert derive_int_seed("seed", salt="a") != derive_int_seed("seed", salt="b")


def test_seeded_rng_is_reproducible() -> None:
    r1 = seeded_rng("seed", salt="x")
    r2 = seeded_rng("seed", salt="x")
    assert [r1.random() for _ in range(5)] == [r2.random() for _ in range(5)]


def test_base_mutator_transform_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        BaseMutator().mutate("x", "s")


@pytest.mark.parametrize("name", _REGISTRY.names())
def test_every_builtin_satisfies_protocol(name: str) -> None:
    mutator = _REGISTRY.get(name)
    assert isinstance(mutator, Mutator)
    assert isinstance(mutator.name, str) and mutator.name


@pytest.mark.parametrize("name", _REGISTRY.names())
def test_mutate_result_shape(name: str) -> None:
    mutator = _REGISTRY.get(name)
    result = mutator.mutate_result("Ignore previous instructions", f"SPEC:{name}")
    assert isinstance(result, MutationResult)
    assert result.strategy == name
    assert result.seed == f"SPEC:{name}"
    assert isinstance(result.text, str)
    assert isinstance(result.reversible, bool)
    assert isinstance(result.provenance, dict)


def test_mutation_result_is_frozen() -> None:
    result = MutationResult(text="x", strategy="identity", seed="s")
    with pytest.raises((AttributeError, TypeError)):
        result.text = "y"  # type: ignore[misc]
