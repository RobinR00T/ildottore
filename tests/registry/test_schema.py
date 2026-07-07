"""Schema validation + safe-load unit tests (contract §7)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.registry import safe_load_yaml, validate_attack_spec_schema
from ildottore.registry.schema import SafeLoadError, load_yaml_file


def test_safe_load_plain_mapping() -> None:
    data = safe_load_yaml("a: 1\nb: [2, 3]\n")
    assert data == {"a": 1, "b": [2, 3]}


def test_safe_load_rejects_python_object_tag() -> None:
    with pytest.raises(SafeLoadError):
        safe_load_yaml("x: !!python/object/apply:os.system ['echo pwned']")


def test_safe_load_rejects_malformed_yaml() -> None:
    with pytest.raises(SafeLoadError):
        safe_load_yaml("a: [1, 2\n  b: broken")


def test_valid_spec_passes_schema(valid_specs_dir: Path) -> None:
    for path in sorted(valid_specs_dir.glob("*.yaml")):
        data = load_yaml_file(path)
        assert validate_attack_spec_schema(data) == [], path.name


@pytest.mark.parametrize(
    ("filename", "needle"),
    [
        ("bad-category-enum.yaml", "category"),
        ("bad-id-pattern.yaml", "id"),
        ("empty-attack.yaml", "attack"),
        ("impact-out-of-range.yaml", "impact"),
        ("missing-required-fixtures.yaml", "fixtures"),
        ("unknown-field.yaml", "totally_unknown_field"),
    ],
)
def test_invalid_spec_fails_schema(invalid_specs_dir: Path, filename: str, needle: str) -> None:
    data = load_yaml_file(invalid_specs_dir / filename)
    errors = validate_attack_spec_schema(data)
    assert errors, filename
    assert any(needle in e for e in errors), (filename, errors)


def test_validator_is_cached() -> None:
    # Two calls must reuse the compiled validator (lru_cache); cheap smoke over identity.
    from ildottore.registry.schema import _attack_spec_validator

    assert _attack_spec_validator() is _attack_spec_validator()
