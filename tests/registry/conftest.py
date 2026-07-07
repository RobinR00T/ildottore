"""Shared paths + fixtures for the u02 registry test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

_TESTS_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _TESTS_ROOT / "fixtures"


@pytest.fixture(scope="session")
def fixtures_root() -> Path:
    """<repo>/tests/fixtures."""
    return _FIXTURES


@pytest.fixture(scope="session")
def packs_root(fixtures_root: Path) -> Path:
    """<repo>/tests/fixtures/packs."""
    return fixtures_root / "packs"


@pytest.fixture(scope="session")
def valid_specs_dir(fixtures_root: Path) -> Path:
    """A loose tree of schema-valid attack specs (no pack.yaml)."""
    return fixtures_root / "specs" / "valid"


@pytest.fixture(scope="session")
def invalid_specs_dir(fixtures_root: Path) -> Path:
    """A loose tree of schema-invalid attack specs."""
    return fixtures_root / "specs" / "invalid"
