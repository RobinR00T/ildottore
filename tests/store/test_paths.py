"""paths.py - id validation, traversal guard, deterministic layout."""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.store import paths
from ildottore.store.paths import UnsafePathError


def test_content_hash_is_deterministic_and_sha256_shaped() -> None:
    h1 = paths.content_hash('{"a":1}')
    h2 = paths.content_hash('{"a":1}')
    assert h1 == h2
    assert len(h1) == 64 and all(c in "0123456789abcdef" for c in h1)
    assert paths.content_hash('{"a":2}') != h1


def test_layout_paths_are_under_root(tmp_path: Path) -> None:
    digest = paths.content_hash("x")
    ap = paths.attempt_path(tmp_path, "run-1", digest)
    assert ap == tmp_path / "run-1" / "attempts" / f"{digest}.json"
    assert paths.run_doc_path(tmp_path, "run-1") == tmp_path / "run-1" / "run.json"
    assert ap.is_relative_to(tmp_path)


@pytest.mark.parametrize("bad", ["..", ".", "../etc", "a/b", "a\\b", "", "with space", "x" * 200])
def test_unsafe_run_ids_rejected(bad: str) -> None:
    with pytest.raises(UnsafePathError):
        paths.validate_run_id(bad)


@pytest.mark.parametrize("ok", ["run-1", "RUN_2", "a.b.c", "run1"])
def test_safe_run_ids_accepted(ok: str) -> None:
    assert paths.validate_run_id(ok) == ok


@pytest.mark.parametrize("bad", ["", "xyz", "g" * 64, "A" * 64, "abc123"])
def test_invalid_sha256_rejected(bad: str) -> None:
    with pytest.raises(UnsafePathError):
        paths.validate_sha256(bad)


def test_relative_uri_is_portable_posix(tmp_path: Path) -> None:
    digest = paths.content_hash("x")
    ap = paths.attempt_path(tmp_path, "run-1", digest)
    uri = paths.relative_uri(tmp_path, ap)
    assert uri == f"run-1/attempts/{digest}.json"
    assert not Path(uri).is_absolute()
