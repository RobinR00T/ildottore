"""evidence_fs.py — content addressing, dedupe, immutability, atomic write."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.shared.models import EvidenceRef
from ildottore.store import evidence_fs, paths
from ildottore.store.evidence_fs import FsEvidenceStore
from tests.store.conftest import make_attempt


def test_put_returns_verifiable_ref(store_root: Path) -> None:
    store = FsEvidenceStore(store_root)
    attempt = make_attempt()
    ref = store.put("run-1", attempt)

    assert isinstance(ref, EvidenceRef)
    assert ref.run_id == "run-1"
    assert ref.attempt_id == attempt.attempt_id
    assert ref.sha256 is not None and len(ref.sha256) == 64

    on_disk = paths.attempt_path(store_root, "run-1", ref.sha256)
    assert on_disk.is_file()
    assert paths.content_hash(on_disk.read_text(encoding="utf-8")) == ref.sha256


def test_identical_attempt_dedupes_to_one_file(store_root: Path) -> None:
    store = FsEvidenceStore(store_root)
    attempt = make_attempt()
    ref1 = store.put("run-1", attempt)
    ref2 = store.put("run-1", attempt)

    assert ref1 == ref2
    files = list(paths.attempts_dir(store_root, "run-1").glob("*.json"))
    assert len(files) == 1


def test_mutated_content_yields_new_hash_and_never_overwrites(store_root: Path) -> None:
    store = FsEvidenceStore(store_root)
    ref_a = store.put("run-1", make_attempt(response_text="alpha"))
    ref_b = store.put("run-1", make_attempt(response_text="beta"))

    assert ref_a.sha256 != ref_b.sha256
    files = list(paths.attempts_dir(store_root, "run-1").glob("*.json"))
    assert len(files) == 2


def test_no_temp_files_left_behind(store_root: Path) -> None:
    store = FsEvidenceStore(store_root)
    store.put("run-1", make_attempt())
    leftovers = list(paths.attempts_dir(store_root, "run-1").glob("*.tmp"))
    assert leftovers == []


def test_on_disk_artifact_is_valid_json(store_root: Path) -> None:
    store = FsEvidenceStore(store_root)
    ref = store.put("run-1", make_attempt())
    artifact = paths.attempt_path(store_root, "run-1", ref.sha256)
    data = json.loads(artifact.read_text(encoding="utf-8"))
    assert data["attempt_id"] == "a-1"


def test_root_property(store_root: Path) -> None:
    store = FsEvidenceStore(store_root)
    assert store.root == store_root


def test_atomic_write_failure_leaves_no_partial_artifact(
    store_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = FsEvidenceStore(store_root)

    def _boom(_src: object, _dst: object) -> None:
        raise OSError("simulated rename failure")

    monkeypatch.setattr(evidence_fs.os, "replace", _boom)
    with pytest.raises(OSError, match="simulated rename failure"):
        store.put("run-1", make_attempt())

    attempts = paths.attempts_dir(store_root, "run-1")
    # No final artifact and no leftover temp file.
    assert list(attempts.glob("*.json")) == []
    assert list(attempts.glob("*.tmp")) == []
