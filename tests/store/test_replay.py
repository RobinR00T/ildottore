"""replay.py — hash-verified reconstruction, tamper detection, repro recompute."""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.shared.enums import VerdictStatus
from ildottore.store import paths, replay
from ildottore.store.evidence_fs import FsEvidenceStore
from ildottore.store.replay import TamperError
from tests.store.conftest import make_attempt


def _seed_run(store_root: Path) -> FsEvidenceStore:
    store = FsEvidenceStore(store_root)
    store.put("run-1", make_attempt(attempt_id="a-1", status=VerdictStatus.FAIL))
    store.put("run-1", make_attempt(attempt_id="a-2", status=VerdictStatus.PASS))
    store.put("run-1", make_attempt(attempt_id="a-3", status=VerdictStatus.FAIL))
    return store


def test_replay_reconstructs_all_attempts(store_root: Path) -> None:
    _seed_run(store_root)
    result = replay.replay_run(store_root, "run-1")
    assert result.n == 3
    assert {a.attempt_id for a in result.attempts} == {"a-1", "a-2", "a-3"}


def test_replay_recomputes_reproducibility(store_root: Path) -> None:
    _seed_run(store_root)
    result = replay.replay_run(store_root, "run-1")
    assert result.successful_attacks() == 2
    assert result.reproducibility() == pytest.approx(2 / 3)


def test_replay_empty_run_is_zero(store_root: Path) -> None:
    result = replay.replay_run(store_root, "run-empty")
    assert result.n == 0
    assert result.reproducibility() == 0.0


def test_tampered_artifact_detected(store_root: Path) -> None:
    store = FsEvidenceStore(store_root)
    ref = store.put("run-1", make_attempt())
    artifact = paths.attempt_path(store_root, "run-1", ref.sha256)
    # Mutate content without renaming the file → hash no longer matches name.
    artifact.write_text('{"attempt_id":"tampered","spec_id":"x","request":{}}', encoding="utf-8")
    with pytest.raises(TamperError):
        replay.replay_run(store_root, "run-1")


def test_verify_ref_present_and_valid(store_root: Path) -> None:
    store = FsEvidenceStore(store_root)
    ref = store.put("run-1", make_attempt())
    assert ref.sha256 is not None
    assert replay.verify_ref(store_root, "run-1", ref.sha256) is True


def test_verify_ref_missing_returns_false(store_root: Path) -> None:
    absent = paths.content_hash("nothing-here")
    assert replay.verify_ref(store_root, "run-1", absent) is False


def test_verify_ref_tampered_raises(store_root: Path) -> None:
    store = FsEvidenceStore(store_root)
    ref = store.put("run-1", make_attempt())
    assert ref.sha256 is not None
    artifact = paths.attempt_path(store_root, "run-1", ref.sha256)
    artifact.write_text('{"attempt_id":"x","spec_id":"y","request":{}}', encoding="utf-8")
    with pytest.raises(TamperError):
        replay.verify_ref(store_root, "run-1", ref.sha256)
