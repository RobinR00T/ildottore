"""evidence_fs.py - content addressing, dedupe, immutability, atomic write."""

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


def test_media_carrier_bytes_are_not_persisted(store_root: Path) -> None:
    """A multimodal carrier's bytes are elided from evidence (asset + digest kept).

    Storing the raw base64 would bloat evidence and, being high-entropy, could trip the
    fail-closed redaction guard. The write must succeed and the on-disk artifact must carry the
    placeholder plus the provenance (asset + media_sha256), never the raw bytes.
    """

    from ildottore.shared.enums import VerdictStatus
    from ildottore.shared.models import Attempt, ModelRequest, ModelResponse, Verdict

    big_b64 = "QUJD" * 40000  # a large, high-entropy carrier blob
    request = ModelRequest(
        prompt="listen",
        media=[{"kind": "audio", "format": "wav", "asset": "assets/c.wav", "data_b64": big_b64}],
        metadata={"media_sha256": ["deadbeef"]},
    )
    attempt = Attempt(
        attempt_id="a-mm",
        spec_id="MM-AUD-PROMPTINJECT-001",
        mutation="identity",
        request=request,
        response=ModelResponse(text="PINEAPPLE"),
        verdict=Verdict(
            status=VerdictStatus.FAIL, confidence=0.9, reasoning="x", evaluator_type="regex_absence"
        ),
    )
    store = FsEvidenceStore(store_root)
    ref = store.put("run-mm", attempt)  # must not raise RedactionLeakError

    on_disk = paths.attempt_path(store_root, "run-mm", ref.sha256).read_text(encoding="utf-8")
    assert big_b64 not in on_disk  # raw carrier bytes never hit disk
    assert "<omitted" in on_disk
    assert "assets/c.wav" in on_disk  # provenance kept
    assert "deadbeef" in on_disk  # chain-of-custody digest kept


def test_media_sha256_digest_survives_redaction(store_root: Path) -> None:
    """The chain-of-custody digest is exempt from redaction (else the audit trail is destroyed)."""

    from ildottore.shared.enums import VerdictStatus
    from ildottore.shared.models import Attempt, ModelRequest, ModelResponse, Verdict

    digest = "7c7b2bdc" + "ab12" * 14  # a 64-hex sha256-shaped string (high entropy)
    req = ModelRequest(
        prompt="x",
        media=[{"kind": "image", "format": "png", "render_text": "HI"}],
        metadata={"media_sha256": [digest]},
    )
    att = Attempt(
        attempt_id="a-dig",
        spec_id="MM",
        mutation="identity",
        request=req,
        response=ModelResponse(text="ok"),
        verdict=Verdict(
            status=VerdictStatus.FAIL, confidence=0.9, reasoning="x", evaluator_type="regex_absence"
        ),
    )
    store = FsEvidenceStore(store_root)
    ref = store.put("run-dig", att)
    disk = paths.attempt_path(store_root, "run-dig", ref.sha256).read_text(encoding="utf-8")
    assert digest in disk  # the digest is present verbatim, not masked into oblivion


def test_media_carrier_bytes_elided_anywhere_not_only_request_media(store_root: Path) -> None:
    """The strip is recursive: a carrier in request.messages is elided too (future multi-turn)."""

    import base64

    from ildottore.shared.enums import VerdictStatus
    from ildottore.shared.models import Attempt, ModelRequest, ModelResponse, Verdict

    low = base64.b64encode(
        b"\x00" * 4000
    ).decode()  # low-entropy: the entropy fallback won't catch it
    req = ModelRequest(
        prompt="x",
        messages=[{"role": "user", "content": "hi", "data_b64": low}],
    )
    att = Attempt(
        attempt_id="a-msg",
        spec_id="MM",
        mutation="identity",
        request=req,
        response=ModelResponse(text="ok"),
        verdict=Verdict(
            status=VerdictStatus.FAIL, confidence=0.9, reasoning="x", evaluator_type="regex_absence"
        ),
    )
    store = FsEvidenceStore(store_root)
    ref = store.put("run-msg", att)
    disk = paths.attempt_path(store_root, "run-msg", ref.sha256).read_text(encoding="utf-8")
    assert low not in disk  # raw carrier bytes never hit disk, wherever they sit
    assert "<omitted" in disk
