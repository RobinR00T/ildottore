"""Deterministic on-disk layout + id derivation for the evidence store (u10).

Every path is derived from the configured **store root** plus a ``run_id`` — the
store never hardcodes a location and never writes outside the root (contract §4
KEEP). Ids and file names are computed, not chosen, so two writers agree on the
same path for the same content:

* run directory ...... ``<root>/<run_id>/``
* run document ....... ``<root>/<run_id>/run.json`` (redacted ``TestRun``)
* attempts directory .. ``<root>/<run_id>/attempts/``
* one attempt ........ ``<root>/<run_id>/attempts/<sha256>.json`` (content-addressed)

Run ids and content hashes are validated so a hostile ``run_id`` (``..``,
absolute paths, separators) can never escape the root (path-traversal guard).
Paths-with-spaces are safe because everything is a :class:`~pathlib.Path`.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Final

# A run id is an opaque token; we allow the usual safe url/id charset only so it
# can never contain a path separator, ``.`` traversal segment or NUL.
_RUN_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_HEX: Final = re.compile(r"^[0-9a-f]{64}$")

_RUN_DOC_NAME: Final = "run.json"
_ATTEMPTS_DIR: Final = "attempts"


class UnsafePathError(ValueError):
    """Raised when a ``run_id`` / hash would resolve outside the store root."""


def validate_run_id(run_id: str) -> str:
    """Return ``run_id`` if it is a safe single path segment, else raise.

    Rejects empty ids, separators, ``.`` / ``..`` traversal and anything with a
    NUL or exotic character — the id becomes a directory name verbatim.
    """

    if not _RUN_ID_PATTERN.match(run_id) or run_id in {".", ".."}:
        raise UnsafePathError(f"unsafe run_id: {run_id!r}")
    return run_id


def validate_sha256(digest: str) -> str:
    """Return ``digest`` if it is a 64-char lowercase hex string, else raise."""

    if not _SHA256_HEX.match(digest):
        raise UnsafePathError(f"not a sha256 hex digest: {digest!r}")
    return digest


def canonical_bytes(payload: str) -> bytes:
    """Encode a canonical JSON string to the exact bytes we hash and write.

    Centralized so the hash and the file content can never diverge.
    """

    return payload.encode("utf-8")


def content_hash(payload: str) -> str:
    """SHA-256 (hex) of the canonical bytes of ``payload`` (content addressing)."""

    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def run_dir(root: Path, run_id: str) -> Path:
    """Directory holding one run's artifacts: ``<root>/<run_id>/``."""

    return root / validate_run_id(run_id)


def run_doc_path(root: Path, run_id: str) -> Path:
    """Path of the redacted ``TestRun`` document for a run."""

    return run_dir(root, run_id) / _RUN_DOC_NAME


def attempts_dir(root: Path, run_id: str) -> Path:
    """Directory holding one run's content-addressed attempt artifacts."""

    return run_dir(root, run_id) / _ATTEMPTS_DIR


def attempt_path(root: Path, run_id: str, sha256: str) -> Path:
    """Path of a single content-addressed attempt: ``attempts/<sha256>.json``."""

    return attempts_dir(root, run_id) / f"{validate_sha256(sha256)}.json"


def relative_uri(root: Path, path: Path) -> str:
    """Return ``path`` as a POSIX string relative to ``root`` (portable ref).

    Used for the ``EvidenceRef.uri`` so a stored reference does not leak the
    operator's absolute filesystem layout and is stable across machines.
    """

    return path.relative_to(root).as_posix()
