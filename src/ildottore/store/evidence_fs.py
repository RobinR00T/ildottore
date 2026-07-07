"""Filesystem :class:`~ildottore.shared.protocols.EvidenceStore` (u10).

``put(run_id, attempt)`` redacts the attempt (u01 redactor, the only masking
choke point — contract §3/§8), serializes it to canonical JSON, content-addresses
it by SHA-256 and writes it **atomically** and **immutably** under the run's
``attempts/`` directory. Identical attempts dedupe to one file / one ref; differing
content yields a new hash (never overwrites) — contract §4 KEEP.

Redaction is **fail-closed** (contract §4 KEEP, ``docs/11 §5`` DL2): the redacted
payload is re-scanned and if any secret/PII shape survives the write is refused and
:class:`RedactionLeakError` raised — no raw secret/PII/canary ever touches disk.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Sequence
from pathlib import Path

from ildottore.redactor import Pattern, Redactor
from ildottore.shared.models import Attempt, EvidenceRef
from ildottore.store import paths


class RedactionLeakError(RuntimeError):
    """A raw secret/PII shape survived redaction — the write is refused (DL2)."""


def _canonical_json(obj: object) -> str:
    """Deterministic JSON: sorted keys, compact, UTF-8 preserved.

    Determinism is what makes content addressing meaningful — the same logical
    attempt always serializes to the same bytes and therefore the same hash.
    """

    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class FsEvidenceStore:
    """Content-addressed, immutable, redact-at-rest evidence store on disk.

    ``root`` comes from config (contract §4 KEEP: never hardcoded); ``planted``
    is an optional list of engagement canary values that must never appear
    verbatim on disk — they are redacted as an extra fail-closed guard even
    though DL1 canaries are synthetic.
    """

    def __init__(
        self,
        root: Path,
        *,
        redactor: Redactor | None = None,
        planted_canaries: Sequence[str] | None = None,
    ) -> None:
        self._root = Path(root)
        self._redactor = redactor if redactor is not None else Redactor()
        for canary in planted_canaries or ():
            if canary:
                # Registered patterns run before the built-ins so a planted
                # canary is always masked verbatim (extra fail-closed guard).
                self._redactor.register(
                    Pattern("canary", re.compile(re.escape(canary)), hashed=True)
                )

    @property
    def root(self) -> Path:
        return self._root

    def put(self, run_id: str, attempt: Attempt) -> EvidenceRef:
        """Redact → hash → atomic-write; return a verifiable :class:`EvidenceRef`.

        Idempotent: re-writing an identical attempt is a no-op that returns the
        same ref (same content → same hash → same path).
        """

        redacted = self._redactor.redact(attempt.model_dump(mode="json"))
        payload = _canonical_json(redacted)
        self._assert_no_leak(payload)

        digest = paths.content_hash(payload)
        target = paths.attempt_path(self._root, run_id, digest)
        target.parent.mkdir(parents=True, exist_ok=True)

        if not target.exists():
            self._atomic_write(target, payload)

        return EvidenceRef(
            run_id=run_id,
            attempt_id=attempt.attempt_id,
            uri=paths.relative_uri(self._root, target),
            sha256=digest,
        )

    def _assert_no_leak(self, payload: str) -> None:
        """Fail-closed: refuse the write if redaction is not a fixed point.

        The redactor is idempotent, so a fully-redacted payload must equal its
        own re-redaction. Any difference means a raw secret/PII shape survived
        the first pass — refuse rather than persist it (DL2).
        """

        if self._redactor.redact_text(payload) != payload:
            raise RedactionLeakError("unredacted secret/PII shape survived; write refused (DL2)")

    def _atomic_write(self, target: Path, payload: str) -> None:
        """Write via a temp file in the same dir + ``os.replace`` (atomic rename).

        Same-directory temp guarantees ``os.replace`` is atomic (no cross-device
        rename) and never leaves a partial artifact at the final path.
        """

        fd, tmp_name = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
