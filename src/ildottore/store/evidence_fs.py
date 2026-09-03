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


def _strip_media_carrier_bytes(obj: object) -> None:
    """Elide multimodal carrier bytes anywhere in the dumped attempt (in place, recursive).

    A carrier (image/audio ``data_b64``) is large binary that is reproducible from its declarative
    part (``render_text`` / ``asset``) plus the recorded ``media_sha256`` digest, so the raw bytes
    are not stored: they would bloat evidence and, being high-entropy, could false-positive the
    fail-closed redaction guard. Every ``data_b64`` string value is replaced with a size
    placeholder **wherever it appears** (not only ``request.media``), so a future carrier location
    (e.g. a multimodal multi-turn message) cannot leak raw bytes past the guard. ``kind`` /
    ``format`` / ``asset`` stay for provenance.
    """

    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "data_b64" and isinstance(value, str):
                obj[key] = f"<omitted {len(value)} b64 chars>"
            else:
                _strip_media_carrier_bytes(value)
    elif isinstance(obj, list):
        for item in obj:
            _strip_media_carrier_bytes(item)


def _pop_media_digest(dump: object) -> object | None:
    """Remove and return ``request.metadata.media_sha256`` (the chain-of-custody digest).

    The digest is a SHA-256 hex list: non-sensitive (a one-way hash) and the whole point of the
    multimodal evidence trail, but its entropy is above the redactor's threshold, so leaving it in
    would let redaction mask it into oblivion. It is exempted from redaction and restored verbatim
    after the fail-closed guard runs (see ``put``).
    """

    if not isinstance(dump, dict):
        return None
    request = dump.get("request")
    if not isinstance(request, dict):
        return None
    metadata = request.get("metadata")
    if not isinstance(metadata, dict) or "media_sha256" not in metadata:
        return None
    digest: object = metadata.pop("media_sha256")
    return digest


def _restore_media_digest(redacted: object, digest: object) -> None:
    """Put the exempted ``media_sha256`` digest back into the redacted request (in place)."""

    if digest is None or not isinstance(redacted, dict):
        return
    request = redacted.get("request")
    if not isinstance(request, dict):
        return
    metadata = request.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        request["metadata"] = metadata
    metadata["media_sha256"] = digest


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

        # Value-redact the dump with the injected redactor, then mask dict KEYS separately
        # so a secret in a key (e.g. a model-controlled tool-call argument name) is masked
        # too (DL2). Keys are masked here but VALUES are left to ``redactor.redact``, so an
        # incomplete object-redactor still leaves a raw value for the fail-closed guard to
        # catch (the guard re-scans keys and values independently).
        dump = attempt.model_dump(mode="json")
        _strip_media_carrier_bytes(dump)
        # The chain-of-custody media digest is a safe one-way hash but its entropy is above the
        # redactor's threshold, so exempt it: pop it out before redaction + the fail-closed guard,
        # then restore it verbatim into the redacted payload that is hashed and written.
        media_digest = _pop_media_digest(dump)
        redacted = self._mask_keys(self._redactor.redact(dump))
        self._assert_no_leak(_canonical_json(redacted))
        _restore_media_digest(redacted, media_digest)
        payload = _canonical_json(redacted)

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

        Re-scans the payload's **string leaves** with ``redact_text`` (independent of
        the object-level ``redact`` that produced it, so an incomplete object-redactor
        is still caught, DL2). Numeric JSON literals are left untouched: a value like a
        logprob float (``-0.0131136…``) or a latency reading is not PII, yet its bare
        digit run matches the phone/card shapes when the whole JSON is scanned as flat
        text. Scanning the parsed structure (strings only) keeps the fixed-point
        guarantee for real secrets without false-positiving on numbers, so evidence from
        a live target, which carries real logprobs/usage/latency, persists correctly.
        """

        if _canonical_json(self._rescan_strings(json.loads(payload))) != payload:
            raise RedactionLeakError("unredacted secret/PII shape survived; write refused (DL2)")

    def _mask_keys(self, obj: object) -> object:
        """Mask dict KEYS via ``redact_text`` (recursively), leaving values untouched.

        Values are already handled by the injected ``redactor.redact``; this only closes
        the secret-in-a-key vector without hiding an incomplete value-redaction from the
        fail-closed guard.
        """

        if isinstance(obj, dict):
            return {
                self._redactor.redact_text(str(key)): self._mask_keys(value)
                for key, value in obj.items()
            }
        if isinstance(obj, list):
            return [self._mask_keys(item) for item in obj]
        return obj

    def _rescan_strings(self, obj: object) -> object:
        """Apply ``redact_text`` to every string leaf; leave numbers/None as-is.

        Deliberately walks the structure directly (not via ``redactor.redact``) so the
        check stays independent of the object-redaction that produced the payload.
        """

        if isinstance(obj, str):
            return self._redactor.redact_text(obj)
        if isinstance(obj, dict):
            # Re-scan KEYS as well as values: a secret in a dict key must be caught by the
            # fail-closed guard, not just masked in values (DL2).
            return {
                self._redactor.redact_text(str(key)): self._rescan_strings(value)
                for key, value in obj.items()
            }
        if isinstance(obj, list):
            return [self._rescan_strings(item) for item in obj]
        return obj

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
