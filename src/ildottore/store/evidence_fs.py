"""Filesystem :class:`~ildottore.shared.protocols.EvidenceStore` (u10).

``put(run_id, attempt)`` redacts the attempt (u01 redactor, the only masking
choke point - contract §3/§8), serializes it to canonical JSON, content-addresses
it by SHA-256 and writes it **atomically** and **immutably** under the run's
``attempts/`` directory. Identical attempts dedupe to one file / one ref; differing
content yields a new hash (never overwrites) - contract §4 KEEP.

Redaction is **fail-closed** (contract §4 KEEP, ``docs/11 §5`` DL2): the redacted
payload is re-scanned and if any secret/PII shape survives the write is refused and
:class:`RedactionLeakError` raised - no raw secret/PII/canary ever touches disk.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Final, Protocol

from ildottore.redactor import (
    KeysNotDistinct,
    Pattern,
    Redactor,
    SpanFinder,
    mask_keys,
    redact_split,
    split_texts,
)
from ildottore.shared.folding import folded, folded_spans
from ildottore.shared.models import Attempt, EvidenceRef
from ildottore.store import paths


class RedactionLeakError(RuntimeError):
    """A raw secret/PII shape survived redaction - the write is refused (DL2).

    ``evidence_refused`` is the structural marker the runner reads (``core`` imports no store):
    it stores the attempt again with the pieces of its reply withheld (u01 A-77) instead of
    ending the campaign, and a second refusal ends it as before.
    """

    evidence_refused = True


class EvidenceStoreError(OSError):
    """The evidence root cannot take a run's artifacts; the message names the root (u10 A-80)."""


def check_root_path(root: Path) -> None:
    """Refuse, writing nothing, an evidence root that cannot hold a directory (u10 A-80).

    For the commands that promise to write nothing: a root that is a regular file, or lies
    under one, is refused there too. The run itself proves the root with :func:`prepare_run`.
    """

    root = Path(root)
    if root.exists():
        if not root.is_dir():
            raise EvidenceStoreError(f"cannot write evidence under {root}: it is not a directory")
        return
    ancestor = paths.nearest_existing(root.parent)
    if ancestor is not None and not ancestor.is_dir():
        raise EvidenceStoreError(
            f"cannot write evidence under {root}: {ancestor} is not a directory"
        )


def prepare_run(root: Path, run_id: str, *, probes: bool = False) -> None:
    """Create ``<root>/<run_id>/attempts`` (and ``probes``) and prove a file can be written there.

    Called before a run sends anything. A root that was a regular file used to be found by the
    first attempt's write, after the batch it belonged to was paid for (125 requests, then
    ``NotADirectoryError``, nothing stored, and the requests counted against the resume's
    ceiling). The proof is a temporary file created and removed in each directory, the way every
    artifact is written (``_atomic_write``); the reader lists ``*.json`` only.
    """

    directories = [paths.attempts_dir(root, run_id)]
    if probes:
        directories.append(paths.probes_dir(root, run_id))
    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            descriptor, name = tempfile.mkstemp(
                dir=directory, prefix=".write-check-", suffix=".tmp"
            )
            os.close(descriptor)
            os.unlink(name)
        except OSError as exc:
            raise EvidenceStoreError(f"cannot write evidence under {root}: {exc}") from exc


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


#: What a declared canary holds for the run's id (``core.runner`` fills it in the same way).
_RUN_ID: Final = "{{run_id}}"

#: One SHA-256 digest as the runner writes it (``shared.media.media_digest``).
_SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")


def _is_digest_list(value: object) -> bool:
    """True for what the runner writes under ``media_sha256``: a list of SHA-256 hex digests."""

    return isinstance(value, list) and all(
        isinstance(digest, str) and _SHA256_HEX.fullmatch(digest) for digest in value
    )


def _pop_media_digest(dump: object) -> object | None:
    """Remove and return ``request.metadata.media_sha256`` (the chain-of-custody digest).

    The digest is a SHA-256 hex list: non-sensitive (a one-way hash) and the whole point of the
    multimodal evidence trail, but its entropy is above the redactor's threshold, so leaving it in
    would let redaction mask it into oblivion. It is exempted from redaction and restored verbatim
    after the fail-closed guard runs (see ``put``), only in that shape: a value under the name
    that is anything else (a text, a list holding one) was put back unread, a key name being no
    proof of what it holds (audit of main de122e26, LOW 7). It is redacted like any value.
    """

    if not isinstance(dump, dict):
        return None
    request = dump.get("request")
    if not isinstance(request, dict):
        return None
    metadata = request.get("metadata")
    if not isinstance(metadata, dict) or not _is_digest_list(metadata.get("media_sha256")):
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

    Determinism is what makes content addressing meaningful - the same logical
    attempt always serializes to the same bytes and therefore the same hash.
    """

    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class ArtifactJournal(Protocol):
    """Where attempt artifacts are recorded as they are written (the run store, schema v4)."""

    def record_artifact(self, run_id: str, spec_id: str, sha256: str) -> None: ...

    def confirm_artifact(self, run_id: str, sha256: str) -> None: ...


class FsEvidenceStore:
    """Content-addressed, immutable, redact-at-rest evidence store on disk.

    ``root`` comes from config (contract §4 KEEP: never hardcoded); ``planted``
    is an optional list of engagement canary values that must never appear
    on disk, as written or as the evaluators read it (re-cased, split by an invisible
    character: u10 A-94) - they are redacted as an extra fail-closed guard even
    though DL1 canaries are synthetic. ``folded_canaries`` are the canaries the evaluators read
    case-folded through the invisible characters (``shared.folding``), as declared, with
    ``{{run_id}}`` standing for the id of the run being stored: each is masked as they read it,
    so one a reply holds re-cased or split is not kept on disk (u10 A-94). ``canary_folds`` says
    which, of each run's canary (the composition root passes ``evaluators.base.foldable``, which
    this unit does not import; none folds every one).
    """

    def __init__(
        self,
        root: Path,
        *,
        redactor: Redactor | None = None,
        planted_canaries: Sequence[str] | None = None,
        folded_canaries: Sequence[str] | None = None,
        canary_folds: Callable[[str], bool] | None = None,
        journal: ArtifactJournal | None = None,
    ) -> None:
        self._root = Path(root)
        self._redactor = redactor if redactor is not None else Redactor()
        # Attempt artifacts are journaled in the run store as they are written (schema v4), so
        # the evidence manifest knows every one even when no finding cites it yet.
        self._journal = journal
        for canary in planted_canaries or ():
            if canary:
                # Registered patterns run before the built-ins so a planted
                # canary is always masked verbatim (extra fail-closed guard).
                self._redactor.register(
                    Pattern("canary", re.compile(re.escape(canary)), hashed=True)
                )
        # The run whose attempt is being stored: a folded canary's `{{run_id}}` is its id.
        self._run_id: str | None = None
        self._canary_folds = canary_folds
        for canary in folded_canaries or ():
            if canary:
                self._redactor.register_spans("canary", canary, self._folded_finder(canary))

    def _folded_finder(self, canary: str) -> SpanFinder:
        """Where ``canary``, its ``{{run_id}}`` filled in, shows in a text as evaluators read it.

        Re-cased, or split by a format or a default ignorable character, a canary showed on disk
        as plainly as written: only the exact pattern was registered (audit of A-92, L4). One mask
        over the whole stretch, the invisible characters inside included, under the digest of the
        canary as declared. Outside a ``put`` a canary that holds the run id is not looked for:
        ``_store`` sets the run id for the redaction it runs and clears it after.
        """

        needles: dict[str | None, str] = {}

        def find(text: str) -> Iterable[tuple[int, int]]:
            run_id = self._run_id
            if run_id is None and _RUN_ID in canary:
                return ()
            needle = needles.get(run_id)
            if needle is None:
                concrete = canary if run_id is None else canary.replace(_RUN_ID, run_id)
                folds = self._canary_folds is None or self._canary_folds(concrete)
                needle = needles[run_id] = folded(concrete) if folds else ""
            return folded_spans(text, needle) if needle else ()

        return find

    @property
    def root(self) -> Path:
        return self._root

    def put(self, run_id: str, attempt: Attempt) -> EvidenceRef:
        """Redact → hash → atomic-write; return a verifiable :class:`EvidenceRef`.

        Idempotent: re-writing an identical attempt is a no-op that returns the
        same ref (same content → same hash → same path).
        """

        return self._store(run_id, attempt, paths.attempt_path, journal=self._journal)

    def put_probe(self, run_id: str, attempt: Attempt) -> EvidenceRef:
        """Store a **recognition probe** (``-sV``), under ``probes/`` rather than ``attempts/``.

        Same redaction, same content-addressing, same fail-closed leak guard: a probe is
        traffic this tool sent to somebody's endpoint, so it is evidence. It is filed apart
        because it is **not an attack attempt**: counting it as one would inflate every
        attempt-derived number (reproducibility over N, the resume skip set, ``replay``'s
        count). Until 2026-09-22 a fingerprint pass left no trace at all, which is how 17
        requests per target, briefly including attack framing, stayed unauditable.
        """

        return self._store(run_id, attempt, paths.probe_path)

    def _store(
        self,
        run_id: str,
        attempt: Attempt,
        path_for: Callable[[Path, str, str], Path],
        *,
        journal: ArtifactJournal | None = None,
    ) -> EvidenceRef:
        # Mask dict KEYS first, so a secret in a key (e.g. a model-controlled tool-call argument
        # name) is masked too (DL2), then the VALUES with the injected redactor: each string,
        # and each text the strings at one place in the items of a list make joined (a logprob's
        # tokens, a WebSocket transcript's deltas: A-77). Keys first, so the lists are joined
        # under the names the guard reads. Values are left to ``redactor.redact``, so an
        # incomplete object-redactor still leaves a raw value for the fail-closed guard to
        # catch (the guard re-scans keys, values and joined texts independently).
        self._run_id = run_id
        try:
            dump = attempt.model_dump(mode="json")
            _strip_media_carrier_bytes(dump)
            # The chain-of-custody media digest is a safe one-way hash but its entropy is above
            # the redactor's threshold, so exempt it: pop it out before redaction + the fail-closed
            # guard, then restore it verbatim into the redacted payload that is hashed and written.
            media_digest = _pop_media_digest(dump)
            redacted = redact_split(self._redactor, self._mask_keys(dump))
            self._assert_no_leak(_canonical_json(redacted))
            _restore_media_digest(redacted, media_digest)
        finally:
            self._run_id = None
        payload = _canonical_json(redacted)

        digest = paths.content_hash(payload)
        target = path_for(self._root, run_id, digest)
        target.parent.mkdir(parents=True, exist_ok=True)

        # Journal first ("pending"), write, then confirm ("written"): a crash between the two
        # leaves a pending digest the manifest tolerates as missing, never an artifact on disk
        # that the run store does not know (which the next resume refused as tampered).
        if journal is not None:
            journal.record_artifact(run_id, attempt.spec_id, digest)
        if not target.exists():
            self._atomic_write(target, payload)
        if journal is not None:
            journal.confirm_artifact(run_id, digest)

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

        parsed = json.loads(payload)
        if _canonical_json(self._rescan_strings(parsed)) != payload:
            raise RedactionLeakError("unredacted secret/PII shape survived; write refused (DL2)")
        # A secret in pieces: each piece passes the scan above, the text they make does not
        # (A-77). Each text the strings at one place in the items of a list make is redacted
        # joined, and must come back as it is.
        for joined in split_texts(parsed):
            if self._redactor.redact_text(joined) != joined:
                raise RedactionLeakError(
                    "a secret/PII shape split over the items of a list survived; "
                    "write refused (DL2)"
                )

    def _mask_keys(self, obj: object) -> object:
        """Mask dict KEYS via ``redact_text`` (recursively), leaving values untouched.

        Values are handled by the injected ``redactor.redact``; this only closes the
        secret-in-a-key vector without hiding an incomplete value-redaction from the fail-closed
        guard. Two keys that mask alike are numbered (:func:`ildottore.redactor.mask_keys`, which
        the reports use too), and keys no number tells apart refuse the write.
        """

        try:
            return mask_keys(self._redactor, obj)
        except KeysNotDistinct as exc:
            message = "evidence keys could not be told apart; write refused"
            raise RedactionLeakError(message) from exc

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
