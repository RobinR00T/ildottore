"""Reproducible-replay reader for stored evidence (u10).

Reconstructs a run's attempts + findings from what the stores wrote so a reader
can recompute reproducibility ``repro = successful_attacks / N`` (``docs/01 §5``)
without re-running the target. Every artifact is **hash-verified**: the file name
is the SHA-256 of its content, so a tampered artifact fails verification and
:class:`TamperError` is raised (contract §7 content-addressing).

Read-only: this module never writes, and it reconstructs from the *redacted*
on-disk form (raw values were never stored - DL2).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import Attempt
from ildottore.store import paths


class TamperError(RuntimeError):
    """A stored artifact's content no longer matches its content-address hash.

    ``digests`` are the hashes this tool computed and the message quotes bare (not as
    ``<hash>.json``): the CLI keeps them readable and passes every other 64-hex token to the
    redactor.
    """

    def __init__(self, message: str, *, digests: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.digests = digests


@dataclass(frozen=True)
class ReplayResult:
    """The reconstructed, hash-verified view of one run's attempts (and its probes)."""

    run_id: str
    attempts: tuple[Attempt, ...]
    #: Recognition traffic (``-sV``), kept SEPARATE from the attempts on purpose: it is
    #: evidence of what this tool sent, and it is not an attack attempt, so it must never
    #: reach ``n`` or the reproducibility ratio below.
    probes: tuple[Attempt, ...] = ()
    #: The content hash (artifact file name) of each attempt, in ``attempts`` order.
    attempt_hashes: tuple[str, ...] = ()

    def effective_attempts(self) -> tuple[Attempt, ...]:
        """One attempt per id, the answered one when an id has several artifacts.

        A resume sends an attempt that ended in an environment error again under its id (F11),
        so the failed try and its re-send can both be on disk. Both are history and the listing
        shows them, but only one is the attempt: counting both printed 10 attempts and a 0.60
        rate for a spec the report scored 6 of 6. A reply stored without a verdict (a ceiling
        stopped its evaluation) is sent again too, and its re-send is the attempt, judged or
        ended in an environment error, as the runner scores it.
        """

        kept: dict[str, Attempt] = {}
        for attempt in self.attempts:
            current = kept.get(attempt.attempt_id)
            if current is None or _answer_rank(attempt) > _answer_rank(current):
                kept[attempt.attempt_id] = attempt
        return tuple(kept.values())

    @property
    def n(self) -> int:
        """Number of attempts (the ``N`` in ``repro = successes / N``), one per attempt id."""

        return len(self.effective_attempts())

    def successful_attacks(self) -> int:
        """Attempts whose verdict is ``fail`` (= target exploited; ``docs/04``)."""

        return sum(
            1
            for a in self.effective_attempts()
            if a.verdict is not None and a.verdict.status is VerdictStatus.FAIL
        )

    def reproducibility(self) -> float:
        """``successful_attacks / N`` in ``[0, 1]``; 0.0 for an empty run."""

        return self.successful_attacks() / self.n if self.n else 0.0


def _answer_rank(attempt: Attempt) -> tuple[bool, bool, bool]:
    """Which artifact of one attempt id is the attempt: answered and judged, then judged.

    The runner's rule (``core.runner._answer_rank``): a verdict outranks a bare reply.
    """

    answered = attempt.response is not None
    judged = attempt.verdict is not None
    return (answered and judged, judged, answered)


def _load_verified_attempt(artifact: Path) -> Attempt:
    """Read one attempt artifact, verify its hash, and rebuild the model."""

    payload = artifact.read_text(encoding="utf-8")
    expected = artifact.stem  # filename (minus .json) == content hash
    actual = paths.content_hash(payload)
    if actual != expected:
        raise TamperError(
            f"artifact hash mismatch for {artifact.name}: content hashes to {actual}",
            digests=(actual,),
        )
    return Attempt.model_validate_json(payload)


def replay_run(root: Path, run_id: str) -> ReplayResult:
    """Load + hash-verify every attempt **and probe** artifact for ``run_id``.

    Raises :class:`TamperError` on the first artifact whose content does not match
    its filename hash. Returns an empty result if the run has no attempts dir.
    """

    hashed = _load_dir_hashed(paths.attempts_dir(Path(root), run_id))
    return ReplayResult(
        run_id=run_id,
        attempts=tuple(attempt for _, attempt in hashed),
        probes=_load_dir(paths.probes_dir(Path(root), run_id)),
        attempt_hashes=tuple(digest for digest, _ in hashed),
    )


def check_manifest(
    result: ReplayResult,
    manifest: dict[str, set[str]],
    pending: frozenset[str] | set[str] = frozenset(),
    *,
    battery: frozenset[str] | set[str] | None = None,
) -> None:
    """Refuse an evidence tree that differs from what the run store recorded.

    Each artifact verifies against its OWN file name, so an edited artifact renamed to its new
    hash verified, and ``--resume`` published it: a clean pass became a confirmed critical
    (audit 2026-10-03, F12). The run store's findings cite the hash of every attempt they
    were scored from, so for a spec in ``manifest``:

    * an attempt artifact that is not one of the recorded hashes was added or replaced,
      including one placed under a spec whose finding cites no evidence at all;
    * a recorded hash with no artifact was deleted (removing every artifact of the failing
      spec used to replay as a clean run, review of PR #32).

    Since schema v4 the run store also journals every attempt artifact as it is written, so a
    spec with no saved finding (a campaign or a resume killed mid-spec) is in ``manifest`` too.
    ``pending`` are digests journaled before a write that was never confirmed: missing, they
    are an interrupted write, not a deletion. ``battery`` is the set of spec ids the run
    recorded before it sent anything: an artifact under any other spec id (one the run never
    ran) is refused. A battery spec still absent from the manifest (stored before the journal,
    or before digests were kept readable) cannot be checked this way and is let through. That is
    the known limit, not a pass.
    """

    present = set(result.attempt_hashes)
    for digest, attempt in zip(result.attempt_hashes, result.attempts, strict=True):
        recorded = manifest.get(attempt.spec_id)
        if recorded is None and battery is not None and attempt.spec_id not in battery:
            recorded = set()
        if recorded is not None and digest not in recorded:
            raise TamperError(
                f"artifact {digest}.json ({attempt.spec_id}) is not one the run store recorded "
                "for that spec: it was added or replaced after the run (or written by an older "
                "version of this tool, which does not journal what it writes)"
            )
    for spec_id, recorded in sorted(manifest.items()):
        missing = sorted(recorded - present - set(pending))
        if missing:
            raise TamperError(
                f"{len(missing)} artifact(s) the run store recorded for {spec_id} are missing "
                f"from the evidence tree (first: {missing[0]}.json): removed after the run"
            )


def _load_dir_hashed(directory: Path) -> tuple[tuple[str, Attempt], ...]:
    """Like :func:`_load_dir`, keeping each artifact's content hash."""

    if not directory.is_dir():
        return ()
    return tuple((a.stem, _load_verified_attempt(a)) for a in sorted(directory.glob("*.json")))


def _load_dir(directory: Path) -> tuple[Attempt, ...]:
    """Every hash-verified artifact in one directory, in stable filename order."""

    if not directory.is_dir():
        return ()
    return tuple(_load_verified_attempt(a) for a in sorted(directory.glob("*.json")))


def verify_ref(root: Path, run_id: str, sha256: str) -> bool:
    """Return ``True`` if the stored artifact for ``sha256`` verifies, else raise.

    A missing artifact returns ``False``; a present-but-tampered artifact raises
    :class:`TamperError` (a silent ``False`` would hide corruption).
    """

    artifact = paths.attempt_path(Path(root), run_id, sha256)
    if not artifact.is_file():
        return False
    _load_verified_attempt(artifact)
    return True
