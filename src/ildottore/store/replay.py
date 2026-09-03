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
    """A stored artifact's content no longer matches its content-address hash."""


@dataclass(frozen=True)
class ReplayResult:
    """The reconstructed, hash-verified view of one run's attempts."""

    run_id: str
    attempts: tuple[Attempt, ...]

    @property
    def n(self) -> int:
        """Number of attempts (the ``N`` in ``repro = successes / N``)."""

        return len(self.attempts)

    def successful_attacks(self) -> int:
        """Attempts whose verdict is ``fail`` (= target exploited; ``docs/04``)."""

        return sum(
            1
            for a in self.attempts
            if a.verdict is not None and a.verdict.status is VerdictStatus.FAIL
        )

    def reproducibility(self) -> float:
        """``successful_attacks / N`` in ``[0, 1]``; 0.0 for an empty run."""

        return self.successful_attacks() / self.n if self.n else 0.0


def _load_verified_attempt(artifact: Path) -> Attempt:
    """Read one attempt artifact, verify its hash, and rebuild the model."""

    payload = artifact.read_text(encoding="utf-8")
    expected = artifact.stem  # filename (minus .json) == content hash
    actual = paths.content_hash(payload)
    if actual != expected:
        raise TamperError(f"artifact hash mismatch for {artifact.name}: content hashes to {actual}")
    return Attempt.model_validate_json(payload)


def replay_run(root: Path, run_id: str) -> ReplayResult:
    """Load + hash-verify every attempt artifact for ``run_id``.

    Raises :class:`TamperError` on the first artifact whose content does not match
    its filename hash. Returns an empty result if the run has no attempts dir.
    """

    directory = paths.attempts_dir(Path(root), run_id)
    attempts: list[Attempt] = []
    if directory.is_dir():
        for artifact in sorted(directory.glob("*.json")):
            attempts.append(_load_verified_attempt(artifact))
    return ReplayResult(run_id=run_id, attempts=tuple(attempts))


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
