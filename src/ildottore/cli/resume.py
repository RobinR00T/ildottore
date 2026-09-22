"""``dottore run --resume <run-id>``: finish a campaign that did not finish (u12 wiring).

The engine has supported resume since u08 (``CampaignRunner.run(resume_from=...)`` skips
attempt ids already persisted and MERGES a spec's prior attempts with the fresh ones). No
command reached it, which mattered the moment a halted run started exiting 3 and saying so:
the operator was told 27 of 72 specs never ran, and the only way to finish the battery was to
shrink ``--runs``, which is the input to the reproducibility axis of the risk score.

The prior run is reconstructed from the **evidence store**, not from the sqlite run store,
for two reasons: evidence is content-addressed and hash-verified (a tampered artifact raises
:class:`~ildottore.store.replay.TamperError` rather than being resumed from), and the sqlite
findings are a redacted projection, not the attempts themselves.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from pydantic import ValidationError

from ildottore.shared.enums import ScanBand, VerdictStatus
from ildottore.shared.models import (
    Attempt,
    EvidenceRef,
    Finding,
    RiskScore,
    Target,
    TestRun,
)
from ildottore.store import paths
from ildottore.store.replay import replay_run

__all__ = ["RESUME_PLACEHOLDER_RISK", "load_resume_run"]

#: The reconstructed findings need a ``risk``, and a prior partial run's score is not stored
#: with the attempts. It is never published: the runner rescores every resumed spec from the
#: MERGED attempt list and builds a fresh :class:`Finding`, reading only ``attempts`` and
#: ``evidence`` off this one. Neutral values, so that a future path that did read it would
#: produce an obviously-unscored result rather than a plausible-looking wrong one.
RESUME_PLACEHOLDER_RISK = RiskScore(
    impact=1,
    exploitability=1,
    reproducibility=0.0,
    risk=0.0,
    band=ScanBand.INFO,
    confidence=0.0,
)


def load_resume_run(
    evidence_root: Path, run_id: str, target: Target, *, run_db: Path | None = None
) -> TestRun:
    """Rebuild the partial :class:`TestRun` for ``run_id`` from stored evidence.

    Raises ``ValueError`` when the run has no stored attempts (a typo in the id, the wrong
    ``--evidence-root``, or a run that was refused before it sent anything): resuming
    "nothing" would quietly re-run the whole battery under an id that promises otherwise.

    ``run_db`` binds the resume to the target the run was made against. Without it, resuming
    target B with target A's run id produced **a full report for B out of A's evidence, with
    zero requests sent**: a hardened target inheriting a vulnerable one's criticals, or (worse)
    a vulnerable one inheriting a clean bill of health and exiting 0. An ``Attempt`` carries no
    target, so the evidence cannot detect it; the run store records ``target_id``, so it can.
    """

    if run_db is not None:
        _assert_same_target(run_db, run_id, target)
    try:
        result = replay_run(Path(evidence_root), run_id)
    except ValidationError as exc:
        # A stray file in the attempts directory, or a half-written artifact, used to surface
        # as a raw "4 validation errors for Attempt" dump.
        raise ValueError(
            f"run {run_id!r} has an artifact that is not a stored attempt (under "
            f"{Path(evidence_root) / run_id}): {exc.error_count()} field error(s). Remove the "
            "stray file or point --evidence-root at the right tree."
        ) from exc
    if not result.attempts:
        raise ValueError(
            f"no stored attempts for run {run_id!r} under {evidence_root}: nothing to resume. "
            "Check the run id and --evidence-root; a run that sent nothing has nothing to "
            "continue."
        )

    refs = _ref_index(Path(evidence_root), run_id)
    by_spec: dict[str, list[Attempt]] = defaultdict(list)
    for attempt in result.attempts:
        by_spec[attempt.spec_id].append(attempt)

    findings = [
        Finding(
            spec_id=spec_id,
            target_id=target.id,
            status=VerdictStatus.INCONCLUSIVE,
            risk=RESUME_PLACEHOLDER_RISK,
            confirmed=False,
            attempts=attempts,
            evidence=[refs[a.attempt_id] for a in attempts if a.attempt_id in refs],
        )
        for spec_id, attempts in sorted(by_spec.items())
    ]
    return TestRun(run_id=run_id, targets=[target], findings=findings)


def _assert_same_target(run_db: Path, run_id: str, target: Target) -> None:
    """Refuse a resume whose stored run belongs to a different target (or is unknown)."""

    from ildottore.store.run_sqlite import SqliteRunStore

    if not Path(run_db).exists():
        raise ValueError(
            f"cannot verify that run {run_id!r} belongs to target {target.id!r}: no run store "
            f"at {run_db}. Point --run-db at the store the original run wrote, or the resume "
            "could splice another target's evidence into this target's report."
        )
    with SqliteRunStore(Path(run_db)) as store:
        row = store.get_run(run_id)
    if row is None:
        raise ValueError(
            f"run {run_id!r} is not in the run store at {run_db}, so the target it was made "
            "against cannot be verified. Resuming would attribute its evidence to "
            f"{target.id!r} on trust."
        )
    stored = row.get("target_id")
    if stored is not None and stored != target.id:
        raise ValueError(
            f"run {run_id!r} was made against target {stored!r}, not {target.id!r}. Resuming "
            "it here would report one target's evidence as another's, with zero requests "
            "sent. Resume it against its own target, or start a fresh run."
        )


def _ref_index(evidence_root: Path, run_id: str) -> dict[str, EvidenceRef]:
    """Map ``attempt_id`` to the reference of the artifact that holds it.

    The artifact's file NAME is its content hash, so the ref is recovered by reading the
    directory rather than by re-hashing the model: a re-hash drifts the moment the redactor
    or the dump shape changes, and would then point at a file that does not exist. Parsed
    rather than string-matched for the same reason (the stored form is canonical JSON with
    no spaces, so ``'"attempt_id": "x"'`` silently matches nothing).
    """

    directory = paths.attempts_dir(Path(evidence_root), run_id)
    index: dict[str, EvidenceRef] = {}
    if not directory.is_dir():
        return index
    for artifact in sorted(directory.glob("*.json")):
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8"))
        except ValueError:
            continue  # replay_run already hash-verifies; an unparseable file is not a ref
        attempt_id = payload.get("attempt_id")
        if isinstance(attempt_id, str):
            index[attempt_id] = EvidenceRef(
                run_id=run_id,
                attempt_id=attempt_id,
                uri=paths.relative_uri(Path(evidence_root), artifact),
                sha256=artifact.stem,
            )
    return index
