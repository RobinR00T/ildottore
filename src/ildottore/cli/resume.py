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


def load_resume_run(evidence_root: Path, run_id: str, target: Target) -> TestRun:
    """Rebuild the partial :class:`TestRun` for ``run_id`` from stored evidence.

    Raises ``ValueError`` when the run has no stored attempts (a typo in the id, the wrong
    ``--evidence-root``, or a run that was refused before it sent anything): resuming
    "nothing" would quietly re-run the whole battery under an id that promises otherwise.
    """

    result = replay_run(Path(evidence_root), run_id)
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
