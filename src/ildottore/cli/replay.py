"""``dottore replay <run-id>`` - re-read a run from stored evidence (contract §5.5).

A thin delegator over the u10 evidence store: reconstruct + hash-verify a run's
attempts and report reproducibility. It performs **no** re-sending and no scoring
logic (contract §8) - it reads the immutable, content-addressed evidence and surfaces
what was recorded (a :class:`~ildottore.store.replay.ReplayResult`), so a finding is
reproducible from disk alone (``docs/07`` determinism-replay).
"""

from __future__ import annotations

from pathlib import Path

from ildottore.store import ReplayResult, SqliteRunStore, check_manifest, replay_run

__all__ = ["render_replay", "replay", "replay_checked"]


def replay(evidence_root: Path, run_id: str, run_db: Path | None = None) -> ReplayResult:
    """:func:`replay_checked` without its warning (for callers that only want the result)."""

    return replay_checked(evidence_root, run_id, run_db)[0]


def replay_checked(
    evidence_root: Path, run_id: str, run_db: Path | None = None
) -> tuple[ReplayResult, str | None]:
    """Reconstruct + hash-verify the attempts stored for ``run_id`` (u10), and say how far.

    Raises :class:`~ildottore.store.replay.TamperError` if any artifact's content no longer
    matches its content-address, or if the evidence tree differs from what the run's findings
    recorded (an artifact added, replaced or removed): verifying a file against its own name
    alone let an edited artifact, renamed to its new hash, replay as genuine (F12).

    The second value is a warning when that manifest check could not run: no run store at
    ``run_db``, or one with no record of this run. It used to be skipped silently, so the
    same tampered run exited 3 with its store and 0 without it (review of PR #32).
    """

    result = replay_run(evidence_root, run_id)
    warning: str | None = None
    if run_db is None or not run_db.is_file():
        warning = (
            f"no run store at {run_db}: each artifact was checked against its own file name "
            "only, not against what the run recorded (pass --run-db)"
        )
    else:
        store = SqliteRunStore(run_db)
        try:
            if store.knows_run(run_id):
                check_manifest(result, store.recorded_evidence(run_id))
            else:
                warning = (
                    f"the run store {run_db} has no record of run {run_id!r}: each artifact "
                    "was checked against its own file name only"
                )
        finally:
            store.close()
    if not result.attempts and not result.probes:
        # "no such run" and "a run with no attempts" printed identically (attempts: 0,
        # exploited: 0, exit 0), so a script could not tell a typo from a real result.
        raise ValueError(
            f"no stored attempts for run {run_id!r} under {evidence_root}: check the run id "
            "and --evidence-root (a run that stored nothing cannot be replayed either)"
        )
    return result, warning


def render_replay(result: ReplayResult) -> str:
    """Render a one-line-per-attempt replay report + a reproducibility footer."""

    lines = [f"run: {result.run_id}"]
    for attempt in result.attempts:
        status = attempt.verdict.status.value if attempt.verdict is not None else "?"
        lines.append(f"  {attempt.attempt_id}  {attempt.spec_id}  {attempt.mutation}  {status}")
    if result.probes:
        # Recognition traffic, listed apart and never folded into the counts below: this is
        # the answer to "what did this tool send my endpoint", which a fingerprint pass could
        # not give at all until probes were stored.
        lines.append(f"  probes ({len(result.probes)}, recognition traffic from -sV):")
        for probe in result.probes:
            answered = "answered" if probe.response is not None else f"no answer ({probe.error})"
            lines.append(f"    {probe.attempt_id}  {answered}")
    # Labelled "pooled": it is k / N over every attempt of the run, all specs and variants
    # together. A report's reproducibility is per spec and takes the best variant, so the two
    # read differently on the same run (0.25 here, 1.0 in the report) and the bare word
    # "reproducibility" let them be compared as if they were one measure (review of PR #32).
    history = len(result.attempts) - result.n
    if history:
        lines.append(
            f"  ({history} more artifact{' shares' if history == 1 else 's share'} an attempt "
            "id with one listed above: one per id is counted below)"
        )
    lines.append(
        f"attempts: {result.n}  exploited: {result.successful_attacks()}  "
        f"pooled rate: {result.reproducibility():.2f} (every attempt of the run; a report's "
        "reproducibility is per spec, best variant)"
    )
    return "\n".join(lines)
