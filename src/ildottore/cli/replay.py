"""``dottore replay <run-id>`` - re-read a run from stored evidence (contract §5.5).

A thin delegator over the u10 evidence store: reconstruct + hash-verify a run's
attempts and report reproducibility. It performs **no** re-sending and no scoring
logic (contract §8) - it reads the immutable, content-addressed evidence and surfaces
what was recorded (a :class:`~ildottore.store.replay.ReplayResult`), so a finding is
reproducible from disk alone (``docs/07`` determinism-replay).
"""

from __future__ import annotations

from pathlib import Path

from ildottore.store import ReplayResult, replay_run

__all__ = ["render_replay", "replay"]


def replay(evidence_root: Path, run_id: str) -> ReplayResult:
    """Reconstruct + hash-verify the attempts stored for ``run_id`` (u10).

    Raises :class:`~ildottore.store.replay.TamperError` if any artifact's content no
    longer matches its content-address - a silent pass would hide corruption.
    """

    result = replay_run(evidence_root, run_id)
    if not result.attempts and not result.probes:
        # "no such run" and "a run with no attempts" printed identically (attempts: 0,
        # exploited: 0, exit 0), so a script could not tell a typo from a real result.
        raise ValueError(
            f"no stored attempts for run {run_id!r} under {evidence_root}: check the run id "
            "and --evidence-root (a run that stored nothing cannot be replayed either)"
        )
    return result


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
    lines.append(
        f"attempts: {result.n}  exploited: {result.successful_attacks()}  "
        f"reproducibility: {result.reproducibility():.2f}"
    )
    return "\n".join(lines)
