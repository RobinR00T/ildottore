"""``dottore replay <run-id>`` - re-read a run from stored evidence (contract §5.5).

A thin delegator over the u10 evidence store: reconstruct + hash-verify a run's
attempts and report reproducibility. It performs **no** re-sending and no scoring
logic (contract §8) - it reads the immutable, content-addressed evidence and surfaces
what was recorded (a :class:`~ildottore.store.replay.ReplayResult`), so a finding is
reproducible from disk alone (``docs/07`` determinism-replay).
"""

from __future__ import annotations

from pathlib import Path

from ildottore.core.runner import SAMPLING_NOT_SENT
from ildottore.redactor import visible_controls
from ildottore.shared.models import Attempt
from ildottore.shared.provider_filter import (
    blocked_by_provider_filter,
    cut_by_output_filter,
    filter_side_unknown,
)
from ildottore.shared.unreadable import unreadable_reply
from ildottore.store import ReplayResult, SqliteRunStore, check_manifest, replay_run
from ildottore.store.run_sqlite import check_store_path

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

    if run_db is not None:
        # A directory, a file that is not SQLite, or a path under a regular file, refused as
        # `run` refuses it: a directory read as "no run store" and replayed without the
        # manifest check (pre-merge audit of e6a1ab9b, LOW 7). A missing file is the warning.
        check_store_path(run_db)
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
                check_manifest(
                    result,
                    store.recorded_evidence(run_id),
                    store.pending_artifacts(run_id),
                    battery=store.recorded_battery(run_id),
                )
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
        if blocked_by_provider_filter(attempt):  # OD-41: not the model's answer, nor its refusal
            status = f"{status} (blocked_by_provider_filter)"
        elif cut_by_output_filter(attempt):  # OD-42: the filter's text, never the model resisting
            status = f"{status} (cut_by_provider_output_filter)"
        elif filter_side_unknown(attempt):
            status = f"{status} (provider_filter_side_unknown)"
        elif unreadable_reply(attempt):  # OD-21: the adapter could not read what came back
            status = f"{status} (unreadable_reply)"
        if _declared(attempt):  # OD-43: the target file's word, not the tool's judgement
            status = f"{status} (operator declaration)"
        # Read back from the evidence tree, written out as every other stored text is.
        fields = visible_controls(f"{attempt.attempt_id}  {attempt.spec_id}  {attempt.mutation}")
        lines.append(f"  {fields}  {status}")
    if result.probes:
        # Recognition traffic, listed apart and never folded into the counts below: this is
        # the answer to "what did this tool send my endpoint", which a fingerprint pass could
        # not give at all until probes were stored.
        lines.append(f"  probes ({len(result.probes)}, recognition traffic from -sV):")
        for probe in result.probes:
            answered = "answered" if probe.response is not None else f"no answer ({probe.error})"
            lines.append(f"    {visible_controls(f'{probe.attempt_id}  {answered}')}")
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
    blocked = result.blocked_by_provider_filter()
    if blocked:
        lines.append(
            f"  {blocked} of {result.n} attempt(s) the provider's input filter refused before the "
            "model saw them (blocked_by_provider_filter): counted in N and never a success; "
            "neither a refusal by the model nor an exploit"
        )
    cut = result.cut_by_provider_output_filter()
    if cut:
        lines.append(
            f"  {cut} of {result.n} attempt(s) the provider's output filter cut or replaced "
            "(cut_by_provider_output_filter): counted in N and never a success; the model may "
            "have written what the filter hid, so review them"
        )
    unread = result.unreadable_replies()
    if unread:
        lines.append(
            f"  {unread} of {result.n} attempt(s) whose reply could not be read as the provider's "
            "(unreadable_reply): counted in N and never a success; each keeps an excerpt for "
            "review"
        )
    unsaid = result.provider_filter_side_unknown()
    if unsaid:
        lines.append(
            f"  {unsaid} of {result.n} attempt(s) the provider's filter stopped on a side it did "
            "not report (provider_filter_side_unknown): counted in N and never a success; "
            "review them"
        )
    # The attempts whose stored verdict the operator's target file changed (OD-43, u06 A-72).
    declared = sum(1 for a in result.attempts if _declared(a))
    if declared:
        lines.append(
            f"  {declared} of {len(result.attempts)} attempt artifact(s) with a call to a tool the "
            "target file declares not destructive, not judged destructive (operator declaration, "
            "OD-43): each verdict names the tool"
        )
    # A model that takes no sampling was sent no temperature (u12 A-68): what each attempt
    # recorded says so, and the rate above is then over the model's own default sampling.
    unpinned = sum(1 for a in result.attempts if _no_temperature(a))
    if unpinned:
        lines.append(
            f"  {unpinned} of {len(result.attempts)} attempt artifact(s) went out with no "
            "temperature (the target takes none: request.metadata.sampling_not_sent), so they "
            "are not temperature-0 deterministic and the rate is over the model's own sampling"
        )
    return "\n".join(lines)


def _declared(attempt: Attempt) -> bool:
    """True when ``attempt``'s verdict says the operator's declaration changed it (OD-43)."""

    return attempt.verdict is not None and bool(attempt.verdict.operator_cleared)


def _no_temperature(attempt: Attempt) -> bool:
    """True when ``attempt`` asked for a temperature that did not go out (A-68)."""

    unsent = (attempt.request.metadata or {}).get(SAMPLING_NOT_SENT)
    return isinstance(unsent, list) and "temperature" in unsent
