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
import sys
from collections import defaultdict
from pathlib import Path

from pydantic import ValidationError

from ildottore.shared.digest import spec_digests, target_digest
from ildottore.shared.enums import ScanBand, VerdictStatus
from ildottore.shared.models import (
    AttackSpec,
    Attempt,
    EvidenceRef,
    Finding,
    RiskScore,
    Target,
    TestRun,
)
from ildottore.store import paths
from ildottore.store.replay import replay_run

__all__ = ["RESUME_PLACEHOLDER_RISK", "load_resume_run", "stored_runs"]

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
    evidence_root: Path,
    run_id: str,
    target: Target,
    *,
    run_db: Path | None = None,
    specs: list[AttackSpec] | None = None,
    mock_scenario: str | None = None,
    runs: int | None = None,
    judge: Target | None = None,
    adaptive: bool | None = None,
    allow_unverified: bool = False,
) -> TestRun:
    """Rebuild the partial :class:`TestRun` for ``run_id`` from stored evidence.

    Raises ``ValueError`` when the run has no stored attempts (a typo in the id, the wrong
    ``--evidence-root``, or a run that was refused before it sent anything): resuming
    "nothing" would quietly re-run the whole battery under an id that promises otherwise.

    ``specs`` binds it to the battery the run was made with (see :func:`_assert_same_specs`).

    ``run_db`` binds the resume to the target the run was made against. Without it, resuming
    target B with target A's run id produced **a full report for B out of A's evidence, with
    zero requests sent**: a hardened target inheriting a vulnerable one's criticals, or (worse)
    a vulnerable one inheriting a clean bill of health and exiting 0. An ``Attempt`` carries no
    target, so the evidence cannot detect it; the run store records ``target_id``, so it can.
    """

    if run_db is not None:
        _assert_same_target(run_db, run_id, target, allow_unverified=allow_unverified)
        _assert_same_context(
            run_db,
            run_id,
            target,
            mock_scenario=mock_scenario,
            runs=runs,
            judge=judge,
            adaptive=adaptive,
            allow_unverified=allow_unverified,
        )
        if specs is not None:
            _assert_same_specs(run_db, run_id, specs, allow_unverified=allow_unverified)
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


def _assert_same_target(
    run_db: Path, run_id: str, target: Target, *, allow_unverified: bool = False
) -> None:
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
    # Compare like with like. `save_run` writes `target_id` through the redactor, so a
    # tenant-shaped id (`tenant-<32 hex>`, an email) is stored masked and never equalled its
    # own raw value: every resume of such a target was refused with "was made against target
    # '«REDACTED:high_entropy:...»'", which is both false and unrecoverable by any flag. The
    # masking is deterministic, so redacting this side too restores the comparison.
    if stored is not None and stored != target.id:
        from ildottore.redactor import Redactor

        if stored == Redactor().redact_text(target.id):
            stored = target.id
    if stored is None:
        # A row with no target id verifies nothing, and `_ensure_run_row` can mint exactly such
        # a row. Treated as unverifiable rather than as a match.
        _unverifiable(
            run_id, "the target of the stored run", allow=allow_unverified, waivable=False
        )
        return
    if stored != target.id:
        raise ValueError(
            f"run {run_id!r} was made against target {stored!r}, not {target.id!r}. Resuming "
            "it here would report one target's evidence as another's, with zero requests "
            "sent. Resume it against its own target, or start a fresh run."
        )


def stored_runs(run_db: Path, run_id: str) -> int | None:
    """The ``--runs`` the halted campaign used, so a resume can inherit it."""

    from ildottore.store.run_sqlite import SqliteRunStore

    if not Path(run_db).exists():
        return None
    with SqliteRunStore(Path(run_db)) as store:
        context = store.get_run_context(run_id)
    value = (context or {}).get("runs")
    return int(value) if value is not None else None


def _unverifiable(run_id: str, what: str, *, allow: bool, waivable: bool = True) -> None:
    """One decision for every "this cannot be checked" case: refuse, or say so loudly.

    Refusing is the default because the alternative was tried and it was wrong. The first
    version continued with a notice, and an audit showed the shape of the mistake: a run that
    predates the digest column also predates the SPEND column, so the same resume that could
    not verify the battery was also handed a brand-new budget ceiling, silently, and the
    commit that claimed to have fixed exactly that could still reproduce it on every run that
    existed at the time.
    """

    if not waivable:
        # The TARGET is never waivable. An audit pointed the opt-in at a run row with no
        # target id and resumed a vulnerable app's evidence into a hardened app's report, with
        # zero requests sent: the original catastrophic bug, one flag away, behind a flag whose
        # help text advertises a budget consequence. One flag must not disarm two checks.
        raise ValueError(
            f"run {run_id!r} does not record which target it was made against, so resuming it "
            "here could publish another target's evidence as this one's, with zero requests "
            "sent. There is no flag for this: start a fresh run against this target."
        )
    if not allow:
        raise ValueError(
            f"cannot verify {what} for run {run_id!r}, so resuming it would merge two halves "
            "that nothing checked are the same campaign, under one id and one report. This is "
            "usually a run recorded before the check existed. Start a fresh run, or pass "
            "--resume-unverified to continue deliberately (its budget ceiling then applies to "
            "this invocation alone, because the earlier spend was never recorded)."
        )
    print(
        f"resume: {what} cannot be verified for run {run_id!r}, continuing because "
        "--resume-unverified was given. The ceiling binds this invocation only.",
        file=sys.stderr,
    )


def _assert_same_specs(
    run_db: Path, run_id: str, specs: list[AttackSpec], *, allow_unverified: bool = False
) -> None:
    """Refuse a resume whose battery changed since the halt, naming what changed.

    The two halves of a resumed run are merged into one finding per spec and scored as one
    campaign. That is only meaningful while both halves ran the same spec: edit a prompt,
    tighten an evaluator or add a spec between the halt and the resume, and the report is a
    single document, under a single id, whose evidence comes from two different batteries,
    with nothing in it saying so. The digest is over a behavioural projection of the loaded
    model, so a corrected description or a reflowed line is not a change while anything that
    reaches the wire, the verdict or a published number is.
    """

    from ildottore.store.run_sqlite import SqliteRunStore

    with SqliteRunStore(Path(run_db)) as store:
        stored = store.get_run_spec_digests(run_id)
    if stored is None:
        _unverifiable(run_id, "the battery", allow=allow_unverified)
        return
    current = spec_digests(specs)
    changed = sorted(k for k in stored.keys() & current.keys() if stored[k] != current[k])
    removed = sorted(stored.keys() - current.keys())
    added = sorted(current.keys() - stored.keys())
    if not (changed or removed or added):
        return
    parts = []
    if changed:
        parts.append(f"{len(changed)} changed ({', '.join(changed[:5])})")
    if removed:
        parts.append(f"{len(removed)} no longer selected ({', '.join(removed[:5])})")
    if added:
        parts.append(f"{len(added)} new ({', '.join(added[:5])})")
    raise ValueError(
        f"the battery changed since run {run_id!r} halted: {'; '.join(parts)}. Resuming "
        "would merge two different batteries into one report under one run id, and score "
        "them as one campaign. Start a fresh run, or restore the specs as they were."
    )


def _assert_same_context(
    run_db: Path,
    run_id: str,
    target: Target,
    *,
    mock_scenario: str | None,
    runs: int | None,
    judge: Target | None = None,
    adaptive: bool | None = None,
    allow_unverified: bool = False,
) -> None:
    """Refuse a resume whose TARGET, route or sample size changed since the halt.

    The id check was one field deep and everything else was unbound. `--resume --hardened`
    needed no file edit at all: it flipped the offline replay, and the vulnerable half's
    criticals were published as findings of a hardened run, scored from evidence the second
    invocation never produced. `--runs` is here for the same reason one field over: it is the
    denominator of the reproducibility axis, and changing it mid-campaign scores one report's
    specs over different sample sizes.
    """

    from ildottore.store.run_sqlite import SqliteRunStore

    with SqliteRunStore(Path(run_db)) as store:
        context = store.get_run_context(run_id)
    if context is None:
        _unverifiable(run_id, "the target and the run parameters", allow=allow_unverified)
        return
    stored_target = context.get("target_digest")
    current_target = target_digest(target, mock_scenario=mock_scenario)
    if stored_target is not None and stored_target != current_target:
        raise ValueError(
            f"run {run_id!r} was made against a different target than the one resolved now "
            "(its endpoint, model, capabilities or offline scenario differ, even though the id "
            "matches). Resuming would publish one target's evidence as another's. Restore the "
            "target as it was, or start a fresh run."
        )
    stored_judge = context.get("judge_digest")
    current_judge = target_digest(judge) if judge is not None else None
    if stored_judge != current_judge:
        raise ValueError(
            f"run {run_id!r} was judged by a different model than this invocation offers "
            f"(stored {'a judge' if stored_judge else 'no judge'}, now "
            f"{'a judge' if current_judge else 'none'}). `semantic_judge` decides verdicts, so "
            "one campaign would be arbitrated by two different models and merged into one "
            "finding per spec. Resume with the same --judge, or start a fresh run."
        )
    stored_adaptive = context.get("adaptive")
    if adaptive is not None and stored_adaptive is not None and bool(stored_adaptive) != adaptive:
        raise ValueError(
            f"run {run_id!r} halted with adaptive planning "
            f"{'on' if stored_adaptive else 'off'} and this invocation asks for "
            f"{'on' if adaptive else 'off'}. It reorders the mutators a spec runs, so the two "
            "halves would not be the same campaign."
        )
    stored_runs = context.get("runs")
    if runs is not None and stored_runs is not None and int(stored_runs) != runs:
        raise ValueError(
            f"run {run_id!r} halted at --runs {stored_runs} and this invocation asks for "
            f"{runs}. One report would then score some specs over {stored_runs} samples and "
            "others over "
            f"{runs}, on the same reproducibility axis. Resume at --runs {stored_runs}."
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
