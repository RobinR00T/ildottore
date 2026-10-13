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

import shlex
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from ildottore import __version__
from ildottore.shared.config_errors import quoted
from ildottore.shared.digest import (
    spec_digests,
    spec_field_digests,
    target_digest,
    target_field_digests,
)
from ildottore.shared.enums import ScanBand, VerdictStatus
from ildottore.shared.judging_rules import (
    JUDGING_RULES_SINCE,
    JUDGING_RULES_VERSION,
    judging_digest,
    judging_files,
    python_build,
)
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

__all__ = [
    "RESUME_PLACEHOLDER_RISK",
    "ResumeRefused",
    "adopt_resumed",
    "declared_not_destructive",
    "evaluator_plugins",
    "evaluator_types",
    "load_resume_run",
    "recorded_version",
    "selection_record",
    "stored_adaptive",
    "stored_runs",
    "stored_sampling_defaults",
    "stored_takes_sampling",
]

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
    adopt: bool = True,
    selection: dict[str, object] | None = None,
    hardened: bool = False,
) -> TestRun:
    """Rebuild the partial :class:`TestRun` for ``run_id`` from stored evidence.

    Raises ``ValueError`` when the run has no stored attempts and its run store records no
    request spent (a typo in the id, or a run that was refused before it sent anything):
    resuming "nothing" would quietly re-run the whole battery under an id that promises
    otherwise. A run that spent requests and stored no attempt is resumed from nothing, with
    its spend carried by the caller: an identity sweep, a ``-sV`` probe pass, a conversation cut
    mid-way, a first request that failed or a Ctrl-C mid-batch leaves no reply to store, for
    example. That run used to be refused
    as one that "sent nothing", and its spend was stranded under an id nothing could continue.
    It is still refused when the run store journals an artifact the evidence root does not
    hold (the wrong ``--evidence-root``), since resuming would send it all again.

    ``specs`` binds it to the battery the run was made with (see :func:`_assert_same_specs`);
    ``selection`` (:func:`selection_record`) and ``hardened`` are this invocation's selection
    flags and ``--hardened``, which a refusal names against the ones the run recorded (M1).

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
            hardened=hardened,
        )
        if specs is not None:
            from ildottore.store.run_sqlite import SqliteRunStore

            with SqliteRunStore(Path(run_db)) as store:
                _assert_same_plugins(run_id, store.get_run_context(run_id) or {}, specs)
            _assert_same_specs(
                run_db, run_id, specs, allow_unverified=allow_unverified, selection=selection
            )
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
    if not result.attempts and _requests_spent(run_db, run_id) <= 0:
        raise ValueError(
            f"no stored attempts for run {run_id!r} under {evidence_root}: nothing to resume. "
            "Check the run id and --evidence-root; a run whose run store records no request "
            "spent has nothing to continue."
        )
    if run_db is not None and Path(run_db).is_file():
        # Each artifact verifies against its own name, so an edited one renamed to its new
        # hash verified and was published by the resume as part of the finding (F12). The
        # run store's findings are the manifest; a refusal here is not waivable.
        from ildottore.store import SqliteRunStore, TamperError, check_manifest

        manifest_store = SqliteRunStore(Path(run_db))
        try:
            if not result.attempts:
                _assert_nothing_written(
                    run_id,
                    evidence_root,
                    manifest_store.recorded_evidence(run_id),
                    manifest_store.pending_artifacts(run_id),
                    manifest_store.get_run_context(run_id),
                )
            check_manifest(
                result,
                manifest_store.recorded_evidence(run_id),
                manifest_store.pending_artifacts(run_id),
                battery=manifest_store.recorded_battery(run_id),
            )
            row = manifest_store.get_run(run_id) or {}
        except TamperError as exc:
            raise ValueError(f"run {run_id!r} cannot be resumed: {exc}") from exc
        finally:
            manifest_store.close()
        # The start of the run being finished: a resume used to restamp it with its own start.
        started_at = _stored_start(row.get("started_at"))
    else:
        started_at = None

    # One reference per ARTIFACT, not per attempt id: a resume sends an errored attempt again
    # under its id (F11), so one id can have the failed try and its re-send on disk. Indexing by
    # id kept one artifact and cited it twice, and `replay` then refused the run as tampered.
    root = Path(evidence_root)
    by_spec: dict[str, list[Attempt]] = defaultdict(list)
    refs_by_spec: dict[str, list[EvidenceRef]] = defaultdict(list)
    for digest, attempt in zip(result.attempt_hashes, result.attempts, strict=True):
        by_spec[attempt.spec_id].append(attempt)
        refs_by_spec[attempt.spec_id].append(
            EvidenceRef(
                run_id=run_id,
                attempt_id=attempt.attempt_id,
                uri=paths.relative_uri(root, paths.attempt_path(root, run_id, digest)),
                sha256=digest,
            )
        )

    findings = [
        Finding(
            spec_id=spec_id,
            target_id=target.id,
            status=VerdictStatus.INCONCLUSIVE,
            risk=RESUME_PLACEHOLDER_RISK,
            confirmed=False,
            attempts=attempts,
            evidence=refs_by_spec[spec_id],
        )
        for spec_id, attempts in sorted(by_spec.items())
    ]
    run = TestRun(run_id=run_id, targets=[target], findings=findings, started_at=started_at)
    if adopt and run_db is not None:
        adopt_resumed(run_db, run)
    return run


def _stored_start(value: object) -> str | None:
    """The halted run's ``started_at``, as this tool writes it, or ``None`` when it has none.

    Anything else is a corrupt record, refused (CLI audit 2026-10-11, L6): ``not-a-date`` was
    published as the run's start in every report of the resume. The value is not quoted.
    """

    from ildottore.store.run_sqlite import CorruptRunContext

    if value is None or value == "":
        return None
    try:
        if not isinstance(value, str) or len(value) != len("2026-01-01T00:00:00Z"):
            raise ValueError
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise CorruptRunContext(
            "runs.started_at holds a value that is not a timestamp (YYYY-MM-DDTHH:MM:SSZ, UTC). "
            "An integrity record that cannot be read is not the same as one that was never "
            "written: refusing rather than continuing."
        ) from None
    return value


def adopt_resumed(run_db: Path, run: TestRun) -> None:
    """Journal every artifact of a resumed ``run`` as written, now that it passed the check.

    Artifacts written before the journal existed (a run started by an older version) were
    otherwise known to no record once this resume journaled new ones under the same spec, and
    the next resume refused the run as tampered (pre-commit audit of F11). A pending row whose
    file is present is confirmed the same way. ``dottore run`` calls this itself, past the last
    refusal before any traffic, so a resume refused before it sends writes nothing (u12 A-48).
    """

    from ildottore.store import SqliteRunStore

    if not Path(run_db).is_file():
        return
    # Every reference load_resume_run builds carries the digest its artifact is stored under.
    with SqliteRunStore(Path(run_db)) as store:
        store.adopt_artifacts(
            run.run_id,
            [
                (finding.spec_id, ref.sha256)
                for finding in run.findings
                for ref in finding.evidence
                if ref.sha256 is not None
            ],
        )


def _assert_same_target(
    run_db: Path, run_id: str, target: Target, *, allow_unverified: bool = False
) -> None:
    """Refuse a resume whose stored run belongs to a different target (or is unknown)."""

    from ildottore.store.run_sqlite import SqliteRunStore

    if not Path(run_db).exists():
        raise ValueError(
            f"cannot verify that run {run_id!r} belongs to target {quoted(target.id)}: no run "
            f"store at {run_db}. Point --run-db at the store the original run wrote, or the "
            "resume could splice another target's evidence into this target's report."
        )
    with SqliteRunStore(Path(run_db)) as store:
        row = store.get_run(run_id)
    if row is None:
        raise ValueError(
            f"run {run_id!r} is not in the run store at {run_db}, so the target it was made "
            "against cannot be verified. Resuming would attribute its evidence to "
            f"{quoted(target.id)} on trust."
        )
    stored = row.get("target_id")
    # Compare like with like. `save_run` writes `target_id` through the redactor, so a
    # tenant-shaped id (`tenant-<32 hex>`, an email) is stored masked and never equalled its
    # own raw value: every resume of such a target was refused with "was made against target
    # '«REDACTED:high_entropy:...»'", which is both false and unrecoverable by any flag. The
    # store masks it with a FIXED identity salt (``redact_identity``), so redacting this side
    # the same way restores the comparison; the general redactor's salt is random per process.
    if stored is not None and stored != target.id:
        from ildottore.redactor import redact_identity

        if stored == redact_identity(target.id):
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
            f"run {run_id!r} was made against target {quoted(stored)}, not {quoted(target.id)}. "
            "Resuming it here would report one target's evidence as another's, with zero "
            "requests sent. Resume it against its own target, or start a fresh run."
        )


def _requests_spent(run_db: Path | None, run_id: str) -> int:
    """The requests the run store records ``run_id`` as having spent (0 when unknown)."""

    from ildottore.store.run_sqlite import SqliteRunStore

    if run_db is None or not Path(run_db).is_file():
        return 0
    with SqliteRunStore(Path(run_db)) as store:
        spend = store.get_run_spend(run_id)
    try:
        return int((spend or {}).get("requests", 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _assert_nothing_written(
    run_id: str,
    evidence_root: Path,
    recorded: dict[str, set[str]],
    pending: set[str],
    context: dict[str, object] | None,
) -> None:
    """Refuse an empty evidence tree unless the run store shows the run wrote nothing.

    A run that spent requests and stored nothing is resumable; the same run looked up under
    the wrong ``--evidence-root`` looks identical from the tree alone, and resuming it would
    send the whole battery again under its id. The artifact journal tells the two apart, so
    any digest it holds refuses, a ``pending`` one too (a write begun and never confirmed, on
    another tree or failed on this one), each with a message that says which it is.
    The journal only knows runs made since it existed (2026-10-04): a run that does not record
    the scope it went out under (D-17, built after the journal) may predate it, and its silence
    proves nothing, so it is refused as well (pre-commit audit: a pre-journal run under the
    wrong root was accepted and would have been sent again whole).
    """

    journaled = {digest for digests in recorded.values() for digest in digests}
    written = journaled - set(pending)
    if written:
        raise ValueError(
            f"run {run_id!r} wrote {len(written)} attempt artifact(s), by its run store, and "
            f"none is under {evidence_root} (not the tree the run wrote). Point "
            "--evidence-root at that tree: resuming from an empty one would send every attempt "
            "again."
        )
    if journaled:
        # A pending row is a write that was begun and never confirmed: on another tree, or one
        # that failed here (a full disk). Nothing tells the two apart, so it is refused, saying
        # both: the first version called it "not the tree the run wrote" (delta audit).
        raise ValueError(
            f"run {run_id!r} began writing {len(journaled)} attempt artifact(s) that it never "
            f"confirmed, and none is under {evidence_root} (either another tree, or those "
            "writes failed here). Nothing tells the two apart: point --evidence-root at the "
            "tree the run wrote, or start a fresh run."
        )
    scopes = (context or {}).get("scope_sha256s")
    if not isinstance(scopes, list) or not scopes:
        raise ValueError(
            f"no stored attempts for run {run_id!r} under {evidence_root} (it spent requests), "
            "and the run predates the artifact journal, so an empty tree cannot be told from "
            "the wrong --evidence-root. Check --evidence-root, or start a fresh run."
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


def stored_adaptive(run_db: Path, run_id: str) -> bool | None:
    """Whether the halted campaign planned adaptively; ``None`` when it recorded no mode.

    A resume has to keep that mode (:func:`_assert_same_context`), so the advice of a refusal
    can only offer what keeps it.
    """

    from ildottore.store.run_sqlite import SqliteRunStore

    if not Path(run_db).exists():
        return None
    with SqliteRunStore(Path(run_db)) as store:
        context = store.get_run_context(run_id)
    value = (context or {}).get("adaptive")  # true or false: the store checked it (L6)
    return value if isinstance(value, bool) else None


def stored_sampling_defaults(run_db: Path, run_id: str) -> bool | None:
    """Whether the halted campaign sent its target files' ``sampling_defaults`` (OD-39).

    ``None`` when it recorded nothing: a run started before the block was applied
    (2026-10-09), which sent none of it. A resume continues as its run started, so the two
    halves are one campaign on the wire (u12 A-66). A value that is not a boolean is a corrupt
    record, refused as the other integrity fields are.
    """

    from ildottore.store.run_sqlite import SqliteRunStore

    if not Path(run_db).exists():
        return None
    with SqliteRunStore(Path(run_db)) as store:
        context = store.get_run_context(run_id)
    # True, false or null: a value of another shape is refused where the store reads it (L6).
    value = (context or {}).get("sampling_defaults_applied")
    return value if isinstance(value, bool) else None


def stored_takes_sampling(run_db: Path, run_id: str) -> tuple[bool | None, bool | None]:
    """Whether the halted campaign sent its target and its judge a temperature (u12 A-68).

    ``(target, judge)``, each ``None`` when the run recorded nothing: a run started before the
    record existed (every version before A-68 sent sampling to every live target and judge). A
    value that is not a boolean is a corrupt record, refused as the other integrity fields are.
    """

    from ildottore.store.run_sqlite import SqliteRunStore

    if not Path(run_db).exists():
        return None, None
    with SqliteRunStore(Path(run_db)) as store:
        context = store.get_run_context(run_id) or {}
    # Each true, false or null: another shape is refused where the store reads it (L6).
    target, judge = context.get("takes_sampling"), context.get("judge_takes_sampling")
    return (
        target if isinstance(target, bool) else None,
        judge if isinstance(judge, bool) else None,
    )


def declared_not_destructive(target: Target) -> list[str]:
    """What the run store records of the tools ``target``'s file declares not destructive.

    OD-43 (u06 A-72): the names, sorted, each masked with the fixed identity salt the store
    masks a target id with (:func:`~ildottore.redactor.redact_identity`), so a name that reads as
    a secret is not kept in clear and the record still compares equal across processes; an
    ordinary tool name is kept as written. Empty when the file declares none.
    """

    from ildottore.redactor import redact_identity

    seeded = target.seeded_setup
    if seeded is None:
        return []
    return [redact_identity(name) for name in seeded.not_destructive]


def _declaration_changed(context: dict[str, object], target: Target) -> str | None:
    """How the target file's declaration differs from the halted run's, or ``None``.

    A run stored before a file could declare one recorded nothing, which is no tool declared; a
    record that is not a list of names is refused where the store reads it (L6).
    """

    stored = context.get("not_destructive_tools", [])
    if not (isinstance(stored, list) and all(isinstance(name, str) for name in stored)):
        return None
    current = sorted(declared_not_destructive(target))
    if sorted(stored) == current:
        return None

    def listed(names: list[str]) -> str:
        return ", ".join(quoted(name) for name in names) if names else "no tool"

    return (
        f"it declared {listed(sorted(stored))} not destructive and now declares {listed(current)}"
    )


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


def selection_record(
    *,
    suite: str | None,
    quick: bool,
    categories: list[str],
    spec: list[str],
    exclude: list[str],
    top_tests: int | None,
) -> dict[str, object]:
    """The selection flags of an invocation, as the run context records them (M1).

    Each string masked with the fixed identity salt the store masks a target id with, so a glob
    that reads as a secret is not kept in clear and the record still compares equal across
    processes; a spec id or an ordinary glob is kept as written.
    """

    from ildottore.redactor import redact_identity

    return {
        "suite": redact_identity(suite) if suite is not None else None,
        "quick": quick,
        "categories": [redact_identity(token) for token in categories],
        "spec": [redact_identity(glob) for glob in spec],
        "exclude": [redact_identity(glob) for glob in exclude],
        "top_tests": top_tests,
    }


def selection_flags(selection: dict[str, object]) -> str:
    """The flags that make ``selection``, as an operator types them."""

    def strings(key: str) -> list[str]:
        value = selection.get(key)
        return [str(item) for item in value] if isinstance(value, list) else []

    parts = ["--quick"] if selection.get("quick") else []
    if isinstance(selection.get("suite"), str):
        parts.append(f"--suite {shlex.quote(str(selection['suite']))}")
    if strings("categories"):
        parts.append(f"-p {shlex.quote(','.join(strings('categories')))}")
    parts += [f"--spec {shlex.quote(glob)}" for glob in strings("spec")]
    parts += [f"--exclude {shlex.quote(glob)}" for glob in strings("exclude")]
    if isinstance(selection.get("top_tests"), int):
        parts.append(f"--top-tests {selection['top_tests']}")
    return " ".join(parts) or "no selection flag"


def _changed_fields(stored: object, specs: list[AttackSpec], changed: list[str]) -> str | None:
    """Where the ``changed`` specs differ, by field: ``attack`` or ``severity (3)`` (M1).

    ``None`` when the run recorded no field digests (a run started before they were kept).
    """

    if not isinstance(stored, dict):
        return None
    by_id = {spec.id: spec for spec in specs}
    fields: Counter[str] = Counter()
    for spec_id in changed:
        before = stored.get(spec_id)
        if not isinstance(before, dict):
            continue
        now = spec_field_digests(by_id[spec_id])
        fields.update(f for f in sorted(before.keys() | now.keys()) if before.get(f) != now.get(f))
    if not fields:
        return None
    ranked = sorted(fields.items(), key=lambda item: (-item[1], item[0]))
    if len(changed) == 1:
        return ", ".join(field for field, _ in ranked)
    return ", ".join(f"{field} ({count})" for field, count in ranked)


def _assert_same_specs(
    run_db: Path,
    run_id: str,
    specs: list[AttackSpec],
    *,
    allow_unverified: bool = False,
    selection: dict[str, object] | None = None,
) -> None:
    """Refuse a resume whose battery changed since the halt, naming what changed.

    The two halves of a resumed run are merged into one finding per spec and scored as one
    campaign. That is only meaningful while both halves ran the same spec: edit a prompt,
    tighten an evaluator or add a spec between the halt and the resume, and the report is a
    single document, under a single id, whose evidence comes from two different batteries,
    with nothing in it saying so. The digest is over a behavioural projection of the loaded
    model, so a corrected description or a reflowed line is not a change while anything that
    reaches the wire, the verdict or a published number is.

    The refusal says which field changed, which selection flags the run was made with and
    which flag restores the battery (CLI audit 2026-10-11, M1): "restore the specs as they
    were" was the advice for a spec edit, for a different ``--spec`` with no file changed, and
    for the OD-19 rename, in which ``evaluator_logic`` was the only field.
    """

    from ildottore.store.run_sqlite import SqliteRunStore

    with SqliteRunStore(Path(run_db)) as store:
        stored = store.get_run_spec_digests(run_id)
        context = store.get_run_context(run_id) or {}
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
        where = _changed_fields(context.get("spec_fields"), specs, changed)
        shown = f"{len(changed)} changed ({', '.join(changed[:5])})"
        parts.append(shown + (f", in {where}" if where else ""))
    if removed:
        parts.append(f"{len(removed)} no longer selected ({', '.join(removed[:5])})")
    if added:
        parts.append(f"{len(added)} new ({', '.join(added[:5])})")
    advice = []
    recorded = context.get("selection")
    if isinstance(recorded, dict) and selection is not None:
        # Compared on the keys this version writes: one a later version adds is not a difference.
        recorded = {key: recorded.get(key) for key in selection}
    if removed or added:
        if isinstance(recorded, dict) and selection is not None and recorded != selection:
            then, now = selection_flags(recorded), selection_flags(selection)
            advice.append(
                "The selection differs"
                + ("" if changed else " and no spec it ran changed")
                + f": the run was made with {then} and this invocation selects with {now}. "
                f"Resume with {then}"
            )
        elif isinstance(recorded, dict):
            holds = [f"holds {len(added)} spec(s) the run did not have"] if added else []
            holds += [f"lacks {len(removed)} spec(s) it had"] if removed else []
            advice.append(
                f"Under the same selection flags the spec path {' and '.join(holds)}: point "
                "--spec-path at the specs the run was made with"
            )
        else:
            advice.append(
                "Resume with the selection flags the run was made with (--suite, --quick, -p, "
                "--spec, --exclude, --top-tests) and its --spec-path"
            )
    if changed:
        advice.append(
            "Point --spec-path at the specs the run was made with (a copy of them, or the "
            "specs/ of the version that started it)"
        )
    raise ValueError(
        f"the battery changed since run {run_id!r} halted: {'; '.join(parts)}. Resuming "
        "would merge two different batteries into one report under one run id, and score "
        f"them as one campaign. {'. '.join(advice)}, or start a fresh run."
    )


def _route_shown(route: object) -> str:
    if route == "live":
        return "the live endpoint"
    return f"the offline {route!r} replay" if isinstance(route, str) else "another route"


def _refuse_other_target(
    run_id: str,
    context: dict[str, object],
    target: Target,
    *,
    mock_scenario: str | None,
    hardened: bool,
) -> None:
    """Refuse a resume whose target digest differs, naming the fields or the route (M1).

    The run records a short digest of each field of the target's digest payload and the route
    it resolved, so the refusal says which field changed, or that only the route did and which
    flag put it there: ``--resume --hardened`` read "Restore the target as it was" over a target
    file nobody had touched (CLI audit 2026-10-11, M1). A run that recorded neither gets the
    list of everything the digest covers, as before.
    """

    stored = context.get("target_fields")
    if not isinstance(stored, dict):
        raise ValueError(
            f"run {run_id!r} was made against a different target than the one resolved now "
            "(its endpoint, model, capabilities, sampling_defaults, offline scenario or "
            "seeded_setup differ, even though the id matches). Resuming would publish one "
            "target's evidence as another's. Restore the target as it was, or start a fresh run."
        )
    now = target_field_digests(target, mock_scenario=mock_scenario)
    differ = sorted(f for f in stored.keys() | now.keys() if stored.get(f) != now.get(f))
    fields = [f for f in differ if f != "__route__"]
    then_route, now_route = context.get("route"), mock_scenario or "live"
    if not fields:
        if hardened and now_route == "hardened":
            why, remedy = " (--hardened forces it)", "Resume without --hardened"
        elif then_route == "hardened":
            why = ""
            remedy = "Resume with --hardened (or the target file's mock_scenario as it was)"
        elif now_route == "live" or then_route == "live":
            why, remedy = "", "Restore the target file's mock_scenario as it was"
        else:
            why = " (the target file's mock_scenario)"
            remedy = f"Restore the target file's mock_scenario: {then_route}"
        raise ValueError(
            f"run {run_id!r} was made on {_route_shown(then_route)} and this invocation "
            f"resolves {_route_shown(now_route)}{why}. The target file is otherwise unchanged, "
            "so the answers would come from another route: resuming would publish one route's "
            f"evidence as the other's. {remedy}, or start a fresh run."
        )
    shown = ", ".join(fields[:-1]) + (" and " if len(fields) > 1 else "") + fields[-1]
    route = (
        f", and it was made on {_route_shown(then_route)} where this invocation resolves "
        f"{_route_shown(now_route)}"
        if "__route__" in differ
        else ""
    )
    one = len(fields) == 1
    raise ValueError(
        f"run {run_id!r} was made against a different target than the one resolved now: its "
        f"{shown} {'field' if one else 'fields'} changed{route}, even though the id matches. "
        "Resuming would publish one target's evidence as another's. Restore "
        f"{'that field' if one else 'those fields'} of the target file as "
        f"{'it was' if one else 'they were'}, or start a fresh run."
    )


def _assert_same_rules(run_id: str, context: dict[str, object]) -> None:
    """Refuse a resume whose halted half was judged by other rules than this version's (A-81).

    A resume keeps the attempts the halted half stored, with the verdicts it gave them, and judges
    only what it sends. Judging the kept ones again is not possible: the stored reply is the
    redacted one (a leaked canary reads ``«REDACTED:canary:…»``), so a rule that looks for the raw
    value would pass it, and the judge would have to be asked again. So under other rules the
    report would judge one kind of reply two ways and contradict itself (CLI audit 2026-10-11, H2:
    4 attempts kept as ``pass`` beside 2 judged cut, and "6 of 10 cut" where all 10 were). A run
    that records no rules was made by a version before the record, and is refused the same way.
    No flag waives it, as for the target: what it would publish is not a matter of trust.
    """

    from ildottore.store.run_sqlite import MAX_JUDGING_RULES, CorruptRunContext

    stored = context.get("judging_rules")
    if stored is not None and (
        isinstance(stored, bool)
        or not isinstance(stored, int)
        or not 1 <= stored <= MAX_JUDGING_RULES
    ):
        raise CorruptRunContext(
            "context_json holds a judging_rules value that is not a whole number from 1 to "
            "1000000. An integrity record that cannot be read is not the same as one that was "
            "never written: refusing rather than continuing."
        )
    if stored == JUDGING_RULES_VERSION:
        _assert_same_code(run_id, context)
        return
    # Each version written with a `v` in front: a bare `1.2.3.4` read as an IPv4 address and a
    # bare `2026.10.12` as a phone number to the redactor every error goes through (L-5).
    this = (
        f"this is Il Dottore {_shown_version(__version__)}, judging rules {JUDGING_RULES_VERSION}"
    )

    def why(which: str) -> str:
        return (
            "A resume keeps the attempts the halted half stored with the verdicts those rules "
            "gave them and judges only what it sends, so one report would judge the same kind of "
            "reply two ways; the stored replies are redacted, so they cannot be judged again. "
            f"There is no flag for this: finish it with the version that started it{which}, or "
            "start a fresh run."
        )

    if stored is None:
        # The date is kept away from the version number: "1 (2026-10-12" reads as a phone
        # number to the redactor every error goes through.
        raise ValueError(
            f"run {run_id!r} records no judging rules (the record exists since "
            f"{JUDGING_RULES_SINCE}), so it was made by an Il Dottore older than this one, whose "
            f"rules this version cannot vouch for ({this}). {why('')}"
        )
    started = context.get("tool_version")
    by = f", started by Il Dottore {_shown_version(started)}" if _is_version(started) else ""
    age = "an older" if stored < JUDGING_RULES_VERSION else "a newer"
    raise ValueError(
        f"run {run_id!r} was judged by the rules of {age} Il Dottore (judging rules {stored}{by}), "
        f"and {this}. {why(' (`dottore --version` names its judging rules)')}"
    )


class ResumeRefused(ValueError):
    """A resume refused with the digests it names, which the CLI's error masking keeps readable.

    A bare SHA-256 reads as a high-entropy secret to the redactor every error goes through: an
    exception that carries the digests it computed in ``digests`` has them kept (as a tampered
    artifact's are, ``store.replay.TamperError``).
    """

    def __init__(self, message: str, *, digests: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.digests = digests


def _changed_files(stored: object, current: dict[str, str]) -> str:
    """The covered files whose digest differs between the record and now, at most five named."""

    if not isinstance(stored, dict):
        return ""
    names = sorted(
        label for label in stored.keys() | current.keys() if stored.get(label) != current.get(label)
    )
    if not names:
        return ""
    shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
    return f"; the files that differ: {shown}"


def _assert_same_code(run_id: str, context: dict[str, object]) -> None:
    """Refuse a resume whose halted half was judged by other code under the same version (A-81).

    The version names the rules and is bumped by a person; the digest is computed from the
    installed package (deny by default, ``shared.judging_rules.judging_digest``), so a change no
    one bumped the version for is caught too: the second audit of the first design edited a default
    of the REST template, a subclass's override, the offline judge and a decorator, each under the
    same version and an unchanged pin, and the resume mixed verdicts. A run that records no digest
    (one a build before it made) is refused the same way, and so is one an interpreter of another
    implementation or ``major.minor`` judged (its ``re``, ``json`` and Unicode tables read a reply
    too). The refusal names the files that differ, from the per-file record. No flag waives it.
    """

    stored = context.get("judging_digest")
    current = judging_digest()
    this = (
        f"this is Il Dottore {_shown_version(__version__)}, judging rules {JUDGING_RULES_VERSION}"
    )
    advice = (
        "A resume keeps the attempts the halted half stored with the verdicts that code gave them "
        "and judges only what it sends, so one report would judge the same kind of reply two ways; "
        "the stored replies are redacted, so they cannot be judged again. There is no flag for "
        "this: finish it with the installation that started it, or start a fresh run."
    )
    if stored is None:
        raise ResumeRefused(
            f"run {run_id!r} records judging rules {JUDGING_RULES_VERSION} and no judging digest, "
            f"so the code that judged it cannot be told from this one ({this}). {advice}"
        )
    if stored != current:
        files = _changed_files(context.get("judging_files"), judging_files())
        raise ResumeRefused(
            f"run {run_id!r} was judged under the same judging rules ({JUDGING_RULES_VERSION}) by "
            f"other code: its judging digest is {stored} and this installation's is {current} (Il "
            f"Dottore's code changed since the halt: an upgrade, a reinstall or a local edit"
            f"{files}; {this}). {advice}",
            digests=(str(stored), current),
        )
    then, now = context.get("python"), python_build()
    if then != now:
        raise ResumeRefused(
            f"run {run_id!r} was judged under {then or 'an unrecorded interpreter'} and this "
            f"invocation runs under {now}. The standard library reads a reply too (its regular "
            "expressions, JSON and Unicode tables change between versions), so one report would "
            "judge the same kind of reply two ways. There is no flag for this: finish it with the "
            "interpreter that started it, or start a fresh run."
        )


def _is_version(value: object) -> bool:
    from ildottore.store.run_sqlite import VERSION_SHAPE

    return isinstance(value, str) and VERSION_SHAPE.fullmatch(value) is not None


def recorded_version() -> str:
    """This package's version as the run store records it: ``unknown`` when it has no PEP 440
    shape, which the store would refuse to read back (a build's odd local version, say)."""

    from ildottore.store.run_sqlite import UNKNOWN_VERSION

    return __version__ if _is_version(__version__) else UNKNOWN_VERSION


def _shown_version(version: object) -> str:
    """A package version as a refusal writes it: ``v`` and the version, which no rule masks."""

    return f"v{version}" if _is_version(version) else "of an unknown version"


def _plugin_source_digest(point: object) -> str:
    """SHA-256 of a plugin's installed Python sources, so a change under the same version shows."""

    import hashlib
    from importlib.util import find_spec

    dist = getattr(point, "dist", None)
    files: list[Path] = []
    if dist is not None and getattr(dist, "files", None):
        files = [Path(str(dist.locate_file(f))) for f in dist.files if str(f).endswith(".py")]
    if not files:
        module = str(getattr(point, "value", "")).partition(":")[0]
        spec = find_spec(module) if module else None
        if spec is not None and spec.origin and spec.origin.endswith(".py"):
            files = [Path(spec.origin)]
    digest = hashlib.sha256()
    for path in sorted(files, key=str):
        if path.is_file():
            digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest() if files else "unknown"


def evaluator_plugins(types: set[str]) -> list[str]:
    """The evaluator plugins that provide a type in ``types``, as a run records them (A-81).

    ``types`` are the evaluator types the selected specs name. Each plugin (a ``dottore.evaluators``
    entry point) whose evaluator is one of them is recorded as ``<name>=<object> (<distribution>
    <version>) sha256:<digest of its Python sources>``, sorted, masked with the store's fixed
    identity salt; a plugin no selected spec names decides nothing in the run and is left out (the
    second audit of the first design: a resume was refused over a plugin no spec used). Today none
    can match: a spec names a type of the schema's ``EvaluatorType`` and a plugin may not reuse a
    built-in type, so the record is empty until the schema admits plugin types.
    """

    from importlib.metadata import entry_points

    from ildottore.evaluators.registry import ENTRY_POINT_GROUP
    from ildottore.redactor import redact_identity

    found = []
    for point in entry_points(group=ENTRY_POINT_GROUP):
        try:
            kind = getattr(point.load(), "type", None)
        except Exception:  # its type cannot be read, so it may be one a spec names: recorded
            kind = None
        else:
            if not isinstance(kind, str) or kind not in types:
                continue
        dist = getattr(point, "dist", None)
        origin = f" ({dist.name} {dist.version})" if dist is not None else ""
        found.append(
            redact_identity(
                f"{point.name}={point.value}{origin} sha256:{_plugin_source_digest(point)}"
            )
        )
    return sorted(found)


def evaluator_types(specs: list[AttackSpec]) -> set[str]:
    """The evaluator types the ``specs`` name."""

    return {str(getattr(c.type, "value", c.type)) for spec in specs for c in spec.evaluators}


def _assert_same_plugins(run_id: str, context: dict[str, object], specs: list[AttackSpec]) -> None:
    """Refuse a resume under other evaluator plugins than the run was judged with (A-81)."""

    stored = context.get("evaluator_plugins", [])
    stored_list = [str(item) for item in stored] if isinstance(stored, list) else []
    current = evaluator_plugins(evaluator_types(specs))
    if sorted(stored_list) == current:
        return

    def listed(names: list[str]) -> str:
        return "; ".join(names) if names else "none"

    raise ValueError(
        f"run {run_id!r} was judged with the evaluator plugins {listed(sorted(stored_list))}, and "
        f"this invocation loads {listed(current)} for the evaluator types its specs name "
        "(dottore.evaluators entry points). A plugin's evaluator decides verdicts, so one report "
        "would judge the same kind of reply two ways. There is no flag for this: finish it with "
        "the plugins it was made with, or start a fresh run."
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
    hardened: bool = False,
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
        # As stored first: a run judged by other rules is refused for them before any other
        # field is checked, so a run a newer version made is not called corrupt over a field this
        # version does not know the shape of (pre-merge audit of 22269e0c, L-4).
        recorded = store.get_run_context(run_id, checked=False) or {}
        if recorded.get("judging_rules", JUDGING_RULES_VERSION) != JUDGING_RULES_VERSION:
            _assert_same_rules(run_id, recorded)
        context = store.get_run_context(run_id)
    stored_target = (context or {}).get("target_digest")
    current_target = target_digest(target, mock_scenario=mock_scenario)
    if stored_target is None:
        # NOT waivable, for the same reason the target id is not: this digest covers the
        # endpoint, the model, the capabilities and the resolved offline scenario, so without
        # it `--resume-unverified --hardened` flips the replay and publishes one half's
        # criticals as the other's. An audit walked straight through that with a run row whose
        # context column was absent, and through a context row that simply lacked this key.
        _unverifiable(run_id, "the target and the route", allow=allow_unverified, waivable=False)
        return
    # The rules before anything else of the invocation: under other rules nothing the operator
    # can restore makes the two halves one campaign (u12 A-81).
    _assert_same_rules(run_id, context or {})
    if stored_target != current_target:
        # The operator's declaration is named when it is what changed (OD-43): the digest alone
        # said "seeded_setup differ", and a reader could not tell a new grant from a tool the
        # file now says destroys nothing, which changes verdicts.
        changed = _declaration_changed(context or {}, target)
        if changed is not None:
            raise ValueError(
                f"run {run_id!r} was made under another operator declaration in its target "
                f"file's seeded_setup.granted_tools: {changed} (OD-43). It decides which "
                "destructive calls fail, so the two halves would be judged two ways in one "
                "report. Restore the declaration as it was, or start a fresh run."
            )
        _refuse_other_target(
            run_id, context or {}, target, mock_scenario=mock_scenario, hardened=hardened
        )
    context = context or {}
    stored_judge = context.get("judge_digest")
    current_judge = target_digest(judge) if judge is not None else None
    if stored_judge != current_judge:
        # Both there and different: the same flag names another file, or the same file was
        # edited; "stored a judge, now a judge" said neither (pre-merge audit of A-66).
        which = (
            "a different --judge file, whose endpoint, model, capabilities or sampling_defaults "
            "differ"
            if stored_judge and current_judge
            else f"{'a judge' if stored_judge else 'no judge'} stored, "
            f"{'a judge' if current_judge else 'none'} now"
        )
        raise ValueError(
            f"run {run_id!r} was judged by a different model than this invocation offers: "
            f"{which}. `semantic_judge` decides verdicts, so one campaign would be arbitrated by "
            "two different models and merged into one finding per spec. Resume with the same "
            "--judge, or start a fresh run."
        )
    stored_adaptive = context.get("adaptive")
    if adaptive is not None and stored_adaptive is not None and bool(stored_adaptive) != adaptive:
        # The flags that turn it on are named: the refusal named none, and it is the one an
        # operator meets first when a -sV resume of a campaign run without it is refused for
        # money too (u12 A-48).
        remedy = (
            "Resume with -sV, -A or --deep, whichever it ran with"
            if stored_adaptive
            else "Resume without -sV, -A or --deep"
        )
        raise ValueError(
            f"run {run_id!r} halted with adaptive planning "
            f"{'on' if stored_adaptive else 'off'} and this invocation asks for "
            f"{'on' if adaptive else 'off'}. A resume keeps the planning mode its campaign "
            "recorded, so the record holds one mode: the mode changes the order in which a "
            "spec's mutators go out, never which attempts are sent (OD-5). "
            f"{remedy}, or start a fresh run."
        )
    stored_runs = context.get("runs")
    if runs is not None and stored_runs is not None and int(stored_runs) != runs:
        raise ValueError(
            f"run {run_id!r} halted at --runs {stored_runs} and this invocation asks for "
            f"{runs}. One report would then score some specs over {stored_runs} samples and "
            "others over "
            f"{runs}, on the same reproducibility axis. Resume at --runs {stored_runs}."
        )
