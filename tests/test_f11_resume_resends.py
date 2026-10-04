"""F11: a resume sends again the attempts that ended in an environment error.

Withdrawn on 2026-10-04 because a resume interrupted mid-spec left artifacts no saved finding
cited, and the next resume refused the run as tampered. The run store now journals every
attempt artifact as it is written (schema v4), so these tests interrupt resumes on purpose.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from ildottore.cli.resume import load_resume_run
from ildottore.core.execute import RetryPolicy
from ildottore.core.planner import PlanBudgets
from ildottore.core.runner import CampaignResult, CampaignRunner, resume_progress
from ildottore.evaluators import build_default_registry as build_evaluators
from ildottore.mutators import build_default_registry as build_mutators
from ildottore.scoring import DefaultRiskScorer
from ildottore.shared.models import (
    AttackSpec,
    Capabilities,
    ModelRequest,
    ModelResponse,
    TestRun,
)
from ildottore.store import TamperError, check_manifest, replay_run
from ildottore.store.evidence_fs import FsEvidenceStore
from ildottore.store.run_sqlite import SqliteRunStore
from tests.core.conftest import AllowAllPolicy, make_spec, make_target, no_sleep

RUN = "run-f11f11f11f11"


class _EnvError(Exception):
    is_env_error = True


class Endpoint:
    """Down (every send is an environment error) or up (always answers)."""

    id = "t1"

    def __init__(self) -> None:
        self.up = False
        self.sends = 0

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        if not self.up:
            raise _EnvError("ConnectError: connection refused")
        return ModelResponse(text="I cannot help with that.")

    def capabilities(self) -> Capabilities:
        return Capabilities()


SPECS = [
    make_spec("JB-REFUSAL-001", mutations=["identity", "rot13"]),
    make_spec("JB-REFUSAL-002", mutations=["identity", "rot13"]),
]


def _run(
    tmp_path: Path,
    endpoint: Endpoint,
    *,
    resume_from: TestRun | None = None,
    budgets: PlanBudgets | None = None,
    specs: list[AttackSpec] | None = None,
    journal: bool = True,
) -> CampaignResult:
    specs = specs if specs is not None else SPECS
    from ildottore.cli.run import _persist_run_integrity

    # What the CLI records before a campaign sends: the target, battery and context a resume
    # is bound to.
    _persist_run_integrity(
        tmp_path / "runs.sqlite",
        RUN,
        specs,
        target=make_target(),
        mock_scenario=None,
        runs=2,
        judge=None,
        adaptive=False,
    )
    runs = SqliteRunStore(tmp_path / "runs.sqlite")
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=build_mutators(discover=False),
        evaluators=build_evaluators(discover=False),
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev", journal=runs if journal else None),
        run_store=runs,
        adapter_factory=lambda _t, _s: endpoint,  # type: ignore[arg-type,return-value]
        n=2,
        concurrency=1,
        retry=RetryPolicy(max_retries=0),
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    try:
        return asyncio.run(
            runner.run(
                run_id=RUN,
                target=make_target(),
                specs=specs,
                resume_from=resume_from,
                budgets=budgets,
            )
        )
    finally:
        runs.close()


def _resume_from(tmp_path: Path, specs: list[AttackSpec] | None = None) -> TestRun:
    return load_resume_run(
        tmp_path / "ev",
        RUN,
        make_target(),
        run_db=tmp_path / "runs.sqlite",
        specs=specs if specs is not None else SPECS,
        runs=2,
    )


def _check(tmp_path: Path) -> None:
    result = replay_run(tmp_path / "ev", RUN)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        check_manifest(
            result,
            store.recorded_evidence(RUN),
            store.pending_artifacts(RUN),
            battery=store.recorded_battery(RUN),
        )


def _artifacts(tmp_path: Path) -> list[Path]:
    return sorted((tmp_path / "ev" / RUN / "attempts").glob("*.json"))


def test_a_resume_resends_what_ended_in_an_environment_error(tmp_path: Path) -> None:
    endpoint = Endpoint()
    first = _run(tmp_path, endpoint)
    assert endpoint.sends == 8
    assert all(a.error for f in first.findings for a in f.attempts)

    endpoint.up = True
    endpoint.sends = 0
    resumed = _run(tmp_path, endpoint, resume_from=_resume_from(tmp_path))
    assert endpoint.sends == 8, "every errored attempt is sent again"
    for finding in resumed.findings:
        assert len(finding.attempts) == 4, "one attempt per id is scored"
        assert all(a.response is not None for a in finding.attempts)
        assert len(finding.evidence) == 8, "the failed tries stay cited as evidence"
    _check(tmp_path)
    replay = replay_run(tmp_path / "ev", RUN)
    assert replay.n == 8 and len(replay.attempts) == 16

    endpoint.sends = 0
    _run(tmp_path, endpoint, resume_from=_resume_from(tmp_path))
    assert endpoint.sends == 0, "a resume of a finished run sends nothing"
    _check(tmp_path)


def test_a_resume_interrupted_mid_spec_can_be_resumed_again(tmp_path: Path) -> None:
    """The case that withdrew F11: the resume's new artifacts were cited by no saved finding,
    and the next resume refused the run as tampered."""

    endpoint = Endpoint()
    _run(tmp_path, endpoint)
    endpoint.up = True
    endpoint.sends = 0
    halted = _run(
        tmp_path, endpoint, resume_from=_resume_from(tmp_path), budgets=PlanBudgets(max_requests=3)
    )
    assert halted.status == "budget_exhausted"
    assert len(_artifacts(tmp_path)) > 8, "the interrupted resume wrote new artifacts"
    _check(tmp_path)

    endpoint.sends = 0
    done = _run(tmp_path, endpoint, resume_from=_resume_from(tmp_path))
    assert done.status == "complete"
    assert sum(len(f.attempts) for f in done.findings) == 8
    assert all(a.response is not None for f in done.findings for a in f.attempts)
    _check(tmp_path)


def test_resume_progress_counts_what_will_be_sent_again(tmp_path: Path) -> None:
    endpoint = Endpoint()
    _run(tmp_path, endpoint)
    assert resume_progress(_resume_from(tmp_path)) == (0, 8)


def test_the_manifest_still_catches_an_added_artifact(tmp_path: Path) -> None:
    endpoint = Endpoint()
    endpoint.up = True
    _run(tmp_path, endpoint)
    source = _artifacts(tmp_path)[0]
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["attempt_id"] = "forged"
    from ildottore.store import paths

    text = json.dumps(payload)
    forged = source.parent / f"{paths.content_hash(text)}.json"
    forged.write_text(text, encoding="utf-8")
    with pytest.raises(TamperError, match="added or replaced"):
        _check(tmp_path)


def test_the_manifest_still_catches_a_removed_artifact(tmp_path: Path) -> None:
    endpoint = Endpoint()
    endpoint.up = True
    _run(tmp_path, endpoint)
    _artifacts(tmp_path)[0].unlink()
    with pytest.raises(TamperError, match="removed after the run"):
        _check(tmp_path)


def test_a_journaled_write_that_never_happened_is_not_a_deletion(tmp_path: Path) -> None:
    """A crash between the journal entry and the write leaves a pending digest."""

    endpoint = Endpoint()
    endpoint.up = True
    _run(tmp_path, endpoint)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store.record_artifact(RUN, "JB-REFUSAL-001", "f" * 64)
    _check(tmp_path)


# --- pre-commit audit of F11 ---------------------------------------------------------------


def test_a_resumed_pass_is_scored_as_a_pass(tmp_path: Path) -> None:
    """Verdicts are rebuilt from the attempts kept: left as prior plus fresh, a resumed pass
    read inconclusive."""

    from ildottore.shared.enums import VerdictStatus

    endpoint = Endpoint()
    _run(tmp_path, endpoint)
    endpoint.up = True
    resumed = _run(tmp_path, endpoint, resume_from=_resume_from(tmp_path))
    assert {f.status for f in resumed.findings} == {VerdictStatus.PASS}


def test_a_halted_resume_keeps_the_findings_the_run_already_had(tmp_path: Path) -> None:
    """A resume stopped by a ceiling while re-sending dropped those specs from the report."""

    endpoint = Endpoint()
    first = _run(tmp_path, endpoint)
    endpoint.up = True
    halted = _run(
        tmp_path, endpoint, resume_from=_resume_from(tmp_path), budgets=PlanBudgets(max_requests=1)
    )
    assert halted.status == "budget_exhausted"
    assert {f.spec_id for f in halted.findings} == {f.spec_id for f in first.findings}


def test_a_re_send_that_fails_identically_is_cited_once(tmp_path: Path) -> None:
    endpoint = Endpoint()
    _run(tmp_path, endpoint)
    resumed = _run(tmp_path, endpoint, resume_from=_resume_from(tmp_path))
    for finding in resumed.findings:
        digests = [ref.sha256 for ref in finding.evidence]
        assert len(digests) == len(set(digests))


def test_a_pending_row_for_a_cited_artifact_does_not_excuse_its_deletion(tmp_path: Path) -> None:
    """A crash between the write and the confirm left a pending row for a file a finding later
    cited; deleting the file then passed the check."""

    endpoint = Endpoint()
    endpoint.up = True
    _run(tmp_path, endpoint)
    victim = _artifacts(tmp_path)[0]
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute(
            "UPDATE artifacts SET state = 'pending' WHERE sha256 = ?", (victim.stem,)
        )
        store._conn.commit()
        assert victim.stem not in store.pending_artifacts(RUN)
    victim.unlink()
    with pytest.raises(TamperError, match="removed after the run"):
        _check(tmp_path)


THREE = [make_spec("JB-REFUSAL-003", mutations=["identity", "rot13", "base64_wrap"])]


def test_a_run_started_before_the_journal_keeps_resuming(tmp_path: Path) -> None:
    """A run halted mid-spec by an older version, resumed and halted again INSIDE the same spec
    by this one, was refused as tampered: its old artifacts were known to no record."""

    endpoint = Endpoint()
    endpoint.up = True
    _run(tmp_path, endpoint, specs=THREE, journal=False, budgets=PlanBudgets(max_requests=3))
    halted = _run(
        tmp_path,
        endpoint,
        specs=THREE,
        resume_from=_resume_from(tmp_path, THREE),
        budgets=PlanBudgets(max_requests=3),
    )
    assert halted.status == "budget_exhausted" and halted.findings == [], "halted mid-spec"
    _check(tmp_path)
    done = _run(tmp_path, endpoint, specs=THREE, resume_from=_resume_from(tmp_path, THREE))
    assert done.status == "complete"
    assert len(done.findings[0].attempts) == 6
    _check(tmp_path)


def test_an_adopted_artifact_is_written_so_its_deletion_is_refused(tmp_path: Path) -> None:
    endpoint = Endpoint()
    endpoint.up = True
    _run(tmp_path, endpoint, specs=THREE, journal=False, budgets=PlanBudgets(max_requests=3))
    _resume_from(tmp_path, THREE)  # adopts what is on disk
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        assert store.pending_artifacts(RUN) == set()
    _artifacts(tmp_path)[0].unlink()
    with pytest.raises(TamperError, match="removed after the run"):
        _check(tmp_path)


def test_a_halted_resume_does_not_publish_an_unfinished_spec(tmp_path: Path) -> None:
    """Only a prior holding every planned attempt is a finished spec: a halted resume published
    a PASS from 2 of 6 attempts and "0 specs did not finish"."""

    endpoint = Endpoint()
    endpoint.up = True
    _run(tmp_path, endpoint, specs=THREE, budgets=PlanBudgets(max_requests=3))
    halted = _run(
        tmp_path,
        endpoint,
        specs=THREE,
        resume_from=_resume_from(tmp_path, THREE),
        budgets=PlanBudgets(max_requests=1),
    )
    assert halted.status == "budget_exhausted"
    assert halted.findings == []
    assert "1 of 1 specs never ran or did not finish" in (halted.status_reason or "")


def test_a_halted_resume_reports_each_finished_prior_once(tmp_path: Path) -> None:
    endpoint = Endpoint()
    _run(tmp_path, endpoint)
    endpoint.up = True
    halted = _run(
        tmp_path, endpoint, resume_from=_resume_from(tmp_path), budgets=PlanBudgets(max_requests=1)
    )
    ids = [f.spec_id for f in halted.findings]
    assert sorted(ids) == sorted(s.id for s in SPECS)


def test_an_aborted_resume_keeps_the_findings_the_run_already_had(tmp_path: Path) -> None:
    class Broken(Endpoint):
        async def send(self, request: ModelRequest) -> ModelResponse:
            raise RuntimeError("a defect, not an outage")

    endpoint = Endpoint()
    first = _run(tmp_path, endpoint)
    aborted = _run(tmp_path, Broken(), resume_from=_resume_from(tmp_path))
    assert aborted.status == "aborted"
    assert sorted(f.spec_id for f in aborted.findings) == sorted(f.spec_id for f in first.findings)


def test_a_journaled_run_refuses_an_artifact_under_a_spec_it_never_ran(tmp_path: Path) -> None:
    endpoint = Endpoint()
    endpoint.up = True
    _run(tmp_path, endpoint)
    source = _artifacts(tmp_path)[0]
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["spec_id"] = "NEVER-RAN-001"
    from ildottore.store import paths

    text = json.dumps(payload)
    (source.parent / f"{paths.content_hash(text)}.json").write_text(text, encoding="utf-8")
    with pytest.raises(TamperError, match="added or replaced"):
        _check(tmp_path)


# --- the journal's write order (unit) -------------------------------------------------------


class _Journal:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def record_artifact(self, run_id: str, spec_id: str, sha256: str) -> None:
        self.calls.append(("record", sha256))

    def confirm_artifact(self, run_id: str, sha256: str) -> None:
        self.calls.append(("confirm", sha256))


def _attempt() -> object:
    from ildottore.shared.models import Attempt

    return Attempt(
        attempt_id="a1",
        spec_id="S-1",
        request=ModelRequest(prompt="hi"),
        response=ModelResponse(text="ok"),
    )


def test_the_journal_is_written_before_and_confirmed_after_every_put(tmp_path: Path) -> None:
    journal = _Journal()
    store = FsEvidenceStore(tmp_path / "ev", journal=journal)
    ref = store.put(RUN, _attempt())  # type: ignore[arg-type]
    store.put(RUN, _attempt())  # type: ignore[arg-type]  # the file exists: confirmed again
    assert journal.calls == [("record", ref.sha256), ("confirm", ref.sha256)] * 2


def test_a_failed_write_is_never_confirmed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    journal = _Journal()
    store = FsEvidenceStore(tmp_path / "ev", journal=journal)

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(store, "_atomic_write", boom)
    with pytest.raises(OSError, match="disk full"):
        store.put(RUN, _attempt())  # type: ignore[arg-type]
    assert [call for call, _ in journal.calls] == ["record"]


def test_probes_are_not_journaled(tmp_path: Path) -> None:
    journal = _Journal()
    FsEvidenceStore(tmp_path / "ev", journal=journal).put_probe(RUN, _attempt())  # type: ignore[arg-type]
    assert journal.calls == []


# --- the not-retryable mark ---------------------------------------------------------------


def test_an_error_that_would_repeat_is_marked_and_kept_by_a_resume() -> None:
    """A reply over the size cap comes back the same: re-sending it on every resume spent a
    request for the same refusal."""

    from ildottore.adapters.base import ResponseTooLarge
    from ildottore.core.budgets import BudgetLedger
    from ildottore.core.execute import NOT_RETRYABLE_MARK, execute_attempt
    from ildottore.core.runner import answered_attempt_ids
    from ildottore.shared.enums import ScanBand, VerdictStatus
    from ildottore.shared.models import Finding, RiskScore

    class Huge(Endpoint):
        async def send(self, request: ModelRequest) -> ModelResponse:
            raise ResponseTooLarge("t1: response exceeded 4194304 bytes; not read further")

    result = asyncio.run(
        execute_attempt(
            Huge(),
            ModelRequest(prompt="hi"),
            attempt_id="a1",
            spec_id="S",
            mutation="identity",
            sampling=None,
            ledger=BudgetLedger(),
            sleep=no_sleep,
            now=lambda: 0.0,
        )
    )
    assert (result.attempt.error or "").endswith(NOT_RETRYABLE_MARK)
    finding = Finding(
        spec_id="S",
        target_id="t1",
        status=VerdictStatus.INCONCLUSIVE,
        risk=RiskScore(
            impact=1, exploitability=1, reproducibility=0.0, risk=0.0, band=ScanBand.INFO,
            confidence=0.0,
        ),
        confirmed=False,
        attempts=[result.attempt],
    )  # fmt: skip
    assert answered_attempt_ids(TestRun(run_id="r", findings=[finding])) == {"a1"}


# --- third audit of F11: the guards its mutants showed untested ----------------------------


def test_a_halted_resume_does_not_repeat_a_spec_that_finished(tmp_path: Path) -> None:
    class FirstFour(Endpoint):
        async def send(self, request: ModelRequest) -> ModelResponse:
            self.sends += 1
            if self.sends > 4 and not self.up:
                raise _EnvError("ConnectError: connection refused")
            return ModelResponse(text="I cannot help with that.")

    endpoint = FirstFour()
    _run(tmp_path, endpoint)  # JB-REFUSAL-001 answered, JB-REFUSAL-002 errored
    endpoint.up = True
    halted = _run(
        tmp_path, endpoint, resume_from=_resume_from(tmp_path), budgets=PlanBudgets(max_requests=1)
    )
    assert halted.status == "budget_exhausted"
    ids = [f.spec_id for f in halted.findings]
    assert ids.count("JB-REFUSAL-001") == 1 and sorted(set(ids)) == sorted(s.id for s in SPECS)
    assert len(ids) == len(set(ids))


def test_adoption_confirms_a_pending_row_whose_file_is_present(tmp_path: Path) -> None:
    endpoint = Endpoint()
    endpoint.up = True
    _run(tmp_path, endpoint, specs=THREE, budgets=PlanBudgets(max_requests=3))
    victim = _artifacts(tmp_path)[0]
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        conn.execute("UPDATE artifacts SET state = 'pending' WHERE sha256 = ?", (victim.stem,))
        conn.commit()
    finally:
        conn.close()
    _resume_from(tmp_path, THREE)  # adopts what is on disk
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        assert store.pending_artifacts(RUN) == set()


def test_the_estimate_counts_every_turn_of_an_answered_conversation() -> None:
    from ildottore.cli.run import _answered_requests
    from ildottore.shared.enums import ScanBand, VerdictStatus
    from ildottore.shared.models import Attempt, Finding, RiskScore

    spec = make_spec("JB-MULTI-001")
    spec = spec.model_copy(
        update={"attack": spec.attack.model_copy(update={"turns": ["a", "b", "c"]})}
    )
    attempt = Attempt(
        attempt_id="JB-MULTI-001::identity#0",
        spec_id="JB-MULTI-001",
        request=ModelRequest(prompt="c"),
        response=ModelResponse(text="no"),
    )
    finding = Finding(
        spec_id="JB-MULTI-001",
        target_id="t1",
        status=VerdictStatus.INCONCLUSIVE,
        risk=RiskScore(
            impact=1, exploitability=1, reproducibility=0.0, risk=0.0, band=ScanBand.INFO,
            confidence=0.0,
        ),
        confirmed=False,
        attempts=[attempt],
    )  # fmt: skip
    assert _answered_requests(TestRun(run_id="r", findings=[finding]), [spec]) == 3


def test_adoption_is_all_or_nothing(tmp_path: Path) -> None:
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store._conn.execute(
            "CREATE TRIGGER boom BEFORE INSERT ON artifacts WHEN NEW.sha256 = '"
            + "b" * 64
            + "' BEGIN SELECT RAISE(ABORT, 'interrupted'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="interrupted"):
            store.adopt_artifacts(RUN, [("S-1", "a" * 64), ("S-1", "b" * 64)])
        count = store._conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        assert count == 0


def test_a_run_with_no_recorded_battery_is_checked_as_before(tmp_path: Path) -> None:
    endpoint = Endpoint()
    endpoint.up = True
    _run(tmp_path, endpoint, specs=THREE, journal=False, budgets=PlanBudgets(max_requests=3))
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        conn.execute("UPDATE runs SET spec_digests_json = NULL")  # a store from before the column
        conn.commit()
    finally:
        conn.close()
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        assert store.recorded_battery(RUN) is None
    _check(tmp_path)  # a spec with no finding and no journal row: the known limit, let through
