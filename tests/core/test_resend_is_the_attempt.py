"""Which artifact of a re-sent attempt id is the attempt: one rule for the report and the replay.

A resume sends an attempt that ended in an environment error or whose reply could not be read
again under its id (F11, u08 A-74), so the evidence holds both. The runner and the replay each had
a copy of the rule, ranking (answered and judged, judged, answered) and keeping the FIRST artifact
at a tie; prior attempts arrive in file-name order, which is their content hash. An environment
error and an unreadable reply tie, so on ``de122e26``:

* an environment error re-sent by a resume that came back unreadable was dropped, and the report
  published a PASS while ``dottore replay`` counted the unreadable reply (audit of the scoring,
  2026-10-11, HIGH 1, ``cli_resume_unreadable.py`` through the CLI, here through the runner);
* the reverse kept the unreadable reply in the report while the replay, in hash order, kept the
  environment error and counted no unreadable reply (``repro_resume_reverse.py``).

Now one helper in ``shared.resend`` decides for both: the rank, then an outcome that never lets
its spec pass over an environment error or a block, whichever came first (rule 2), then the later
send by the ``send_number`` the runner stamps on every artifact, then the first.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ildottore.adapters import ProviderFilterBlock, ResponseMalformed
from ildottore.cli.resume import load_resume_run
from ildottore.core.execute import RetryPolicy
from ildottore.core.runner import (
    CampaignResult,
    CampaignRunner,
    answered_attempt_ids,
    resume_progress,
)
from ildottore.evaluators import build_default_registry as build_evaluators
from ildottore.mutators import build_default_registry as build_mutators
from ildottore.scoring import DefaultRiskScorer
from ildottore.shared.enums import InconclusiveReason, ScanBand, VerdictStatus
from ildottore.shared.models import (
    Attempt,
    Capabilities,
    Finding,
    ModelRequest,
    ModelResponse,
    PlanBudgets,
    RiskScore,
    TestRun,
    Verdict,
)
from ildottore.shared.unreadable import UNREADABLE_MARK, unreadable_attempt_ids
from ildottore.store import replay_run
from ildottore.store.evidence_fs import FsEvidenceStore
from ildottore.store.replay import ReplayResult
from ildottore.store.run_sqlite import SqliteRunStore
from tests.core.conftest import AllowAllPolicy, make_spec, make_target, no_sleep

RUN = "run-resend000001"
_SPEC = make_spec("JB-REFUSAL-001", mutations=["identity"])
_FIRST = f"{_SPEC.id}::identity#0"


class _Env(Exception):
    is_env_error = True


class Endpoint:
    """Attempt ``#0`` answers ``first`` on the first campaign and ``again`` on the resume.

    The other attempts refuse, which the ``refusal`` evaluator passes.
    """

    id = "t1"

    def __init__(self, first: str, again: str) -> None:
        self.outcome = {"first": first, "again": again}
        self.phase = "first"
        self.sends = 0

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        if (request.metadata or {}).get("mock_attempt") != 0:
            return ModelResponse(text="I cannot help with that.")
        outcome = self.outcome[self.phase]
        if outcome == "unreadable":
            raise ResponseMalformed(
                "t1: success response was not valid JSON: Expecting value: line 1 column 1 "
                "(char 0); not evaluated",
                excerpt="<html>portal</html>",
                size=19,
                advice="check the stub",
            )
        if outcome == "block":
            raise ProviderFilterBlock(
                "t1: non-retryable HTTP 400 from /v1/chat/completions: the provider's input "
                "filter refused the prompt before the model saw it (error code content_filter)",
                status_code=400,
                code="content_filter",
            )
        if outcome == "env":
            raise _Env("ConnectError: connection refused")
        return ModelResponse(text="I cannot help with that.")

    def capabilities(self) -> Capabilities:
        return Capabilities()


def _campaign(
    tmp_path: Path,
    endpoint: Endpoint,
    *,
    resume_from: TestRun | None = None,
    budgets: PlanBudgets | None = None,
) -> CampaignResult:
    runs = SqliteRunStore(tmp_path / "runs.sqlite")
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=build_mutators(discover=False),
        evaluators=build_evaluators(discover=False),
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev", journal=runs),
        run_store=runs,
        adapter_factory=lambda _t, _s: endpoint,  # type: ignore[arg-type,return-value]
        n=5,
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
                specs=[_SPEC],
                resume_from=resume_from,
                budgets=budgets,
            )
        )
    finally:
        runs.close()


def _first_then_resume(tmp_path: Path, first: str, again: str) -> tuple[Endpoint, CampaignResult]:
    endpoint = Endpoint(first, again)
    _campaign(tmp_path, endpoint)
    endpoint.phase = "again"
    prior = load_resume_run(tmp_path / "ev", RUN, make_target())
    return endpoint, _campaign(tmp_path, endpoint, resume_from=prior)


def _scored(result: CampaignResult) -> Attempt:
    (finding,) = result.findings
    return {a.attempt_id: a for a in finding.attempts}[_FIRST]


def test_an_unreadable_re_send_of_an_environment_error_is_the_attempt(tmp_path: Path) -> None:
    """The audit's HIGH 1: the resume's unreadable reply was dropped and the spec passed."""

    endpoint, resumed = _first_then_resume(tmp_path, "env", "unreadable")

    assert endpoint.sends == 6, "the environment error is sent again, once"
    (finding,) = resumed.findings
    assert finding.status is VerdictStatus.INCONCLUSIVE, finding.reasoning
    assert finding.reasoning.endswith(
        "; 1/5 could not be read as the provider's reply, which may be the one an attack changed"
    )
    scored = _scored(resumed)
    assert scored.verdict is not None
    assert scored.verdict.inconclusive_reason is InconclusiveReason.UNREADABLE_REPLY
    assert (scored.request.metadata or {})["send_number"] == 2
    replay = replay_run(tmp_path / "ev", RUN)
    assert len(replay.attempts) == 6 and replay.n == 5
    assert replay.unreadable_replies() == 1, "the replay and the report count the same attempt"


def test_an_environment_error_re_send_does_not_drop_an_unreadable_reply(tmp_path: Path) -> None:
    """The reverse (``repro_resume_reverse.py``): the replay dropped the unreadable reply.

    An environment error says nothing about the reply, and the one that could not be read may be
    the one an attack changed, so a resume that met a network failure keeps it (rule 2): the spec
    stays inconclusive, the replay agrees, and a later resume sends it again.
    """

    endpoint, resumed = _first_then_resume(tmp_path, "unreadable", "env")

    assert endpoint.sends == 6
    (finding,) = resumed.findings
    assert finding.status is VerdictStatus.INCONCLUSIVE, finding.reasoning
    scored = _scored(resumed)
    assert scored.verdict is not None
    assert scored.verdict.inconclusive_reason is InconclusiveReason.UNREADABLE_REPLY
    assert (scored.request.metadata or {})["send_number"] == 1
    replay = replay_run(tmp_path / "ev", RUN)
    assert replay.unreadable_replies() == 1, "on de122e26 the replay kept the error: 0"
    stored = {a.request.metadata["send_number"] for a in replay.attempts if a.attempt_id == _FIRST}  # type: ignore[index]
    assert stored == {1, 2}


def test_a_readable_re_send_replaces_an_unreadable_reply(tmp_path: Path) -> None:
    """A-74: the target may have been fixed since, so a reply the adapter reads is the attempt."""

    _, resumed = _first_then_resume(tmp_path, "unreadable", "answer")

    (finding,) = resumed.findings
    assert finding.status is VerdictStatus.PASS, finding.reasoning
    assert _scored(resumed).response is not None
    assert replay_run(tmp_path / "ev", RUN).unreadable_replies() == 0


def test_a_second_environment_error_is_the_attempt_in_place_of_the_first(tmp_path: Path) -> None:
    _, resumed = _first_then_resume(tmp_path, "env", "env")

    assert (_scored(resumed).request.metadata or {})["send_number"] == 2


def test_a_block_on_the_re_send_of_an_environment_error_is_the_attempt(tmp_path: Path) -> None:
    """Both carry a verdict and no reply; the later send is the attempt, in either file order."""

    _, resumed = _first_then_resume(tmp_path, "env", "block")

    (finding,) = resumed.findings
    assert "; 1/5 blocked by the provider's input filter before the model saw it" in (
        finding.reasoning
    )
    assert replay_run(tmp_path / "ev", RUN).blocked_by_provider_filter() == 1


def test_an_unreadable_reply_whose_re_send_was_blocked_is_sent_again(tmp_path: Path) -> None:
    """Unreadable, then the resume's re-send refused by the input filter: the unreadable copy is
    still the attempt (rule 2), so the id is not answered and the next resume sends it again.

    An id counted as answered when any of its copies was blocked, so on ``d07a1088`` the next
    resume kept all 5 and sent none, and the spec stayed inconclusive however healthy the target
    had become (``repro_unread_then_block.py``, pre-merge audit of ``d07a1088``, LOW 1).
    """

    endpoint, resumed = _first_then_resume(tmp_path, "unreadable", "block")

    (finding,) = resumed.findings
    assert finding.status is VerdictStatus.INCONCLUSIVE, finding.reasoning
    prior = load_resume_run(tmp_path / "ev", RUN, make_target())
    assert _FIRST not in answered_attempt_ids(prior)
    assert resume_progress(prior) == (4, 1), "d07a1088: (5, 0)"
    endpoint.outcome["again"] = "answer"
    before = endpoint.sends
    healthy = _campaign(tmp_path, endpoint, resume_from=prior)

    assert endpoint.sends - before == 1
    (finding,) = healthy.findings
    assert finding.status is VerdictStatus.PASS, finding.reasoning
    assert _scored(healthy).response is not None


# --- the tie, in both file orders, for artifacts with and without the stamp -----------------


def _verdict(reason: InconclusiveReason | None = None) -> Verdict:
    return Verdict(
        status=VerdictStatus.INCONCLUSIVE,
        confidence=0.0,
        reasoning="r",
        evaluator_type="aggregate",
        inconclusive_reason=reason,
    )


def _artifact(kind: str, number: int | None) -> Attempt:
    metadata = {"send_number": number} if number is not None else None
    error = {
        "env": "AdapterEnvError: HTTP 503",
        "unreadable": f"ResponseMalformed: not JSON; not evaluated{UNREADABLE_MARK}",
        "block": "ProviderFilterBlock: refused [blocked_by_provider_filter]",
    }[kind]
    reason = {
        "env": None,
        "unreadable": InconclusiveReason.UNREADABLE_REPLY,
        "block": InconclusiveReason.BLOCKED_BY_PROVIDER_FILTER,
    }[kind]
    return Attempt(
        attempt_id=_FIRST,
        spec_id=_SPEC.id,
        mutation="identity",
        request=ModelRequest(prompt="x", metadata=metadata),
        error=error,
        verdict=_verdict(reason),
    )


_RISK = RiskScore(
    impact=1, exploitability=1, reproducibility=0.0, risk=0.0, band=ScanBand.INFO, confidence=0.0
)


def _halted_report(tmp_path: Path, artifacts: list[Attempt]) -> Finding:
    """The finding a halted resume publishes from the stored attempts, scored by the runner."""

    others = [
        Attempt(
            attempt_id=f"{_SPEC.id}::identity#{index}",
            spec_id=_SPEC.id,
            mutation="identity",
            request=ModelRequest(prompt="x"),
            response=ModelResponse(text="I cannot help with that."),
            verdict=Verdict(
                status=VerdictStatus.PASS, confidence=1.0, reasoning="ok", evaluator_type="refusal"
            ),
        )
        for index in range(1, 5)
    ]
    prior = TestRun(
        run_id=RUN,
        findings=[
            Finding(
                spec_id=_SPEC.id,
                target_id="t1",
                status=VerdictStatus.INCONCLUSIVE,
                risk=_RISK,
                confirmed=False,
                attempts=[*artifacts, *others],
            )
        ],
    )
    # No request left: the resume sends nothing and publishes the prior finding as it scores it
    # (halted when the id is one it would send again, complete when a block keeps it).
    endpoint = Endpoint("env", "env")
    resumed = _campaign(tmp_path, endpoint, resume_from=prior, budgets=PlanBudgets(max_requests=0))
    assert endpoint.sends == 0
    assert resumed.status in {"budget_exhausted", "complete"}
    (finding,) = resumed.findings
    return finding


@pytest.mark.parametrize("reverse", [False, True], ids=["as-listed", "reversed"])
@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        # Stored before the stamp: which came later is unknown, and the unreadable reply wins.
        (("env", None), ("unreadable", None), "unreadable"),
        # Stamped: the unreadable reply wins over an environment error sent before or after it.
        (("env", 1), ("unreadable", 2), "unreadable"),
        (("unreadable", 1), ("env", 2), "unreadable"),
        # And over a block, which says nothing about the model's reply either.
        (("unreadable", 1), ("block", 2), "unreadable"),
        # Otherwise the later send: a block that followed an environment error.
        (("env", 1), ("block", 2), "block"),
        # A stamped artifact is later than one stored before the stamp existed.
        (("block", None), ("env", 1), "env"),
    ],
)
def test_the_tie_is_decided_alike_in_either_file_order(
    tmp_path: Path,
    reverse: bool,
    first: tuple[str, int | None],
    second: tuple[str, int | None],
    expected: str,
) -> None:
    artifacts = [_artifact(*first), _artifact(*second)]
    if reverse:
        artifacts.reverse()

    replay = ReplayResult(run_id=RUN, attempts=tuple(artifacts))
    (kept,) = replay.effective_attempts()
    assert _artifact(*(first if first[0] == expected else second)) == kept
    finding = _halted_report(tmp_path, artifacts)
    scored = {a.attempt_id: a for a in finding.attempts}[_FIRST]
    assert scored == kept, "the report scores the artifact the replay counts"
    unreadable = expected == "unreadable"
    assert (_FIRST in unreadable_attempt_ids(finding.attempts)) is unreadable
    assert (finding.status is VerdictStatus.INCONCLUSIVE) is unreadable, finding.reasoning
