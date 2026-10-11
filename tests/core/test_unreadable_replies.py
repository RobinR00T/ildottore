"""A reply the adapters cannot read fails its attempt; a target none of whose first replies can be
read stops the campaign (OD-21, u08 A-74).

Decided 2026-10-11 under the owner's delegation (best practice), revisable. Before, a 200 that
was not JSON (or not the provider's shape) was a product error and stopped the campaign at the
first one. Now it is a ``ResponseMalformed``: the attempt is inconclusive, not retried, debited,
its tokens released, kept by a resume, and the campaign goes on. A wrong endpoint, provider or
template answers every request that way, so the runner stops a campaign whose first
:data:`~ildottore.core.execute.UNREADABLE_REPLIES_TO_STOP` replies could all not be read, with
none that could, instead of sending the whole battery to be scored inconclusive; one readable
reply (or a provider's filter block, which is the provider answering in its own documented shape)
proves the endpoint, and from then on an unreadable reply fails only its attempt.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

from ildottore.adapters import AdapterEnvError, ProviderFilterBlock, ResponseMalformed
from ildottore.core.execute import (
    UNREADABLE_REPLIES_TO_STOP,
    UNREADABLE_STREAK_TO_STOP,
    RetryPolicy,
)
from ildottore.core.runner import CampaignResult, CampaignRunner, resume_progress
from ildottore.evaluators import build_default_registry as build_evaluators
from ildottore.mutators import build_default_registry as build_mutators
from ildottore.scoring import DefaultRiskScorer
from ildottore.shared.enums import InconclusiveReason, VerdictStatus
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse, TestRun
from ildottore.shared.unreadable import (
    UNREADABLE_MARK,
    UNREADABLE_REPLY_KEY,
    unreadable_attempt_ids,
)
from ildottore.store.evidence_fs import FsEvidenceStore
from ildottore.store.run_sqlite import SqliteRunStore
from tests.core.conftest import HARDENED_RESPONSE, AllowAllPolicy, make_spec, make_target, no_sleep

_BAD, _BLOCK, _DOWN = "<html>", "block", "down"


class Scripted:
    """Answers each send with the next outcome of a script, then ``default`` for the rest."""

    id = "t1"

    def __init__(self, script: list[str], default: str = _BAD) -> None:
        self._script: Iterator[str] = iter(script)
        self._default = default
        self.sends = 0

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        await asyncio.sleep(0)  # let concurrent specs interleave
        outcome = next(self._script, self._default)
        if outcome == _BAD:
            raise ResponseMalformed(
                "t1: success response was not valid JSON: Expecting value: line 1 column 1 "
                "(char 0); not evaluated",
                excerpt="<html>portal</html>",
                size=19,
                advice="check the stub",
            )
        if outcome == _BLOCK:
            raise ProviderFilterBlock(
                "t1: non-retryable HTTP 400 from /v1/chat/completions: the provider's input "
                "filter refused the prompt before the model saw it (error code content_filter)",
                status_code=400,
                code="content_filter",
            )
        if outcome == _DOWN:
            raise AdapterEnvError("t1: exhausted 1 attempt(s) to /v1/chat/completions: HTTP 503")
        return ModelResponse(text=outcome)

    def capabilities(self) -> Capabilities:
        return Capabilities()


def _run(
    adapter: Scripted,
    tmp_path: Path,
    *,
    specs: int = 1,
    n: int = 5,
    concurrency: int = 1,
    resume_from: TestRun | None = None,
) -> CampaignResult:
    runs = SqliteRunStore(tmp_path / "runs.sqlite")
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=build_mutators(discover=False),
        evaluators=build_evaluators(discover=False),
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev"),
        run_store=runs,
        adapter_factory=lambda _t, _s: adapter,  # type: ignore[arg-type,return-value]
        n=n,
        concurrency=concurrency,
        retry=RetryPolicy(max_retries=3),
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    try:
        return asyncio.run(
            runner.run(
                run_id="run-0d21od21od21",
                target=make_target(),
                specs=[make_spec(f"JB-REFUSAL-{i:03d}") for i in range(1, specs + 1)],
                resume_from=resume_from,
            )
        )
    finally:
        runs.close()


def _attempts(result: CampaignResult) -> list[object]:
    return [a for f in result.findings for a in f.attempts]


def test_the_stop_figures_are_five_before_a_reply_is_read_and_twenty_in_a_row_after() -> None:
    assert (UNREADABLE_REPLIES_TO_STOP, UNREADABLE_STREAK_TO_STOP) == (5, 20)


def test_a_target_that_breaks_after_readable_replies_stops_after_twenty_in_a_row(
    tmp_path: Path,
) -> None:
    """Pre-merge audit of 598f0858, MEDIUM 2: two readable replies and then a login page for
    everything (a token that expired behind an SSO proxy) sent 355 requests, 353 unreadable, and
    exited 0. The watch counts unreadable replies in a row, reset by each one it reads: 20 in a
    row after the endpoint was proven stop the campaign too, with a reason of their own."""

    adapter = Scripted([HARDENED_RESPONSE, HARDENED_RESPONSE])  # then every reply unreadable
    result = _run(adapter, tmp_path, specs=6, n=5)

    assert result.status == "aborted"
    assert adapter.sends == 2 + UNREADABLE_STREAK_TO_STOP
    reason = result.status_reason or ""
    assert reason.startswith(
        "aborted on UnreadableReplies: the target's last 20 replies in this run could not be "
        "read as replies, in a row after ones that could"
    ), reason
    assert "expired session" in reason and "check the stub" in reason


def test_a_readable_reply_resets_the_run_of_unreadable_ones(tmp_path: Path) -> None:
    """Nineteen in a row, a readable reply, nineteen more: never twenty in a row."""

    streak = [_BAD] * (UNREADABLE_STREAK_TO_STOP - 1)
    script = [HARDENED_RESPONSE, *streak, HARDENED_RESPONSE, *streak]
    adapter = Scripted(script, default=HARDENED_RESPONSE)
    result = _run(adapter, tmp_path, specs=8, n=5)

    assert result.status == "complete", result.status_reason
    assert adapter.sends == 40


def test_one_unreadable_reply_fails_its_attempt_and_the_campaign_goes_on(tmp_path: Path) -> None:
    adapter = Scripted([_BAD], default=HARDENED_RESPONSE)
    result = _run(adapter, tmp_path, specs=2, n=3)

    assert result.status == "complete", result.status_reason
    attempts = [a for f in result.findings for a in f.attempts]
    assert len(attempts) == 6 and adapter.sends == 6  # sent once, not retried
    failed = [a for a in attempts if a.error]
    assert len(failed) == 1
    assert failed[0].error.startswith("ResponseMalformed: t1: success response was not valid")
    assert failed[0].error.endswith(UNREADABLE_MARK)
    assert failed[0].response is None
    verdict = failed[0].verdict
    assert verdict is not None
    assert verdict.status is VerdictStatus.INCONCLUSIVE
    assert verdict.inconclusive_reason is InconclusiveReason.UNREADABLE_REPLY
    # The reply is kept for review, bounded and redacted by the adapter, beside its size.
    kept = (failed[0].request.metadata or {})[UNREADABLE_REPLY_KEY]
    assert kept == {"excerpt": "<html>portal</html>", "bytes": 19, "advice": "check the stub"}
    assert result.spend.requests == 6


def test_an_unreadable_reply_never_lets_its_spec_pass(tmp_path: Path) -> None:
    """Pre-merge audit of 598f0858, HIGH 1: a wrapper whose JSON a quote in the model's output
    broke is the attempt where the jailbreak worked, and two refusals outvoted it (a strict
    majority passed the spec, exit 0). One unreadable reply keeps the spec from passing, as a
    reply the provider's filter cut does (OD-42); the other spec, read in full, still passes."""

    adapter = Scripted([_BAD], default=HARDENED_RESPONSE)
    result = _run(adapter, tmp_path, specs=2, n=3)

    statuses = {f.spec_id: f.status for f in result.findings}
    assert statuses == {
        "JB-REFUSAL-001": VerdictStatus.INCONCLUSIVE,
        "JB-REFUSAL-002": VerdictStatus.PASS,
    }
    first = next(f for f in result.findings if f.spec_id == "JB-REFUSAL-001")
    assert "1/3 could not be read as the provider's reply" in first.reasoning
    assert unreadable_attempt_ids(first.attempts) == {"JB-REFUSAL-001::identity#0"}


def test_a_target_whose_first_replies_are_all_unreadable_stops_the_campaign(
    tmp_path: Path,
) -> None:
    adapter = Scripted([])  # every reply unreadable
    result = _run(adapter, tmp_path, specs=4, n=5)

    assert result.status == "aborted"
    assert adapter.sends == UNREADABLE_REPLIES_TO_STOP
    reason = result.status_reason or ""
    assert reason.startswith("aborted on UnreadableReplies: the target's first 5 replies")
    assert "ResponseMalformed: t1: success response was not valid JSON" in reason
    assert "and none could: check the stub." in reason  # the adapter's own advice
    assert "a resume sends them again" in reason
    assert reason.endswith("; 4 of 4 specs never ran or did not finish")
    # The halted spec has no finding; every reply it was sent is in the evidence as an
    # inconclusive attempt, the fifth (which carried the stop) included (pre-merge audit of
    # 598f0858, MEDIUM 1: it went with the halt, and its token reservation stayed spent).
    assert result.findings == []
    stored = sorted((tmp_path / "ev").rglob("*.json"))
    assert len(stored) == UNREADABLE_REPLIES_TO_STOP
    assert all(b"ResponseMalformed" in path.read_bytes() for path in stored)
    assert result.spend.requests == UNREADABLE_REPLIES_TO_STOP
    assert result.spend.tokens == 0  # no reply was read: every reservation released


def test_one_readable_reply_first_proves_the_endpoint(tmp_path: Path) -> None:
    adapter = Scripted([HARDENED_RESPONSE])  # then every reply unreadable
    result = _run(adapter, tmp_path, specs=2, n=5)

    assert result.status == "complete", result.status_reason
    assert adapter.sends == 10
    attempts = _attempts(result)
    assert sum(1 for a in attempts if a.error) == 9
    assert {f.status for f in result.findings} == {VerdictStatus.INCONCLUSIVE}


def test_a_readable_reply_among_the_first_disarms_the_stop(tmp_path: Path) -> None:
    script = [_BAD] * (UNREADABLE_REPLIES_TO_STOP - 1) + [HARDENED_RESPONSE]
    result = _run(Scripted(script), tmp_path, specs=2, n=6)
    assert result.status == "complete", result.status_reason


def test_a_provider_filter_block_is_the_provider_answering(tmp_path: Path) -> None:
    """Azure's 400 ``content_filter`` is a documented reply: the endpoint is the provider's."""

    result = _run(Scripted([_BLOCK]), tmp_path, specs=2, n=5)
    assert result.status == "complete", result.status_reason


def test_a_transport_failure_neither_counts_nor_disarms(tmp_path: Path) -> None:
    script = [_DOWN, _BAD, _DOWN, _BAD, _BAD, _BAD]
    adapter = Scripted(script)
    result = _run(adapter, tmp_path, specs=2, n=5)
    assert result.status == "aborted"
    # Each 503 is retried (RetryPolicy(max_retries=3)) and the fifth unreadable reply stops it.
    assert "first 5 replies" in (result.status_reason or "")


def test_concurrent_specs_stop_at_their_next_unreadable_reply(tmp_path: Path) -> None:
    """The stop is campaign-wide: a spec already sending stops at its own next unreadable
    reply instead of finishing its batch, so the campaign sends at most the figure plus one
    reply per other spec in flight."""

    adapter = Scripted([])
    result = _run(adapter, tmp_path, specs=6, n=5, concurrency=4)
    assert result.status == "aborted"
    assert UNREADABLE_REPLIES_TO_STOP <= adapter.sends <= UNREADABLE_REPLIES_TO_STOP + 3
    # Every reply sent is stored, the ones that stopped the specs in flight included.
    assert len(sorted((tmp_path / "ev").rglob("*.json"))) == adapter.sends
    assert result.spend.tokens == 0


def test_a_resume_sends_an_unreadable_attempt_again(tmp_path: Path) -> None:
    """Pre-merge audit of 598f0858, LOW 1: the target may have been fixed since (an endpoint
    behind a proxy that was down), and a resume cannot tell a broken endpoint from a garbled
    reply, so an unreadable attempt is not kept: within a run it is not retried, and a resume
    sends it once more, its re-send scored in its place."""

    first = _run(Scripted([HARDENED_RESPONSE, _BAD, HARDENED_RESPONSE]), tmp_path, n=3)
    assert first.status == "complete"
    assert resume_progress(first.run) == (2, 1)  # two kept, the unreadable one sent again

    again = Scripted([], default=HARDENED_RESPONSE)
    (tmp_path / "again").mkdir()
    second = _run(again, tmp_path / "again", n=3, resume_from=first.run)
    assert again.sends == 1
    assert second.status == "complete"
    (finding,) = second.findings
    assert finding.status is VerdictStatus.PASS
    assert unreadable_attempt_ids(finding.attempts) == set()
