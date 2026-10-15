"""A refused evidence write withholds the reply's pieces, and only then (u08 half of A-77).

Pre-merge audit of ``c4bd2012``, HIGH 1: the evidence store's refusal ended the campaign. The
runner answers a refusal the store marks (``evidence_refused``) by storing the attempt again with
the pieces of its reply withheld; any other error, a refusal of an attempt with no reply, or one
with no piece to withhold, is raised as before.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from ildottore.core.runner import EVIDENCE_WITHHELD, CampaignRunner
from ildottore.shared.models import Attempt, EvidenceRef, ModelRequest, ModelResponse, TokenLogprob


class _Refused(RuntimeError):
    evidence_refused = True


class _Store:
    """Refuses every attempt whose reply still holds a non-empty logprob token."""

    def __init__(self, error: type[Exception] = _Refused) -> None:
        self.error = error
        self.stored: list[Attempt] = []

    def put(self, run_id: str, attempt: Attempt) -> EvidenceRef:
        logprobs = attempt.response.logprobs if attempt.response is not None else None
        if attempt.response is None or not logprobs or any(lp.token for lp in logprobs):
            raise self.error("refused for the test")
        self.stored.append(attempt)
        return EvidenceRef(run_id=run_id, attempt_id=attempt.attempt_id, uri="u", sha256=None)


def _attempt(*, logprobs: bool = True, response: bool = True) -> Attempt:
    tokens = [TokenLogprob(token=t, logprob=-0.2, top=[(t, -0.2)]) for t in ("sk-", "pro", "j")]
    reply = ModelResponse(text="the reply «REDACTED:x»", logprobs=tokens if logprobs else None)
    return Attempt(
        attempt_id="a-1",
        spec_id="PI-DEMO-001",
        request=ModelRequest(prompt="p", metadata={"turn_index": 0}),
        response=reply if response else None,
    )


def _stored(store: _Store, attempt: Attempt) -> tuple[EvidenceRef, Attempt]:
    runner = cast("CampaignRunner", SimpleNamespace(_evidence=store))
    return CampaignRunner._stored(runner, "run-1", attempt)


def test_a_refused_write_is_stored_again_with_the_pieces_withheld() -> None:
    store = _Store()
    ref, kept = _stored(store, _attempt())
    assert store.stored == [kept] and ref.attempt_id == "a-1"
    assert kept.response is not None and kept.response.logprobs is not None
    assert [(lp.token, lp.logprob, lp.top) for lp in kept.response.logprobs] == [
        ("", -0.2, [("", -0.2)])
    ] * 3
    assert kept.response.text == "the reply «REDACTED:x»"
    assert kept.request.metadata is not None and kept.request.metadata["turn_index"] == 0
    assert "refused for the test" in str(kept.request.metadata[EVIDENCE_WITHHELD])


@pytest.mark.parametrize(
    ("store", "attempt"),
    [
        (_Store(ValueError), _attempt()),  # not the store's refusal
        (_Store(), _attempt(response=False)),  # no reply to withhold from
        (_Store(), _attempt(logprobs=False)),  # a reply with no piece to withhold
    ],
)
def test_any_other_refusal_is_raised_as_before(store: _Store, attempt: Attempt) -> None:
    with pytest.raises((ValueError, _Refused), match="refused for the test"):
        _stored(store, attempt)
    assert store.stored == []


def test_the_watch_s_benign_check_is_stored_withheld_too() -> None:
    """A refused probe write raised and ended the campaign (second pre-merge audit, LOW 4)."""

    class _ProbeStore(_Store):
        def put_probe(self, run_id: str, attempt: Attempt) -> EvidenceRef:
            return self.put(run_id, attempt)

    store = _ProbeStore()
    runner = cast("CampaignRunner", SimpleNamespace(_evidence=store))
    CampaignRunner._record_probe(runner, "run-1", _attempt())
    assert len(store.stored) == 1
    assert store.stored[0].request.metadata is not None
    assert EVIDENCE_WITHHELD in store.stored[0].request.metadata
