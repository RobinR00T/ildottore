"""The guardrail layer's moderation latency is read only when it is a figure (2026-10-07).

A 400-digit integer made ``float()`` raise and ``-sV`` exit 1; an infinity, a NaN or a negative
figure was recorded as a latency, and the evidence signal carried an infinity or a NaN as the
bare tokens ``Infinity`` and ``NaN``, which are not JSON. Pinned here on the profile and on the
evidence it emits; ``tests/cli/test_usage_figures.py`` shows them through ``fingerprint``.
"""

from __future__ import annotations

import json

import pytest

from ildottore.fingerprint.base import ProbeContext
from ildottore.fingerprint.layers.guardrail import (
    GUARDRAIL_PROFILE_DETAIL,
    GuardrailLayer,
    guardrail_profile,
)
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse


@pytest.mark.parametrize(
    "figure",
    [int("9" * 400), float("inf"), float("nan"), -5, True, "12", [12]],
    ids=["400-digits", "inf", "nan", "negative", "bool", "string", "list"],
)
def test_a_latency_that_is_not_a_figure_is_none(figure: object) -> None:
    response = ModelResponse(text="I can't help.", usage={"moderation_latency_ms": figure})
    assert guardrail_profile(response)["moderation_latency_ms"] is None


@pytest.mark.parametrize("figure", [0, 12, 12.5])
def test_a_reported_latency_is_kept(figure: float) -> None:
    response = ModelResponse(text="I can't help.", usage={"moderation_latency_ms": figure})
    latency = guardrail_profile(response)["moderation_latency_ms"]
    assert isinstance(latency, float)
    assert latency == float(figure)


async def test_the_evidence_carries_no_infinity() -> None:
    class Reply:
        id = "t"

        async def send(self, request: ModelRequest) -> ModelResponse:
            return ModelResponse(text="I can't.", usage={"moderation_latency_ms": float("inf")})

        def capabilities(self) -> Capabilities:
            return Capabilities()

    evidence = await GuardrailLayer().probe(Reply(), ProbeContext(target_id="t"))
    (profile,) = [e for e in evidence if e.signal.startswith(f"{GUARDRAIL_PROFILE_DETAIL}=")]
    detail = profile.signal.removeprefix(f"{GUARDRAIL_PROFILE_DETAIL}=")
    assert json.loads(detail)["moderation_latency_ms"] is None
