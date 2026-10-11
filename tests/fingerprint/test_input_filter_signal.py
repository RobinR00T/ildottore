"""``input_filter`` says what a pass saw of the provider's input filter (OD-40, u09 §7 A-67).

Decided 2026-10-11 under the owner's delegation (best practice, revisable): the key stays in
the guardrail profile and is filled from the one input-filter signal a ``-sV`` pass sees, a probe
the provider's own input filter refused in a shape the provider documents (Azure OpenAI's HTTP
400 ``content_filter``; Gemini's ``promptFeedback.blockReason``: the adapters'
``ProviderFilterBlock``, OD-41). Such a refusal is the provider saying so, not an inference from a
reply, so ``input_filter`` is ``true``. Anything else leaves it ``null``, never ``false``: a pass
sends benign probes only, and a filter that acts on harmful content never acts on them. An
undocumented 4xx to the benign request is still a failed probe and claims no filter.

Before, ``input_filter`` was ``null`` on every pass (since A-67, 2026-10-09), a key that could
only ever say "unknown".
"""

from __future__ import annotations

import asyncio

from ildottore.adapters.base import AdapterStatusError, ProviderFilterBlock
from ildottore.adapters.comprehending import ComprehendingMock
from ildottore.cli.wiring import build_fingerprint_engine
from ildottore.fingerprint import failed_probes
from ildottore.shared.models import Capabilities, ModelFingerprint, ModelRequest, ModelResponse

_ANSWER = "Find its process id with ps, then end it with kill (kill -9 if it ignores that)."
_REFUSAL = "I'm sorry, but I can't help with that."


class _Stub:
    """Answers like a model; raises ``errors[probe]`` for the probes named there."""

    id = "stub"

    def __init__(self, errors: dict[str, Exception] | None = None) -> None:
        self._errors = errors or {}
        self._mock = ComprehendingMock()

    def capabilities(self) -> Capabilities:
        return Capabilities()

    async def send(self, request: ModelRequest) -> ModelResponse:
        probe = str((request.metadata or {}).get("probe", ""))
        if probe in self._errors:
            raise self._errors[probe]
        if probe.startswith("carrier_"):
            return await self._mock.send(request)
        prompt = (request.prompt or "").lower()
        text = _REFUSAL if "refuse" in prompt else _ANSWER
        return ModelResponse(text=text, finish_reason="stop")


def _azure_block() -> ProviderFilterBlock:
    return ProviderFilterBlock(
        "azure: the provider's input filter refused the prompt", status_code=400, code="x"
    )


def _fingerprint(errors: dict[str, Exception] | None = None) -> ModelFingerprint:
    return asyncio.run(build_fingerprint_engine().run(_Stub(errors)))


def test_the_provider_s_filter_on_the_benign_request_is_an_input_filter() -> None:
    fp = _fingerprint({"guardrail_benign": _azure_block()})
    assert fp.guardrails["input_filter"] is True
    # The probe is still a failed probe, and the reply it never got is still unknown.
    assert failed_probes(fp) == ["guardrail/guardrail_benign: ProviderFilterBlock"]
    assert fp.guardrails["benign_refused"] is None
    assert fp.guardrails["refusal_style"] == "polite-explain"


def test_the_provider_s_filter_on_a_carrier_is_an_input_filter() -> None:
    fp = _fingerprint({"carrier_base64_wrap": _azure_block()})
    assert fp.guardrails["input_filter"] is True
    assert failed_probes(fp) == ["carrier/carrier_base64_wrap: ProviderFilterBlock"]
    # What the guardrail layer itself read is unchanged.
    assert fp.guardrails["benign_refused"] is False


def test_an_undocumented_4xx_claims_no_filter() -> None:
    fp = _fingerprint({"guardrail_benign": AdapterStatusError("HTTP 400", status_code=400)})
    assert failed_probes(fp) == ["guardrail/guardrail_benign: AdapterStatusError"]
    assert fp.guardrails["input_filter"] is None


def test_no_refusal_is_unknown_never_false() -> None:
    fp = _fingerprint()
    assert failed_probes(fp) == []
    assert fp.guardrails["input_filter"] is None


def test_the_guardrail_layer_s_own_evidence_is_unchanged() -> None:
    """The layer sees replies only and writes ``null``; the engine, which sees every probe's
    failure, sets the profile's ``true``. So the evidence, and the golden fingerprint, hold what
    they held."""

    fp = _fingerprint({"guardrail_benign": _azure_block()})
    (profile,) = [ev.signal for ev in fp.evidence if ev.signal.startswith("guardrail_profile=")]
    assert '"input_filter": null' in profile
