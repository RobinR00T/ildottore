"""A carrier probe the provider's input filter refuses costs that carrier, not the pass (OD-41).

The carrier layer sends a benign marker instruction through each obscuring mutator (base64,
rot13, leetspeak, homoglyphs, ...). Microsoft's Prompt Shields classes such an instruction as a
user prompt attack ("Encoding attacks"), so Azure OpenAI's filter can refuse a carrier with HTTP
400 ``content_filter`` after every other probe was answered, and ``-sV`` stopped there with exit 3
(pre-merge audit of ``3d739f3``, L6). A carrier the filter refused is now a failed probe: the
carrier layer leaves it unmeasured, as it does a carrier whose reply comes back refused (A-35),
and the pass goes on. Any other error of a carrier still stops the pass, and so does the same
refusal of an attributing probe.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from ildottore.adapters.base import AdapterStatusError, ProviderFilterBlock
from ildottore.adapters.comprehending import ComprehendingMock
from ildottore.cli.wiring import build_fingerprint_engine
from ildottore.core.execute import default_is_env_error
from ildottore.fingerprint import PROBES_FAILED_FLAG, FingerprintEngine, failed_probes
from ildottore.fingerprint.layers.carrier import CARRIER_PROBE_DETAIL, CARRIER_PROBE_PREFIX
from ildottore.fingerprint.signatures import load_corpus
from ildottore.shared.models import Capabilities, ModelFingerprint, ModelRequest, ModelResponse
from tests.fingerprint.conftest import CorpusAdapter

_CASE = "gpt-4o-clean"
_CORPUS = {case.case_id: case for case in load_corpus()}


def _block(status: int = 400) -> ProviderFilterBlock:
    return ProviderFilterBlock(
        "t: non-retryable HTTP 400 from /v1/chat/completions: the provider's input filter refused "
        "the prompt before the model saw it (error code content_filter; filtered: jailbreak)",
        status_code=status,
        code="content_filter",
    )


class _Target:
    """Corpus replies for the attributing probes, the decoding mock for the carriers, and an
    exception raised on the probes named in ``failures``."""

    def __init__(self, failures: dict[str, BaseException] | None = None) -> None:
        self._corpus = CorpusAdapter(_CORPUS[_CASE])
        self._mock = ComprehendingMock()
        self.id = self._corpus.id
        self._failures = failures or {}
        self.sent: list[str] = []

    def capabilities(self) -> Capabilities:
        return self._corpus.capabilities()

    async def send(self, request: ModelRequest) -> ModelResponse:
        probe = str((request.metadata or {}).get("probe", ""))
        self.sent.append(probe)
        if probe in self._failures:
            raise self._failures[probe]
        inner = self._mock if probe.startswith(CARRIER_PROBE_PREFIX) else self._corpus
        return await inner.send(request)


def _run(target: _Target, engine: FingerprintEngine | None = None) -> ModelFingerprint:
    return asyncio.run((engine or build_fingerprint_engine()).run(target))


def _comprehension(fp: ModelFingerprint) -> dict[str, float]:
    for e in fp.evidence:
        if e.layer == "carrier" and e.signal.startswith(f"{CARRIER_PROBE_DETAIL}="):
            return dict(json.loads(e.signal.split("=", 1)[1]))
    raise AssertionError("no carrier comprehension evidence")


_BASELINE = _run(_Target())


@pytest.mark.parametrize("status", [400, 200], ids=["azure-400", "gemini-200"])
def test_a_carrier_the_filter_refused_is_a_failed_probe_and_the_pass_goes_on(status: int) -> None:
    target = _Target({"carrier_base64_wrap": _block(status)})
    fp = _run(target)

    assert len(target.sent) == 18, "every probe still went out"
    assert failed_probes(fp) == ["carrier/carrier_base64_wrap: ProviderFilterBlock"]
    assert PROBES_FAILED_FLAG in fp.spoofing_flags
    # Unmeasured, not scored zero; the other carriers are measured as in a full pass.
    measured = _comprehension(fp)
    assert "base64_wrap" not in measured
    assert measured == {k: v for k, v in _comprehension(_BASELINE).items() if k != "base64_wrap"}
    # The attribution is the full pass's: the carriers attribute nothing.
    assert fp.family == _BASELINE.family
    assert fp.version == _BASELINE.version


def test_every_carrier_refused_leaves_the_carriers_unmeasured() -> None:
    probe_target = _Target()
    _run(probe_target)
    names = [p for p in probe_target.sent if p.startswith(CARRIER_PROBE_PREFIX)]
    assert len(names) == 7
    fp = _run(_Target(dict.fromkeys(names, _block())))
    assert len(failed_probes(fp)) == 7
    assert _comprehension(fp) == {}
    assert fp.family == _BASELINE.family


def test_another_4xx_on_a_carrier_still_stops_the_pass() -> None:
    """Only the provider's filter: a plain 4xx is what it was."""

    error = AdapterStatusError(
        "t: non-retryable HTTP 400 from /v1/chat/completions", status_code=400
    )
    with pytest.raises(AdapterStatusError):
        _run(_Target({"carrier_base64_wrap": error}))


def test_the_same_refusal_of_an_attributing_probe_still_stops_the_pass() -> None:
    with pytest.raises(ProviderFilterBlock):
        _run(_Target({"self_id": _block()}))


def test_an_engine_without_the_predicate_isolates_no_carrier() -> None:
    """The predicate is the composition root's: an engine built without it is as before."""

    engine = FingerprintEngine(
        layers=build_fingerprint_engine().layers, is_env_error=default_is_env_error
    )
    with pytest.raises(ProviderFilterBlock):
        _run(_Target({"carrier_base64_wrap": _block()}), engine)
