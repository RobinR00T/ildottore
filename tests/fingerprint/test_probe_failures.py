"""A probe that gets no usable reply costs that probe, not the pass (u09 §7 A-35, OD-23).

With ``dottore run -sV`` (or ``-A``), one target reply the adapters refuse as an environment
error (``ResponseTooLarge``, ``ResponseUndecodable``) stopped the whole run with exit 3 after one
request, before any attack, while without ``-sV`` the same reply failed only its attempt; three
503 in a row on one probe did the same (pre-commit audit of ``fix/target-deep-json``,
2026-10-07). The layers called ``adapter.send`` with nothing between one probe and the pass.

Now a reply that comes back refused (an environment failure, by the predicate the attack phase
uses, that a retry would repeat: ``retryable = False``) is a failed probe: that probe's layer
gives no evidence from it, and every other probe still goes out and counts as before. A probe
that gets no answer at all (a 503 or a timeout after the retries) still stops the pass, as does
anything else (a product error, a refusal by the scope, a budget breach): isolating those too
made a target that never answers cost 25.5 minutes of probing (pre-commit audit).

The target here answers the attributing probes from the ``gpt-4o-clean`` corpus case and the
carriers through the decoding mock, so a pass with no failure has evidence in every layer and a
comprehension split, and each check below has something to lose.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from ildottore.adapters.base import (
    AdapterEnvError,
    AdapterProductError,
    EndpointNotAllowed,
    ResponseTooLarge,
    ResponseUndecodable,
)
from ildottore.adapters.comprehending import ComprehendingMock
from ildottore.cli.wiring import build_fingerprint_engine
from ildottore.core.execute import default_is_env_error
from ildottore.fingerprint import PROBES_FAILED_FLAG, FingerprintEngine, failed_probes
from ildottore.fingerprint.base import ProbeContext, ProbeFailed
from ildottore.fingerprint.layers.behavioral import SELF_REPORT_DETAIL
from ildottore.fingerprint.layers.carrier import CARRIER_PROBE_DETAIL
from ildottore.fingerprint.layers.statistical import StatisticalLayer, response_vector
from ildottore.fingerprint.probes import STATISTICAL_BATTERY
from ildottore.fingerprint.signatures import (
    SignatureEntry,
    SignaturePack,
    StatSignature,
    load_corpus,
    load_pack,
)
from ildottore.shared.models import (
    Capabilities,
    FingerprintEvidence,
    ModelFingerprint,
    ModelRequest,
    ModelResponse,
)
from ildottore.shared.protocols import TargetAdapter
from tests.fingerprint.conftest import CorpusAdapter

_CASE = "gpt-4o-clean"
_CORPUS = {case.case_id: case for case in load_corpus()}
_SECRET = "sk-live-0123456789abcdefTARGETTEXT"


class _Target:
    """Corpus replies for the attributing probes, the decoding mock for the carriers, and a
    chosen exception raised on chosen sends (by position in the pass, from 0)."""

    def __init__(self, failures: dict[int, BaseException] | None = None, case: str = _CASE) -> None:
        self._corpus = CorpusAdapter(_CORPUS[case])
        self._mock = ComprehendingMock()
        self.id = self._corpus.id
        self._failures = failures or {}
        self.sent: list[str] = []

    def capabilities(self) -> Capabilities:
        return self._corpus.capabilities()

    async def send(self, request: ModelRequest) -> ModelResponse:
        index = len(self.sent)
        probe = str((request.metadata or {}).get("probe", ""))
        self.sent.append(probe)
        if index in self._failures:
            raise self._failures[index]
        inner = self._mock if probe.startswith("carrier_") else self._corpus
        return await inner.send(request)


def _run(target: _Target, engine: FingerprintEngine | None = None) -> ModelFingerprint:
    return asyncio.run((engine or build_fingerprint_engine()).run(target))


_BASELINE_TARGET = _Target()
_BASELINE = _run(_BASELINE_TARGET)
#: The probe each send carries, in the order of a pass (``self_id`` twice: metadata, then
#: behavioral), and the layer that sent it.
_ORDER = list(_BASELINE_TARGET.sent)
_LAYER_OF = [
    layer.layer
    for layer in build_fingerprint_engine().layers
    for _ in range(getattr(layer, "probe_count", 1))
]


def _evidence(fp: ModelFingerprint, *, without: set[str]) -> list[FingerprintEvidence]:
    return [e for e in fp.evidence if e.layer not in without]


def _comprehension(fp: ModelFingerprint) -> dict[str, float]:
    for e in fp.evidence:
        if e.layer == "carrier" and e.signal.startswith(f"{CARRIER_PROBE_DETAIL}="):
            return dict(json.loads(e.signal.split("=", 1)[1]))
    raise AssertionError("no carrier comprehension evidence")


def test_the_baseline_has_something_to_lose_in_every_layer() -> None:
    """Not vacuous: with no failure, every probing layer gives evidence."""

    assert len(_ORDER) == len(_LAYER_OF) == 17
    weighted = {e.layer for e in _BASELINE.evidence if e.weight > 0}
    assert {"metadata", "behavioral", "tokenizer", "guardrail", "statistical"} <= weighted
    assert any(SELF_REPORT_DETAIL in e.signal for e in _BASELINE.evidence)
    assert _BASELINE.guardrails["output_filter"] is True
    scores = _comprehension(_BASELINE)
    assert len(scores) == 7 and 0.0 in scores.values() and 1.0 in scores.values()
    assert failed_probes(_BASELINE) == []
    assert PROBES_FAILED_FLAG not in _BASELINE.spoofing_flags


@pytest.mark.parametrize("index", range(17))
def test_a_refused_probe_costs_its_own_reply_and_nothing_else(index: int) -> None:
    target = _Target({index: ResponseTooLarge("hostile: response exceeded 4194304 bytes")})
    fp = _run(target)

    # Every probe still went out once: none skipped, none sent again (A-3: declared cost).
    assert target.sent == _ORDER
    assert failed_probes(fp) == [f"{_LAYER_OF[index]}/{_ORDER[index]}: ResponseTooLarge"]
    assert PROBES_FAILED_FLAG in fp.spoofing_flags
    # Every other layer's evidence is exactly what the pass with no failure gave.
    layer = _LAYER_OF[index]
    assert _evidence(fp, without={layer, "engine"}) == _evidence(
        _BASELINE, without={layer, "engine"}
    )


def test_a_refused_metadata_probe_gives_no_envelope_evidence() -> None:
    fp = _run(_Target({0: ResponseTooLarge("x")}))
    assert not [e for e in fp.evidence if e.layer == "metadata"]


def test_a_refused_self_id_probe_gives_no_self_report() -> None:
    fp = _run(_Target({1: ResponseTooLarge("x")}))
    assert not [e for e in fp.evidence if SELF_REPORT_DETAIL in e.signal]


def test_a_refused_behavioral_probe_leaves_the_other_three_counting() -> None:
    """In this case every behavioral tell is in the ``self_id`` reply: losing ``cutoff`` changes
    nothing, and the missing reply is not read as an empty one."""

    fp = _run(_Target({_ORDER.index("cutoff"): ResponseTooLarge("x")}))
    behavioral = [e for e in fp.evidence if e.layer == "behavioral"]
    assert behavioral
    assert behavioral == [e for e in _BASELINE.evidence if e.layer == "behavioral"]


def test_a_refused_tokenizer_probe_gives_no_tokenizer_evidence() -> None:
    fp = _run(_Target({_ORDER.index("tokenizer_glitch"): ResponseTooLarge("x")}))
    assert not [e for e in fp.evidence if e.layer == "tokenizer"]


def test_a_refused_guardrail_probe_leaves_the_guardrails_unknown_not_absent() -> None:
    """No reply is not "no filter": the profile is left out, not written as all false."""

    fp = _run(_Target({_ORDER.index("guardrail_nudge"): ResponseTooLarge("x")}))
    assert fp.guardrails == {}
    assert not [e for e in fp.evidence if e.layer == "guardrail"]


@pytest.mark.parametrize("probe", ["stat_greeting", "stat_list", "stat_explain"])
def test_a_refused_statistical_probe_gives_no_statistical_evidence(probe: str) -> None:
    """The vector needs all three replies; a short one would land near the wrong centroid."""

    fp = _run(_Target({_ORDER.index(probe): ResponseTooLarge("x")}))
    assert not [e for e in fp.evidence if e.layer == "statistical"]


@pytest.mark.parametrize("probe", [p for p in _ORDER if p.startswith("carrier_")])
def test_a_refused_carrier_is_left_unmeasured_not_scored_zero(probe: str) -> None:
    """Zero says the target did not understand the carrier; no reply says nothing."""

    fp = _run(_Target({_ORDER.index(probe): ResponseTooLarge("x")}))
    name = probe.removeprefix("carrier_")
    expected = {k: v for k, v in _comprehension(_BASELINE).items() if k != name}
    assert _comprehension(fp) == expected


def test_every_probe_refused_gives_an_empty_fingerprint_and_says_so() -> None:
    target = _Target({i: ResponseUndecodable("x") for i in range(17)})
    fp = _run(target)

    assert target.sent == _ORDER
    assert failed_probes(fp) == [
        f"{layer}/{p}: ResponseUndecodable" for layer, p in zip(_LAYER_OF, _ORDER, strict=True)
    ]
    assert fp.family.guess == "unknown"
    assert fp.family.confidence == 0.0
    assert fp.version is None
    assert fp.guardrails == {}
    assert "effective_mutators" not in fp.capability_guess
    assert [e for e in fp.evidence if e.weight > 0] == []
    assert PROBES_FAILED_FLAG in fp.spoofing_flags
    # Nothing came back, so nothing came back alike either.
    assert "non_discriminating_target" not in fp.spoofing_flags


class _TooDeep(AdapterEnvError):
    """Stands for ``ResponseTooDeep`` (on ``fix/target-deep-json``): env, not retried."""

    is_env_error = True
    retryable = False


@pytest.mark.parametrize(
    "error",
    [ResponseTooLarge("x"), ResponseUndecodable("x"), _TooDeep("x")],
    ids=["too-large", "undecodable", "too-deep"],
)
def test_every_kind_of_refused_reply_is_a_failed_probe(error: BaseException) -> None:
    """The marker is structural, so a refusal added later is covered with no change here."""

    fp = _run(_Target({0: error}))
    assert failed_probes(fp) == [f"metadata/self_id: {type(error).__name__}"]


@pytest.mark.parametrize(
    "error",
    [
        AdapterEnvError("exhausted 1 attempt(s): HTTP 503"),
        AdapterEnvError("ConnectError: All connection attempts failed"),
        TimeoutError(),
    ],
    ids=["unavailable", "connection-refused", "timeout"],
)
def test_a_probe_that_gets_no_answer_at_all_stops_the_pass(error: BaseException) -> None:
    """The target is not answering: the run stops at once with the cause, as before the fix.

    Isolated like a refused reply, a target that never answered cost 17 probes of three 30 s
    timeouts, 25.5 minutes, before an attack that failed the same way, and ``dottore
    fingerprint`` exited 0 on a closed port with the cause reduced to a class name.
    """

    index = _ORDER.index("tokenizer_glitch")
    target = _Target({index: error})
    with pytest.raises(type(error)) as raised:
        _run(target)
    assert raised.value is error
    assert len(target.sent) == index + 1


class _Interrupted(BaseException):
    """Stands for an interrupt or a cancellation: never caught as a failed probe."""


@pytest.mark.parametrize(
    "error",
    [
        AdapterProductError("success response was not valid JSON"),
        EndpointNotAllowed("http://elsewhere.example/v1"),
        PermissionError("refused"),
        _Interrupted(),
    ],
    ids=["product", "scope", "other", "base-exception"],
)
def test_what_is_not_an_environment_failure_still_stops_the_pass(error: BaseException) -> None:
    """Not masked as a flake (AGENTS.md §2): nothing more is sent after it."""

    index = _ORDER.index("guardrail_nudge")
    target = _Target({index: error})
    with pytest.raises(type(error)):
        _run(target)
    assert len(target.sent) == index + 1


def test_the_failure_record_carries_no_text_from_the_target() -> None:
    """Only the probe name and the error's class: the message can quote the reply."""

    fp = _run(_Target({0: ResponseUndecodable(f"body {_SECRET} in 'br'")}))
    assert failed_probes(fp) == ["metadata/self_id: ResponseUndecodable"]
    assert _SECRET not in fp.model_dump_json()


def test_a_failed_pass_replays_byte_identically() -> None:
    failures: dict[int, BaseException] = {3: ResponseTooLarge("x"), 12: ResponseTooLarge("x")}
    first = _run(_Target(dict(failures)))
    second = _run(_Target(dict(failures)))
    assert first.model_dump_json() == second.model_dump_json()


class _CarelessLayer:
    """A third-party layer that lets a failed probe escape: it loses its evidence, not the pass."""

    layer = "careless"
    probe_count = 2

    async def probe(self, adapter: TargetAdapter, ctx: ProbeContext) -> list[FingerprintEvidence]:
        for name in ("careless_one", "careless_two"):
            await adapter.send(ModelRequest(prompt="hello", metadata={"probe": name}))
        return [FingerprintEvidence(layer=self.layer, signal="careless=1", weight=0.0)]


def test_a_layer_that_does_not_handle_a_failed_probe_loses_only_its_own_evidence() -> None:
    engine = FingerprintEngine(
        layers=[*build_fingerprint_engine().layers, _CarelessLayer()],
        is_env_error=default_is_env_error,
    )
    target = _Target({17: ResponseTooLarge("x")})
    fp = _run(target, engine)

    assert target.sent == [*_ORDER, "careless_one"]
    assert failed_probes(fp) == ["careless/careless_one: ResponseTooLarge"]
    assert not [e for e in fp.evidence if e.layer == "careless"]
    assert _evidence(fp, without={"engine"}) == _evidence(_BASELINE, without={"engine"})


class _Constant:
    """A target that says the same self-identifying sentence to everything."""

    id = "constant"

    def __init__(self, refused: set[int]) -> None:
        self._refused = refused
        self.sent = 0

    def capabilities(self) -> Capabilities:
        return Capabilities()

    async def send(self, request: ModelRequest) -> ModelResponse:
        index = self.sent
        self.sent += 1
        if index in self._refused:
            raise ResponseTooLarge("x")
        return ModelResponse(text="I am Llama, a model by Meta.")


def _run_constant(target: _Constant) -> ModelFingerprint:
    return asyncio.run(build_fingerprint_engine().run(target))


def test_too_few_replies_to_check_for_a_constant_target_name_nothing_from_text() -> None:
    """With 8 of its 10 attributing replies refused, a constant target was named meta-llama at
    0.41 (pre-commit audit): the constant check needs three replies and never ran. A full pass
    names nothing; refusals may not be the way past the check."""

    full = _run_constant(_Constant(set()))
    assert full.family.guess == "unknown"
    assert "non_discriminating_target" in full.spoofing_flags

    attributing = [i for i, layer in enumerate(_LAYER_OF) if layer != "carrier"]
    refused = set(attributing) - {attributing[1]}  # only behavioral's self_id answers
    partial = _run_constant(_Constant(refused))
    assert len(failed_probes(partial)) == len(attributing) - 1
    assert partial.family.guess == "unknown"
    assert partial.family.confidence == 0.0
    # Not called constant: two replies cannot show that; the failures say why instead.
    assert "non_discriminating_target" not in partial.spoofing_flags
    assert PROBES_FAILED_FLAG in partial.spoofing_flags


def test_the_statistical_layer_does_not_featurize_two_replies_against_any_centroid() -> None:
    """A pack's centroid is only required to be non-empty: one as long as two replies' vector
    would match it exactly, so a missing reply drops the layer explicitly."""

    case = _CORPUS[_CASE]
    answered = [case.responses[p.name] for p in STATISTICAL_BATTERY[1:]]
    entry = SignatureEntry(
        family="short-centroid",
        weights={"statistical": 1.0},
        stat=StatSignature(centroid=response_vector(answered)),
    )
    pack = SignaturePack(pack_version=load_pack().pack_version, name="short", entries=[entry])

    class _FirstRefused:
        id = "t"

        def __init__(self) -> None:
            self.sent = 0

        def capabilities(self) -> Capabilities:
            return Capabilities()

        async def send(self, request: ModelRequest) -> ModelResponse:
            self.sent += 1
            probe = str((request.metadata or {}).get("probe"))
            if probe == STATISTICAL_BATTERY[0].name:
                raise ProbeFailed(probe, ResponseTooLarge("x"))
            return ModelResponse(text=case.responses[probe])

    adapter = _FirstRefused()
    ctx = ProbeContext(target_id="t", signature_pack=pack)
    assert asyncio.run(StatisticalLayer().probe(adapter, ctx)) == []
    assert adapter.sent == len(STATISTICAL_BATTERY)


def test_without_a_failure_a_short_pass_is_attributed_from_its_text() -> None:
    """The too-few-replies rule applies only when replies were refused: an engine composed with
    two attributing probes and no failure keeps its text evidence, as it did before."""

    from ildottore.fingerprint.combine import combine
    from ildottore.fingerprint.layers import MetadataLayer, TokenizerLayer

    engine = FingerprintEngine(
        layers=[MetadataLayer(), TokenizerLayer()], is_env_error=default_is_env_error
    )
    case = _CORPUS[_CASE]
    fp = asyncio.run(engine.run(CorpusAdapter(case)))
    assert failed_probes(fp) == []
    expected = combine(fp.evidence).family
    assert (fp.family.guess, fp.family.confidence) == (expected.guess, expected.confidence)
    assert fp.family.confidence > 0.4  # above the envelope-only cap, so text counted


def test_three_answered_replies_are_enough_for_the_constant_check() -> None:
    """The boundary: with every other attributing probe refused, three different replies still
    run the check and the text evidence counts (the envelope probe is refused, so without text
    the family would be unknown)."""

    attributing = [i for i, layer in enumerate(_LAYER_OF) if layer != "carrier"]
    kept = {_ORDER.index("tokenizer_glitch"), _ORDER.index("guardrail_nudge"), 1}
    fp = _run(_Target({i: ResponseTooLarge("x") for i in attributing if i not in kept}))
    assert len(failed_probes(fp)) == len(attributing) - 3
    assert fp.family.guess == "openai-gpt"
    assert fp.family.confidence > 0.4


@pytest.mark.parametrize(("failed", "empty"), [(16, False), (17, True)])
def test_the_warning_calls_the_fingerprint_empty_only_when_nothing_came_back(
    failed: int, empty: bool
) -> None:
    from ildottore.cli.run import probe_failure_warning
    from ildottore.fingerprint.engine import PROBE_ERRORS_DETAIL
    from ildottore.shared.models import FingerprintGuess

    errors = [f"carrier/carrier_{i}: ResponseTooLarge" for i in range(failed)]
    fp = ModelFingerprint(
        target_id="t",
        family=FingerprintGuess(guess="unknown", confidence=0.0),
        evidence=[
            FingerprintEvidence(
                layer="engine", signal=f"{PROBE_ERRORS_DETAIL}={json.dumps(errors)}", weight=0.0
            )
        ],
    )
    line = probe_failure_warning("t", fp, probes=17)
    assert line is not None
    assert line.startswith(f"warning: t: {failed} of 17 probe(s) got no usable reply")
    assert ("none did, so the fingerprint is empty" in line) is empty
    assert ("built from the replies that came back" in line) is not empty


def test_alike_replies_with_refusals_are_not_called_constant() -> None:
    """The replies that came back are alike, and the refused ones could have varied: the flag
    then said "every attributing probe alike" of a target a full pass names (pre-merge audit).
    With attributing replies refused the check cannot be completed, so the text evidence is not
    counted and the flag is not set."""

    attributing = [i for i, layer in enumerate(_LAYER_OF) if layer != "carrier"]
    fp = _run_constant(_Constant(set(attributing[:2])))
    assert len(failed_probes(fp)) == 2
    assert fp.family.guess == "unknown"
    assert "non_discriminating_target" not in fp.spoofing_flags
    assert PROBES_FAILED_FLAG in fp.spoofing_flags


class _Bland(_Target):
    """The same target with the chosen sends answered by an empty reply instead of refused."""

    async def send(self, request: ModelRequest) -> ModelResponse:
        index = len(self.sent)
        if index in self._failures:
            self.sent.append(str((request.metadata or {}).get("probe", "")))
            return ModelResponse(text="", finish_reason=self._corpus._case.finish_reason)
        return await super().send(request)


def _names_more(partial: ModelFingerprint, bland: ModelFingerprint) -> bool:
    if partial.family.guess == "unknown":
        return False
    return (
        partial.family.guess != bland.family.guess
        or partial.family.confidence > bland.family.confidence
    )


def test_a_partial_pass_never_names_more_than_the_same_probes_answered_blandly() -> None:
    """The domain of A-35, measured. Exhaustively once (2026-10-07: 12 corpus cases, every subset
    of the 10 attributing sends, 12,276 passes): identical when no statistical probe is refused,
    otherwise less or the same family with lower confidence, never more. Pinned here on every
    single and paired refusal and on every pass with two replies or fewer left."""

    from itertools import combinations

    engine = build_fingerprint_engine()
    attributing = [i for i, layer in enumerate(_LAYER_OF) if layer != "carrier"]
    subsets = [
        set(sub)
        for size in (1, 2, len(attributing) - 2, len(attributing) - 1, len(attributing))
        for sub in combinations(attributing, size)
    ]
    for case in _CORPUS:
        for refused in subsets:
            failures = dict.fromkeys(refused, ResponseTooLarge("x"))
            partial_fp = asyncio.run(engine.run(_Target(failures, case)))
            bland_fp = asyncio.run(engine.run(_Bland(failures, case)))
            assert not _names_more(partial_fp, bland_fp), (case, sorted(refused))


def test_a_refused_carrier_does_not_hide_a_constant_target() -> None:
    """The constant check reads only the attributing probes: with all ten answered alike and
    a carrier refused it is complete, and the flag stays (delta audit of PR #68)."""

    carriers = [i for i, layer in enumerate(_LAYER_OF) if layer == "carrier"]
    for refused in ({carriers[0]}, set(carriers)):
        fp = _run_constant(_Constant(refused))
        assert len(failed_probes(fp)) == len(refused)
        assert "non_discriminating_target" in fp.spoofing_flags
        assert PROBES_FAILED_FLAG in fp.spoofing_flags
        assert fp.family.guess == "unknown"
