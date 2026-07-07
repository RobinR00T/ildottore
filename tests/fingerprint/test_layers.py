"""Per-layer unit tests (u09 contract §5 steps 2-5)."""

from __future__ import annotations

from ildottore.fingerprint.attribution import Attribution, encode_signal, parse_signal
from ildottore.fingerprint.base import ProbeContext, seed_for
from ildottore.fingerprint.layers.behavioral import (
    BehavioralLayer,
    self_reported_family,
)
from ildottore.fingerprint.layers.capability import CapabilityLayer, capability_guess
from ildottore.fingerprint.layers.guardrail import (
    GUARDRAIL_PROFILE_DETAIL,
    GuardrailLayer,
    classify_refusal,
)
from ildottore.fingerprint.layers.metadata import MetadataLayer, envelope_signal
from ildottore.fingerprint.layers.statistical import (
    StatisticalLayer,
    featurize,
    response_vector,
)
from ildottore.fingerprint.layers.tokenizer import TokenizerLayer
from ildottore.fingerprint.signatures import SignaturePack
from ildottore.shared.models import Capabilities, ModelResponse
from tests.fingerprint.conftest import CorpusAdapter


def test_seed_for_is_deterministic() -> None:
    assert seed_for("t", "p") == "t:p"
    assert seed_for("a", "b") != seed_for("b", "a")


def test_attribution_roundtrip() -> None:
    sig = encode_signal("openai-gpt", "gpt-4o", "detail here")
    attr = parse_signal(sig)
    assert attr == Attribution(family="openai-gpt", version="gpt-4o", detail="detail here")


def test_attribution_family_only() -> None:
    attr = parse_signal(encode_signal("meta-llama", None, "x"))
    assert attr.family == "meta-llama"
    assert attr.version is None


def test_attribution_unattributed_signal() -> None:
    attr = parse_signal("just a plain string")
    assert attr.family is None and attr.version is None
    assert attr.detail == "just a plain string"


def test_envelope_signal_flattens_tells() -> None:
    resp = ModelResponse(
        text="hi",
        finish_reason="stop",
        raw_ids={"system_fingerprint": "fp_abc"},
        usage={"prompt_tokens": 3},
        tool_calls=[{"name": "f"}],
    )
    sig = envelope_signal(resp)
    assert "finish_reason=stop" in sig
    assert "system_fingerprint=fp_abc" in sig
    assert "usage.prompt_tokens" in sig
    assert "tool.name" in sig


def test_self_reported_family_maps() -> None:
    assert self_reported_family("I am Claude, made by Anthropic") == "anthropic-claude"
    assert self_reported_family("I am ChatGPT") == "openai-gpt"
    assert self_reported_family("just a helpful assistant") is None


def test_classify_refusal_styles() -> None:
    assert classify_refusal("I can't help with that") == "polite-explain"
    assert classify_refusal("I will not do that") == "firm"
    assert classify_refusal("As an AI, I cannot") in {"polite-explain", "canned"}
    assert classify_refusal("sure, here you go") == "unknown"


def test_capability_guess_projection() -> None:
    caps = Capabilities(tools=True, multimodal=True, streaming=True, seed=True)
    guess = capability_guess(caps)
    assert guess["tools"] is True
    assert guess["vision"] is True
    assert guess["json_mode"] is True  # rides along with tools MVP-1
    assert guess["seed"] is True


def test_featurize_is_bounded_and_deterministic() -> None:
    v1 = featurize("Hello there, how are you today?")
    v2 = featurize("Hello there, how are you today?")
    assert v1 == v2
    assert all(0.0 <= x <= 1.0 for x in v1)


def test_response_vector_length() -> None:
    from ildottore.fingerprint.layers.statistical import FEATURES_PER_PROBE

    vec = response_vector(["a", "b", "c"])
    assert len(vec) == FEATURES_PER_PROBE * 3


async def test_layers_return_empty_without_pack() -> None:
    # ctx without a valid pack ⇒ every pack-driven layer emits nothing (no crash)
    from ildottore.fingerprint.signatures import load_corpus

    case = load_corpus()[0]
    adapter = CorpusAdapter(case)
    ctx = ProbeContext(target_id="t", signature_pack=None)
    for layer in (
        MetadataLayer(),
        CapabilityLayer(),
        BehavioralLayer(),
        TokenizerLayer(),
    ):
        assert await layer.probe(adapter, ctx) == []
    # statistical also empty without a pack
    assert await StatisticalLayer().probe(adapter, ctx) == []


async def test_guardrail_emits_profile_even_without_pack() -> None:
    from ildottore.fingerprint.signatures import load_corpus

    case = load_corpus()[0]
    adapter = CorpusAdapter(case)
    ctx = ProbeContext(target_id="t", signature_pack=None)
    ev = await GuardrailLayer().probe(adapter, ctx)
    # the unattributed profile evidence is always emitted (weight 0)
    assert any(e.signal.startswith(f"{GUARDRAIL_PROFILE_DETAIL}=") for e in ev)


async def test_metadata_layer_matches_pack(pack: SignaturePack) -> None:
    from ildottore.fingerprint.signatures import load_corpus

    case = next(c for c in load_corpus() if c.case_id == "gpt-4o-clean")
    adapter = CorpusAdapter(case)
    ctx = ProbeContext(target_id="t", signature_pack=pack)
    ev = await MetadataLayer().probe(adapter, ctx)
    fams = {parse_signal(e.signal).family for e in ev}
    assert "openai-gpt" in fams


async def test_statistical_layer_ranks_correct_family(pack: SignaturePack) -> None:
    from ildottore.fingerprint.signatures import load_corpus

    case = next(c for c in load_corpus() if c.case_id == "llama-3-8b-clean")
    adapter = CorpusAdapter(case)
    ctx = ProbeContext(target_id="t", signature_pack=pack)
    ev = await StatisticalLayer().probe(adapter, ctx)
    # highest-weight statistical evidence should attribute to the true family
    top = max(ev, key=lambda e: e.weight)
    assert parse_signal(top.signal).family == "meta-llama"
