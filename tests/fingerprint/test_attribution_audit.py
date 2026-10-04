"""Fingerprint attribution: the audit of the fingerprint that followed the 2026-10-03 audit.

A target answering with two canned texts was named meta-llama with a 2023-03 cutoff: its short
replies sat within reach of the llama centroid, and the version was the alphabetical winner of a
tie. An envelope-only attribution was named on one field at 0.52. Declared capabilities counted
toward a family, and a live probe reported the adapter's defaults instead of the target file's.
The pre-commit audit of the fix added the cases that need the real OpenAI adapter: its redactor
masked mixed-case model names, and the example target's capabilities outvoted a gpt envelope.
"""

from __future__ import annotations

import pytest

from ildottore.cli import wiring
from ildottore.fingerprint.attribution import encode_signal
from ildottore.fingerprint.base import ProbeContext
from ildottore.fingerprint.combine import combine
from ildottore.fingerprint.layers.statistical import StatisticalLayer
from ildottore.fingerprint.signatures import load_pack
from ildottore.shared.models import (
    Capabilities,
    FingerprintEvidence,
    ModelRequest,
    ModelResponse,
)


class _Canned:
    """Alternates two texts; optional envelope and declared capabilities."""

    id = "canned"

    def __init__(self, raw: dict[str, str] | None = None, caps: Capabilities | None = None):
        self.sends = 0
        self.raw = raw or {}
        self.caps = caps or Capabilities()

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        text = "Sure, here is a short answer." if self.sends % 2 else "Sorry, I can't help."
        return ModelResponse(text=text, raw_ids=self.raw, finish_reason="stop")

    def capabilities(self) -> Capabilities:
        return self.caps


class _Constant(_Canned):
    async def send(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(text="I cannot help.", raw_ids=self.raw, finish_reason="stop")


async def test_a_two_answer_target_gets_no_family_and_no_invented_version() -> None:
    fingerprint = await wiring.build_fingerprint_engine().run(_Canned())
    assert fingerprint.family.guess == "unknown"
    assert fingerprint.version is None


async def test_canned_replies_give_no_statistical_evidence() -> None:
    evidence = await StatisticalLayer().probe(
        _Canned(), ProbeContext(target_id="canned", signature_pack=load_pack())
    )
    assert evidence == []


def test_a_tie_names_neither_a_family_nor_a_version() -> None:
    def ev(family: str, version: str) -> FingerprintEvidence:
        return FingerprintEvidence(
            layer="metadata", signal=encode_signal(family, version, "x"), weight=0.4
        )

    tied_versions = combine([ev("openai-gpt", "gpt-4o"), ev("openai-gpt", "gpt-4-turbo")])
    assert tied_versions.family.guess == "openai-gpt" and tied_versions.version is None
    tied_families = combine([ev("openai-gpt", "gpt-4o"), ev("meta-llama", "llama-3-8b")])
    assert tied_families.family.guess == "unknown"


async def test_an_envelope_only_attribution_is_no_surer_than_the_metadata_weight() -> None:
    fingerprint = await wiring.build_fingerprint_engine().run(
        _Constant({"model": "gpt-4o-2024-08-06"})
    )
    assert fingerprint.family.guess == "openai-gpt"
    assert fingerprint.family.confidence <= 0.4


async def test_a_vllm_model_name_is_recognised() -> None:
    fingerprint = await wiring.build_fingerprint_engine().run(
        _Constant({"model": "meta-llama/Meta-Llama-3-8B-Instruct"})
    )
    assert fingerprint.family.guess == "meta-llama"


def test_finish_reason_is_no_longer_a_family_signal() -> None:
    for entry in load_pack().entries:
        assert not any("finish_reason" in s for s in entry.signals.get("metadata", []))


async def test_declared_capabilities_are_listed_but_never_counted() -> None:
    for caps in (Capabilities(), Capabilities(tools=True, streaming=True)):
        fingerprint = await wiring.build_fingerprint_engine().run(_Canned(caps=caps))
        assert fingerprint.family.guess == "unknown"
        capability = [e for e in fingerprint.evidence if e.layer == "capability"]
        assert capability and all(e.weight == 0.0 for e in capability)


# --- through the real OpenAI adapter (pre-commit audit of this block) ---------------------


def _openai(model: str, texts: list[str]):  # type: ignore[no-untyped-def]
    import json

    import httpx

    from ildottore.adapters.openai import OpenAIAdapter
    from ildottore.policy.allowlist import EndpointAllowlist
    from ildottore.policy.scope import Endpoint

    served = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        text = texts[served["n"] % len(texts)]
        served["n"] += 1
        body = {
            "model": model,
            "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
        }
        return httpx.Response(
            200, content=json.dumps(body).encode(), headers={"content-type": "application/json"}
        )

    return OpenAIAdapter(
        id="live",
        base_url="https://api.example.test",
        allowlist=EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])]),
        api_key="k",
        model="m",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


async def test_the_example_capabilities_do_not_outvote_a_gpt_envelope() -> None:
    """`examples/target.openai.yaml` declares tools: false, streaming: true, the whole meta-llama
    capability profile; counted, it tied a real `model=gpt-4o` envelope into unknown."""

    declared = Capabilities(tools=False, streaming=True)
    adapter = wiring._DeclaredCapabilities(
        _openai("gpt-4o-2024-08-06", ["Sure, here is a short answer.", "Sorry, I can't help."]),
        declared,
    )
    fingerprint = await wiring.build_fingerprint_engine().run(adapter)  # type: ignore[arg-type]
    assert fingerprint.family.guess == "openai-gpt"
    assert fingerprint.family.confidence <= 0.4, "named by the envelope alone: capped"


@pytest.mark.parametrize(
    "model", ["meta-llama/Meta-Llama-3-8B-Instruct", "llama-3.1-70b-versatile"]
)
async def test_a_llama_model_name_survives_the_adapter_and_fills_the_envelope_slot(
    model: str,
) -> None:
    """The adapter's redactor masked mixed-case names as high-entropy before the metadata layer
    read them, and two `model=` fragments that can never both match halved meta-llama."""

    fingerprint = await wiring.build_fingerprint_engine().run(_openai(model, ["I cannot help."]))
    assert fingerprint.family.guess == "meta-llama"
    metadata = [e for e in fingerprint.evidence if e.layer == "metadata"]
    assert metadata and all(e.weight == 0.4 for e in metadata)


async def test_the_model_exemption_keeps_patterns_credentials_and_other_ids() -> None:
    """Only the entropy rule is skipped, only for a string `model`, and only that key."""

    from ildottore.redactor import register_known_secret

    register_known_secret("ZzRegisteredOperatorKey0123456789")
    adapter = _openai("gpt-4o", ["hi"])
    ids = adapter._redact_ids(
        {
            "id": "chatcmpl-AbCdEfGhIjKlMnOpQrStUv12",
            "model": "proxy-ZzRegisteredOperatorKey0123456789-ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        }
    )
    assert "REDACTED:high_entropy" in ids["id"]
    assert "ZzRegisteredOperatorKey" not in ids["model"] and "REDACTED:credential" in ids["model"]
    assert "REDACTED:github_token" in ids["model"]
    nested = adapter._redact_ids({"model": {"name": "Meta-Llama-3-8B-Instruct-XyZ987"}})
    assert "REDACTED:high_entropy" in str(nested["model"]), "a non-string model gets it all"


async def test_a_capped_llama_with_declared_capabilities_stays_capped() -> None:
    """Zero-weight capability evidence must not count as a second layer and lift the cap."""

    declared = Capabilities(tools=True, streaming=True, multimodal=True)
    adapter = wiring._DeclaredCapabilities(
        _openai("llama-3.1-70b-versatile", ["Sure, here is a short answer.", "Sorry, no."]),
        declared,
    )
    fingerprint = await wiring.build_fingerprint_engine().run(adapter)  # type: ignore[arg-type]
    assert fingerprint.family.guess == "meta-llama"
    assert fingerprint.family.confidence <= 0.4


def test_a_self_report_the_combiner_excluded_does_not_lift_the_cap() -> None:
    from ildottore.fingerprint.combine import SPOOF_FLAG
    from ildottore.fingerprint.engine import _from_envelope_only
    from ildottore.fingerprint.layers.behavioral import SELF_REPORT_DETAIL

    evidence = [
        FingerprintEvidence(
            layer="metadata", signal=encode_signal("x", "x-a", "metadata tells"), weight=0.4
        ),
        FingerprintEvidence(
            layer="behavioral", signal=encode_signal("x", None, SELF_REPORT_DETAIL), weight=0.15
        ),
    ]
    assert _from_envelope_only(evidence, "x", [SPOOF_FLAG])
    assert not _from_envelope_only(evidence, "x", [])


def test_a_real_difference_is_not_a_tie() -> None:
    def ev(family: str, weight: float) -> FingerprintEvidence:
        return FingerprintEvidence(
            layer="metadata", signal=encode_signal(family, None, "x"), weight=weight
        )

    assert combine([ev("openai-gpt", 0.4), ev("meta-llama", 0.399)]).family.guess == "openai-gpt"


def test_a_rounding_sized_difference_is_a_tie() -> None:
    def ev(family: str, version: str, weight: float) -> FingerprintEvidence:
        return FingerprintEvidence(
            layer="metadata", signal=encode_signal(family, version, "x"), weight=weight
        )

    thirds = [ev("openai-gpt", f"v{i}", 0.133333) for i in range(3)]
    assert combine([*thirds, ev("meta-llama", "llama-3-8b", 0.4)]).family.guess == "unknown"


async def test_whitespace_alone_does_not_make_replies_different() -> None:
    class _Padded(_Canned):
        async def send(self, request: ModelRequest) -> ModelResponse:
            self.sends += 1
            return ModelResponse(text="Sorry, I can't help." + " " * self.sends)

    evidence = await StatisticalLayer().probe(
        _Padded(), ProbeContext(target_id="padded", signature_pack=load_pack())
    )
    assert evidence == []


def test_two_model_names_of_one_entry_fill_one_slot() -> None:
    from ildottore.fingerprint.layers.metadata import _match
    from ildottore.fingerprint.signatures import SignatureEntry, SignaturePack

    entry = SignatureEntry(
        family="x",
        version="x-1",
        signals={"metadata": ["model=x", "model=x-1", "system_fingerprint"]},
        weights={"metadata": 0.4},
    )
    pack = SignaturePack(pack_version=1, name="overlap", entries=[entry])
    (evidence,) = _match(pack, "model=x-1-2026 system_fingerprint=fp_1")
    assert evidence.weight == 0.4, "both names match, and they still count once"
    (half,) = _match(pack, "model=x-1-2026")
    assert half.weight == 0.2


async def test_an_envelope_only_version_is_no_surer_than_its_family() -> None:
    from ildottore.fingerprint.engine import FingerprintEngine
    from ildottore.fingerprint.layers import default_layers
    from ildottore.fingerprint.signatures import SignatureEntry, SignaturePack

    weights = {"metadata": 0.4}
    pack = SignaturePack(
        pack_version=1,
        name="per-version-names",
        entries=[
            SignatureEntry(
                family="x", version="x-a", signals={"metadata": ["model=x-a"]}, weights=weights
            ),
            SignatureEntry(
                family="x", version="x-b", signals={"metadata": ["model=x-b"]}, weights=weights
            ),
        ],
    )
    for target in (_Constant({"model": "x-a-2026"}), _Canned({"model": "x-a-2026"})):
        fingerprint = await FingerprintEngine(layers=default_layers(), pack=pack).run(target)
        assert fingerprint.family.guess == "x" and fingerprint.version is not None
        assert fingerprint.version.confidence <= fingerprint.family.confidence <= 0.4


def test_a_live_probe_reports_the_target_files_capabilities(tmp_path: object) -> None:
    from pathlib import Path

    from ildottore.shared.models import Target

    base = Path(str(tmp_path))
    scope = base / "scope.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n  - id: live\n    base_url: "http://127.0.0.1:9/v1"\n'
        '    endpoints:\n      - host: "127.0.0.1:9"\n        path_prefixes: ["/v1"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    live = Target(  # type: ignore[call-arg]
        id="live",
        type="chatbot",
        provider="openai",
        endpoint="http://127.0.0.1:9/v1/chat/completions",
        model="m",
        capabilities=Capabilities(tools=False, streaming=False),
    )
    adapter = wiring.build_probe_adapter(wiring.build_scope(scope), live, real_target=live)
    caps = adapter.capabilities()
    assert caps.tools is False and caps.streaming is False
