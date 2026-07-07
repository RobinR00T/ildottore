"""Engine orchestration, detection gate, determinism, spoofing, safety (u09 §7)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.fingerprint.combine import combine, rank_families, rank_versions
from ildottore.fingerprint.engine import FingerprintEngine, fingerprint
from ildottore.fingerprint.layers import default_layers
from ildottore.fingerprint.signatures import CorpusCase, SignaturePack, load_corpus
from ildottore.shared.models import Capabilities, ModelFingerprint, ModelRequest, ModelResponse
from tests.fingerprint.conftest import CorpusAdapter

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "fingerprint"


# --- basic orchestration ---------------------------------------------------------


async def test_default_engine_has_six_layers() -> None:
    assert len(default_layers()) == 6


async def test_fingerprint_convenience_runs(corpus: list[CorpusCase]) -> None:
    case = corpus[0]
    fp = await fingerprint(CorpusAdapter(case))
    assert isinstance(fp, ModelFingerprint)
    assert fp.target_id == case.case_id
    # ADR-0006: u09 never builds a plan
    assert fp.recommended_plan_ref is None


async def test_fingerprint_carries_capability_guess_and_guardrails(
    corpus: list[CorpusCase],
) -> None:
    case = next(c for c in corpus if c.case_id == "gpt-4o-clean")
    adapter = CorpusAdapter(case, capabilities=Capabilities(tools=True, streaming=True))
    fp = await FingerprintEngine().run(adapter)
    assert fp.capability_guess["tools"] is True
    assert fp.capability_guess["streaming"] is True
    # guardrail profile recovered from the guardrail layer
    assert "refusal_style" in fp.guardrails


async def test_version_guess_carries_cutoff_hint(corpus: list[CorpusCase]) -> None:
    case = next(c for c in corpus if c.case_id == "gpt-4o-clean")
    fp = await FingerprintEngine().run(CorpusAdapter(case))
    assert fp.version is not None
    assert fp.version.cutoff_hint == "2023-10"


# --- detection gate (contract §7 / docs/10 §6) -----------------------------------


async def _fingerprint_all(corpus: list[CorpusCase]) -> list[tuple[CorpusCase, ModelFingerprint]]:
    eng = FingerprintEngine()
    return [(c, await eng.run(CorpusAdapter(c))) for c in corpus]


async def test_family_precision_and_recall(corpus: list[CorpusCase]) -> None:
    results = await _fingerprint_all(corpus)
    families = sorted({c.family for c in corpus})
    tp = fp_ = fn = 0
    for case, result in results:
        guess = result.family.guess
        if guess == case.family:
            tp += 1
        else:
            fn += 1
            if guess in families:
                fp_ += 1
    precision = tp / (tp + fp_) if (tp + fp_) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    assert precision >= 0.90, f"family precision {precision}"
    assert recall >= 0.85, f"family recall {recall}"


async def test_version_top1_and_top3(corpus: list[CorpusCase]) -> None:
    eng = FingerprintEngine()
    top1 = top3 = total = 0
    for case in corpus:
        if case.version is None:
            continue
        total += 1
        # run layers to get evidence, then rank
        fp = await eng.run(CorpusAdapter(case))
        assert fp.version is not None
        if fp.version.guess == case.version:
            top1 += 1
        ranked = rank_versions(fp.evidence, case.family)
        if case.version in ranked[:3]:
            top3 += 1
    assert total > 0
    assert top1 / total >= 0.70, f"version top-1 {top1}/{total}"
    assert top3 / total >= 0.90, f"version top-3 {top3}/{total}"


async def test_rank_families_puts_true_family_first(corpus: list[CorpusCase]) -> None:
    eng = FingerprintEngine()
    for case in corpus:
        fp = await eng.run(CorpusAdapter(case))
        assert rank_families(fp.evidence)[0] == case.family


# --- determinism (contract §7) ---------------------------------------------------


async def test_replay_is_byte_identical(corpus: list[CorpusCase]) -> None:
    case = corpus[0]
    a = await FingerprintEngine().run(CorpusAdapter(case))
    b = await FingerprintEngine().run(CorpusAdapter(case))
    assert a.model_dump_json() == b.model_dump_json()


async def test_matches_committed_golden() -> None:
    golden_path = _FIXTURES / "golden" / "gpt-4o-clean.json"
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    case = next(c for c in load_corpus() if c.case_id == "gpt-4o-clean")
    adapter = CorpusAdapter(
        case,
        capabilities=Capabilities(tools=True, streaming=True),
        target_id="golden-target",
    )
    fp = await FingerprintEngine().run(adapter)
    assert json.loads(fp.model_dump_json()) == golden


# --- spoofing honesty (contract §7) ----------------------------------------------


async def test_spoofed_self_id_never_silently_wins() -> None:
    cases = load_corpus(_FIXTURES / "spoofed" / "cases.yaml")
    eng = FingerprintEngine()
    spoof_seen = 0
    for case in cases:
        fp = await eng.run(CorpusAdapter(case))
        # family always resolves to the ground-truth (statistical) family
        assert fp.family.guess == case.family
        if case.spoofed:
            spoof_seen += 1
            assert "self_report_conflicts_with_statistical" in fp.spoofing_flags
        else:
            assert "self_report_conflicts_with_statistical" not in fp.spoofing_flags
    assert spoof_seen >= 1  # the fixture actually exercised a spoof


# --- safety-negative (contract §7 / §8) ------------------------------------------


class _RefusingAdapter:
    """An out-of-scope target whose adapter refuses before any probe leaves."""

    id = "out-of-scope"

    def __init__(self) -> None:
        self.calls = 0

    def capabilities(self) -> Capabilities:
        return Capabilities()

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        raise PermissionError("endpoint not allowed by scope")


async def test_adapter_refusal_propagates_no_probe_masked() -> None:
    adapter = _RefusingAdapter()
    with pytest.raises(PermissionError):
        await FingerprintEngine().run(adapter)
    # the refusal came from the first probe; the engine did not swallow it
    assert adapter.calls == 1


async def test_engine_emits_only_benign_probes(corpus: list[CorpusCase]) -> None:
    # capture every prompt the engine sends and assert none carry attack markers
    sent: list[str] = []

    class _Recording(CorpusAdapter):
        async def send(self, request: ModelRequest) -> ModelResponse:
            if request.prompt:
                sent.append(request.prompt.lower())
            return await super().send(request)

    await FingerprintEngine().run(_Recording(corpus[0]))
    assert sent  # probes were actually sent
    banned = ("ignore previous", "jailbreak", "do anything now", "exfiltrate", "system prompt:")
    for prompt in sent:
        assert not any(marker in prompt for marker in banned)


def test_combine_and_rank_are_pure_reexports() -> None:
    # smoke: the public combine/rank helpers import cleanly for downstream u08
    assert callable(combine)
    assert callable(rank_families)
    assert callable(rank_versions)


async def test_unknown_target_yields_low_confidence() -> None:
    # a target with empty responses matches (at most) a weak capability tell — the
    # verdict must be honestly low-confidence, never a confident fabrication, and
    # carry no version guess (contract §4 KEEP).
    blank = CorpusCase(case_id="blank", family="none", responses={})
    fp = await FingerprintEngine().run(CorpusAdapter(blank))
    assert fp.family.confidence < 0.5
    assert fp.version is None


def test_signature_pack_fixture_is_the_real_pack(pack: SignaturePack) -> None:
    assert pack.name == "ildottore-mvp1"
