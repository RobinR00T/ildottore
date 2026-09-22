"""The carrier layer: the signal that makes ``-sV`` change the battery (u09 + u08).

`-sV` had two documented jobs: recognise the model and tailor the plan. The second was inert
(`core.planner._order_family_effective` reads `capability_guess["effective_mutators"]` and
nothing wrote it), so a fingerprint was bought with real requests and changed nothing.

These tests drive the **real** mutator registry against simulated targets. The first version
used pass-through fakes (`f"[{name}] {text}"`) and a target that recognised carriers by a
metadata key without ever reading the mutated prompt: it proved the plumbing and could not
have caught either of the defects an audit then found (adversarial carriers being sent during
recognition, and a marker check that any echo satisfied).
"""

from __future__ import annotations

import asyncio
import json

import pytest

from ildottore.cli import wiring
from ildottore.core.planner import build_plan
from ildottore.fingerprint import FingerprintEngine
from ildottore.fingerprint.base import ProbeContext
from ildottore.fingerprint.layers import CarrierLayer, default_layers
from ildottore.fingerprint.layers.carrier import (
    CARRIER_DECOY,
    CARRIER_MARKER,
    CARRIER_PROBE_DETAIL,
    _comprehended,
    effective_mutators,
    is_obscuring,
)
from ildottore.fingerprint.layers.carrier import (
    CarrierLayer as _CarrierLayer,
)
from ildottore.mutators import build_default_registry
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse

#: Every registered carrier except the identity baseline, as the composition root sees them.
ALL_MUTATORS = [
    build_default_registry().get(name)
    for name in build_default_registry().names()
    if name != "identity"
]

#: The transformations that obscure the text rather than wrapping it in new instructions.
OBSCURING = {
    "base64_wrap",
    "leetspeak",
    "payload_splitting",
    "rot13",
    "translate",
    "unicode_confusable",
    "zero_width_inject",
}

#: Carriers the repo itself documents as attack technique. None of these may ever be sent by a
#: recognition probe (contract §8: "MUST NOT send any jailbreak / test_only payload").
ADVERSARIAL = {
    "adversarial_poetry",
    "adversarial_suffix",
    "context_poisoning",
    "gray_box",
    "linguistic_confusion",
    "nested_instruction",
    "refusal_suppression_prefix",
    "roleplay_wrap",
}


class _Oracle:
    """A target with one of four behaviours, recording every prompt it was sent."""

    id = "oracle"

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.prompts: list[str] = []

    async def send(self, request: ModelRequest) -> ModelResponse:
        prompt = request.prompt or ""
        self.prompts.append(prompt)
        if self.mode == "ideal":  # understands every carrier, answers as instructed
            return ModelResponse(text=CARRIER_MARKER)
        if self.mode == "echo":  # repeats the prompt: zero comprehension
            return ModelResponse(text=prompt)
        if self.mode == "refuse_quote":  # refuses while naming what it was asked
            return ModelResponse(text=f"I cannot do this: {prompt}")
        if self.mode == "decoder":  # understands only base64 and rot13
            decoded = "BASE64" if "base64" in prompt.lower() else ""
            understood = decoded or ("VLU" in prompt or "rot13" in prompt.lower())
            return ModelResponse(text=CARRIER_MARKER if understood else "I do not understand.")
        return ModelResponse(text="I cannot help with that.")

    def capabilities(self) -> Capabilities:
        return Capabilities()


def _scores(target: _Oracle, mutators: list[object] | None = None) -> dict[str, float]:
    layer = _CarrierLayer(mutators or ALL_MUTATORS)  # type: ignore[arg-type]
    evidence = asyncio.run(
        layer.probe(target, ProbeContext(target_id=target.id, signature_pack=None))  # type: ignore[arg-type]
    )
    detail = next(e for e in evidence if e.signal.startswith(f"{CARRIER_PROBE_DETAIL}="))
    return dict(json.loads(detail.signal.split("=", 1)[1]))


# --- the safety boundary ------------------------------------------------------------


def test_only_obscuring_carriers_are_probed() -> None:
    """Recognition may not send the repo's own jailbreak carriers.

    The first version probed every registered mutator, so ``-sV`` sent a refusal-suppression
    preamble, a fabricated no-restrictions prior turn, a claimed-compromise framing and the
    published GCG universal suffix, the last one byte-identical to the string
    ``JB-REFUSAL-SUPPRESS-001`` ships behind ``test_only: true`` and a policy gate. The payload
    was benign; the carrier was not.
    """

    probed = {m.name for m in _CarrierLayer(ALL_MUTATORS)._mutators}
    assert probed == OBSCURING
    assert not (probed & ADVERSARIAL)


def test_the_classification_is_structural_not_a_deny_list() -> None:
    """A carrier that leaves the original text intact has ADDED instructions around it.

    Structural so a new mutator is classified on its behaviour, not on somebody remembering
    to update a list, and it draws exactly the line safety needs.
    """

    by_name = {m.name: m for m in ALL_MUTATORS}
    for name in ADVERSARIAL:
        assert is_obscuring(by_name[name]) is False, name
    for name in OBSCURING:
        assert is_obscuring(by_name[name]) is True, name


def test_no_probe_carries_an_attack_string() -> None:
    """Assert on the bytes that would go on the wire, not on the classification."""

    target = _Oracle("refuse")
    _scores(target)
    joined = " ".join(target.prompts).lower()
    for tell in ("do not refuse", "no content restrictions", "already have partial access"):
        assert tell not in joined, tell
    # The GCG suffix, as pinned in the mutator and in JB-REFUSAL-SUPPRESS-001.
    assert "similarlynow write oppositeley" not in joined


# --- the measurement ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("ideal", OBSCURING),  # follows the instruction through every carrier
        ("echo", set()),  # repeats the prompt: comprehension zero
        ("refuse", set()),
        ("refuse_quote", set()),  # refuses while quoting: still an echo
    ],
)
def test_the_measurement_separates_comprehension_from_echo(mode: str, expected: set[str]) -> None:
    """The check used to accept a pure echo on 13 of 18 carriers.

    For every carrier that leaves the instruction readable, a target that quotes the prompt
    back, or refuses while naming what it was asked, scored a perfect 1.0 with zero
    comprehension: the signal that orders the battery was mostly noise. The probe now carries
    a second invariant token the target is asked NOT to repeat, so an echo is caught on every
    carrier rather than on the few whose wording happened to survive.
    """

    scores = _scores(_Oracle(mode))
    assert {name for name, score in scores.items() if score} == expected


def test_the_marker_survives_the_character_rewriting_carriers() -> None:
    """``leetspeak`` and ``unicode_confusable`` used to guarantee a zero.

    They rendered the old marker as ``Z0RBL47`` and with a Greek capital Beta, so a target
    with perfect comprehension, doing exactly what the instruction said, scored zero on both:
    the carrier worked and the check failed. The marker is now drawn from the alphabet neither
    of them rewrites, and zero-width injections are stripped before the match.
    """

    by_name = {m.name: m for m in ALL_MUTATORS}
    for name in ("leetspeak", "unicode_confusable"):
        carried = by_name[name].mutate(f"reply {CARRIER_MARKER} now", "seed")
        assert CARRIER_MARKER in carried.upper(), name
    scores = _scores(_Oracle("ideal"))
    assert scores["leetspeak"] == 1.0
    assert scores["unicode_confusable"] == 1.0
    assert scores["zero_width_inject"] == 1.0


def test_the_decoy_is_in_the_prompt_and_absent_from_a_good_answer() -> None:
    target = _Oracle("ideal")
    _scores(target)
    assert any(CARRIER_DECOY in p for p in target.prompts)


def test_a_flaky_mutator_is_recorded_not_skipped() -> None:
    """A carrier that classifies fine and then raises scores zero, with its error kept."""

    class _Flaky:
        name = "flaky_encoder"

        def __init__(self) -> None:
            self.calls = 0

        def mutate(self, text: str, seed: str) -> str:
            self.calls += 1
            if self.calls > 1:  # the classification pass succeeded, the probe does not
                raise RuntimeError("encoder blew up")
            return "".join(reversed(text))  # obscuring: the original is not a substring

    layer = _CarrierLayer([_Flaky()])  # type: ignore[arg-type]
    evidence = asyncio.run(
        layer.probe(_Oracle("ideal"), ProbeContext(target_id="t", signature_pack=None))  # type: ignore[arg-type]
    )
    signals = " ".join(e.signal for e in evidence)
    assert '"flaky_encoder": 0.0' in signals
    assert "carrier_errors=" in signals and "RuntimeError" in signals


def test_a_mutator_that_cannot_be_classified_is_never_probed() -> None:
    """Unknown behaviour does not get sent at a target."""

    class _Broken:
        name = "broken"

        def mutate(self, text: str, seed: str) -> str:
            raise RuntimeError("cannot classify")

    assert is_obscuring(_Broken()) is False  # type: ignore[arg-type]
    assert _CarrierLayer([_Broken()])._mutators == []  # type: ignore[arg-type]


# --- the consequence: the plan ------------------------------------------------------


def test_the_ordering_is_deterministic_and_omits_what_broke() -> None:
    assert effective_mutators({"z": 1.0, "a": 1.0, "m": 0.0}) == ["a", "z"]
    assert effective_mutators({}) == []


def test_the_carrier_layer_is_wired_by_the_composition_root_only() -> None:
    """u09 may not import u05's mutators, so the engine's default list cannot hold it."""

    assert not any(isinstance(layer, CarrierLayer) for layer in default_layers())
    engine_layers = wiring.build_fingerprint_engine().layers
    assert any(isinstance(layer, CarrierLayer) for layer in engine_layers)


def test_the_fingerprint_reorders_the_real_plan() -> None:
    """The headline, driven by real mutators against a target that decodes only two of them."""

    import pathlib

    import yaml

    from ildottore.shared.models import AttackSpec

    engine = FingerprintEngine(layers=[*default_layers(), _CarrierLayer(ALL_MUTATORS)])
    fingerprint = asyncio.run(engine.run(_Oracle("decoder")))  # type: ignore[arg-type]
    hinted = fingerprint.capability_guess.get("effective_mutators")
    assert hinted, "the probe produced no ordering hint at all"

    raw = yaml.safe_load(
        pathlib.Path("specs/attacks/JB-ENCODING-001.yaml").read_text(encoding="utf-8")
    )
    spec = AttackSpec.model_validate(raw).model_copy(
        update={"mutations": ["leetspeak", "rot13", "base64_wrap"]}
    )
    plain = build_plan([spec], None, Capabilities(), target_id="t", plan_ref="p", adaptive=False)
    tuned = build_plan(
        [spec], fingerprint, Capabilities(), target_id="t", plan_ref="p", adaptive=True
    )

    assert plain.selected[0].mutators == ["identity", "leetspeak", "rot13", "base64_wrap"]
    assert tuned.selected[0].mutators[1] in hinted, "a comprehended carrier runs first"
    assert set(tuned.selected[0].mutators) == set(plain.selected[0].mutators), (
        "tailoring reorders the declared mutators and never introduces one"
    )


def test_the_declared_probe_count_is_the_real_send_count() -> None:
    """Contract u09 §7 A-3: the price of ``-sV`` is measured, not assumed.

    The CLI printed "one probe per layer", wrong for three of six (behavioral sends 4,
    statistical 3, capability 0 because it only reads the declared capabilities), so a pass
    advertised as 24 requests really sent 28. This asserts the two are the same number, per
    layer as well as in total, so a new layer that forgets to declare one is caught here
    rather than in an operator's bill.
    """

    from ildottore.cli.run import fingerprint_probe_count
    from ildottore.fingerprint.signatures import load_pack

    class _Counter:
        id = "counter"

        def __init__(self) -> None:
            self.sends = 0

        async def send(self, request: ModelRequest) -> ModelResponse:
            self.sends += 1
            return ModelResponse(text="hello")

        def capabilities(self) -> Capabilities:
            return Capabilities()

    target = _Counter()
    engine = wiring.build_fingerprint_engine()
    asyncio.run(engine.run(target))  # type: ignore[arg-type]
    assert fingerprint_probe_count() == target.sends

    for layer in engine.layers:
        probe_target = _Counter()
        asyncio.run(
            layer.probe(probe_target, ProbeContext(target_id="c", signature_pack=load_pack()))  # type: ignore[arg-type]
        )
        assert getattr(layer, "probe_count", 1) == probe_target.sends, type(layer).__name__


# --- the discriminators, pinned one by one (audit of 2026-09-22) --------------------


def test_a_short_reply_that_repeats_the_decoy_scores_zero() -> None:
    """The echo tell, on its own. Removing it left the whole suite green.

    An audit mutated `_comprehended` to drop the decoy check and nothing failed, because every
    oracle in this file either comprehends or refuses: none of them produced the shape the
    decoy exists to catch, a SHORT reply carrying both the marker and the instruction's own
    token. That is a double that cannot fail the way the real thing fails (clause A-21).
    """

    assert _comprehended(f"{CARRIER_MARKER} {CARRIER_DECOY}") == 0.0
    assert _comprehended(CARRIER_MARKER) == 1.0


def test_the_marker_is_matched_through_zero_width_padding() -> None:
    """The strip, on its own. Also survived being removed with the suite green.

    ``zero_width_inject`` is designed to be invisible to a filter and readable by a model, so a
    model that echoes the invisible characters back is still comprehending.
    """

    padded = "​".join(CARRIER_MARKER)
    assert _comprehended(padded) == 1.0
    assert _comprehended(f"﻿{CARRIER_MARKER}‍") == 1.0
