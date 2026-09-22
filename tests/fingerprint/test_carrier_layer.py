"""The carrier layer: the signal that makes ``-sV`` change the battery (u09 + u08).

`-sV` had two documented jobs: recognise the model and tailor the plan. The second was
**inert**: `core.planner._order_family_effective` reads
`capability_guess["effective_mutators"]` and nothing ever wrote it, so a fingerprint was
bought with real requests and changed nothing. These tests pin both halves of the fix: the
layer measures something real, and the measurement reaches the plan.
"""

from __future__ import annotations

import asyncio

import pytest

from ildottore.cli import wiring
from ildottore.core.planner import build_plan
from ildottore.fingerprint import FingerprintEngine
from ildottore.fingerprint.layers import CarrierLayer, default_layers
from ildottore.fingerprint.layers.carrier import (
    CARRIER_MARKER,
    CARRIER_PROBE_DETAIL,
    effective_mutators,
)
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse


class _Carrier:
    """A mutator stand-in: tags the prompt so the fake target can recognise it."""

    def __init__(self, name: str, *, raises: bool = False) -> None:
        self.name = name
        self._raises = raises

    def mutate(self, text: str, seed: str) -> str:
        if self._raises:
            raise RuntimeError("this plugin is broken")
        return f"[{self.name}] {text}"


class _Target:
    """Understands only the carriers in ``understands``; answers everything else blankly."""

    id = "picky"

    def __init__(self, understands: set[str]) -> None:
        self._understands = understands
        self.sent: list[str] = []

    async def send(self, request: ModelRequest) -> ModelResponse:
        probe = str((request.metadata or {}).get("probe", ""))
        self.sent.append(probe)
        name = probe.removeprefix("carrier_")
        if probe.startswith("carrier_") and name in self._understands:
            return ModelResponse(text=CARRIER_MARKER)
        return ModelResponse(text="I do not understand that.")

    def capabilities(self) -> Capabilities:
        return Capabilities()


def _probe(target: _Target, mutators: list[_Carrier]) -> dict[str, float]:
    from ildottore.fingerprint.base import ProbeContext

    layer = CarrierLayer(mutators)  # type: ignore[arg-type]
    ctx = ProbeContext(target_id=target.id, signature_pack=None)
    evidence = asyncio.run(layer.probe(target, ctx))  # type: ignore[arg-type]
    detail = next(e for e in evidence if e.signal.startswith(f"{CARRIER_PROBE_DETAIL}="))
    import json

    return dict(json.loads(detail.signal.split("=", 1)[1]))


def test_the_layer_measures_which_carriers_the_target_recovers() -> None:
    """One probe per carrier, scored by whether the benign instruction survived it."""

    target = _Target({"base64_wrap", "rot13"})
    scores = _probe(target, [_Carrier(n) for n in ("base64_wrap", "leetspeak", "rot13")])

    assert scores == {"base64_wrap": 1.0, "leetspeak": 0.0, "rot13": 1.0}
    assert target.sent == ["carrier_base64_wrap", "carrier_leetspeak", "carrier_rot13"]


def test_a_broken_mutator_is_recorded_not_skipped() -> None:
    """A third-party plugin that raises scores zero and says so, and does not sink the pass."""

    from ildottore.fingerprint.base import ProbeContext

    layer = CarrierLayer([_Carrier("good"), _Carrier("broken", raises=True)])  # type: ignore[arg-type]
    evidence = asyncio.run(
        layer.probe(_Target({"good"}), ProbeContext(target_id="t", signature_pack=None))
    )  # type: ignore[arg-type]

    signals = " ".join(e.signal for e in evidence)
    assert '"broken": 0.0' in signals
    assert "carrier_errors=" in signals and "RuntimeError" in signals


def test_the_ordering_is_deterministic_and_omits_what_broke() -> None:
    """The planner treats the list as a priority hint, so an unusable carrier is not listed."""

    assert effective_mutators({"z": 1.0, "a": 1.0, "m": 0.0}) == ["a", "z"]
    assert effective_mutators({}) == []


def test_the_carrier_layer_is_wired_by_the_composition_root_only() -> None:
    """u09 may not import u05's mutators, so the engine's default list cannot hold it.

    `default_layers()` is the six self-contained layers; `cli.wiring` injects the registry.
    The import contract (`fingerprint -> mutators` forbidden) is what forces this seam, and
    it is worth a test because the obvious implementation breaks it.
    """

    assert not any(isinstance(layer, CarrierLayer) for layer in default_layers())
    assert any(
        isinstance(layer, CarrierLayer) for layer in wiring.build_fingerprint_engine().layers
    )


def test_the_fingerprint_reorders_the_real_plan() -> None:
    """The headline: `-sV` changes the battery now, and this is the assertion that proves it.

    Before this layer, a plan built from a fingerprint was **byte-identical** to one built
    without it, except for the wording of each selection's `reason`.
    """

    from ildottore.shared.models import AttackSpec

    carriers = [_Carrier(n) for n in ("base64_wrap", "leetspeak", "rot13", "unicode_confusable")]
    engine = FingerprintEngine(layers=[*default_layers(), CarrierLayer(carriers)])  # type: ignore[arg-type]
    fingerprint = asyncio.run(engine.run(_Target({"rot13", "base64_wrap"})))  # type: ignore[arg-type]

    assert fingerprint.capability_guess["effective_mutators"] == ["base64_wrap", "rot13"]

    spec = _spec_with(["leetspeak", "unicode_confusable", "rot13", "base64_wrap"])
    plain = build_plan([spec], None, Capabilities(), target_id="t", plan_ref="p", adaptive=False)
    tuned = build_plan(
        [spec], fingerprint, Capabilities(), target_id="t", plan_ref="p", adaptive=True
    )

    assert plain.selected[0].mutators == [
        "identity",
        "leetspeak",
        "unicode_confusable",
        "rot13",
        "base64_wrap",
    ]
    assert tuned.selected[0].mutators == [
        "identity",
        "base64_wrap",
        "rot13",
        "leetspeak",
        "unicode_confusable",
    ], "the carriers this target understands must run first"
    assert isinstance(spec, AttackSpec)


def _spec_with(mutations: list[str]):  # type: ignore[no-untyped-def]
    import pathlib

    import yaml

    from ildottore.shared.models import AttackSpec

    raw = yaml.safe_load(
        pathlib.Path("specs/attacks/JB-ENCODING-001.yaml").read_text(encoding="utf-8")
    )
    return AttackSpec.model_validate(raw).model_copy(update={"mutations": mutations})


def test_the_probes_are_paced_like_attack_traffic(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fingerprint pass is ~24 requests and they used to leave unpaced.

    They do not travel through the runner, so the S8 ceiling was enforced on the attack path
    and nowhere else.
    """

    acquired: list[int] = []

    class _CountingLimiter:
        def __init__(self, *_a: object, **_k: object) -> None: ...

        async def acquire(self) -> None:
            acquired.append(1)

    monkeypatch.setattr(wiring, "RateLimiter", _CountingLimiter)
    target = _Target(set())
    monkeypatch.setattr(wiring, "build_probe_adapter", lambda *a, **k: target)
    monkeypatch.setattr(
        wiring,
        "build_fingerprint_engine",
        lambda: FingerprintEngine(layers=[CarrierLayer([_Carrier("a"), _Carrier("b")])]),  # type: ignore[arg-type]
    )

    from ildottore.shared.models import Target as TargetModel

    wiring.fingerprint_probe(
        None,  # type: ignore[arg-type]
        TargetModel(id="picky", type="chatbot"),  # type: ignore[arg-type]
        rate_rps=5.0,
    )
    assert len(acquired) == 2, "every probe passes the rate gate"
