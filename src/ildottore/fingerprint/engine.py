"""Fingerprint engine orchestrator (u09, contract §5 step 7, ADR-0006).

Runs the composed signal layers against an injected
:class:`~ildottore.shared.protocols.TargetAdapter`, fuses their evidence
(:mod:`ildottore.fingerprint.combine`) and assembles a
:class:`~ildottore.shared.models.ModelFingerprint` - **and stops** (ADR-0006: u09
produces the fingerprint only; the u08 planner consumes it. There is no
``fingerprint/planner.py`` and this engine never builds a ``TestPlan``).

Standalone recognition is the safe default first step (``docs/10 §1``): benign
probes only, gated by the adapter's scope allowlist (an out-of-scope target has the
adapter raise before any probe leaves, contract §7 safety-negative). Every run is
deterministic: a fixed layer order + a seeded probe battery ⇒ a byte-identical
``ModelFingerprint`` on replay (contract §7).
"""

from __future__ import annotations

import json

from ildottore.fingerprint.attribution import parse_signal
from ildottore.fingerprint.base import FingerprintLayer, ProbeContext
from ildottore.fingerprint.combine import SPOOF_FLAG, CombinedFingerprint, combine
from ildottore.fingerprint.layers import default_layers
from ildottore.fingerprint.layers.behavioral import SELF_REPORT_DETAIL
from ildottore.fingerprint.layers.capability import capability_guess
from ildottore.fingerprint.layers.carrier import CARRIER_PROBE_DETAIL, effective_mutators
from ildottore.fingerprint.layers.guardrail import GUARDRAIL_PROFILE_DETAIL
from ildottore.fingerprint.signatures import SignaturePack, load_pack
from ildottore.shared.models import (
    Capabilities,
    FingerprintEvidence,
    FingerprintGuess,
    JsonDict,
    ModelFingerprint,
    ModelRequest,
    ModelResponse,
)
from ildottore.shared.protocols import TargetAdapter

__all__ = ["FingerprintEngine", "fingerprint"]


class FingerprintEngine:
    """Composes signal layers into a :class:`ModelFingerprint` (contract §5 step 7).

    Layers and the signature pack are injected for testability + pluggable
    extension (contract §1); defaults are the six self-contained built-in layers and
    the in-repo MVP-1 pack. The **seventh**, the carrier layer, probes with u05's
    mutators and u09 may not import them, so the composition root
    (``cli.wiring.build_fingerprint_engine``) appends it with the registry injected:
    a ``FingerprintEngine()`` built here therefore has six layers and the one the CLI
    builds has seven. The engine holds no per-run state (a fresh :class:`ProbeContext`
    is built per call) so one engine instance can fingerprint many targets.
    """

    def __init__(
        self,
        *,
        layers: list[FingerprintLayer] | None = None,
        pack: SignaturePack | None = None,
    ) -> None:
        self._layers = layers if layers is not None else default_layers()
        self._pack = pack if pack is not None else load_pack()

    @property
    def layers(self) -> list[FingerprintLayer]:
        """The composed layer list (read-only; the CLI prices a pass off it)."""

        return list(self._layers)

    async def run(self, adapter: TargetAdapter) -> ModelFingerprint:
        """Probe ``adapter`` with every layer and assemble the fingerprint.

        Layer order is fixed (determinism). Any layer's evidence is appended in
        order, so the assembled ``evidence`` list is byte-stable across replays.
        """

        target_id = adapter.id
        ctx = ProbeContext(target_id=target_id, signature_pack=self._pack)

        # The carrier layer's probes are left out of the check: a target can answer carriers
        # differently (that is what comprehension measures) and every attributing probe alike.
        recorder = _RecordingAdapter(adapter)
        evidence: list[FingerprintEvidence] = []
        for layer in self._layers:
            target_for_layer = adapter if layer.layer == _CARRIER_LAYER else recorder
            evidence.extend(await layer.probe(target_for_layer, ctx))

        fused = combine(evidence)
        if recorder.non_discriminating():
            # Every attributing probe got the same text, so nothing the text layers matched
            # came from the model: a constant mock was named meta-llama at 0.67 and a
            # refuse-all target llama-3-8b with a 2023-03 cutoff (audit 2026-10-03, R16). The
            # response ENVELOPE (a provider's `model` field) is not text and still counts, so
            # only the metadata layer's evidence is kept; without it, unknown, and said so.
            from_envelope = _from_model_field(evidence)
            cap = self._metadata_weight(from_envelope.family.guess)
            fused = CombinedFingerprint(
                family=_capped(from_envelope.family, cap),
                version=(
                    None if from_envelope.version is None else _capped(from_envelope.version, cap)
                ),
                spoofing_flags=[*fused.spoofing_flags, NON_DISCRIMINATING_FLAG],
            )
        elif _from_envelope_only(evidence, fused.family.guess, fused.spoofing_flags):
            # The same cap when the replies differed but only the envelope named the family (a
            # canned responder whose `model` says gpt-4o was 0.44, surer than a constant one).
            cap = self._metadata_weight(fused.family.guess)
            fused = CombinedFingerprint(
                family=_capped(fused.family, cap),
                version=None if fused.version is None else _capped(fused.version, cap),
                spoofing_flags=fused.spoofing_flags,
            )
        guardrails = _guardrails_from_evidence(evidence)
        caps = capability_guess(adapter.capabilities())
        # The one key the PLANNER reads (``core.planner._order_family_effective``). Without
        # it, adaptive mode reordered nothing and ``-sV`` bought a fingerprint that changed
        # no part of the battery: a probe pass with real cost and no consequence.
        carriers = _carriers_from_evidence(evidence)
        if carriers:
            caps["effective_mutators"] = carriers
        version = _with_cutoff(fused, self._pack)

        return ModelFingerprint(
            target_id=target_id,
            family=fused.family,
            version=version,
            capability_guess=caps,
            guardrails=guardrails,
            evidence=evidence,
            spoofing_flags=fused.spoofing_flags,
            recommended_plan_ref=None,  # ADR-0006: u08 owns plan building.
        )

    def _metadata_weight(self, family: str) -> float:
        """The pack's largest metadata weight for ``family``: the cap of an envelope-only name.

        An attribution from the envelope alone has a share of the mass of 1 by construction
        (nothing else is kept), so a constant target whose envelope said gpt-4o was named at
        0.52 on that one field (audit of the fingerprint).
        """

        return max(
            (e.weights.get(_METADATA_LAYER, 0.0) for e in self._pack.entries if e.family == family),
            default=0.0,
        )


#: Flag set when the target answered every attributing probe identically: the text layers had
#: no signal, so the family comes from the response envelope alone or is unknown.
NON_DISCRIMINATING_FLAG = "non_discriminating_target"

_CARRIER_LAYER = "carrier"
_METADATA_LAYER = "metadata"

#: Fewer answered probes than this is too little to call a target constant.
_MIN_PROBES_FOR_CONSTANT = 3


def _from_envelope_only(evidence: list[FingerprintEvidence], family: str, flags: list[str]) -> bool:
    """True if every counted piece of evidence for ``family`` is from the metadata layer.

    A self-report the combiner left out (it conflicted with the statistical layer) is not
    counted here either.
    """

    excluded_self_report = SPOOF_FLAG in flags
    layers = {
        ev.layer
        for ev in evidence
        if ev.weight > 0
        and parse_signal(ev.signal).family == family
        and not (excluded_self_report and parse_signal(ev.signal).detail == SELF_REPORT_DETAIL)
    }
    return layers == {_METADATA_LAYER}


def _capped(guess: FingerprintGuess, cap: float) -> FingerprintGuess:
    """``guess`` with its confidence lowered to ``cap`` when above it.

    Applied to the version too, so a custom pack cannot make the version surer than the family.
    """

    if guess.confidence <= cap:
        return guess
    return guess.model_copy(update={"confidence": cap})


def _from_model_field(evidence: list[FingerprintEvidence]) -> CombinedFingerprint:
    """Attribute from the envelope's ``model`` field alone, for a target with no text signal.

    Only metadata evidence that matched a ``model=`` fragment names the model. The rest of the
    envelope does not: ``finish_reason=stop`` was in the meta-llama signature (dropped since)
    and every OpenAI-compatible server sends it, so a constant target behind such a server was
    still named meta-llama with a 2023-03 cutoff (re-audit of R16). A version is kept only when one
    clearly leads (the combiner gives none on a tie).
    """

    kept = [
        ev
        for ev in evidence
        if ev.layer == _METADATA_LAYER and "model=" in parse_signal(ev.signal).detail
    ]
    return combine(kept)


class _RecordingAdapter:
    """Passes every probe through and keeps the reply texts, to see whether they ever differ."""

    def __init__(self, inner: TargetAdapter) -> None:
        self._inner = inner
        self.id = inner.id
        self.texts: list[str] = []

    async def send(self, request: ModelRequest) -> ModelResponse:
        response = await self._inner.send(request)
        self.texts.append((response.text or "").strip())
        return response

    def capabilities(self) -> Capabilities:
        return self._inner.capabilities()

    def non_discriminating(self) -> bool:
        return len(self.texts) >= _MIN_PROBES_FOR_CONSTANT and len(set(self.texts)) <= 1


def _guardrails_from_evidence(evidence: list[FingerprintEvidence]) -> JsonDict:
    """Recover the guardrail profile the guardrail layer emitted (JSON detail)."""

    prefix = f"{GUARDRAIL_PROFILE_DETAIL}="
    for ev in evidence:
        if ev.layer == "guardrail" and ev.signal.startswith(prefix):
            raw = ev.signal.split("=", 1)[1]
            try:
                parsed = json.loads(raw)
            except ValueError:
                return {}
            if isinstance(parsed, dict):
                return parsed
    return {}


def _carriers_from_evidence(evidence: list[FingerprintEvidence]) -> list[str]:
    """Order the carriers this target still understands, best-first (see ``layers/carrier``)."""

    prefix = f"{CARRIER_PROBE_DETAIL}="
    for ev in evidence:
        if ev.layer == "carrier" and ev.signal.startswith(prefix):
            try:
                parsed = json.loads(ev.signal.split("=", 1)[1])
            except ValueError:
                return []
            if isinstance(parsed, dict):
                return effective_mutators(
                    {str(k): float(v) for k, v in parsed.items() if isinstance(v, (int, float))}
                )
    return []


def _with_cutoff(fused: CombinedFingerprint, pack: SignaturePack) -> FingerprintGuess | None:
    """Attach the pack's ``cutoff_hint`` to the version guess when one is known.

    ``combine`` produces the version guess from evidence only; the human-readable
    cutoff hint lives in the pack, so the engine enriches the guess post-fusion
    (keeping ``combine`` pack-free).
    """

    version = fused.version
    if version is None:
        return None
    for entry in pack.entries:
        if (
            entry.family == fused.family.guess
            and entry.version == version.guess
            and entry.cutoff_hint is not None
        ):
            return FingerprintGuess(
                guess=version.guess,
                confidence=version.confidence,
                cutoff_hint=entry.cutoff_hint,
            )
    return version


async def fingerprint(adapter: TargetAdapter) -> ModelFingerprint:
    """Convenience: fingerprint ``adapter`` with the default engine (standalone mode)."""

    return await FingerprintEngine().run(adapter)
