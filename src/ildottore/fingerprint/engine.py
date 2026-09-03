"""Fingerprint engine orchestrator (u09, contract §5 step 7, ADR-0006).

Runs the six signal layers against an injected
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

from ildottore.fingerprint.base import FingerprintLayer, ProbeContext
from ildottore.fingerprint.combine import CombinedFingerprint, combine
from ildottore.fingerprint.layers import default_layers
from ildottore.fingerprint.layers.capability import capability_guess
from ildottore.fingerprint.layers.guardrail import GUARDRAIL_PROFILE_DETAIL
from ildottore.fingerprint.signatures import SignaturePack, load_pack
from ildottore.shared.models import (
    FingerprintEvidence,
    FingerprintGuess,
    JsonDict,
    ModelFingerprint,
)
from ildottore.shared.protocols import TargetAdapter

__all__ = ["FingerprintEngine", "fingerprint"]


class FingerprintEngine:
    """Composes signal layers into a :class:`ModelFingerprint` (contract §5 step 7).

    Layers and the signature pack are injected for testability + pluggable
    extension (contract §1); defaults are the six built-in layers and the in-repo
    MVP-1 pack. The engine holds no per-run state (a fresh :class:`ProbeContext` is
    built per call) so one engine instance can fingerprint many targets.
    """

    def __init__(
        self,
        *,
        layers: list[FingerprintLayer] | None = None,
        pack: SignaturePack | None = None,
    ) -> None:
        self._layers = layers if layers is not None else default_layers()
        self._pack = pack if pack is not None else load_pack()

    async def run(self, adapter: TargetAdapter) -> ModelFingerprint:
        """Probe ``adapter`` with every layer and assemble the fingerprint.

        Layer order is fixed (determinism). Any layer's evidence is appended in
        order, so the assembled ``evidence`` list is byte-stable across replays.
        """

        target_id = adapter.id
        ctx = ProbeContext(target_id=target_id, signature_pack=self._pack)

        evidence: list[FingerprintEvidence] = []
        for layer in self._layers:
            evidence.extend(await layer.probe(adapter, ctx))

        fused = combine(evidence)
        guardrails = _guardrails_from_evidence(evidence)
        caps = capability_guess(adapter.capabilities())
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
