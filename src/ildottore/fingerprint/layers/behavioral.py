"""Behavioral / active signal layer (u09, contract §5 step 3, ``docs/10 §1``).

Runs the small fixed **benign** behavioral battery (seeded) and matches the
responses against each signature entry's ``signals["behavioral"]`` fragments:
self-identification phrasing, knowledge-cutoff answers, refusal-style phrasing and
formatting idioms - the family "tells" (``docs/10 §1``).

Self-identification is a **weak** signal (contract §2, ``docs/10 §5``). This layer
additionally emits a distinct ``self_report`` evidence carrying the family the
target *claims*; the combiner compares that against the statistical verdict and
raises ``self_report_conflicts_with_statistical`` when they disagree - the
self-report is never allowed to silently win (contract §7 spoofing honesty).
"""

from __future__ import annotations

from ildottore.fingerprint.attribution import encode_signal
from ildottore.fingerprint.base import ProbeContext, seed_for
from ildottore.fingerprint.probes import BEHAVIORAL_BATTERY, build_request
from ildottore.fingerprint.signatures import SignaturePack
from ildottore.shared.models import (
    FingerprintEvidence,
    ModelRequest,
    ModelResponse,
    Sampling,
)
from ildottore.shared.protocols import TargetAdapter

__all__ = ["SELF_REPORT_DETAIL", "BehavioralLayer", "self_reported_family"]

_LAYER = "behavioral"
# Marker in the evidence ``detail`` that flags the weak self-report signal so the
# combiner can single it out for the spoofing check (never fuse it as strong).
SELF_REPORT_DETAIL = "self_report"

# Self-id phrases → canonical family. Deliberately tiny + explicit (benign, no
# heuristic guessing): only a plain first-person claim counts as a self-report.
_SELF_ID_MAP: tuple[tuple[str, str], ...] = (
    ("i am claude", "anthropic-claude"),
    ("i'm claude", "anthropic-claude"),
    ("anthropic", "anthropic-claude"),
    ("i am chatgpt", "openai-gpt"),
    ("i'm chatgpt", "openai-gpt"),
    ("gpt-4", "openai-gpt"),
    ("openai", "openai-gpt"),
    ("i am gemini", "google-gemini"),
    ("i'm gemini", "google-gemini"),
    ("google", "google-gemini"),
    ("llama", "meta-llama"),
)


def self_reported_family(self_id_text: str) -> str | None:
    """Map a self-identification response to a canonical family, or ``None``.

    Pure + case-insensitive; the *first* matching phrase (declaration order) wins
    so the mapping is deterministic (contract §7 replay).
    """

    low = self_id_text.lower()
    for phrase, family in _SELF_ID_MAP:
        if phrase in low:
            return family
    return None


class BehavioralLayer:
    """Seeded self-id / cutoff / refusal-style / idiom probes (contract §5 step 3)."""

    layer: str = _LAYER

    async def probe(self, adapter: TargetAdapter, ctx: ProbeContext) -> list[FingerprintEvidence]:
        """Run the behavioral battery, match the pack, surface the self-report."""

        pack = ctx.signature_pack
        if not isinstance(pack, SignaturePack):
            return []
        responses: dict[str, ModelResponse] = {}
        for probe in BEHAVIORAL_BATTERY:
            request = _seeded(build_request(probe), ctx.target_id, probe.name)
            responses[probe.kind] = await adapter.send(request)

        out: list[FingerprintEvidence] = []
        out.extend(self._self_report_evidence(responses))
        out.extend(self._pack_evidence(pack, responses))
        return out

    def _self_report_evidence(
        self, responses: dict[str, ModelResponse]
    ) -> list[FingerprintEvidence]:
        """Emit the weak self-report evidence (or nothing if the target won't self-id)."""

        self_id = responses.get("self_id")
        if self_id is None:
            return []
        claimed = self_reported_family(self_id.text)
        if claimed is None:
            return []
        # Weight is deliberately small - a self-report is a *weak* signal (docs/10 §5).
        return [
            FingerprintEvidence(
                layer=_LAYER,
                signal=encode_signal(claimed, None, SELF_REPORT_DETAIL),
                weight=0.15,
            )
        ]

    def _pack_evidence(
        self, pack: SignaturePack, responses: dict[str, ModelResponse]
    ) -> list[FingerprintEvidence]:
        """Match every behavioral response against each entry's behavioral fragments."""

        combined = " ".join(r.text for r in responses.values()).lower()
        out: list[FingerprintEvidence] = []
        for entry in pack.entries:
            fragments = entry.signals.get(_LAYER, [])
            hits = [f for f in fragments if f.lower() in combined]
            if not hits:
                continue
            weight = entry.weights.get(_LAYER, 0.0) * (len(hits) / len(fragments))
            out.append(
                FingerprintEvidence(
                    layer=_LAYER,
                    signal=encode_signal(entry.family, entry.version, f"behavioral tells {hits}"),
                    weight=round(weight, 6),
                )
            )
        return out


def _seeded(request: ModelRequest, target_id: str, probe_name: str) -> ModelRequest:
    """Fold the deterministic seed into the request metadata (replay-stable)."""

    seed = seed_for(target_id, probe_name)
    meta = dict(request.metadata or {})
    meta["seed"] = seed
    sampling = request.sampling or Sampling()
    return request.model_copy(update={"metadata": meta, "sampling": sampling})
