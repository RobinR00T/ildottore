"""Tokenizer / glitch-token signal layer (u09, contract §5 step 3, ``docs/10 §1``).

Probes known-benign tokenizer tells: a family's BPE artifacts surface as
characteristic echo/repair behavior when asked to repeat a specific benign string
(GPT-family ``SolidGoldMagikarp``-style artifacts vs Claude vs Llama tokenization).
The probe is **benign** (a plain "repeat this token" request, no payload) and
seeded. The response is matched against each entry's ``signals["tokenizer"]``
fragments — e.g. a family that reliably mangles a given token leaves a stable tell.

Kept deterministic + offline-replayable: the layer sends one seeded benign probe
and matches textual tells; no live-tokenizer dependency (no heavy dep, ``AGENTS.md §3``).
"""

from __future__ import annotations

from ildottore.fingerprint.attribution import encode_signal
from ildottore.fingerprint.base import ProbeContext, seed_for
from ildottore.fingerprint.signatures import SignaturePack
from ildottore.shared.models import (
    FingerprintEvidence,
    ModelRequest,
    Sampling,
)
from ildottore.shared.protocols import TargetAdapter

__all__ = ["GLITCH_TOKENS", "TokenizerLayer"]

_LAYER = "tokenizer"

# Benign strings historically distinctive across tokenizers. Sending "repeat this
# verbatim" is harmless; the *response* behavior is the signal, not the string.
GLITCH_TOKENS: tuple[str, ...] = (
    "SolidGoldMagikarp",
    " petertodd",
    "รอยเท้า",
)


class TokenizerLayer:
    """Glitch-token family tells (contract §5 step 3)."""

    layer: str = _LAYER

    async def probe(self, adapter: TargetAdapter, ctx: ProbeContext) -> list[FingerprintEvidence]:
        """Send one benign repeat-token probe and match tokenizer tells in the pack."""

        pack = ctx.signature_pack
        if not isinstance(pack, SignaturePack):
            return []
        prompt = "Repeat the following tokens back verbatim: " + " ".join(GLITCH_TOKENS)
        request = _seeded(
            ModelRequest(prompt=prompt, metadata={"probe": "tokenizer_glitch"}),
            ctx.target_id,
            "tokenizer_glitch",
        )
        response = await adapter.send(request)
        haystack = response.text.lower()
        out: list[FingerprintEvidence] = []
        for entry in pack.entries:
            fragments = entry.signals.get(_LAYER, [])
            hits = [f for f in fragments if f.lower() in haystack]
            if not hits:
                continue
            weight = entry.weights.get(_LAYER, 0.0) * (len(hits) / len(fragments))
            out.append(
                FingerprintEvidence(
                    layer=_LAYER,
                    signal=encode_signal(entry.family, entry.version, f"tokenizer tells {hits}"),
                    weight=round(weight, 6),
                )
            )
        return out


def _seeded(request: ModelRequest, target_id: str, probe_name: str) -> ModelRequest:
    """Fold the deterministic seed into the request metadata (replay-stable)."""

    seed = seed_for(target_id, probe_name)
    meta = dict(request.metadata or {})
    meta["seed"] = seed
    return request.model_copy(update={"metadata": meta, "sampling": Sampling()})
