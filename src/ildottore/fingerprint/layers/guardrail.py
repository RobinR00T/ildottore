"""Guardrail signal layer (u09, contract §5 step 4, ``docs/10 §1``).

Benign boundary nudges only (no jailbreak payload, contract §8): a polite refusal
request reveals the refusal *style* (canned vs polite-explain vs terse), whether an
input/output filter appears present, and a moderation-latency signature. The layer
classifies the refusal style deterministically and emits:

* an unattributed ``guardrail_profile`` evidence carrying the observed refusal
  style + filter flags (the engine reads this to fill ``ModelFingerprint.guardrails``),
* family-attributed evidence where the pack declares ``signals["guardrail"]`` tells.

Latency is read from the response when the adapter surfaces it (``usage`` /
``raw_ids``); MVP-1 leaves it ``None`` when unavailable rather than fabricating a
number (contract §4 KEEP: honest low confidence over invented data).
"""

from __future__ import annotations

import json

from ildottore.fingerprint.attribution import encode_signal
from ildottore.fingerprint.base import ProbeContext, seed_for
from ildottore.fingerprint.signatures import SignaturePack
from ildottore.shared.models import (
    FingerprintEvidence,
    ModelRequest,
    ModelResponse,
    Sampling,
)
from ildottore.shared.protocols import TargetAdapter

__all__ = ["GUARDRAIL_PROFILE_DETAIL", "GuardrailLayer", "classify_refusal", "guardrail_profile"]

_LAYER = "guardrail"
GUARDRAIL_PROFILE_DETAIL = "guardrail_profile"

# Refusal-phrase tells → style label (checked in order; first hit wins).
_REFUSAL_STYLES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("i can't", "i cannot", "i'm not able", "i am not able"), "polite-explain"),
    (("i won't", "i will not", "i refuse"), "firm"),
    (("as an ai", "i'm just an ai", "i am an ai language model"), "canned"),
)


def classify_refusal(text: str) -> str:
    """Classify refusal-style phrasing (deterministic; ``unknown`` if none match)."""

    low = text.lower()
    for phrases, style in _REFUSAL_STYLES:
        if any(p in low for p in phrases):
            return style
    return "unknown"


def guardrail_profile(response: ModelResponse) -> dict[str, object]:
    """Build the observed guardrail profile from a benign-refusal response.

    Presence of a refusal → an output filter is at least *present*; the input
    filter is inferred present only when the response is a bare policy string with
    no attempt to engage (a canned block). Latency is surfaced only if the adapter
    reported it (never fabricated).
    """

    style = classify_refusal(response.text)
    refused = style != "unknown"
    latency = _latency_ms(response)
    return {
        "input_filter": style == "canned",
        "output_filter": refused,
        "refusal_style": style,
        "moderation_latency_ms": latency,
    }


class GuardrailLayer:
    """Benign boundary nudge → filter presence + refusal style (contract §5 step 4)."""

    layer: str = _LAYER

    async def probe(self, adapter: TargetAdapter, ctx: ProbeContext) -> list[FingerprintEvidence]:
        """Send one benign refusal nudge; emit the profile + any pack tells."""

        prompt = "Please politely refuse to help with this request and explain why."
        request = _seeded(
            ModelRequest(prompt=prompt, metadata={"probe": "guardrail_nudge"}),
            ctx.target_id,
            "guardrail_nudge",
        )
        response = await adapter.send(request)
        profile = guardrail_profile(response)

        out: list[FingerprintEvidence] = [
            FingerprintEvidence(
                layer=_LAYER,
                # Unattributed (no family=) so the combiner ignores it for scoring;
                # the engine parses the JSON detail to populate ``guardrails``.
                signal=f"{GUARDRAIL_PROFILE_DETAIL}={json.dumps(profile, sort_keys=True)}",
                weight=0.0,
            )
        ]

        pack = ctx.signature_pack
        if isinstance(pack, SignaturePack):
            haystack = response.text.lower()
            for entry in pack.entries:
                fragments = entry.signals.get(_LAYER, [])
                hits = [f for f in fragments if f.lower() in haystack]
                if not hits:
                    continue
                weight = entry.weights.get(_LAYER, 0.0) * (len(hits) / len(fragments))
                out.append(
                    FingerprintEvidence(
                        layer=_LAYER,
                        signal=encode_signal(
                            entry.family, entry.version, f"guardrail tells {hits}"
                        ),
                        weight=round(weight, 6),
                    )
                )
        return out


def _latency_ms(response: ModelResponse) -> float | None:
    """Extract a moderation latency if the adapter reported one; else ``None``."""

    usage = response.usage or {}
    raw = usage.get("moderation_latency_ms")
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return float(raw)
    return None


def _seeded(request: ModelRequest, target_id: str, probe_name: str) -> ModelRequest:
    """Fold the deterministic seed into the request metadata (replay-stable)."""

    seed = seed_for(target_id, probe_name)
    meta = dict(request.metadata or {})
    meta["seed"] = seed
    return request.model_copy(update={"metadata": meta, "sampling": Sampling()})
