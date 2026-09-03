"""Capability-probe signal layer (u09, contract §5 step 2, ``docs/10 §1``).

Benign feature reflection: reads ``adapter.capabilities()`` (the target-declared
:class:`~ildottore.shared.models.Capabilities`) and surfaces it as fingerprint
evidence. Adapters declare capabilities statically (they do **not** probe at send
time - that is explicitly this layer's job, per ``adapters/base`` docstring), so
this layer reflects the declaration into the fingerprint's ``capability_guess``
via :func:`capability_guess` and emits per-capability evidence.

No adversarial probing - this is a read of the declared surface plus (where the
pack declares capability tells) family-attributed evidence when a distinctive
capability profile matches a signature (e.g. a 200k-context tell).
"""

from __future__ import annotations

from ildottore.fingerprint.attribution import encode_signal
from ildottore.fingerprint.base import ProbeContext
from ildottore.fingerprint.signatures import SignaturePack
from ildottore.shared.models import Capabilities, FingerprintEvidence, JsonDict
from ildottore.shared.protocols import TargetAdapter

__all__ = ["CapabilityLayer", "capability_guess"]

_LAYER = "capability"


def capability_guess(caps: Capabilities) -> JsonDict:
    """Project declared :class:`Capabilities` into the fingerprint guess shape.

    ``ModelFingerprint.capability_guess`` is a *free-shaped* probe result distinct
    from the ``Capabilities`` enum (ADR-0006 §4). It mirrors the ``docs/10 §2``
    example keys (``tools``/``json_mode``/``vision``/``streaming``/``seed``/
    ``max_context_tokens``). ``max_context_tokens`` is left unset here (not a
    declared flag) - the behavioral/statistical layers can fill it when a family
    is recognized; MVP-1 reports the known booleans honestly.
    """

    return {
        "tools": caps.tools,
        "json_mode": caps.tools,  # structured-output ride-alongs with tool support MVP-1
        "vision": caps.multimodal,
        "streaming": caps.streaming,
        "seed": caps.seed,
        "rag": caps.rag,
        "memory": caps.memory,
        "logprobs": caps.logprobs,
    }


class CapabilityLayer:
    """``adapter.capabilities()`` reflection + pack capability tells (contract §5)."""

    layer: str = _LAYER

    async def probe(self, adapter: TargetAdapter, ctx: ProbeContext) -> list[FingerprintEvidence]:
        """Reflect declared capabilities; match any capability tells in the pack."""

        caps = adapter.capabilities()
        haystack = _caps_haystack(caps)
        pack = ctx.signature_pack
        if not isinstance(pack, SignaturePack):
            return []
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
                    # Declared capabilities identify a *family*, not a specific
                    # version (a 200k-context/tools profile is family-wide) - emit
                    # family-only attribution so a generic ``tools=false`` tell can
                    # never pin a version on an otherwise-blank target.
                    signal=encode_signal(entry.family, None, f"capability tells {hits}"),
                    weight=round(weight, 6),
                )
            )
        return out


def _caps_haystack(caps: Capabilities) -> str:
    """Flatten declared capabilities into a searchable ``key=bool`` string."""

    return " ".join(f"{name}={value}" for name, value in sorted(caps.model_dump().items())).lower()
