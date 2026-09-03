"""Passive / metadata signal layer (u09, contract §5 step 2, ``docs/10 §1``).

The safest layer: it interrogates the **response envelope**, not the model. From a
single benign send it reads the model echo, the OpenAI ``system_fingerprint``, the
``finish_reason``/``stop_reason`` vocab, role names, tool-call schema shape, usage
field names and HTTP-ish ids. It matches these textual fragments against each
signature entry's ``signals["metadata"]`` list and emits weighted
:class:`~ildottore.shared.models.FingerprintEvidence` per matching candidate.

No model reasoning is exercised - a target that spoofs its ``model`` echo is caught
later by the statistical layer, and the contradiction becomes a ``spoofing_flag``
in :mod:`ildottore.fingerprint.combine` (contract §2: self-report is weak).
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

__all__ = ["MetadataLayer", "envelope_signal"]

_LAYER = "metadata"


def envelope_signal(response: ModelResponse) -> str:
    """Flatten a response envelope into one lowercase searchable string.

    Concatenates the passive tells - redacted ids, usage field names, finish
    reason and tool-call schema keys - so a signature matcher can look for e.g.
    ``system_fingerprint`` (OpenAI) vs ``stop_reason`` (Anthropic) without the
    layer hardcoding any single provider (``docs/10 §1``).
    """

    parts: list[str] = []
    if response.finish_reason:
        parts.append(f"finish_reason={response.finish_reason}")
    for key in sorted(response.raw_ids):
        parts.append(f"{key}={response.raw_ids[key]}")
    if response.usage:
        parts.extend(f"usage.{k}" for k in sorted(response.usage))
    for call in response.tool_calls:
        parts.extend(f"tool.{k}" for k in sorted(call))
    return " ".join(parts).lower()


class MetadataLayer:
    """Passive envelope/header/error parsing (contract §5 step 2)."""

    layer: str = _LAYER

    async def probe(self, adapter: TargetAdapter, ctx: ProbeContext) -> list[FingerprintEvidence]:
        """Send one benign probe, read the envelope, match the pack.

        Uses the first behavioral probe as the single benign send (contract §5:
        "No model call needed for metadata beyond one benign send"). The seed is
        threaded so a replay is byte-identical.
        """

        pack = ctx.signature_pack
        if not isinstance(pack, SignaturePack):
            return []
        probe = BEHAVIORAL_BATTERY[0]
        request = _seeded(build_request(probe), ctx.target_id, probe.name)
        response = await adapter.send(request)
        haystack = envelope_signal(response)
        return _match(pack, haystack)


def _seeded(request: ModelRequest, target_id: str, probe_name: str) -> ModelRequest:
    """Return ``request`` with the deterministic seed folded into metadata."""

    seed = seed_for(target_id, probe_name)
    meta = dict(request.metadata or {})
    meta["seed"] = seed
    sampling = request.sampling or Sampling()
    return request.model_copy(update={"metadata": meta, "sampling": sampling})


def _match(pack: SignaturePack, haystack: str) -> list[FingerprintEvidence]:
    """Emit one evidence per entry whose metadata fragments appear in ``haystack``."""

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
                signal=encode_signal(entry.family, entry.version, f"metadata tells {hits}"),
                weight=round(weight, 6),
            )
        )
    return out
