"""Statistical (LLMmap-style) signal layer (u09, contract §5 step 5, OD-9).

Runs the fixed statistical query battery, turns each response into a small
**deterministic response feature vector** (no embedder — OD-9 resolved to a
response feature-vector nearest-neighbor to avoid a heavy/ambiguous-license dep,
``AGENTS.md §3``), concatenates them into one fingerprint vector, and finds the
nearest signature-pack centroid by Euclidean distance. The closest entry emits
strong family/version evidence weighted by ``weights["statistical"]`` scaled by a
similarity in ``[0,1]`` (``1 / (1 + distance)``).

The feature set is intentionally shallow + robust (length, sentence/line/list
structure, markdown/hedge markers, digit ratio) so it is stable across benign
paraphrase yet separates families whose style differs. Because it is derived only
from response *structure*, a target that spoofs its self-reported identity cannot
spoof this layer — which is exactly why a contradiction here becomes a
``spoofing_flag`` (contract §2, ``docs/10 §5``).
"""

from __future__ import annotations

import math

from ildottore.fingerprint.attribution import encode_signal
from ildottore.fingerprint.base import ProbeContext, seed_for
from ildottore.fingerprint.probes import STATISTICAL_BATTERY, build_request
from ildottore.fingerprint.signatures import SignatureEntry, SignaturePack
from ildottore.shared.models import (
    FingerprintEvidence,
    ModelRequest,
    Sampling,
)
from ildottore.shared.protocols import TargetAdapter

__all__ = ["FEATURES_PER_PROBE", "StatisticalLayer", "featurize", "response_vector"]

_LAYER = "statistical"
# Number of scalar features extracted per probe response. The pack centroid length
# must equal ``FEATURES_PER_PROBE * len(STATISTICAL_BATTERY)`` (validated on match).
FEATURES_PER_PROBE = 6
# Beyond this Euclidean distance a centroid is "not a match": emit no evidence so a
# genuinely-unknown endpoint stays honestly unrecognized (contract §4 KEEP: empty/
# far signals ⇒ low confidence, never a fabricated guess) rather than snapping to
# the nearest (possibly irrelevant) family.
MAX_MATCH_DISTANCE = 0.35

_MARKDOWN_MARKERS = ("**", "`", "#", "- ", "* ", "1.")
_HEDGE_WORDS = ("might", "could", "perhaps", "generally", "typically", "often")


def featurize(text: str) -> list[float]:
    """Extract a fixed-length, deterministic feature vector from one response.

    All features are normalized to roughly ``[0,1]`` so Euclidean distance is not
    dominated by raw length. Pure — same text ⇒ same vector (contract §7 replay).
    """

    stripped = text.strip()
    n = max(len(stripped), 1)
    sentences = [s for s in stripped.replace("!", ".").replace("?", ".").split(".") if s.strip()]
    lines = [ln for ln in stripped.splitlines() if ln.strip()]
    digits = sum(c.isdigit() for c in stripped)
    markdown = sum(stripped.count(m) for m in _MARKDOWN_MARKERS)
    hedges = sum(stripped.lower().count(w) for w in _HEDGE_WORDS)
    return [
        min(len(stripped) / 400.0, 1.0),  # response length
        min(len(sentences) / 8.0, 1.0),  # sentence count
        min(len(lines) / 8.0, 1.0),  # line/paragraph count
        min(digits / n * 10.0, 1.0),  # digit density
        min(markdown / 6.0, 1.0),  # markdown/formatting density
        min(hedges / 4.0, 1.0),  # hedging density
    ]


def response_vector(texts: list[str]) -> list[float]:
    """Concatenate per-probe feature vectors into the full fingerprint vector."""

    vec: list[float] = []
    for text in texts:
        vec.extend(featurize(text))
    return vec


def _distance(a: list[float], b: list[float]) -> float:
    """Euclidean distance; ``inf`` if the dimensions disagree (bad centroid)."""

    if len(a) != len(b):
        return math.inf
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b, strict=True)))


class StatisticalLayer:
    """Fixed battery → feature vector → nearest-neighbor vs pack (contract §5 step 5)."""

    layer: str = _LAYER

    async def probe(self, adapter: TargetAdapter, ctx: ProbeContext) -> list[FingerprintEvidence]:
        """Featurize the battery responses and emit nearest-centroid evidence."""

        pack = ctx.signature_pack
        if not isinstance(pack, SignaturePack):
            return []
        texts: list[str] = []
        for probe in STATISTICAL_BATTERY:
            request = _seeded(build_request(probe), ctx.target_id, probe.name)
            response = await adapter.send(request)
            texts.append(response.text)
        vector = response_vector(texts)

        scored: list[tuple[float, SignatureEntry]] = []
        for entry in pack.entries:
            if entry.stat is None:
                continue
            dist = _distance(vector, entry.stat.centroid)
            if math.isinf(dist) or dist > MAX_MATCH_DISTANCE:
                continue
            scored.append((dist, entry))
        if not scored:
            return []
        scored.sort(key=lambda pair: (pair[0], pair[1].family, pair[1].version or ""))

        out: list[FingerprintEvidence] = []
        for dist, entry in scored:
            similarity = 1.0 / (1.0 + dist)
            weight = entry.weights.get(_LAYER, 0.0) * similarity
            out.append(
                FingerprintEvidence(
                    layer=_LAYER,
                    signal=encode_signal(entry.family, entry.version, f"nn-dist {round(dist, 4)}"),
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
