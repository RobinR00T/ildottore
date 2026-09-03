"""Seeded benign probe battery (u09, contract §5 step 1).

A fixed, ordered set of **benign** probes (contract §8: no jailbreak / ``test_only``
payloads). Each probe is a small, named, declarative unit that a layer turns into a
:class:`~ildottore.shared.models.ModelRequest`. The battery is a module-level
constant so the set is identical on every run (contract §4 KEEP: deterministic
replay); the per-probe seed comes from :func:`ildottore.fingerprint.base.seed_for`.

Probes never carry adversarial intent - a self-identification question, a
knowledge-cutoff question, a benign structured-output nudge and a couple of
neutral idiom/formatting prompts. They are safe to send to any endpoint on the
scope allowlist and are the "banner-grab" analogue (``docs/10 §1``).
"""

from __future__ import annotations

from dataclasses import dataclass

from ildottore.shared.models import ModelRequest, Sampling

__all__ = [
    "BEHAVIORAL_BATTERY",
    "STATISTICAL_BATTERY",
    "Probe",
    "build_request",
]


@dataclass(frozen=True)
class Probe:
    """One benign probe (contract §8: benign-only).

    ``name`` is stable and feeds the deterministic seed. ``prompt`` is the user
    turn sent to the target. ``kind`` tags what the probe interrogates so a layer
    can route the response to the right matcher.
    """

    name: str
    kind: str
    prompt: str


# --- behavioral / active battery (seeded, benign) --------------------------------
# Order is load-bearing: the battery is replayed in-order so evidence lists are
# byte-stable. Extending the battery appends; never reorders (would break goldens).
BEHAVIORAL_BATTERY: tuple[Probe, ...] = (
    Probe(
        name="self_id",
        kind="self_id",
        prompt="Which AI model are you? State your model family and version plainly.",
    ),
    Probe(
        name="cutoff",
        kind="cutoff",
        prompt="What is your knowledge cutoff date? Answer with just the month and year.",
    ),
    Probe(
        name="refusal_style",
        kind="refusal_style",
        prompt="Politely decline to answer this and explain why you are declining.",
    ),
    Probe(
        name="idiom",
        kind="idiom",
        prompt="Summarize the water cycle in exactly one short sentence.",
    ),
)


# --- statistical battery (fixed query set → response feature vector, OD-9) --------
# LLMmap-style: a fixed set of neutral queries whose responses form a feature
# vector compared (nearest-neighbor) against the signature pack. No embedder dep.
STATISTICAL_BATTERY: tuple[Probe, ...] = (
    Probe(
        name="stat_greeting",
        kind="statistical",
        prompt="Say hello and briefly offer to help.",
    ),
    Probe(
        name="stat_list",
        kind="statistical",
        prompt="List three primary colors.",
    ),
    Probe(
        name="stat_explain",
        kind="statistical",
        prompt="Explain what a hash function is to a beginner.",
    ),
)


def build_request(probe: Probe) -> ModelRequest:
    """Turn a :class:`Probe` into a deterministic benign :class:`ModelRequest`.

    Sampling is pinned to ``temperature=0`` so a target that honors it responds
    reproducibly; a target that ignores sampling still yields a stable fingerprint
    because the combiner is tolerant (evidence weights, not exact text equality).
    """

    return ModelRequest(
        prompt=probe.prompt,
        sampling=Sampling(temperature=0.0),
        metadata={"probe": probe.name},
    )
