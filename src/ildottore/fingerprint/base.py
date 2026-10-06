"""Fingerprint-layer protocol + shared probe context (u09, contract §3/§5 step 1).

Every signal layer (``metadata``, ``capability``, ``behavioral``, ``tokenizer``,
``guardrail``, ``statistical``) implements the local :class:`FingerprintLayer`
protocol: a stable ``layer`` name and an ``async probe`` that consumes a
:class:`~ildottore.shared.protocols.TargetAdapter` (via the injected instance -
never a provider SDK, contract §3/§8) plus a :class:`ProbeContext` and returns a
list of :class:`~ildottore.shared.models.FingerprintEvidence`.

The layer contract is deliberately narrow so the set is *pluggable* (contract §1:
"registered by name for pluggable extension"): a new layer is a new object with a
unique ``layer`` name; the engine iterates the registry it is handed. Layers carry
**no fusion logic** - they only emit weighted evidence; :mod:`ildottore.fingerprint.combine`
fuses them (separation of concerns, ``AGENTS.md §3``).

``FingerprintEvidence`` (``shared.models``) is intentionally distinct from the
per-verdict ``Evidence`` bundle: a fingerprint signal is ``{layer, signal, weight}``
where ``weight`` is a signed contribution the combiner sums per candidate family.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Protocol, runtime_checkable

from ildottore.shared.models import FingerprintEvidence, Sampling
from ildottore.shared.protocols import TargetAdapter

__all__ = [
    "PROBE_MAX_TOKENS",
    "PROBE_SAMPLING",
    "FingerprintLayer",
    "ProbeContext",
    "seed_for",
]


#: The longest reply a probe asks for. The cap cannot change the statistical or carrier result:
#: a reply long enough to be cut (in Latin script, past 400 characters) has its length feature
#: at 1.0, at least 0.45 from every statistical centroid (the largest centroid length is 0.55; a
#: match needs 0.35 or less), and a carrier probe scores only on a reply of 48 characters or
#: fewer. The phrase-matching layers (behavioral, tokenizer, guardrail) would miss a tell
#: written after token 512; no reply to those layers' probes came near in the three live runs
#: (the longest, the guardrail nudge, was 163 tokens), nor does any corpus reply. Without it a
#: small model at temperature 0 looped on a carrier it could not read until the 30 s timeout,
#: three times, and a live ``-sV`` pass (``llama3.2:3b``, 2026-10-07) stopped there.
PROBE_MAX_TOKENS: Final = 512
#: The sampling every probe is sent with: temperature 0, so a target that is deterministic at
#: temperature 0 answers the same way twice, and the reply cap above.
PROBE_SAMPLING: Final = Sampling(temperature=0.0, max_tokens=PROBE_MAX_TOKENS)


def seed_for(target_id: str, probe_name: str) -> str:
    """Deterministic per-probe seed string (contract §4 KEEP).

    Seed = ``(target_id, probe.name)`` so a fixed probe battery yields a
    byte-identical fingerprint on replay. Kept as a plain string (not an int) so
    it can be threaded straight into the mock adapter's request metadata and into
    :class:`~ildottore.shared.protocols.Mutator.mutate` (which takes ``seed: str``).
    """

    return f"{target_id}:{probe_name}"


@dataclass(frozen=True)
class ProbeContext:
    """Immutable per-run context handed to every layer (contract §5).

    Frozen so a layer cannot mutate shared state between layers (determinism). The
    ``target_id`` seeds the probe battery; the loaded ``signature_pack`` is shared
    so the statistical/behavioral layers score against the same versioned data.
    """

    target_id: str
    # The parsed signature pack (``signatures.SignaturePack``). Typed as ``object``
    # here to keep ``base`` a leaf that does not import the loader (avoids an import
    # cycle: signatures → base is fine; base → signatures would loop). Layers that
    # need it re-narrow via ``isinstance``.
    signature_pack: object = None
    extra: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class FingerprintLayer(Protocol):
    """One independent signal layer (contract §3).

    Implementations are pure w.r.t. their inputs: given the same adapter responses
    and the same context they emit byte-identical evidence. They perform **benign**
    probes only (contract §8) - no jailbreak / ``test_only`` payloads.
    """

    layer: str

    async def probe(
        self, adapter: TargetAdapter, ctx: ProbeContext
    ) -> list[FingerprintEvidence]: ...
