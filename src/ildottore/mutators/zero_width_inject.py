"""``zero_width_inject`` — insert zero-width characters between visible characters.

Reversible (contract §7): the injected codepoints (ZWSP/ZWNJ/ZWJ) are stripped to recover
the original payload; the reversibility test asserts ``strip_zero_width(out) == text``.
Bounded (contract §4 KEEP): a density cap limits how many inter-character gaps receive an
injection, and the injected set is a fixed, documented table — no unbounded blow-up.
Deterministic: injection positions and which zero-width char to use are drawn from an RNG
seeded by ``(spec.id, mutation.name)``.
"""

from __future__ import annotations

from ildottore.mutators.base import BaseMutator, seeded_rng

__all__ = [
    "DEFAULT_DENSITY",
    "ZERO_WIDTH_CHARS",
    "ZeroWidthInjectMutator",
    "strip_zero_width",
]

# Documented zero-width codepoints (bounded set).
ZERO_WIDTH_CHARS: tuple[str, ...] = (
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
)

DEFAULT_DENSITY = 0.25  # fraction of inter-character gaps to inject into (contract §4 cap).


def strip_zero_width(text: str) -> str:
    """Remove all injected zero-width codepoints, recovering the original payload (§7)."""
    return "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS)


class ZeroWidthInjectMutator(BaseMutator):
    """Deterministically injects a density-capped number of zero-width characters."""

    name = "zero_width_inject"
    reversible = True

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        rng = seeded_rng(seed, salt=self.name)
        gaps = list(range(1, len(text)))  # candidate insertion points (between chars).
        n_inject = int(len(gaps) * DEFAULT_DENSITY)
        chosen = set(rng.sample(gaps, n_inject)) if n_inject else set()
        out: list[str] = []
        for i, ch in enumerate(text):
            if i in chosen:
                out.append(rng.choice(ZERO_WIDTH_CHARS))
            out.append(ch)
        provenance: dict[str, object] = {
            "decode": "strip_zero_width",
            "density": DEFAULT_DENSITY,
            "injected": n_inject,
        }
        return "".join(out), provenance
