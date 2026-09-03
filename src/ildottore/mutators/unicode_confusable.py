"""``unicode_confusable`` - swap ASCII letters for visually confusable codepoints.

Bounded (contract §4 KEEP): a documented, in-module confusable table (Cyrillic/Greek
homoglyphs) and a density cap so at most ``density`` fraction of eligible characters are
substituted. Deterministic - which eligible positions are swapped is chosen by an RNG
seeded from ``(spec.id, mutation.name)``. Intent-preserving: the text still *reads* as the
same ask to a human; only the byte-level codepoints shift. Not losslessly reversible (the
map is one-way per character), so ``reversible=False`` and the substitution map is recorded
in provenance for evidence.
"""
# ruff: noqa: RUF001 - the confusable table intentionally maps ASCII to look-alike Cyrillic/
# Greek codepoints; RUF001 (ambiguous-character) flags exactly the behavior we implement here.

from __future__ import annotations

from ildottore.mutators.base import BaseMutator, seeded_rng

__all__ = ["CONFUSABLES", "DEFAULT_DENSITY", "UnicodeConfusableMutator"]

# Documented homoglyph table: ASCII -> visually-confusable codepoint (Cyrillic/Greek).
CONFUSABLES: dict[str, str] = {
    "a": "а",  # CYRILLIC SMALL LETTER A
    "c": "с",  # CYRILLIC SMALL LETTER ES
    "e": "е",  # CYRILLIC SMALL LETTER IE
    "i": "і",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "o": "о",  # CYRILLIC SMALL LETTER O
    "p": "р",  # CYRILLIC SMALL LETTER ER
    "s": "ѕ",  # CYRILLIC SMALL LETTER DZE
    "x": "х",  # CYRILLIC SMALL LETTER HA
    "y": "у",  # CYRILLIC SMALL LETTER U
    "A": "Α",  # GREEK CAPITAL LETTER ALPHA
    "B": "Β",  # GREEK CAPITAL LETTER BETA
    "E": "Ε",  # GREEK CAPITAL LETTER EPSILON
    "O": "Ο",  # GREEK CAPITAL LETTER OMICRON
}

DEFAULT_DENSITY = 0.3  # fraction of eligible characters to substitute (contract §4 cap).


class UnicodeConfusableMutator(BaseMutator):
    """Deterministically substitutes a density-capped subset of confusable characters."""

    name = "unicode_confusable"
    reversible = False

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        rng = seeded_rng(seed, salt=self.name)
        eligible = [i for i, ch in enumerate(text) if ch in CONFUSABLES]
        n_swap = int(len(eligible) * DEFAULT_DENSITY)
        # Deterministic choice of which eligible positions to swap.
        chosen = sorted(rng.sample(eligible, n_swap)) if n_swap else []
        chars = list(text)
        swaps: dict[str, str] = {}
        for i in chosen:
            original = chars[i]
            replacement = CONFUSABLES[original]
            chars[i] = replacement
            swaps[str(i)] = f"{original}->U+{ord(replacement):04X}"
        provenance: dict[str, object] = {
            "density": DEFAULT_DENSITY,
            "swapped_positions": swaps,
        }
        return "".join(chars), provenance
