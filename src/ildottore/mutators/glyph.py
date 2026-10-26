"""``glyph:<style>`` - the payload in look-alike or decorated characters a filter does not match.

A keyword filter or a classifier trained on plain ASCII misses "ignore" written in fullwidth or
mathematical bold letters, while a model reads them as the plain words. ``unicode_confusable``
swaps a few letters for homoglyphs; these styles rewrite every letter:

* ``fullwidth``: the Halfwidth and Fullwidth Forms block (``A`` -> U+FF21).
* ``bold``: Mathematical Bold letters and digits (``A`` -> U+1D400).
* ``circled``: Enclosed Alphanumerics (``A`` -> U+24B6).
* ``zalgo``: one to three combining marks on every letter, drawn from the seed (garak's
  ``InjectZalgo`` probe).
* ``spaced``: a space between letters and three between words, which splits every token.

``fullwidth``, ``bold`` and ``circled`` fold back to the payload under NFKC; ``zalgo`` and
``spaced`` do not fold back by normalization alone.
"""

from __future__ import annotations

import unicodedata

from ildottore.mutators.base import BaseMutator, derive_int_seed, seeded_rng

__all__ = ["STYLES", "GlyphMutator", "restyle"]

STYLES: tuple[str, ...] = ("bold", "circled", "fullwidth", "spaced", "zalgo")

_NFKC_REVERSIBLE = frozenset({"bold", "circled", "fullwidth"})

# Combining diacritical marks a zalgo writer stacks (above and below the letter).
_ZALGO_MARKS = tuple(chr(point) for point in range(0x0300, 0x0370) if point not in {0x034F})


def _fullwidth(char: str) -> str:
    if char == " ":
        return "　"
    return chr(ord(char) + 0xFEE0) if 0x21 <= ord(char) <= 0x7E else char


def _bold(char: str) -> str:
    if "A" <= char <= "Z":
        return chr(0x1D400 + ord(char) - ord("A"))
    if "a" <= char <= "z":
        return chr(0x1D41A + ord(char) - ord("a"))
    if "0" <= char <= "9":
        return chr(0x1D7CE + ord(char) - ord("0"))
    return char


def _circled(char: str) -> str:
    if "A" <= char <= "Z":
        return chr(0x24B6 + ord(char) - ord("A"))
    if "a" <= char <= "z":
        return chr(0x24D0 + ord(char) - ord("a"))
    if char == "0":
        return "⓪"
    if "1" <= char <= "9":
        return chr(0x2460 + ord(char) - ord("1"))
    return char


def restyle(text: str, style: str, seed: str = "") -> str:
    """``text`` written in ``style`` (a key of :data:`STYLES`)."""

    if style == "fullwidth":
        return "".join(_fullwidth(char) for char in text)
    if style == "bold":
        return "".join(_bold(char) for char in text)
    if style == "circled":
        return "".join(_circled(char) for char in text)
    if style == "spaced":
        return "   ".join(" ".join(word) for word in text.split())
    if style == "zalgo":
        rng = seeded_rng(seed, salt="glyph:zalgo")
        out = []
        for char in text:
            out.append(char)
            if char.isalpha():
                out.extend(rng.choice(_ZALGO_MARKS) for _ in range(rng.randint(1, 3)))
        return "".join(out)
    raise ValueError(f"unknown glyph style {style!r}")


def _resolve_style(seed: str) -> str:
    tail = seed.rsplit(":", 1)[-1].strip().lower()
    if tail in STYLES:
        return tail
    return STYLES[derive_int_seed(seed, salt="glyph") % len(STYLES)]


class GlyphMutator(BaseMutator):
    """Rewrites every letter of the payload in a decorated or look-alike Unicode style."""

    name = "glyph"
    fingerprint_probe = False  # run on request only (--obfuscate, --fuzz)
    reversible = True  # per style: _reversible_for
    accepted_params: frozenset[str] = frozenset(STYLES)

    def _reversible_for(self, seed: str) -> bool:
        return _resolve_style(seed) in _NFKC_REVERSIBLE

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        style = _resolve_style(seed)
        styled = restyle(text, style, seed)
        folds_back = unicodedata.normalize("NFKC", styled) == unicodedata.normalize("NFKC", text)
        return styled, {"style": style, "nfkc_folds_back": folds_back}
