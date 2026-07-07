"""``rot13`` — reversible letter-rotation obfuscation (contract §2, §7 reversibility).

ROT13 is its own inverse, so the original payload is trivially reconstructable from the
output (asserted by the reversibility test). Non-ASCII-letter codepoints pass through
unchanged, preserving intent.
"""

from __future__ import annotations

import codecs

from ildottore.mutators.base import BaseMutator

__all__ = ["Rot13Mutator"]


class Rot13Mutator(BaseMutator):
    """Applies ROT13 to ASCII letters; other characters unchanged."""

    name = "rot13"
    reversible = True

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        transformed = codecs.encode(text, "rot_13")
        return transformed, {"decode": "rot13", "note": "ROT13 is its own inverse"}
