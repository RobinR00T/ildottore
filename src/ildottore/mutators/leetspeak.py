"""``leetspeak``, obfuscate the payload with common letter→symbol substitutions.

Maps a small fixed set of letters to their canonical leet digits/symbols (a→4, e→3, i→1,
o→0, s→5, t→7). Deterministic and pure. Not marked reversible: the mapping is lossy and
ambiguous (0 could be o or O, etc.), so it is an obfuscation carrier, not a decodable
encoding (docs/14 closes the JB-ENCODING leetspeak gap).
"""

from __future__ import annotations

from ildottore.mutators.base import BaseMutator

__all__ = ["LeetspeakMutator"]

_LEET_MAP = str.maketrans(
    {
        "a": "4",
        "A": "4",
        "e": "3",
        "E": "3",
        "i": "1",
        "I": "1",
        "o": "0",
        "O": "0",
        "s": "5",
        "S": "5",
        "t": "7",
        "T": "7",
    }
)


class LeetspeakMutator(BaseMutator):
    """Substitutes common letters with leetspeak digits/symbols (lossy obfuscation)."""

    name = "leetspeak"
    reversible = False

    def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
        return text.translate(_LEET_MAP), {"scheme": "leetspeak", "note": "lossy obfuscation"}
