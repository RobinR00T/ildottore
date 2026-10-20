"""How a canary is looked for in text: case-folded, every format character removed (u08 A-87).

A canary is the scanner's own marker, and a reply that holds it re-cased (``CANARY-B-7F3A91C2``
for ``CANARY-B-7f3a91c2``) or split by a zero-width or other invisible format character (Unicode
category ``Cf``: U+200B, U+2060, U+FEFF, a soft hyphen, a tag character, a bidi control) shows it
to whoever reads the reply as plainly as one that holds it as written. Read exactly, such a reply
hid the crossing (inconclusive, exit 0, measured through the CLI on ``fef4963e``). The identity
sweep's request was already read this way (u08 A-85, audit of ``8a42d08f``, LOW 5); the replies
are now read by the same function, so a canary a request carries in one form is carried in every
form a reply can echo, and the echo rule cannot be stepped around by a fold the request did not
get.

Case folding is Python's full folding (``str.casefold``: ``ß`` reads as ``ss``, the Kelvin sign
as ``k``), no compatibility normalization (a fullwidth or confusable letter is another letter
here). Measured on a benign corpus, the fold makes no ordinary text match a canary of the floors
the scope sets (u08 A-87).
"""

from __future__ import annotations

import sys
import unicodedata
from functools import cache

__all__ = ["folded"]


@cache
def _format_characters() -> dict[int, None]:
    """Every format (``Cf``) code point of this interpreter's Unicode table, mapped to nothing.

    Built once, on first use (170 code points under Unicode 16.0, a scan of about 0.1 s), so the
    table is bounded whatever a reply holds: a cache filled from the reply's own characters
    could hold every code point a hostile reply sends.
    """

    return dict.fromkeys(
        point for point in range(sys.maxunicode + 1) if unicodedata.category(chr(point)) == "Cf"
    )


def folded(text: str) -> str:
    """``text`` with its format characters removed, then case-folded."""

    if text.isascii():  # no format character is ASCII
        return text.casefold()
    return text.translate(_format_characters()).casefold()
