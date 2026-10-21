"""How a canary is looked for in text: case-folded, format and default ignorables removed (A-87).

A canary is the scanner's own marker, and a reply that holds it re-cased (``CANARY-B-7F3A91C2``
for ``CANARY-B-7f3a91c2``) or split by a zero-width or other invisible character shows it to
whoever reads the reply as plainly as one that holds it as written. Read exactly, such a reply
hid the crossing (inconclusive, exit 0, measured through the CLI on ``fef4963e``). The identity
sweep's request was already read this way (u08 A-85, audit of ``8a42d08f``, LOW 5); the replies
are now read by the same function, so a canary a request carries in one form is carried in every
form a reply can echo, and the echo rule cannot be stepped around by a fold the request did not
get.

The invisible characters are the format characters (Unicode category ``Cf``: U+200B, U+2060,
U+FEFF, a soft hyphen, a tag character, a bidi control) and the default ignorable code points
(``Default_Ignorable_Code_Point``), the set Unicode says a renderer shows as nothing when it does
not support one: besides most of ``Cf``, the variation selectors (U+FE00 to U+FE0F, U+E0100 to
U+E01EF), the combining grapheme joiner U+034F, the Hangul fillers (U+115F, U+1160, U+3164,
U+FFA0), the Mongolian free variation selectors (U+180B to U+180F) and the reserved code points of
those blocks. Removing only ``Cf`` let one of the others hide a crossing (pre-merge audit of
A-87, LOW 2). Both are pinned to Unicode 16.0 here, as the redactor pins its format characters,
so a verdict does not depend on the Python's Unicode version (3.11 has 14.0).

Case folding is Python's full folding (``str.casefold``: ``ß`` reads as ``ss``, the Kelvin sign
as ``k``), no compatibility normalization (a fullwidth or confusable letter is another letter
here). Measured on a benign corpus, the fold makes no ordinary text match a canary of the floors
the scope sets (u08 A-87), and dropping the default ignorables as well changes no match (11,134
files, 27 of them holding 1,290 default ignorables outside ``Cf``, u08 A-92). Control characters
(U+0000 to U+001F, U+007F to U+009F) are not removed.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final

__all__ = ["INVISIBLE_RANGES", "folded", "folded_spans", "visible"]

#: ``Default_Ignorable_Code_Point`` as of Unicode 16.0 (``DerivedCoreProperties.txt``), reserved
#: code points included, as Unicode asks of a renderer.
_DEFAULT_IGNORABLE_RANGES: Final = (
    *((0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160)),
    *((0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E)),
    *((0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF)),
    *((0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A)),
    (0xE0000, 0xE0FFF),
)
#: The format characters (``Cf``, Unicode 16.0) that are not default ignorable: the prepended
#: concatenation marks (the Arabic number signs, the end of ayah, the Syriac abbreviation mark, the
#: Kaithi number signs), the interlinear annotation characters and the Egyptian hieroglyph format
#: controls. Removed as before, so no reply the ``Cf`` fold read as a crossing reads otherwise.
_OTHER_FORMAT_RANGES: Final = (
    *((0x0600, 0x0605), (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891)),
    *((0x08E2, 0x08E2), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD)),
    (0x13430, 0x1343F),
)
#: Every code point :func:`folded` removes, as inclusive ranges.
INVISIBLE_RANGES: Final = (*_DEFAULT_IGNORABLE_RANGES, *_OTHER_FORMAT_RANGES)
#: The same, for ``str.translate``: 4,206 code points, bounded whatever a reply holds.
_DROP: Final = dict.fromkeys(
    code for low, high in INVISIBLE_RANGES for code in range(low, high + 1)
)


def visible(text: str) -> str:
    """``text`` with its invisible characters removed, letter case kept (u08 A-93)."""

    if text.isascii():  # no invisible character is ASCII
        return text
    return text.translate(_DROP)


def folded(text: str) -> str:
    """``text`` with its invisible characters removed, then case-folded."""

    return visible(text).casefold()


def folded_spans(text: str, needle: str) -> Iterator[tuple[int, int]]:
    """Each stretch of ``text`` whose fold holds ``needle``, in order, overlapping ones as one.

    ``needle`` is folded already (:func:`folded`) and not empty. A stretch runs from the first
    character of ``text`` that the match folds from to the last, the invisible characters inside
    included: what the evidence store masks for a canary a reply holds re-cased or split, as the
    evaluators read it (u10 A-94). A match that starts or ends inside a character folding to more
    than one (``ß`` to ``ss``) takes the whole character. Linear in the text: the fold, a
    ``find`` per match, and one walk over the characters up to the last match for a text that is
    not ASCII (ASCII folds one character to one).
    """

    if not needle:
        raise ValueError("folded_spans needs a needle that folds to something")
    clean = folded(text)
    found = clean.find(needle)
    if found == -1:
        return
    ascii_text = text.isascii()
    walked = cursor = 0  # the folded length of text[:cursor]

    def _at(index: int) -> int:
        # The character of `text` the folded index `index` comes from; asked in growing order.
        nonlocal walked, cursor
        if ascii_text:
            return index
        while True:
            char = text[cursor]
            width = 0 if ord(char) in _DROP else len(char.casefold())
            if walked + width > index:
                return cursor
            walked += width
            cursor += 1

    def _stretches() -> Iterator[tuple[int, int]]:
        # In the folded text, overlapping matches as one.
        nonlocal found
        start, end = found, found + len(needle)
        found = clean.find(needle, found + 1)
        while found != -1:
            if found >= end:  # this match does not touch the stretch open
                yield start, end
                start = found
            end = found + len(needle)
            found = clean.find(needle, found + 1)
        yield start, end

    # In `text`, two stretches that end and start in one character folding to more than one (`ß`
    # holds two matches of `s`) are one.
    group: tuple[int, int] | None = None
    for start, end in _stretches():
        first = _at(start)
        last = _at(end - 1) + 1
        if group is not None and first < group[1]:
            group = (group[0], last)
            continue
        if group is not None:
            yield group
        group = (first, last)
    if group is not None:
        yield group
