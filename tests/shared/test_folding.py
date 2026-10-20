"""``shared.folding.folded``: how a canary is looked for in text (u08 A-87, item 3).

Every Unicode format character (category ``Cf``) and default ignorable code point removed (pinned
to Unicode 16.0), then Python's full case folding; one function for the request and the replies,
so the echo rule of A-85 cannot be stepped around by a fold the request did not get.
"""

from __future__ import annotations

import itertools
import sys
import unicodedata

import pytest

from ildottore import redactor
from ildottore.shared import folding
from ildottore.shared.folding import folded


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("CANARY-B-7F3A91C2", "canary-b-7f3a91c2"),
        ("CANARY-B-7f3a​91c2", "canary-b-7f3a91c2"),  # zero-width space
        ("CANARY⁠-B", "canary-b"),  # word joiner
        ("﻿CANARY", "canary"),  # byte order mark
        ("CAN­ARY", "canary"),  # soft hyphen
        ("CA\U000e0041NARY", "canary"),  # a tag character
        ("A‮B", "ab"),  # a bidi control
        ("Straße", "strasse"),
        ("\u212a", "k"),  # the Kelvin sign
        ("plain ascii", "plain ascii"),
        ("", ""),
    ],
)
def test_format_characters_go_and_case_folds(text: str, expected: str) -> None:
    assert folded(text) == expected


def test_the_table_holds_every_format_character_of_this_python() -> None:
    """Pinned to Unicode 16.0, it holds every ``Cf`` of the running Python (3.11 has 14.0)."""

    cf = {point for point in range(sys.maxunicode + 1) if unicodedata.category(chr(point)) == "Cf"}
    assert cf <= set(folding._DROP)
    assert all(value is None for value in folding._DROP.values())


def test_the_table_is_format_and_default_ignorable_and_nothing_visible() -> None:
    """Besides ``Cf``, only marks, fillers and reserved code points a renderer shows as nothing."""

    def of(category: str) -> set[int]:
        return {point for point in folding._DROP if unicodedata.category(chr(point)) == category}

    assert of("Lo") == {0x115F, 0x1160, 0x3164, 0xFFA0}  # the Hangul fillers
    marks = {0x034F, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180F}
    marks |= set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))
    assert of("Mn") == marks  # the grapheme joiner, two Khmer vowels, the variation selectors
    assert set(folding._DROP) - of("Cf") - of("Lo") - of("Mn") == of("Cn")
    assert len(folding._DROP) == 4206
    pinned_cf = {
        point
        for low, high in (
            *redactor.EMPTY_FORMAT_RANGES,
            *redactor.FORMAT_SIGN_RANGES,
            *redactor.TAG_RANGES,
        )
        for point in range(low, high + 1)
    }
    others = {point for low, high in folding._OTHER_FORMAT_RANGES for point in range(low, high + 1)}
    assert pinned_cf <= set(folding._DROP)  # the redactor's Unicode 16.0 Cf, the same pin
    assert others <= pinned_cf  # the Cf that are not default ignorable are Cf there too
    flat = sorted(folding.INVISIBLE_RANGES)
    assert all(low <= high for low, high in flat)
    assert all(a[1] < b[0] for a, b in itertools.pairwise(flat))  # no overlap


@pytest.mark.parametrize(
    "invisible",
    [
        "\ufe0f",  # variation selector 16
        "\ufe00",  # variation selector 1
        "\U000e0100",  # variation selector 17
        "\U000e01ef",  # variation selector 256
        "\u034f",  # combining grapheme joiner
        "\u115f",  # Hangul choseong filler
        "\u1160",  # Hangul jungseong filler
        "\u3164",  # Hangul filler
        "\uffa0",  # halfwidth Hangul filler
        "\u180b",  # Mongolian free variation selector 1
        "\u180f",  # Mongolian free variation selector 4
        "\u17b4",  # Khmer vowel inherent aq
        "\u2065",  # reserved, default ignorable
        "\ufff0",  # reserved, default ignorable
        "\U000e0fff",  # reserved, default ignorable
    ],
)
def test_a_default_ignorable_character_does_not_hide_a_canary(invisible: str) -> None:
    """Pre-merge audit of A-87, LOW 2: removing only ``Cf`` let these hide a crossing."""

    assert folded(f"CANARY-B-7f3a{invisible}91c2") == "canary-b-7f3a91c2"
    assert folded(invisible * 3) == ""


def test_a_fold_that_matched_still_matches() -> None:
    """Dropping more characters keeps every match the ``Cf`` fold made: a substring stays one."""

    canary = "CANARY-B-7f3a91c2"
    reply = "x \u200bCANARY-B-7f3a\u200d91c2\ufe0f y"
    assert folded(canary) in folded(reply)


def test_a_space_or_a_letter_is_kept() -> None:
    """Only invisible characters go: a space, a hyphen or a confusable letter stays."""

    assert folded("C A N\u00a0A-R\u0430Y") == "c a n\u00a0a-r\u0430y"
