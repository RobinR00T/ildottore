"""``shared.folding.folded``: how a canary is looked for in text (u08 A-87, item 3).

Every Unicode format character (category ``Cf``) removed, then Python's full case folding; one
function for the request and the replies, so the echo rule of A-85 cannot be stepped around by a
fold the request did not get.
"""

from __future__ import annotations

import sys
import unicodedata

import pytest

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
        ("K", "k"),  # the Kelvin sign
        ("plain ascii", "plain ascii"),
        ("", ""),
    ],
)
def test_format_characters_go_and_case_folds(text: str, expected: str) -> None:
    assert folded(text) == expected


def test_the_table_is_every_format_character_and_nothing_else() -> None:
    """Built once from the interpreter's Unicode data, bounded whatever a reply holds."""

    table = folding._format_characters()
    expected = {
        point for point in range(sys.maxunicode + 1) if unicodedata.category(chr(point)) == "Cf"
    }
    assert set(table) == expected
    assert all(value is None for value in table.values())
    assert folding._format_characters() is table


def test_a_space_or_a_letter_is_kept() -> None:
    """Only invisible format characters go: a space, a hyphen or a confusable letter stays."""

    assert folded("C A N A-RаY") == "c a n a-rаy"
