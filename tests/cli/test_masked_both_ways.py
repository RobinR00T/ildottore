"""A CLI error holding U+0000 or U+0001 is read both ways, as the redactor reads a text (u01/u12
A-83, items 6 and 4).

``_masked`` runs every rule but the entropy fallback, then the entropy fallback on what it does not
keep. Its first pass reads a text holding a stash delimiter both ways (the redactor's
``redact_text``), but its entropy pass read only what that pass wrote, with the delimiters shown,
so a token the joined reading glues (``...the\\x00myafdbfdrg``) was never judged whole: on
``7d01521f`` the output was the joined reading or the visible one, whichever the first pass kept.
The passes now run on each reading and what either masks is masked
(``redactor.read_both_ways``). The CLI's output can hold text the message does not: a later pass
reads an earlier pass's mask as a URL's user and rewrites it
(``redis://«REDACTED:«REDACTED:url_password»@``), so placing its masks back in the message reads
such an opener as part of the mask and drops a literal it cannot place; the first version of this
showed that literal with the masks, which showed text one reading masked (``myafdbfdrg`` below),
and before that masked such a message whole as ``«REDACTED:fragment»`` (about 1% of the fuzz's
messages).
"""

from __future__ import annotations

import pytest

from ildottore.cli.app import _masked

#: Registered credentials are process-wide: none from an earlier test changes a mask here.
pytestmark = pytest.mark.usefixtures("no_known_secrets")

CASES = {
    # A URL's user the first pass masks, and a delimiter elsewhere in the message.
    "rewritten user": (
        "x\x01y redis://xoxa-PT7CgfXZ3BZxPk9MGFXpxEbPUzQ5Zwrc9Xsm:ghr_F5vth@h/ end",
        ["PT7CgfXZ3BZ", "ghr_F5vth"],
    ),
    # The joined reading masks a word glued to a token; the visible one shows it.
    "glued word": (
        "ASIALGOoRDEHXIQE2npweivepWgx1lXufltEuXemQYNYXybuUpDbthe\x00myafdbfdrg:x# in redis://"
        "xoxp-kqxz804fjyv5hsmsne74ym1rzslxmh3th36m50buc1zxlg4ndyvu5nwppk5qee3f0u3i6jvhfknze40s:"
        "293w47d5ysj0k6hl4b6y@example.com:5432/ end",
        ["myafdbfdrg", "kqxz804fjyv5", "293w47d5ysj0"],
    ),
    # The rewritten opener at the very start of the message.
    "opener first": (
        "https://sk-tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt:27c41796@db"
        ".internal/x \x00 end",
        ["tttttttttt", "27c41796"],
    ),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_both_readings_are_masked_and_the_rest_is_shown(case: str) -> None:
    message, hidden = CASES[case]
    shown = _masked(ValueError(message))
    assert "fragment" not in shown, shown
    assert shown.endswith(" end"), shown
    for value in hidden:
        assert value not in shown, shown


@pytest.mark.parametrize("unrelated", ["alice@example.org", "5f0eb9d2-2c10-4000-ac58-6fdf9029c33d"])
def test_a_line_is_masked_as_it_is_on_its_own(unrelated: str) -> None:
    line = "note\x01credential: 'Summer2026xQ' end"
    alone = _masked(ValueError(line))
    both = _masked(ValueError(f"{unrelated}\n{line}"))
    assert "Summer2026xQ" not in both
    assert both.endswith("␊" + alone), (both, alone)  # the newline is written out
