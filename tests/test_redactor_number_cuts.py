"""A number read inside a UUID, read as main read it (u01 A-78, pre-merge audit H2, M1 and L1).

The card and the phone rules read a UUID's digit-only groups as a number. Main masked that
number where it read it, and the rules after them read the text with its mask in it. The branch
first left the UUID whole and replayed, for the entropy rule, the cuts it had recorded: with two
cut UUIDs in one token the pieces it judged were not main's, and a value glued between them was
readable (M1); each judged piece ran to an end of the token, so a token of glued UUIDs took
quadratic time (H2); and a phone rule read across a card's cut that main's mask had stopped it at,
which joined two lines for the labelled rule (L1). The number inside a UUID is now written in
stand-ins of the same length, which every rule reads as main read its mask, and which the late
pattern reads back to mask the UUID whole.
"""

from __future__ import annotations

import random
import re
import time

import pytest

from ildottore.redactor import Redactor

_DIGITS = "0123456789"


def _windows(secret: str, size: int = 8) -> list[str]:
    return [secret[at : at + size] for at in range(len(secret) - size + 1)]


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        # The audit's two repros: main masked the value glued between the two cut UUIDs.
        (
            "id 00000000-0950-2215-c8dd-000000000000-c9edbf4469097ca89b+"
            "00770530-5BBA-3F56-7F00-000000000000 end",
            "c9edbf4469097ca89b",
        ),
        (
            "see: 00000000-0000-8852-7d2e-076268ef2652_gww0g9w9890w9w9898ww080gsg9w988s9w00s0/"
            "80666385-a499-7850-9b91-000000000000",
            "gww0g9w9890w9w9898ww080gsg9w988s9w00s0",
        ),
        # Three UUIDs, the value between the last two.
        (
            "x 12345678-1234-1234-1234-123456789012_00000000-1111-2222-3333-444444444444"
            "-Qm7xL2pR9vK4wN8sZ3cB+55555555-6666-7777-8888-999999999999 y",
            "Qm7xL2pR9vK4wN8sZ3cB",
        ),
    ],
)
def test_a_value_glued_between_cut_uuids_is_masked(text: str, secret: str) -> None:
    out = Redactor().redact_text(text)
    assert not any(window in out for window in _windows(secret)), out
    assert "«REDACTED:" in out


def test_a_phone_rule_stops_where_a_cards_cut_stopped_main() -> None:
    # L1: the card rule cut the second UUID; the phone rule then read from the first UUID's last
    # group across the line break into it, masked only the `\n` between them, and the labelled
    # value of `access_key` ran on through `@token:` and took its label.
    text = (
        "access_key=2c1b9386-0000-0000-3f39-000000000000\n"
        "00000000-0840-5250-d179-439774756746@token: 't5p1ah2t@"
    )
    out = Redactor().redact_text(text)
    assert "t5p1ah2t" not in out, out
    assert "\n" in out and "@token: '" in out
    assert "d179" not in out and "0840" not in out  # the second UUID is masked whole


def test_each_uuid_is_masked_whole_and_the_text_between_kept() -> None:
    text = (
        "request 2c1b9386-0000-0000-3f39-000000000000 00000000-0840-5250-d179-439774756746 "
        "password: Summer2026!"
    )
    out = Redactor().redact_text(text)
    assert out.startswith("request «REDACTED:uuid:")
    assert out.count("«REDACTED:uuid:") == 2
    assert "3f39" not in out and "d179" not in out
    assert "Summer2026" not in out


def test_the_same_uuid_in_two_places_is_masked_whole_in_both() -> None:
    # Two occurrences that the number rules read differently: after a phone label and alone.
    uuid = "12345678-1234-1234-9abc-123456789012"
    out = Redactor(salt="s").redact_text(f"tel +34 600 123 456\n{uuid} and {uuid}_tail")
    assert "9abc" not in out
    assert out.count("«REDACTED:uuid:") >= 2


@pytest.mark.parametrize("glue", ["_", "/", "+", "="])
def test_a_token_of_glued_uuids_takes_linear_time(glue: str) -> None:
    # H2: UUIDs whose groups are all digits, glued into one token. 160 KB took 32.8 s at the
    # audited head (main 0.08 s); twice the size must not take much more than twice the time.
    rng = random.Random(7)  # noqa: S311 - test data, not a secret

    def uuid() -> str:
        return "-".join("".join(rng.choice(_DIGITS) for _ in range(n)) for n in (8, 4, 4, 4, 12))

    def timed(size: int) -> float:
        parts: list[str] = []
        while sum(map(len, parts)) < size:
            parts.append(uuid())
        text = glue.join(parts)
        started = time.perf_counter()
        out = Redactor().redact_text(text)
        assert not any(c.isdigit() for c in re.sub(r"«REDACTED:[^»]*»", "", out))
        return time.perf_counter() - started

    small, large = timed(40_000), timed(160_000)
    assert large < 3.0, large
    assert large < 8 * small + 0.5, (small, large)


def test_no_stand_in_reaches_the_output() -> None:
    from ildottore.redactor import _PRIVATE_USE_CHAR

    rng = random.Random(11)  # noqa: S311 - test data, not a secret
    redactor = Redactor()
    for _ in range(300):
        groups = [
            "".join(
                rng.choice(_DIGITS if rng.random() < 0.6 else "0123456789abcdef") for _ in range(n)
            )
            for n in (8, 4, 4, 4, 12)
        ]
        uuid = "-".join(groups)
        text = (
            rng.choice(["", "tel ", "card ", "id "])
            + uuid
            + rng.choice(["", "_x", "\n600 123 456"])
        )
        out = redactor.redact_text(text)
        assert _PRIVATE_USE_CHAR.search(out) is None, (text, out)
        assert redactor.redact_text(out) == out


def test_a_text_using_the_first_block_gets_another() -> None:
    # A Private Use character the text holds is its own, never read back as a digit.
    from ildottore.redactor import _Cuts

    text = " 2c1b9386-0000-0000-3f39-000000000000 "
    cuts = _Cuts.for_text(text)
    assert cuts is not None and cuts.run.search(text) is None
    out = Redactor().redact_text(text)
    assert out.startswith(" «REDACTED:uuid:") and out.endswith(" ")


def test_with_no_free_block_numbers_are_masked_as_main_masked_them() -> None:
    from ildottore.redactor import _PRIVATE_USE, _STAND_IN_BLOCK, _Cuts

    every_block = "".join(
        chr(base)
        for first, last in _PRIVATE_USE
        for base in range(first, last + 1 - _STAND_IN_BLOCK, _STAND_IN_BLOCK)
    )
    assert _Cuts.for_text(every_block) is None
    out = Redactor().redact_text(every_block + " 2c1b9386-0000-0000-3f39-000000000000")
    assert out.endswith(" 2c1b9386-«REDACTED:phone»-3f39-«REDACTED:phone»")


def test_a_labelled_digest_is_the_value_as_written() -> None:
    # The stand-ins of a pass are not part of a value: the same labelled UUID gets the same
    # digest whichever block the pass took, and the digest of the value as written.
    value = "2c1b9386-0000-0000-3f39-000000000000"
    redactor = Redactor(salt="s")
    plain = redactor.redact_text(f"secret: {value}")
    other_block = redactor.redact_text(f" secret: {value}")
    assert plain == f"secret: «REDACTED:labeled_secret:{redactor._digest(value)}»"
    assert other_block == " " + plain
