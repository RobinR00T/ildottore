"""A text holding U+0000 or U+0001 is masked the same whatever else it holds (u01 A-83, item 6).

The redactor's stash tokens are ``\\x00<number>\\x01``, so it never reads those two characters as
text. ``redact_text`` dropped them and returned that reading whenever it masked anything, and
otherwise read the text again with them made visible (``␀``, ``␁``). Dropped, they glue what they
separate (``x\\x01credential: <value>`` loses its label, ``bob@corp.io\\x00_`` its address); shown,
they split what they join (``AKIA\\x00IOSF...``). So whether a value was masked depended on
whether anything at all was masked in the text, however far from it: a UUID on one line showed
the labelled secret on the next (disclosed as F2 by the pre-merge audits of A-78). Both readings
are now made, and what either masks is masked, in the text with the delimiters made visible.
"""

from __future__ import annotations

import random
import time
import tracemalloc

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ildottore.redactor import Redactor, mask_split

#: Registered credentials are process-wide: none from an earlier test changes a mask here.
pytestmark = pytest.mark.usefixtures("no_known_secrets")

#: Each: a text whose secret one reading of the delimiters hides, and the secret.
CASES = {
    "label glued by U+0001": ("note\x01credential: 'Summer2026xQ'", "Summer2026xQ"),
    "label glued by U+0000": ("x)idfknfiuys\x00password=Hunter2Secret99", "Hunter2Secret99"),
    "address ended by U+0000": ("write bob.smith@corp.io\x00_x", "bob.smith@corp.io"),
    "number ended by U+0001": ("call 600123456\x01x", "600123456"),
    "key split by U+0000": ("AKIA\x00IOSFODNN7EXAMPLE", "IOSFODNN7EXAMPLE"),
    "key read as UTF-16": ("\x00".join("sk-Ab3dE5fG7hJ9kL1mN3pQ5rS7") + "\x00", "Ab3dE5fG7h"),
}
#: Something the redactor masks, unrelated to the case, as F2 found them.
UNRELATED = (
    "5f0eb9d2-2c10-4000-ac58-6fdf9029c33d",
    "alice@example.org",
    "OPENAI_API_KEY=sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z",
    "2222222222222222222222222222222",
)


def _shown(text: str) -> str:
    return text.replace("␀", "").replace("␁", "")


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_secret_is_masked_alone(case: str) -> None:
    text, secret = CASES[case]
    redactor = Redactor(salt="s")
    out = redactor.redact_text(text)
    assert secret not in _shown(out), out
    assert "\x00" not in out and "\x01" not in out
    assert redactor.redact_text(out) == out


@pytest.mark.parametrize("unrelated", UNRELATED)
@pytest.mark.parametrize("case", sorted(CASES))
def test_the_secret_is_masked_whatever_else_the_text_holds(case: str, unrelated: str) -> None:
    """On ``7d01521f`` the first three cases showed their secret once anything else was masked."""

    text, secret = CASES[case]
    redactor = Redactor(salt="s")
    alone = redactor.redact_text(text)
    both = redactor.redact_text(f"{unrelated}\n{text}")
    assert secret not in _shown(both), both
    # The line is masked as it is on its own.
    assert both.endswith("\n" + alone), (both, alone)


def test_the_delimiters_show_whether_or_not_anything_is_masked() -> None:
    """Dropped from the output whenever something was masked, `cmd\\x01` and `cmd` read alike in
    one text and apart in another."""

    redactor = Redactor(salt="s")
    assert redactor.redact_text("cmd\x01 run") == "cmd␁ run"
    masked = redactor.redact_text("cmd\x01 run AKIAIOSFODNN7EXAMPLE")
    assert masked.startswith("cmd␁ run «REDACTED:aws_access_key:"), masked


def test_a_text_without_a_delimiter_is_read_once() -> None:
    redactor = Redactor(salt="s")
    text = "tenant 5f0eb9d2-2c10-4000-ac58-6fdf9029c33d, password: Hunter2Secret99"
    assert redactor.redact_text(text) == redactor._to_fixed_point(text)


_PIECES = st.sampled_from(
    [
        "password: Hunter2Secret99",
        "credential: 'Summer2026xQ'",
        "bob.smith@corp.io",
        "AKIAIOSFODNN7EXAMPLE",
        "5f0eb9d2-2c10-4000-ac58-6fdf9029c33d",
        "call 600123456",
        "«REDACTED:email»",
        "«REDACTED:uuid:0123abcd»",
        "https://ops:Secr3tPassw0rd@db.internal/v1",
        "word",
        "x)",
        "_",
        " ",
        "\n",
        "\x00",
        "\x01",
        "\x00\x01",
    ]
)


@settings(max_examples=300, deadline=None)
@given(st.lists(_PIECES, min_size=1, max_size=12))
def test_every_output_is_a_fixed_point_and_shows_no_delimiter(pieces: list[str]) -> None:
    redactor = Redactor(salt="s")
    out = redactor.redact_text("".join(pieces))
    assert "\x00" not in out and "\x01" not in out
    assert redactor.redact_text(out) == out


def test_reading_both_ways_stays_linear() -> None:
    """Twice the text, about twice the time: the positions of the characters the joined reading
    keeps are held as the delimiters' places, not one entry a character."""

    redactor = Redactor(salt="s")
    unit = "user@corp.io\x00 AKIA\x00IOSFODNN7EXAMPLE x\x01credential: 'Summer2026xQ'\n"

    def cost(copies: int) -> float:
        text = unit * copies
        started = time.perf_counter()
        redactor.redact_text(text)
        return time.perf_counter() - started

    cost(200)  # warm the patterns
    small, large = min(cost(2_000) for _ in range(3)), min(cost(8_000) for _ in range(3))
    assert large < 8 * small, (small, large)


def _glued_hex_runs(size: int) -> str:
    """Distinct 32-hex runs glued by U+0000, ``size`` characters: the joined reading masks one run,
    the visible one each of them, a mask of its own each, and every mask merges into one stretch."""

    draw = random.Random(0)  # noqa: S311 - test data, not a secret
    runs = (size // 33) + 1
    return "\x00".join(f"{draw.getrandbits(128):032x}" for _ in range(runs))[:size]


def test_merging_many_masks_into_one_stretch_stays_linear() -> None:
    """Four times the text, under six times the time. The merged stretch's masks were a tuple
    rebuilt and searched for each mask merged into it: 4 MiB took 177 s where main took 0.73 s
    (pre-merge audit of A-83, HIGH 1)."""

    redactor = Redactor(salt="s")

    def cost(size: int) -> float:
        text = _glued_hex_runs(size)
        started = time.perf_counter()
        redactor.redact_text(text)
        return time.perf_counter() - started

    cost(16 * 1024)  # warm the patterns
    small = min(cost(256 * 1024) for _ in range(2))
    large = min(cost(1024 * 1024) for _ in range(2))
    assert large < 6 * small, (small, large)


def _glued_key_stream(size: int) -> list[dict[str, object]]:
    """A logprob stream of 4-character tokens, ``size`` characters of distinct `ghp_` keys glued
    by U+0000: the joined reading masks them as one stretch, which every token lies in."""

    keys: list[str] = []
    written = 0
    while written < size:
        key = "ghp_" + format(written * 7919 % 36**8, "08x") * 4 + "abcd"
        keys.append(key)
        written += len(key) + 1
    text = "\x00".join(keys)[:size]
    return [{"token": text[i : i + 4], "logprob": -0.5} for i in range(0, len(text), 4)]


def test_a_logprob_stream_s_memory_grows_with_its_length() -> None:
    """Four times the stream, under eight times the peak memory. Each token held a copy of its
    stretch's masks, so memory grew as tokens times masks: 4.19 GB on 256 KiB (pre-merge audit of
    A-83, round 2, MEDIUM 1); 16 KiB and 64 KiB peaked at 15 MiB and 211 MiB, 13.8 times."""

    redactor = Redactor(salt="s")

    def peak(size: int) -> int:
        items = _glued_key_stream(size)
        tracemalloc.start()
        try:
            mask_split(redactor, items)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    small, large = peak(16 * 1024), peak(64 * 1024)
    assert large < 8 * small, (small, large)
