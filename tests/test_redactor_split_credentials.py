"""A registered credential split by characters that do not show is masked whole (2026-10-07).

The redactor finds a credential the tool registered by its value. Found by the audit of PR #51
and already on main:
- one split by a newline, a tab or another control character was kept in two readable halves by
  `redact_text`, so in every report, in the evidence store and on the terminal (a target replying
  `echo <first half>\\n<second half>` put both halves in the JSON report);
- one split by a format character (Unicode category Cf: a zero-width space, a soft hyphen, a word
  joiner, a byte order mark, a bidi control, a tag character) was kept the same way, and on a
  terminal it reads whole.
Split by the redactor's own stash delimiters (`\\x00`, `\\x01`) it was already masked whole.
"""

from __future__ import annotations

import asyncio
import json
import time
import tracemalloc
import unicodedata
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ildottore import redactor as redactor_mod
from ildottore.redactor import Redactor, register_known_secret

KEY = "Zq7vR2mK9pL4xW8nT3"  # 18 characters, no shape rule matches it
HEAD, TAIL = KEY[:9], KEY[9:]


@pytest.fixture
def no_known_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Registered credentials are process-wide: a test's own do not outlive it."""

    monkeypatch.setattr(redactor_mod, "_KNOWN_SECRETS", set())


@pytest.fixture
def key(no_known_secrets: None) -> str:
    register_known_secret(KEY)
    return KEY


def _whole_mask(redactor: Redactor) -> str:
    return redactor.redact_text(KEY)


_SPLITTERS = {
    "newline": "\n",
    "tab": "\t",
    "CR": "\r",
    "CRLF": "\r\n",
    "VT": "\x0b",
    "ESC": "\x1b",
    "DEL": "\x7f",
    "NEL (C1)": "\x85",
    "CSI (C1)": "\x9b",
    "line separator": chr(0x2028),
    "paragraph separator": chr(0x2029),
    "lone surrogate": chr(0xDC80),
    "zero-width space": chr(0x200B),
    "soft hyphen": chr(0xAD),
    "word joiner": chr(0x2060),
    "byte order mark": chr(0xFEFF),
    "right-to-left override": chr(0x202E),
    "left-to-right isolate": chr(0x2066),
    "zero-width joiner": chr(0x200D),
    "Mongolian vowel separator": chr(0x180E),
    "tag letter A": chr(0xE0041),
    "a run of several": "\n" + chr(0x200B) + "\t" + chr(0xE0020) + "\x7f",
}


@pytest.mark.parametrize("splitter", list(_SPLITTERS.values()), ids=list(_SPLITTERS))
@pytest.mark.usefixtures("key")
def test_a_credential_split_by_an_invisible_character_is_masked_whole(splitter: str) -> None:
    redactor = Redactor(salt="s")
    out = redactor.redact_text(f"echo {HEAD}{splitter}{TAIL} done")
    assert out == f"echo {_whole_mask(redactor)} done"
    assert redactor.redact_text(out) == out


@pytest.mark.usefixtures("key")
def test_a_credential_split_at_every_character_is_masked_with_the_unsplit_digest() -> None:
    redactor = Redactor(salt="s")
    zwsp = chr(0x200B)
    for joiner in ("\n", zwsp, "\x02" + zwsp, chr(0xE0041) + "\r"):
        out = redactor.redact_text("[" + joiner.join(KEY) + "]")
        assert out == f"[{_whole_mask(redactor)}]", repr(joiner)


@pytest.mark.usefixtures("key")
def test_what_lies_outside_the_credential_stays_where_it_is() -> None:
    redactor = Redactor(salt="s")
    zwsp = chr(0x200B)
    text = f"a\n{zwsp}{HEAD}\n{TAIL}{zwsp}\nb"
    assert redactor.redact_text(text) == f"a\n{zwsp}{_whole_mask(redactor)}{zwsp}\nb"


@pytest.mark.usefixtures("key")
def test_every_occurrence_is_masked_split_or_not() -> None:
    redactor = Redactor(salt="s")
    mask = _whole_mask(redactor)
    text = f"{KEY} {HEAD}\n{TAIL} {KEY[:3]}{chr(0xAD)}{KEY[3:]}{KEY} {KEY[:1]}\t{KEY[1:]}"
    assert redactor.redact_text(text) == f"{mask} {mask} {mask}{mask} {mask}"


@pytest.mark.usefixtures("no_known_secrets")
def test_two_overlapping_split_credentials_are_masked_as_one() -> None:
    """Masking one of them would leave the other's tail readable."""

    first, second = "Zz1Cd2Ef3Gh4", "Gh4Ij5Kl6Mn7Op8"  # the longer sorts first by value
    register_known_secret(first)
    register_known_secret(second)
    redactor = Redactor(salt="s")
    out = redactor.redact_text(f"x {first[:5]}\n{first[5:]}{second[3:7]}\t{second[7:]} y")
    assert out == f"x {redactor.redact_text(second)} y"  # named by the longer one
    assert "Zz1" not in out and "Op8" not in out


@pytest.mark.parametrize(
    ("first", "second"),
    [("Ab1Cd2Ef3Gh4", "Gh4Ij5Kl6Mn7"), ("Zb1Cd2Ef3Gh4", "Gh4Ij5Kl6Mn7")],
    ids=["first sorts first", "first sorts last"],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_two_overlapping_credentials_of_one_length_are_named_by_the_first(
    first: str, second: str
) -> None:
    """The first to start names the mask, as PR #51 and PR #56 name it, whatever the values."""

    register_known_secret(first)
    register_known_secret(second)
    redactor = Redactor(salt="s")
    out = redactor.redact_text(f"x {first[:5]}\n{first[5:]}{second[3:]} y")
    assert out == f"x {redactor.redact_text(first)} y"


@pytest.mark.usefixtures("no_known_secrets")
def test_a_split_credential_overlapping_an_unsplit_one_is_masked_with_it() -> None:
    """Taking the unsplit one first left 8 of the split one's 12 characters readable."""

    first, second = "Zz1Cd2Ef3Gh4", "Gh4Ij5Kl6Mn7Op8"
    register_known_secret(first)
    register_known_secret(second)
    redactor = Redactor(salt="s")
    for text in (f"{first[:4]}\n{first[4:]}{second[3:]}", f"{first}{second[3:6]}\t{second[6:]}"):
        assert redactor.redact_text(f"x {text} y") == f"x {redactor.redact_text(second)} y"


@pytest.mark.usefixtures("no_known_secrets")
def test_a_credential_that_repeats_itself_twice_in_a_row_is_one_mask() -> None:
    """The end of one and the start of the next, split by a tab, are the credential too."""

    register_known_secret("hunter2hunter2")
    redactor = Redactor(salt="s")
    mask = redactor.redact_text("hunter2hunter2")
    assert redactor.redact_text("a hunter2hunter2\thunter2hunter2 b") == f"a {mask} b"
    assert redactor.redact_text("a hunter2hunter2 hunter2hunter2 b") == f"a {mask} {mask} b"


@pytest.mark.usefixtures("no_known_secrets")
def test_a_key_read_with_a_trailing_cr_is_masked_as_its_plain_form() -> None:
    """One credential, one digest: the CR form, unsplit, used to get a digest of its own."""

    register_known_secret(KEY + "\r")  # registers the stripped form too
    redactor = Redactor(salt="s")
    plain = redactor.redact_text(KEY)
    assert redactor.redact_text(f"{HEAD}\n{TAIL}\r") == plain + "\r"
    assert redactor.redact_text(f"a {KEY}\r b") == f"a {plain}\r b"
    assert redactor.redact_text(f"b'Bearer {KEY}\\r'").count("«REDACTED:credential:") == 1


@pytest.mark.usefixtures("no_known_secrets")
def test_a_credential_registered_with_an_invisible_character_inside_matches_without_it() -> None:
    zwsp = chr(0x200B)
    register_known_secret(f"{HEAD}{zwsp}{TAIL}")
    redactor = Redactor(salt="s")
    as_registered = redactor.redact_text(f"{HEAD}{zwsp}{TAIL}")
    assert as_registered.startswith("«REDACTED:credential:")
    for written in (KEY, f"{HEAD}\n{TAIL}", f"{KEY[:2]}{chr(0x2060)}{KEY[2:]}"):
        assert redactor.redact_text(f"<{written}>") == f"<{as_registered}>"


@pytest.mark.usefixtures("no_known_secrets")
def test_a_key_read_with_a_byte_order_mark_is_masked_when_echoed_without_it() -> None:
    """`strip()` keeps U+FEFF, so main registered only the form with it and printed the key."""

    register_known_secret(chr(0xFEFF) + KEY)
    redactor = Redactor(salt="s")
    out = redactor.redact_text(f"auth failed for {KEY} here")
    assert KEY not in out and out.startswith("auth failed for «REDACTED:credential:")
    # Written with it, the mark lies outside the stretch the credential covers: same mask after it.
    with_mark = out.replace("for «", f"for {chr(0xFEFF)}«")
    assert redactor.redact_text(f"auth failed for {chr(0xFEFF)}{KEY} here") == with_mark


@pytest.mark.usefixtures("no_known_secrets")
def test_a_credential_shorter_than_eight_without_its_invisible_characters_is_not_matched() -> None:
    """Registered from 8 characters: dropping them must not grow a short word into a mask."""

    zwsp = chr(0x200B)
    register_known_secret(f"abc{zwsp}defg")
    redactor = Redactor(salt="s")
    assert redactor.redact_text("x abcdefg y") == "x abcdefg y"
    assert redactor.redact_text("x abc\ndefg y") == "x abc\ndefg y"
    assert redactor.redact_text(f"x abc{zwsp}defg y").startswith("x «REDACTED:credential:")


@pytest.mark.usefixtures("no_known_secrets")
def test_a_short_credential_with_invisible_characters_inside_is_masked_as_written() -> None:
    """Matched neither joined (too short) nor as written (the text holds a splitter): kept raw."""

    for secret in ("ab\tcd\tefg", "pass\x0bwd!", f"Xy7{chr(0x200B)}Q9{chr(0x200B)}z", "short7\r\n"):
        redactor_mod._KNOWN_SECRETS.clear()
        register_known_secret(secret)
        redactor = Redactor(salt="s")
        out = redactor.redact_text(f"say {secret} now")
        assert secret not in out and out.startswith("say «REDACTED:credential:"), repr(secret)
        assert redactor.redact_text(out) == out


@pytest.mark.parametrize(
    ("registered", "text", "longer"),
    [
        (["ab\tcd\tefgHIJKLMN", "ab\tcd\tefg"], "say ab\tcd\tefgHIJKLMN now", "ab\tcd\tefgHIJKLMN"),
        (["ABCDEFGHxy", "Hxy\x0b\x0b\x0bzq"], "ABCDEFGHxy\x0b\x0b\x0bzq tail", "ABCDEFGHxy"),
        (["abcdef  QRSTUVWX", "  abcdef  "], "x  abcdef  QRSTUVWX\n", "abcdef  QRSTUVWX"),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_short_credential_matched_as_written_does_not_break_a_longer_one(
    registered: list[str], text: str, longer: str
) -> None:
    """Replaced before the longer matches, a short one took a longer credential's head and left
    up to 7 of its characters readable (delta audit); now both are masked as one stretch."""

    for value in registered:
        register_known_secret(value)
    redactor = Redactor(salt="s")
    out = redactor.redact_text(text)
    assert longer not in out and f"«REDACTED:credential:{redactor._digest(longer)}»" in out
    assert redactor.redact_text(out) == out


@pytest.mark.parametrize(
    ("registered", "text", "outside"),
    [
        (
            ["\t\t\t\t\t\tAKdke\xad\xad\xad", "HdgYGmDj", "gYGmDjAK"],
            "cmceenHdgYGmDj\t\t\t\t\t\tAKdke\xad\xad\xadEHeH",
            ("cmceen", "EHeH"),
        ),
        (
            [" c\newUw\x7fYv   ", "v   SSG\rQV", "SSGQVYtecKB"],
            "DBHDt c\newUw\x7fYv   SSGQVYtecKBhsM",
            ("DBHDt", "hsM"),
        ),
        (["ab\t\t\t\t\tcd\tefg", "WXYZQRab"], "WXYZQRab\t\t\t\t\tcd\tefg\n", ("", "\n")),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_short_credential_and_a_longer_match_over_it_are_masked_as_one(
    registered: list[str], text: str, outside: tuple[str, str]
) -> None:
    """Replaced after the longer matches, a short form kept up to 6 characters they had not
    taken, where main masked everything (pre-merge audit); their union is masked now."""

    for value in registered:
        register_known_secret(value)
    redactor = Redactor(salt="s")
    out = redactor.redact_text(text)
    head, tail = outside
    assert out.startswith(head + "«REDACTED:credential:") and out.endswith("»" + tail)
    assert out.count("«") == 1 and redactor.redact_text(out) == out


@pytest.mark.usefixtures("no_known_secrets")
def test_two_overlapping_short_credentials_are_masked_as_one() -> None:
    zwsp = chr(0x200B)
    register_known_secret(f"ab{zwsp}cd{zwsp}efg")
    register_known_secret(f"efg{zwsp}hi{zwsp}jk")
    redactor = Redactor(salt="s")
    out = redactor.redact_text(f"x ab{zwsp}cd{zwsp}efg{zwsp}hi{zwsp}jk y")
    assert out.startswith("x «REDACTED:credential:") and out.endswith("» y")
    assert out.count("«") == 1


@pytest.mark.parametrize(
    ("registered", "text"),
    [
        (["QRSTUVWabc", "abc\t\t\tabc"], "QRSTUVWabc\t\t\tabc\t\t\tabc."),
        (
            ["KLMNOPQxyz", "xyz" + chr(0x200B) * 3 + "xyz"],
            "KLMNOPQxyz" + (chr(0x200B) * 3 + "xyz") * 2 + ".",
        ),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_short_credential_overlapping_itself_under_a_longer_match_is_masked_whole(
    registered: list[str], text: str
) -> None:
    """Taken without overlaps, its second occurrence was lost when a longer match covered the
    first, and its tail stayed readable where main masked it (delta audit of the follow-ups)."""

    for value in registered:
        register_known_secret(value)
    redactor = Redactor(salt="s")
    out = redactor.redact_text(text)
    assert out.startswith("«REDACTED:credential:") and out.endswith("».") and out.count("«") == 1
    assert redactor.redact_text(out) == out


@pytest.mark.parametrize("before", ["x ", "QRSTUVW"])
@pytest.mark.usefixtures("no_known_secrets")
def test_a_short_credential_repeating_a_piece_three_times_is_masked_through_its_overlaps(
    before: str,
) -> None:
    """The shortcut the long forms take (no overlaps once a piece repeats three times) left the
    last piece readable for a short one (final delta audit)."""

    piece = "a\t" + chr(0x200B)
    register_known_secret(piece * 3)
    if before != "x ":
        register_known_secret(before + "a")  # a longer match over the first piece
    redactor = Redactor(salt="s")
    out = redactor.redact_text(before + piece * 4 + "!")
    assert out.endswith("»!") and out.count("«") == 1
    assert out.startswith("x «") if before == "x " else out.startswith("«")


@pytest.mark.usefixtures("no_known_secrets")
def test_every_occurrence_of_a_short_credential_is_masked_in_one_pass() -> None:
    """Redaction runs to a fixed point in at most four passes: a placement that took one
    occurrence a pass still looked whole with two or three of them (delta audit)."""

    register_known_secret("ab\tcd\tefg")
    redactor = Redactor(salt="s")
    out = redactor.redact_text("ab\tcd\tefg " * 6)
    assert out.count("«REDACTED:credential:") == 6 and "efg" not in out


@pytest.mark.usefixtures("key")
def test_what_follows_a_group_that_is_not_the_last_stays_outside_it() -> None:
    redactor = Redactor(salt="s")
    mask = _whole_mask(redactor)
    text = f"{HEAD}\n{TAIL}\x85 and {HEAD}\t{TAIL}{chr(0x2028)}"
    assert redactor.redact_text(text) == f"{mask}\x85 and {mask}{chr(0x2028)}"


@pytest.mark.usefixtures("no_known_secrets")
def test_whitespace_at_the_ends_does_not_count_toward_the_name() -> None:
    """`strip()` keeps a leading zero-width space, so the spaces after it were registered too."""

    padded = chr(0x200B) + "  abcdefgh"  # 8 characters show, 10 without the strip
    register_known_secret(padded)
    register_known_secret("efghIJKLM")
    redactor = Redactor(salt="s")
    out = redactor.redact_text("x abcdefghIJKLM\n")
    assert out == f"x «REDACTED:credential:{redactor._digest('efghIJKLM')}»\n"


@pytest.mark.usefixtures("no_known_secrets")
def test_an_overlapping_group_is_named_by_the_longest_as_it_shows() -> None:
    """Counted with its invisible characters, a shorter credential named the group."""

    padded = "abcdefgh" + chr(0x200B) * 5  # 8 characters show, 13 counted
    register_known_secret(padded)
    register_known_secret("efghIJKLMN")
    redactor = Redactor(salt="s")
    out = redactor.redact_text("x abcdefghIJKLMN\n")
    assert out == f"x «REDACTED:credential:{redactor._digest('efghIJKLMN')}»\n"


@pytest.mark.usefixtures("no_known_secrets")
def test_spaces_around_a_short_value_do_not_make_it_long_enough_to_match_prose() -> None:
    """` # back \r` without its CR is 8 characters only with its spaces, and masked prose."""

    register_known_secret(" # back \r")
    redactor = Redactor(salt="s")
    assert redactor.redact_text("go # back to the app\n") == "go # back to the app\n"
    assert " # back \r" not in redactor.redact_text("go # back \r to")


@pytest.mark.usefixtures("no_known_secrets")
def test_a_stretch_written_as_a_registered_form_gets_that_form_s_digest() -> None:
    """Two forms that differ by an invisible character: the first by value named both, and
    which one came first changed with the hash seed (pre-commit audit)."""

    zwsp, joiner = chr(0x200B), chr(0x2060)
    by_zwsp, by_joiner = f"{HEAD}{zwsp}{TAIL}", f"{HEAD}{joiner}{TAIL}"
    register_known_secret(by_zwsp)
    register_known_secret(by_joiner)
    redactor = Redactor(salt="s")
    for form in (by_zwsp, by_joiner):
        digest = redactor._digest(form)
        assert redactor.redact_text(f"a {form} b") == f"a «REDACTED:credential:{digest}» b"
    # Written some other way, it is named by the first of the two by value, whatever order the
    # registered set gives them in (it follows the hash seed).
    first = min(by_zwsp, by_joiner)
    expected = f"a «REDACTED:credential:{redactor._digest(first)}» b"
    for order in ([by_zwsp, by_joiner], [by_joiner, by_zwsp]):
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(redactor_mod, "_known_secrets", lambda order=order: list(order))
            assert redactor.redact_text(f"a {HEAD}\n{TAIL} b") == expected


@pytest.mark.parametrize(
    ("registered", "text"),
    [
        (["00000000", "0000001\x00"], "0000001\x0000000000"),
        (["\x01abcdefgh"], "x «REDACTED:email»abcdefgh"),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_registered_value_holding_a_stash_delimiter_breaks_no_stash_token(
    registered: list[str], text: str, tmp_path: Path
) -> None:
    """It matched across a stash token: a raw delimiter out, a second pass that differed, and
    the evidence store refusing the reply (pre-commit audit; on main too)."""

    from ildottore.shared.models import ModelResponse
    from ildottore.store.evidence_fs import FsEvidenceStore
    from tests.store.conftest import make_attempt

    for value in registered:
        register_known_secret(value)
    redactor = Redactor(salt="s")
    once = redactor.redact_text(text)
    assert "\x00" not in once and "\x01" not in once
    assert redactor.redact_text(once) == once
    store = FsEvidenceStore(tmp_path, redactor=redactor)
    attempt = make_attempt().model_copy(update={"response": ModelResponse(text=text)})
    assert store.put("run-1", attempt).sha256 is not None


@pytest.mark.usefixtures("no_known_secrets")
def test_a_value_holding_a_stash_delimiter_does_not_cross_a_url_separator() -> None:
    """Registered without the delimiter, `abc@host` took the URL's `@` and left the start of
    the password readable, where main masks the whole password (as PR #56 found)."""

    register_known_secret("abc\x00@host.example")
    out = Redactor(salt="s").redact_text("https://u:xyzabc@host.example/p")
    assert out == "https://u:«REDACTED:url_password»@host.example/p"


def test_a_lone_surrogate_in_a_hashed_value_is_digested() -> None:
    """`_digest` encoded strictly and raised `UnicodeEncodeError` (on main)."""

    redactor = Redactor(salt="s")
    assert len(redactor._digest("Abc" + chr(0xDC80) + "def")) == 8
    out = redactor.redact_text("password: Abc" + chr(0xDC80) + "defg9")
    assert out.startswith("password: «REDACTED:labeled_secret:")


@pytest.mark.usefixtures("key")
def test_the_stash_delimiters_and_other_invisible_characters_together() -> None:
    redactor = Redactor(salt="s")
    assert redactor.redact_text(f"{HEAD[:4]}\x00{HEAD[4:]}\n{TAIL}") == _whole_mask(redactor)
    assert redactor.redact_text(f"{HEAD}\x01{chr(0x200B)}{TAIL}") == _whole_mask(redactor)


@pytest.mark.usefixtures("key")
def test_a_split_credential_in_a_mask_written_by_the_target_is_masked() -> None:
    redactor = Redactor(salt="s")
    for forged in (f"«REDACTED:{HEAD}\n{TAIL}»", f"«REDACTED:credential:{HEAD}\t{TAIL}»"):
        out = redactor.redact_text(f"key {forged} end")
        assert HEAD not in out and TAIL not in out and _whole_mask(redactor) in out
        assert redactor.redact_text(out) == out


# --- the format characters ---------------------------------------------------------------


def _ranges_as_set(ranges: tuple[tuple[int, int], ...]) -> set[int]:
    return {code for low, high in ranges for code in range(low, high + 1)}


def test_the_format_characters_are_every_cf_character_of_this_python() -> None:
    """Pinned to Unicode 16.0 so a mask never depends on the Python's Unicode version."""

    pinned = _ranges_as_set(redactor_mod._FORMAT_RANGES)
    here = {code for code in range(0x110000) if unicodedata.category(chr(code)) == "Cf"}
    assert here <= pinned
    # An older Python (3.11 has Unicode 14.0) does not know the newest ones yet.
    assert {unicodedata.category(chr(code)) for code in pinned - here} <= {"Cn"}
    assert len(pinned) == 170


def test_the_splitters_dropped_and_the_splitters_walked_are_the_same_characters() -> None:
    """A character dropped but not walked over would shift every later mask (or vice versa)."""

    walked = {code for code in range(0x110000) if redactor_mod._SPLITTER_RUN.fullmatch(chr(code))}
    assert walked == set(redactor_mod._DROP_SPLITTERS)
    assert walked | {0x00, 0x01} == set(redactor_mod._DROP_INVISIBLE)
    assert walked >= _ranges_as_set(redactor_mod._FORMAT_RANGES) - {0x00, 0x01}


@pytest.mark.usefixtures("key")
def test_every_format_character_splits_a_credential() -> None:
    redactor = Redactor(salt="s")
    mask = _whole_mask(redactor)
    for code in sorted(_ranges_as_set(redactor_mod._FORMAT_RANGES)):
        assert redactor.redact_text(f"{HEAD}{chr(code)}{TAIL}") == mask, hex(code)


# --- every path that keeps a target's text ---------------------------------------------------


class _Echo:
    """Answers with the operator's key split by a newline and a zero-width space."""

    id = "t1"

    async def send(self, request: object) -> object:
        from ildottore.shared.models import ModelResponse

        return ModelResponse(
            text=f"echo {HEAD}\n{TAIL} and {KEY[:4]}{chr(0x200B)}{KEY[4:]}",
            tool_calls=[{"name": "f", "arguments": {"q": f"{HEAD}{chr(0xAD)}{TAIL}"}}],
        )

    def capabilities(self) -> object:
        from ildottore.shared.models import Capabilities

        return Capabilities()


@pytest.mark.usefixtures("key")
def test_the_json_report_the_evidence_and_the_run_store_keep_no_half(tmp_path: Path) -> None:
    from ildottore.core.runner import CampaignRunner
    from ildottore.evaluators import build_default_registry as build_evaluators
    from ildottore.mutators import build_default_registry as build_mutators
    from ildottore.reporting.json_reporter import JsonReporter
    from ildottore.scoring import DefaultRiskScorer
    from ildottore.store.evidence_fs import FsEvidenceStore
    from ildottore.store.run_sqlite import SqliteRunStore
    from tests.core.conftest import AllowAllPolicy, make_spec, make_target, no_sleep

    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=build_mutators(discover=False),
        evaluators=build_evaluators(discover=False),
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev"),
        run_store=SqliteRunStore(tmp_path / "runs.sqlite"),
        adapter_factory=lambda _t, _s: _Echo(),
        n=1,
        concurrency=1,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    result = asyncio.run(runner.run(run_id="r1", target=make_target(), specs=[make_spec()]))
    report = JsonReporter().render(result.run, list(result.run.findings)).decode("utf-8")
    evidence = [p.read_text(encoding="utf-8") for p in (tmp_path / "ev").rglob("*.json")]
    stored = (tmp_path / "runs.sqlite").read_bytes().decode("latin-1")
    assert evidence, "the attempt was stored"
    for kept in (report, *evidence, stored):
        assert HEAD not in kept and TAIL not in kept and KEY[4:] not in kept
    assert "REDACTED:credential:" in report  # the JSON report escapes the guillemets


@pytest.mark.usefixtures("key")
def test_the_evidence_store_leak_guard_accepts_a_split_credential(tmp_path: Path) -> None:
    from ildottore.shared.models import ModelResponse
    from ildottore.store.evidence_fs import FsEvidenceStore
    from tests.store.conftest import make_attempt

    store = FsEvidenceStore(tmp_path, redactor=Redactor(salt="s"))
    args = {f"{HEAD}\n{TAIL}": 1, f"{HEAD}{chr(0x2060)}{TAIL}": 2, f"a{chr(0x200B)}b": 3}
    response = ModelResponse(
        text=f"{HEAD}\r\n{TAIL}", tool_calls=[{"name": "f", "arguments": args}]
    )
    ref = store.put("run-1", make_attempt().model_copy(update={"response": response}))
    stored = (tmp_path / ref.uri).read_text(encoding="utf-8") if ref.uri else ""
    payload = json.loads(stored)
    assert HEAD not in stored and TAIL not in stored
    assert len(payload["response"]["tool_calls"][0]["arguments"]) == 3


@pytest.mark.usefixtures("key")
def test_an_error_printed_by_the_cli_keeps_no_half() -> None:
    from ildottore.cli.app import _masked

    out = _masked(RuntimeError(f"bad reply: {HEAD}\n{TAIL} / {HEAD}{chr(0xFEFF)}{TAIL}"))
    assert HEAD not in out and TAIL not in out
    assert out.count("«REDACTED:credential:") == 2


# --- text without such characters is redacted as before --------------------------------------

_PRINTABLE = st.lists(
    st.sampled_from(
        [
            *"abcxyzZqR29 -_.:=@/«»",
            *(HEAD, TAIL, KEY, "password: ", "«REDACTED:credential:0123abcd»", "tel 555-123-4567"),
        ]
    ),
    max_size=40,
).map("".join)


@settings(max_examples=300, deadline=None)
@given(text=_PRINTABLE)
def test_text_without_invisible_characters_never_enters_the_split_match(text: str) -> None:
    """A guard: the split match changes nothing in text without such characters.

    It compares the redactor with itself with the match stubbed out; the evidence that the output
    is byte for byte main's is the differential fuzz against main, run before a merge (A-31).
    """

    saved = set(redactor_mod._KNOWN_SECRETS)
    try:
        redactor_mod._KNOWN_SECRETS.clear()
        register_known_secret(KEY)
        redactor = Redactor(salt="s")
        out = redactor.redact_text(text)
        plain = Redactor(salt="s")
        plain._redact_split_credentials = lambda working, _keep, _known, split: working  # type: ignore[method-assign]
        assert plain.redact_text(text) == out
    finally:
        redactor_mod._KNOWN_SECRETS.clear()
        redactor_mod._KNOWN_SECRETS.update(saved)


_HOSTILE_PIECES = st.sampled_from(
    [
        *KEY,
        HEAD,
        TAIL,
        KEY,
        "\n",
        "\t",
        "\r",
        "\x00",
        "\x01",
        "\x7f",
        "\x85",
        chr(0x200B),
        chr(0xAD),
        chr(0x2060),
        chr(0xFEFF),
        chr(0x202E),
        chr(0xE0041),
        chr(0x2028),
        chr(0xDC80),
        " ",
        "«REDACTED:credential:0123abcd»",
        "«REDACTED:x»",
        "password: ",
        "@x.io",
        "555-0142",
        chr(0x2400),
    ]
)


@settings(max_examples=400, deadline=None)
@given(pieces=st.lists(_HOSTILE_PIECES, max_size=30))
def test_redaction_of_hostile_text_is_a_fixed_point_and_leaves_no_joined_credential(
    pieces: list[str],
) -> None:
    saved = set(redactor_mod._KNOWN_SECRETS)
    try:
        redactor_mod._KNOWN_SECRETS.clear()
        register_known_secret(KEY)
        redactor = Redactor(salt="s")
        text = "".join(pieces)
        once = redactor.redact_text(text)
        assert redactor.redact_text(once) == once
        joined = once.translate(redactor_mod._DROP_INVISIBLE)
        assert KEY not in joined
    finally:
        redactor_mod._KNOWN_SECRETS.clear()
        redactor_mod._KNOWN_SECRETS.update(saved)


# --- bounded in time and memory ---------------------------------------------------------------

_MB = 1024 * 1024


def _hostile(name: str, size: int) -> str:
    zwsp = chr(0x200B)
    unit = {
        "zero-width spaces, no credential": "x" + zwsp,
        "controls only": "\x02",
        "the credential split at every character": "\x02".join(KEY) + " ",
        "the credential split once, repeated": HEAD + zwsp + TAIL + " ",
        "a tag character after every letter": "a" + chr(0xE0041),
    }[name]
    return unit * (size // len(unit))


_HOSTILE_NAMES = [
    "zero-width spaces, no credential",
    "controls only",
    "the credential split at every character",
    "the credential split once, repeated",
    "a tag character after every letter",
]


@pytest.mark.parametrize("name", _HOSTILE_NAMES)
@pytest.mark.usefixtures("key")
def test_hostile_text_is_redacted_in_bounded_memory(name: str) -> None:
    """Memory, not seconds: a time limit under coverage tests the runner, not the code.

    The first terminal-only version took about 140 MB a megabyte of control characters.
    """

    text = _hostile(name, 2 * _MB)
    redactor = Redactor(salt="s")
    tracemalloc.start()
    try:
        out = redactor.redact_text(text)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    # No credential is readable once the invisible characters are dropped (main fails this on
    # the inputs that hold one; on the others the test is a bound only).
    assert KEY not in out.translate(redactor_mod._DROP_INVISIBLE)
    # The text with its invisible characters dropped, the output and the masks: a few
    # copies of the input at most, whatever its shape (4 bytes a character when it holds
    # a tag character).
    assert peak < 24 * len(text), f"{peak / len(text):.1f} bytes a character"


@pytest.mark.parametrize("piece", ["a", "ab12"])
@pytest.mark.usefixtures("no_known_secrets")
def test_a_credential_that_repeats_itself_costs_no_more_the_longer_it_is(piece: str) -> None:
    """Following every overlap cost a `find` of the whole credential per character: 4 MB with
    `a` written 1,000 times registered took 11 s, against 0.02 s on main (pre-commit audit)."""

    text = piece * (_MB // len(piece)) + "\n"

    def seconds(length: int) -> float:
        credential = piece * (length // len(piece))
        redactor_mod._KNOWN_SECRETS.clear()
        register_known_secret(credential)
        started = time.perf_counter()
        out = Redactor(salt="s").redact_text(text)
        elapsed = time.perf_counter() - started
        assert credential not in out and out.startswith("«REDACTED:credential:")
        return elapsed

    short, long = seconds(40), seconds(800)
    assert long < 3 * short + 0.3, f"{short:.3f}s for 40 characters, {long:.3f}s for 800"


@pytest.mark.parametrize("name", _HOSTILE_NAMES)
@pytest.mark.usefixtures("key")
def test_hostile_text_is_redacted_in_linear_time(name: str) -> None:
    """Four times the text takes about four times as long, not sixteen."""

    redactor = Redactor(salt="s")

    def seconds(size: int) -> float:
        text = _hostile(name, size)
        best = float("inf")
        for _ in range(2):
            started = time.perf_counter()
            redactor.redact_text(text)
            best = min(best, time.perf_counter() - started)
        return best

    small, large = seconds(_MB // 4), seconds(_MB)
    assert large < 10 * small + 0.5, f"{small:.3f}s then {large:.3f}s"
