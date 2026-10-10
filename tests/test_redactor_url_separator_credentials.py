"""A registered credential that holds one of a URL's separators (issue #96, 2026-10-09).

Two regressions the owner accepted for the merge of PR #56, and the class they belong to:
- a registered credential holding an `@` across a URL's `@` (`Adm1n@2026` in
  `redis://ops:Adm1n@2026-db.internal:6379,password=Secr3t@Value99xyz`) let the URL rule read on
  to a later `@`, a labelled value's: the URL mask took the label and the value's head, and the
  tail (`Value99xyz`) was readable, where the redactor before A-31 masked the value whole;
- two overlapping registered credentials masked as one run (`key-ABCD1234` and `1234://bob`)
  covered the URL's `://`, so the URL rule found no URL and the password was readable, where the
  one-at-a-time replacement before A-31 left the `://` showing and masked it. One credential
  holding the `://`, the `:` or the password's `@` with no later `@` stopped the rule the same
  way, before A-31 too.

The proposal of the pre-merge audit for the first (leave a password holding such a credential to
the other rules) was measured against main with a differential fuzz: on 300,000 texts it left
readable, in 18,444 of them, a character main masked (the password's head before the
credential, `AAAA` in `redis://ops:AAAAAdm1n@2026-token=QQQQQQ@host`). The fix keeps main's
URL mask and masks the rest of the labelled value after it, and the labelled values after that
as the redactor before A-31 read them; the second reads the URL in the text as written and
masks what of its password is still readable, last in the pass. The audit of the fix found the
chained labelled values and the CLI's own URL pass, tested below too.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
import tracemalloc
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ildottore import redactor as redactor_mod
from ildottore.redactor import Redactor, register_known_secret

_SALT = "s"
_URL = "«REDACTED:url_password»"


def _hmac8(value: str) -> str:
    """The digest a mask carries, computed here independently of the redactor."""

    return hmac.new(_SALT.encode(), value.encode(), hashlib.sha256).hexdigest()[:8]


def _expected(template: str) -> str:
    """``<x>`` is the credential mask of `x`, ``[x]`` the labelled-secret mask of `x`."""

    out = re.sub(r"<([^>]*)>", lambda m: f"«REDACTED:credential:{_hmac8(m.group(1))}»", template)
    return re.sub(r"\[([^\]]*)\]", lambda m: f"«REDACTED:labeled_secret:{_hmac8(m.group(1))}»", out)


def _redacted(credentials: tuple[str, ...], text: str) -> str:
    for value in credentials:
        register_known_secret(value)
    redactor = Redactor(salt=_SALT)
    out = redactor.redact_text(text)
    assert redactor.redact_text(out) == out, "the redaction is a fixed point"
    return out


@contextmanager
def _registered(*values: str) -> Iterator[None]:
    """`no_known_secrets` for a Hypothesis example (a function fixture is not reset per example)."""

    saved = set(redactor_mod._KNOWN_SECRETS)
    redactor_mod._KNOWN_SECRETS.clear()
    try:
        for value in values:
            register_known_secret(value)
        yield
    finally:
        redactor_mod._KNOWN_SECRETS.clear()
        redactor_mod._KNOWN_SECRETS.update(saved)


# --- 1. a credential holding an `@` across the URL's `@`, then a labelled value -----------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # The issue's case: main printed `redis://ops:«REDACTED:url_password»@Value99xyz`. The
        # digest is the one the redactor before A-31 gave the value.
        (
            "redis://ops:Adm1n@2026-db.internal:6379,password=Secr3t@Value99xyz",
            f"redis://ops:{_URL}@[Secr3t@Value99xyz]",
        ),
        (
            "redis://ops:Adm1n@2026-db:6379,password=Secr3t@Value99.example.com end",
            f"redis://ops:{_URL}@[Secr3t@Value99.example.com] end",
        ),
        # A pattern that starts in the tail and runs past it is masked first, then taken in.
        (
            "redis://ops:Adm1n@2026-db:6379,password=Secr3t@Value99xyz-555 123 4567 end",
            f"redis://ops:{_URL}@[Secr3t@Value99xyz-555] end",
        ),
        # Masked before the labelled rule ran, the tail took `TOKEN:` and its value was readable
        # (pre-commit differential fuzz).
        (
            "redis://ops:Adm1n@2026-db:6379,secret=Secr3t@BT8Ibd/&TOKEN: 3DdqL_@78kB9 end",
            f"redis://ops:{_URL}@[Secr3t@BT8Ibd/&TOKEN:] [3DdqL_@78kB9] end",
        ),
        # The tail stops before a `://` with an `@` after it before any whitespace: running on,
        # it took the next URL's scheme, which the URL rule reads (pre-commit fuzz).
        (
            "a://u:Adm1n@2026,token=Secr3t@ja5redis://u:Hunter2pw@h",
            f"a://u:{_URL}@[Secr3t@ja5redis://u:Hunter2pw@h]://u:{_URL}@h",
        ),
        # A value that starts at the `@`, and one of 6 characters that ends 4 past it: the
        # value is read up to 6 characters past the `@`, its pattern's least.
        (
            "redis://ops:Adm1n@2026-db:6379,password=@Secr3tVal",
            f"redis://ops:{_URL}@[@Secr3tVal]",
        ),
        ("redis://ops:Adm1n@2026-db:6379,password=Se@cr3t", f"redis://ops:{_URL}@[Se@cr3t]"),
        # The audit's narrow fix left the password's head readable here (`AAAA` and the label):
        # main masks it, and so does this fix.
        (
            "redis://ops:AAAAAdm1n@2026-token=QQQQQQ@host",
            f"redis://ops:{_URL}@[QQQQQQ@host]",
        ),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_labelled_value_after_a_url_keeps_its_tail_masked(text: str, expected: str) -> None:
    assert _redacted(("Adm1n@2026",), text) == _expected(expected)


#: What the entropy rule masks, high in entropy and 20 characters long.
_OPAQUE = "Zq8Xw3Yv6Ut1Sr4Qp7On"


@pytest.mark.parametrize(
    ("credentials", "text", "expected"),
    [
        # A label in the value's tail took the next label into its value, and the secret after
        # it was readable, on main too (pre-merge audit of #96). The tail is not read for a
        # label, as the redactor before A-31, which matched the value whole, did not read it.
        (
            ("Adm1n@2026",),
            'redis://ops:Adm1n@2026-db,password=Secr3t@x-token abcdef/secret="Hunter2Secret99"',
            f'redis://ops:{_URL}@[Secr3t@x-token] [abcdef/secret=]"[Hunter2Secret99]"',
        ),
        (
            ("Adm1n@2026",),
            "redis://ops:Adm1n@2026-db,password=Secr3t@x-api key is e@:X/"
            "passphrase=`Hunter2Secret99",
            f"redis://ops:{_URL}@[Secr3t@x-api] key is [e@:X/passphrase=]`[Hunter2Secret99]",
        ),
        # The credential holding an `@` in the user: the label is the user's tail.
        (
            ("ops@corp",),
            "redis://ops@corp;password:Secr3t@Value99xyz",
            f"redis://<ops@corp>;password:{_URL}@[Secr3t@Value99xyz]",
        ),
        # A `://` with no `@` after it is part of the value: stopped at it, the tail left
        # `://Secr3tTail99` readable (pre-merge audit).
        (
            ("Adm1n@2026",),
            "redis://ops:Adm1n@2026-db,password=Secr3t@hunter2://Secr3tTail99",
            f"redis://ops:{_URL}@[Secr3t@hunter2://Secr3tTail99]",
        ),
        (
            ("Adm1n@2026",),
            "redis://ops:Adm1n@2026-db,password=Secr3t@Val://vault/x99Q",
            f"redis://ops:{_URL}@[Secr3t@Val://vault/x99Q]",
        ),
        # One with an `@` after it stops the tail, even where the URL rule reads no URL in this
        # pass: in the next, with this pass's masks as stash tokens, it reads one and masks
        # `")tok`. Stopped only at a URL read in this pass, the tail took `tail://ops:` and
        # `")tok` was readable (pre-commit differential fuzz: 3 texts of 300,000).
        (
            ("Q0@Fdznql4", "VOxX4@U6C4890"),
            "p://o:Q0@Fdznql4;passphrase=7@tail://ops:VOxX4@U6C4890:5432/0secrets="
            'COVFTvuW1smkF")tok@j9 end',
            f"p://o:{_URL}@[7@tail://ops:]://ops:{_URL}@j9 end",
        ),
        # A plain word after a label and a path the entropy rule exempts stay as they are.
        (
            ("Adm1n@2026",),
            "redis://ops:Adm1n@2026-db,password=Secr3t@Val token=lowercaseword "
            "path/to/some-long-path/x end",
            f"redis://ops:{_URL}@[Secr3t@Val] token=lowercaseword path/to/some-long-path/x end",
        ),
        # The masks of the labelled and the entropy rules after the tail are theirs, in place.
        (
            ("Adm1n@2026",),
            f"redis://ops:Adm1n@2026-db,password=Secr3t@Val token=abcdefgh9 key {_OPAQUE} end",
            f"redis://ops:{_URL}@[Secr3t@Val] token=[abcdefgh9] key "
            f"«REDACTED:high_entropy:{_hmac8(_OPAQUE)}» end",
        ),
        (
            ("Adm1n@2026",),
            f"redis://ops:Adm1n@2026-db,password=Secr3t@Val {_OPAQUE} token=abcdefgh9 end",
            f"redis://ops:{_URL}@[Secr3t@Val] «REDACTED:high_entropy:{_hmac8(_OPAQUE)}» "
            "token=[abcdefgh9] end",
        ),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_the_rest_of_a_labelled_value_after_a_url_is_read_as_one_value(
    credentials: tuple[str, ...], text: str, expected: str
) -> None:
    assert _redacted(credentials, text) == _expected(expected)


@pytest.mark.parametrize(
    ("credentials", "text", "expected"),
    [
        # No labelled value: the URL mask is main's, the host readable.
        (
            ("Adm1n@2026",),
            "redis://ops:Adm1n@2026x@db.example.com",
            f"redis://ops:{_URL}@db.example.com",
        ),
        # No registered credential holding an `@`: as written the URL ends at the labelled
        # value's `@` too, so its tail is the host, as it is unregistered and was on main.
        (
            ("Adm1n2026",),
            "redis://ops:Adm1n2026-db:6379,password=Secr3t@Value99xyz",
            f"redis://ops:{_URL}@Value99xyz",
        ),
        ((), "https://user:token=abc123@example.com", f"https://user:{_URL}@example.com"),
        # A labelled value that ends before the `@` keeps the host readable.
        (
            ("Adm1n@2026",),
            "redis://ops:Adm1n@2026-db,token=Secr3tValue,x@host",
            f"redis://ops:{_URL}@host",
        ),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_url_password_with_no_labelled_value_across_its_at_is_masked_as_on_main(
    credentials: tuple[str, ...], text: str, expected: str
) -> None:
    assert _redacted(credentials, text) == expected


# --- 2. a credential holding the `://`, the `:` or the `@` the URL rule needs -------------------


@pytest.mark.parametrize(
    ("credentials", "text", "expected"),
    [
        # The issue's case: main printed `x «REDACTED:credential:...»:Sup3rS3cretPw@localhost y`.
        (
            ("key-ABCD1234", "1234://bob"),
            "x key-ABCD1234://bob:Sup3rS3cretPw@localhost y",
            f"x <key-ABCD1234>:{_URL}@localhost y",
        ),
        # One credential holding the `://`, before A-31 too.
        (
            ("1234://bob",),
            "x key-ABCD1234://bob:Sup3rS3cretPw@localhost y",
            f"x key-ABCD<1234://bob>:{_URL}@localhost y",
        ),
        # One ending inside the `://`.
        (
            ("key-ABCD1234:",),
            "x key-ABCD1234://bob:Sup3rS3cretPw@localhost y",
            f"x <key-ABCD1234:>//bob:{_URL}@localhost y",
        ),
        # Across the `://` and the `:`: the password's rest is masked, the credential stays.
        (
            ("1234://bob:Sup",),
            "x key-ABCD1234://bob:Sup3rS3cretPw@localhost y",
            f"x key-ABCD<1234://bob:Sup>{_URL}@localhost y",
        ),
        # Across the `:` alone.
        (("ABCD:Sup3r",), "x://key-ABCD:Sup3rS3cretPw@h", f"x://key-<ABCD:Sup3r>{_URL}@h"),
        # Across the password's `@`, with no later `@`: the head was readable.
        (
            ("Adm1n@2026",),
            "redis://ops:abcAdm1n@2026-db.internal:6379/0",
            f"redis://ops:{_URL}<Adm1n@2026>-db.internal:6379/0",
        ),
        # A credential inside the password, and a mask of a type the tool does not write, which
        # is text: one mask from the password's first readable character to its last.
        (
            ("1234://bob", "Hunter2Secret"),
            "x key-ABCD1234://bob:preHunter2Secretpost@localhost",
            f"x key-ABCD<1234://bob>:{_URL}@localhost",
        ),
        (
            ("1234://bob",),
            "x key-ABCD1234://bob:«REDACTED:Sup3rS3cretPw»@localhost",
            f"x key-ABCD<1234://bob>:{_URL}@localhost",
        ),
        # A dotted host: where the URL rule found no URL, the email rule took the password's
        # tail and the host as one address, and the head before it was readable.
        (
            ("key-ABCD1234", "1234://bob"),
            "x key-ABCD1234://bob:Sup3r!S3cret@db.example.com y",
            f"x <key-ABCD1234>:{_URL}«REDACTED:email» y",
        ),
        # The `:` the URL rule takes after the user stays, where the URL is read in the next
        # pass on to a later `@`: masked, it kept the next pass from reading it (pre-commit
        # differential fuzz).
        (
            ("T8RI://zR:3ujv", ";Km(.ieY@localhost:"),
            "mongodb+srv://T8RI://zR:3ujv:Y;Km(.ieY@localhost:6379"
            "&passphrase=Rv://IfdO9t:YSjWOLkV@oWCIf9w end",
            f"mongodb+srv://<T8RI://zR:3ujv>:{_URL}@oWCIf9w end",
        ),
        # The same with the user's tail readable: as written it is the password's head, and the
        # kept `:` splits the mask; with nothing readable but that `:`, nothing is added.
        (
            ("T8RI://zR:3ujv", ";Km(.ieY@localhost:"),
            "mongodb+srv://T8RI://zR:3ujvQQ:Y;Km(.ieY@localhost:6379"
            "&passphrase=Rv://IfdO9t:YSjWOLkV@oWCIf9w end",
            f"mongodb+srv://<T8RI://zR:3ujv>{_URL}:{_URL}@oWCIf9w end",
        ),
        (
            ("T8RI://zR:3ujv", ";Km(.ieY@localhost:"),
            "mongodb+srv://T8RI://zR:3ujv:;Km(.ieY@localhost:6379"
            "&passphrase=Rv://IfdO9t:YSjWOLkV@oWCIf9w end",
            f"mongodb+srv://<T8RI://zR:3ujv>:{_URL}@oWCIf9w end",
        ),
        # A labelled value in the password: the labelled rule masks it whole, as on main.
        (
            ("key-ABCD1234", "1234://bob"),
            "x key-ABCD1234://bob:password=Secr3t@Value99xyz",
            "x <key-ABCD1234>:password=[Secr3t@Value99xyz]",
        ),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_url_password_behind_a_credential_holding_a_separator_is_masked(
    credentials: tuple[str, ...], text: str, expected: str
) -> None:
    assert _redacted(credentials, text) == _expected(expected)


@pytest.mark.parametrize(
    ("credentials", "text", "expected"),
    [
        # Each credential one piece of the user or of the password (A-31's test, unchanged).
        (
            ("ops:svc-key", "P@ssw0rd!"),
            "redis://ops:svc-key:P@ssw0rd!@db",
            "redis://<ops:svc-key>:<P@ssw0rd!>@db",
        ),
        # Left open: the URL rule reads `XYZ` as the user's, after a credential holding the
        # user's `:`, and masks the password after the next `:`; as written (urllib's reading)
        # `XYZ` is the password's head. The URL rule's reading stands where it found a URL.
        (
            ("ops:svc-key",),
            "redis://ops:svc-keyXYZ:pw@host",
            f"redis://<ops:svc-key>XYZ:{_URL}@host",
        ),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_url_the_url_rule_read_is_left_as_it_masked_it(
    credentials: tuple[str, ...], text: str, expected: str
) -> None:
    assert _redacted(credentials, text) == _expected(expected)


#: The scheme, the user and the host are written in capitals and digits, the password in small
#: letters and punctuation, so what of the password the output shows can only be the password's.
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_MASK = re.compile(r"«REDACTED:[A-Za-z0-9_]+(?::[0-9a-f]{8})?»")


@settings(max_examples=500, deadline=None)
@given(
    scheme=st.text(_UPPER, min_size=1, max_size=10),
    user=st.text(_UPPER, max_size=10),
    password=st.text("abcdefghijkmnopqrstuvwxyz-_.!~", min_size=8, max_size=20),
    host=st.sampled_from(["LOCALHOST", "DB:6379", "INTRANET", "H.EXAMPLE.COM"]),
    separator=st.sampled_from(["://", ":", "@"]),
    before=st.integers(0, 8),
    after=st.integers(0, 8),
    overlapping=st.booleans(),
)
def test_no_url_password_survives_a_credential_across_a_separator(
    scheme: str,
    user: str,
    password: str,
    host: str,
    separator: str,
    before: int,
    after: int,
    overlapping: bool,
) -> None:
    """A registered credential across the URL's `://`, its `:` or its `@`, alone or as two
    overlapping credentials, leaves nothing of the password readable outside it. Main failed it
    for each separator (for the `@` only with no later `@`, which this text never holds)."""

    text = f"see {scheme}://{user}:{password}@{host} end"
    scheme_at = text.index("://")
    colon = text.index(":", scheme_at + 3)
    at = {"://": scheme_at, ":": colon, "@": text.index("@")}[separator]
    first, last = max(4, at - before), min(len(text) - 4, at + len(separator) + after)
    while last - first < 8:  # registered from 8 characters
        first, last = max(4, first - 1), min(len(text) - 4, last + 1)
    credential = text[first:last]
    credentials = [credential]
    if overlapping and len(credential) >= 9:  # two that overlap, masked as one run
        credentials = [credential[:-1], credential[1:]]
    covered = set(range(first, last))
    readable = "".join(
        ch if i not in covered else "|"
        for i, ch in enumerate(text[colon + 1 : colon + 1 + len(password)], colon + 1)
    )
    with _registered(*credentials):
        redactor = Redactor(salt=_SALT)
        out = redactor.redact_text(text)
        shown = _MASK.sub("|", out)
        for part in readable.split("|"):
            assert len(part) < 3 or part not in shown, (credentials, out)
        assert redactor.redact_text(out) == out


# --- the CLI's errors ----------------------------------------------------------------------------

_DIGEST = re.compile(r"(«REDACTED:[a-z_]+):[0-9a-f]{8}»")


@pytest.mark.parametrize(
    ("credentials", "text", "expected"),
    [
        (
            ("Adm1n@2026",),
            "connect failed: redis://ops:Adm1n@2026-db.internal:6379,password=Secr3t@Value99xyz",
            f"connect failed: redis://ops:{_URL}@«REDACTED:labeled_secret»",
        ),
        # The URL rule run on the raw text took `Adm1n` and left `2026` of the credential.
        (
            ("Adm1n@2026",),
            "connect failed: redis://ops:Adm1n@2026-db.internal:6379/0",
            "connect failed: redis://ops:«REDACTED:credential»-db.internal:6379/0",
        ),
        (
            ("ABCD:Sup3r",),
            "connect failed: x://key-ABCD:Sup3rS3cretPw@h",
            f"connect failed: x://key-«REDACTED:credential»{_URL}@h",
        ),
        (
            ("key-ABCD1234", "1234://bob"),
            "connect failed: x key-ABCD1234://bob:Sup3rS3cretPw@localhost y",
            f"connect failed: x «REDACTED:credential»:{_URL}@localhost y",
        ),
        # The audit's case: `...«REDACTED:url_password»@ssw0rd!«REDACTED:email»/v1`.
        (
            ("P@ssw0rd!x",),
            "connect failed: https://ops:P@ssw0rd!x@db.internal/v1",
            "connect failed: https://ops:«REDACTED:credential»@db.internal/v1",
        ),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_cli_error_is_masked_as_the_redactor_masks_it(
    credentials: tuple[str, ...], text: str, expected: str
) -> None:
    """`cli/app._masked` ran the URL rule on the raw text before the redactor, and cut there a
    registered credential holding an `@` or a `:`, which the redactor then no longer found
    (pre-merge audit of #96)."""

    from ildottore.cli.app import _masked

    for value in credentials:
        register_known_secret(value)
    shown = _masked(ValueError(text))
    assert _DIGEST.sub(r"\1»", shown) == expected


# --- bounded in time and memory ---------------------------------------------------------------

_MB = 1024 * 1024
_HOSTILE = {
    # A URL mask per repetition, a labelled tail each, and the text read as written.
    "a credential holding an @ in every password": (
        ("Adm1n@2026",),
        "a://u:Adm1n@2026-password=x@",
    ),
    "the issue's two credentials in every URL": (
        ("key-ABCD1234", "1234://bob"),
        "x key-ABCD1234://bob:pw@h ",
    ),
    "a credential holding a scheme, glued": (("1234://bob",), "1234://bob"),
}


@pytest.mark.parametrize("name", list(_HOSTILE))
@pytest.mark.usefixtures("no_known_secrets")
def test_hostile_text_is_redacted_in_bounded_memory(name: str) -> None:
    """The text read as written holds one entry of four integers a mask: a list of tuples a
    piece took 270 MB of RSS on 4 MB of the first shape where main's redactor took 122 MB.
    Main's redactor takes 17.6, 14.7 and 23.2 bytes a character on these shapes at 2 MB."""

    credentials, unit = _HOSTILE[name]
    for value in credentials:
        register_known_secret(value)
    text = unit * (2 * _MB // len(unit))
    redactor = Redactor(salt=_SALT)
    tracemalloc.start()
    try:
        redactor.redact_text(text)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 32 * len(text), f"{peak / len(text):.1f} bytes a character"


@pytest.mark.parametrize("name", list(_HOSTILE))
@pytest.mark.usefixtures("no_known_secrets")
def test_hostile_text_is_redacted_in_linear_time(name: str) -> None:
    """Four times the text takes about four times as long, not sixteen."""

    credentials, unit = _HOSTILE[name]
    for value in credentials:
        register_known_secret(value)
    redactor = Redactor(salt=_SALT)

    def seconds(size: int) -> float:
        text = unit * (size // len(unit))
        best = float("inf")
        for _ in range(2):
            started = time.process_time()
            redactor.redact_text(text)
            best = min(best, time.process_time() - started)
        return best

    small, large = seconds(_MB // 8), seconds(_MB // 2)
    assert large < 10 * small + 0.5, f"{small:.3f}s then {large:.3f}s"
