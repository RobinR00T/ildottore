"""A URL password behind a registered user, and digests that depended on the process (2026-10-07).

Two defects already on main (`d19b221`), found by the pre-commit audit of `fix/cli-control-chars`
with differential fuzzing against main:
- a registered credential as the user of a URL (`https://<it>:<password>@localhost:8080/v1`) is
  set aside as a stash token before the URL rule runs, and the URL rule refused a user holding
  one, so the password stayed readable in reports, evidence and on the terminal. A dotted host
  hid it only because the email rule then took `<password>@<host>` as an address;
- the digest of a `pem_private_key` mask was computed over the key's text with the stash tokens
  inside it. Their numbers depend on how many masks came before the key and on the order the
  registered credentials are tried in, which for two of one length was a set's iteration order:
  the digest changed with PYTHONHASHSEED, and within one process with the text before the key.
  The same order decided which of two overlapping credentials was masked, and the other one's
  tail stayed readable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import subprocess
import sys
import time
import tracemalloc
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ildottore import redactor as redactor_mod
from ildottore.redactor import Pattern, Redactor, mask_url_passwords, register_known_secret

_SALT = "s"
_USER = "svc-account-7"  # registered by the tests that use it
_PASSWORD = "Sup3rS3cretPw"
_BEGIN, _END = "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"
_URL_MASK = "«REDACTED:url_password»"


def _hmac8(value: str) -> str:
    """The digest a mask carries, computed here independently of the redactor."""

    return hmac.new(_SALT.encode(), value.encode(), hashlib.sha256).hexdigest()[:8]


@pytest.fixture
def no_known_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Registered credentials are process-wide: a test's own do not outlive it."""

    monkeypatch.setattr(redactor_mod, "_KNOWN_SECRETS", set())


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


# --- a URL password behind a registered user ---------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        f"https://{_USER}:{_PASSWORD}@localhost:8080/v1",
        f"http://{_USER}:{_PASSWORD}@intranet/",
        f"https://x-{_USER}:{_PASSWORD}@localhost:8080/v1",  # the credential inside the user
        f"https://«REDACTED:email»:{_PASSWORD}@localhost:8080/v1",  # a mask the target wrote
        f"https://{_USER}:{_PASSWORD}@api.example.com/v1",  # the email rule took it, host too
        f"redis://:{_PASSWORD}@localhost:6379/0",  # no user at all, Redis's own form
        # Behind ten masks the stash tokens have two digits (a one-digit token shape passed).
        "«REDACTED:ip» " * 11 + f"https://{_USER}:{_PASSWORD}@localhost:8080/v1",
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_url_password_is_masked_behind_a_registered_masked_or_empty_user(url: str) -> None:
    register_known_secret(_USER)
    redactor = Redactor(salt=_SALT)
    out = redactor.redact_text(url)
    assert _PASSWORD not in out and _USER not in out
    host = url.split("@", 1)[1]
    assert out.endswith(f":{_URL_MASK}@{host}"), "the host stays readable, as for any user"
    assert redactor.redact_text(out) == out


@pytest.mark.usefixtures("no_known_secrets")
def test_a_registered_user_is_masked_by_value_next_to_the_masked_password() -> None:
    register_known_secret(_USER)
    out = Redactor(salt=_SALT).redact_text(f"https://{_USER}:{_PASSWORD}@localhost:8080/v1")
    assert out == f"https://«REDACTED:credential:{_hmac8(_USER)}»:{_URL_MASK}@localhost:8080/v1"


@pytest.mark.parametrize(
    "password", [f"pre{_USER}post", f"{_USER}LEAKEDTAIL", f"pre{_USER}", f"{_USER}{_USER}"]
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_url_password_holding_a_registered_credential_is_masked_whole(password: str) -> None:
    """The registered part was masked and the rest of the password (`pre`, `post`) was not."""

    register_known_secret(_USER)
    redactor = Redactor(salt=_SALT)
    out = redactor.redact_text(f"https://bob:{password}@localhost/")
    assert out == f"https://bob:{_URL_MASK}@localhost/"
    assert redactor.redact_text(out) == out


@pytest.mark.parametrize(
    ("credential", "url", "masked"),
    [
        ("password@db", "redis://u:Sup3rS3cretpassword@db:6379 end", "redis://u:{}:6379 end"),
        ("pass" + chr(1) + "word@db", "redis://u:Sup3rS3cretpassword@db:6379 end", None),
        ("bob:hunter2", "https://bob:hunter2XYZSECRET@intranet/v1", "https://{}@intranet/v1"),
        ("https://bob", "https://bob:Sup3rS3cretPw@intranet/v1", "{}@intranet/v1"),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_registered_credential_across_a_url_separator_takes_the_password_with_it(
    credential: str, url: str, masked: str | None
) -> None:
    """Across `://`, the `:` or the `@` it stopped the URL rule: the rest of the password showed.

    With a stash delimiter in it, the credential is read as the text is (`password@db`), which
    main never matched, so main masked that password and the first version of this fix did not
    (pre-merge audit).
    """

    register_known_secret(credential)
    redactor = Redactor(salt=_SALT)
    out = redactor.redact_text(url)
    name = credential.replace(chr(1), "")
    expected = (masked or "redis://u:{}:6379 end").format(f"«REDACTED:credential:{_hmac8(name)}»")
    assert out == expected
    assert redactor.redact_text(out) == out


def test_the_url_separator_pass_is_linear_in_the_urls() -> None:
    """A slice of the runs per URL made it quadratic: 20,000 registered-user URLs took 0.35 s."""

    url = "https://svc-account-7:Pw123456@localhost:8080/v1 "

    def cost(count: int) -> float:
        text = url * count
        runs = [(n * len(url) + 8, n * len(url) + 21, "svc-account-7") for n in range(count)]
        best = math.inf
        for _ in range(3):
            started = time.perf_counter()
            assert redactor_mod._straddled_passwords(text, runs) == []  # every run is a user
            best = min(best, time.perf_counter() - started)
        return best

    assert cost(80_000) / cost(20_000) < 10  # four times the URLs: 4 when linear, 16 when not


@pytest.mark.usefixtures("no_known_secrets")
def test_a_registered_url_password_keeps_its_own_mask() -> None:
    register_known_secret(_PASSWORD)
    redactor = Redactor(salt=_SALT)
    for user in ("bob", _PASSWORD):
        out = redactor.redact_text(f"https://{user}:{_PASSWORD}@localhost/")
        mask = f"«REDACTED:credential:{_hmac8(_PASSWORD)}»"
        assert out == f"https://{mask if user == _PASSWORD else user}:{mask}@localhost/"
        assert redactor.redact_text(out) == out


def test_mask_url_passwords_is_unchanged_on_text_with_no_mask() -> None:
    url = f"https://{_USER}:{_PASSWORD}@localhost:8080/v1 and https://a:b@h"
    assert mask_url_passwords(url) == (
        f"https://{_USER}:{_URL_MASK}@localhost:8080/v1 and https://a:{_URL_MASK}@h"
    )


_URL_CHARS = st.text(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + "._~!$&'()*+,;=-"
)


@settings(max_examples=300, deadline=None)
@given(
    user=st.one_of(
        _URL_CHARS.filter(lambda s: len(s) >= 8), st.sampled_from(["«REDACTED:email»", ""])
    ),
    password=_URL_CHARS.filter(lambda s: len(s) >= 1),
    host=st.sampled_from(
        ["localhost", "localhost:8080", "intranet", "10.0.0.7:1", "h.example.com"]
    ),
    registered=st.booleans(),
    before=st.sampled_from(["", "see ", "«REDACTED:ip» ", "x@y.io ", "«REDACTED:ip» " * 11]),
)
def test_no_url_password_survives_and_the_redaction_is_a_fixed_point(
    user: str, password: str, host: str, registered: bool, before: str
) -> None:
    secret = "Zq" + password  # marked, so it cannot be found by chance in the user or the host
    with _registered(*((user,) if registered and user and not user.startswith("«") else ())):
        redactor = Redactor(salt=_SALT)
        out = redactor.redact_text(f"{before}https://{user}:{secret}@{host}/v1 end")
        assert secret not in out
        assert redactor.redact_text(out) == out


@pytest.mark.usefixtures("no_known_secrets")
def test_the_evidence_store_writes_the_masked_url_and_its_leak_guard_passes(
    tmp_path: Path,
) -> None:
    from ildottore.store.evidence_fs import FsEvidenceStore
    from tests.store.conftest import make_attempt

    register_known_secret(_USER)
    store = FsEvidenceStore(tmp_path, redactor=Redactor(salt=_SALT))
    url = f"https://{_USER}:{_PASSWORD}@localhost:8080/v1"
    assert store.put("run-1", make_attempt(prompt=f"call {url}", response_text=f"done: {url}"))
    written = "".join(path.read_text("utf-8") for path in tmp_path.rglob("*.json"))
    assert written and _PASSWORD not in written and _USER not in written
    assert written.count(_URL_MASK) == 2


# --- digests that depended on the process --------------------------------------------------

_PEM = (
    f"{_BEGIN}\nxx aaaaaaaa1111 bbbbbbbb2222 «REDACTED:ip» https://bob:pw123456@h"
    f" https://u:pre-aaaaaaaa1111-post@h yy\n{_END}"
)


@pytest.mark.parametrize("before", ["", "«REDACTED:email» ", "aaaaaaaa1111 ", "a@b.io "])
@pytest.mark.parametrize("credentials", [(), ("aaaaaaaa1111",), ("aaaaaaaa1111", "bbbbbbbb2222")])
@pytest.mark.usefixtures("no_known_secrets")
def test_a_pem_digest_is_the_hmac_of_the_key_as_written(
    before: str, credentials: tuple[str, ...]
) -> None:
    """Not of the key with the stash tokens of the masks inside it, numbered by what came first."""

    for value in credentials:
        register_known_secret(value)
    redactor = Redactor(salt=_SALT)
    out = redactor.redact_text(before + _PEM)
    assert out.endswith(f"«REDACTED:pem_private_key:{_hmac8(_PEM)}»")
    assert redactor.redact_text(out) == out


@pytest.mark.parametrize("before", ["", "«REDACTED:email» ", "«REDACTED:ip» «REDACTED:ip» "])
def test_a_hashed_pattern_of_the_operator_digests_the_text_as_written(before: str) -> None:
    redactor = Redactor(salt=_SALT)
    redactor.register(Pattern("blob", re.compile(r"<blob>[\s\S]*?</blob>"), hashed=True))
    blob = "<blob>x «REDACTED:ip» y</blob>"
    assert redactor.redact_text(before + blob) == f"{before}«REDACTED:blob:{_hmac8(blob)}»"


@pytest.mark.parametrize(
    ("credentials", "text", "named"),
    [
        (("12345678ab", "ab87654321"), "12345678ab87654321", "12345678ab"),  # one length: first
        (("ab87654321", "12345678ab"), "12345678ab87654321", "12345678ab"),  # registered order
        (("0123456789ab", "89abcdefgh"), "0123456789abcdefgh", "0123456789ab"),  # the longer
        (("89abcdefgh", "0123456789ab"), "0123456789abcdefgh", "0123456789ab"),
        (("0123456789abcdef", "456789ab"), "0123456789abcdef", "0123456789abcdef"),  # inside
        (("456789ab", "0123456789abcdef"), "0123456789abcdef", "0123456789abcdef"),
        (("abababab",), "ababababab", "abababab"),  # a credential overlapping itself
        (("aaaaaaaa1111", "aaaaaaaa1111\r"), "aaaaaaaa1111\r", "aaaaaaaa1111\r"),  # contained
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_overlapping_registered_credentials_are_masked_as_one(
    credentials: tuple[str, ...], text: str, named: str
) -> None:
    """One of two overlapping credentials was masked, by set order, and the other's tail was not."""

    for value in credentials:
        register_known_secret(value)
    redactor = Redactor(salt=_SALT)
    out = redactor.redact_text(f"key {text} end")
    assert out == f"key «REDACTED:credential:{_hmac8(named)}» end"
    assert redactor.redact_text(out) == out


@pytest.mark.usefixtures("no_known_secrets")
def test_a_key_holding_a_run_named_after_a_credential_seen_before_digests_the_run() -> None:
    """The credential's mask is reused for the same text only, not for a run named after it."""

    register_known_secret("12345678ab")
    register_known_secret("ab87654321")
    pem = f"{_BEGIN}\nxx 12345678ab87654321 yy\n{_END}"
    out = Redactor(salt=_SALT).redact_text(f"12345678ab then {pem}")
    first = f"«REDACTED:credential:{_hmac8('12345678ab')}»"
    assert out == f"{first} then «REDACTED:pem_private_key:{_hmac8(pem)}»"


@pytest.mark.usefixtures("no_known_secrets")
def test_a_credential_holding_a_stash_delimiter_cannot_break_a_stash_token() -> None:
    """It matched across the end of a token: a raw NUL out, a mask lost, and no fixed point."""

    register_known_secret("0" + chr(1) + "abcdefgh")  # `\x01` after a digit: a token's end
    register_known_secret("abcdefgh" + chr(0) + "0")  # `\x00` before a digit: a token's start
    register_known_secret(chr(0) * 6 + "ab")  # under 8 characters without them: not registered
    register_known_secret(chr(1) * 8)
    redactor = Redactor(salt=_SALT)
    for text in ("«REDACTED:ip»abcdefgh", "key abcdefgh«REDACTED:ip» tail", "a cab", "hello"):
        assert redactor.redact_text(text) == text
    assert redactor.redact_text("key 0" + chr(1) + "abcdefgh end") == (
        f"key «REDACTED:credential:{_hmac8('0abcdefgh')}» end"
    )


@pytest.mark.usefixtures("no_known_secrets")
def test_a_credential_is_registered_as_the_redactor_reads_it() -> None:
    """Stripped of the stash delimiters, before and after its surrounding whitespace."""

    register_known_secret(chr(1) + " abcdefgh " + chr(1))
    out = Redactor(salt=_SALT).redact_text("key=abcdefgh;")
    assert out == f"key=«REDACTED:credential:{_hmac8('abcdefgh')}»;"
    register_known_secret("abc" + chr(0) + "defghij")
    assert redactor_mod.overlaps_known_secret("abc" + chr(0) + "defghij")
    assert redactor_mod.overlaps_known_secret("abc" + chr(1) + "defghij")
    # The value as given is quoted by a library too: `repr` writes the delimiter as `\x01`.
    value = "Sup3r" + chr(1) + "Secret" + chr(10)
    register_known_secret(value)
    for quoted in (repr(value)[1:-1], json.dumps(value)[1:-1]):
        out = Redactor(salt=_SALT).redact_text(f"b'Bearer {quoted}'")
        assert "Secret" not in out and "«REDACTED:credential:" in out


_CHILD_URL_MEMORY = """
import resource, sys
from ildottore.redactor import _URL_USERINFO
size = 2_000_000
texts = ["https://u:" + "a" * size, "https://u" + ":" * size, "https://" + "a" * size]
# Class characters and stash tokens in turn, in the user and in the password: a run of class
# characters alone never reaches the outer repeat (delta audit).
token = "a" + chr(0) + "1" + chr(1)
texts += ["https://" + token * (size // 4), "https://u:" + token * (size // 4)]
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
for text in texts:
    _URL_USERINFO.sub("X", text)
after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
sys.stdout.write(str((after - before) * (1 if sys.platform == "darwin" else 1024)))
"""


def test_the_url_rule_scans_a_long_run_in_bounded_memory() -> None:
    """With an alternation and no possessive quantifier it kept a frame a character: 640 MB."""

    pytest.importorskip("resource")
    grown = int(_in_a_process(_CHILD_URL_MEMORY, "", (), seed=0))
    assert grown < 48_000_000, f"the URL rule grew the process by {grown} bytes on 2 MB"


@pytest.mark.usefixtures("no_known_secrets")
def test_a_credential_repeated_over_itself_is_one_run_in_bounded_memory() -> None:
    """Every overlapping occurrence is found: kept one by one, 400 KB of them took 30 MB."""

    register_known_secret("abababab")
    text = "ab" * 200_000
    tracemalloc.start()
    try:
        runs = redactor_mod._credential_runs(text)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert runs == [(0, len(text), "abababab")]
    assert peak < 3_000_000


@pytest.mark.usefixtures("no_known_secrets")
def test_the_evidence_store_keeps_the_key_digest_and_its_leak_guard_passes(
    tmp_path: Path,
) -> None:
    from ildottore.store.evidence_fs import FsEvidenceStore
    from tests.store.conftest import make_attempt

    register_known_secret("aaaaaaaa1111")
    register_known_secret("bbbbbbbb2222")
    store = FsEvidenceStore(tmp_path, redactor=Redactor(salt=_SALT))
    text = f"«REDACTED:email» {_PEM} and key 12345678ab87654321"
    register_known_secret("12345678ab")
    register_known_secret("ab87654321")
    assert store.put("run-1", make_attempt(response_text=text))
    written = "".join(path.read_text("utf-8") for path in tmp_path.rglob("*.json"))
    assert f"«REDACTED:pem_private_key:{_hmac8(_PEM)}»" in written
    assert "87654321" not in written and "12345678" not in written


_CHILD = """
import sys
from ildottore.redactor import Redactor, register_known_secret
for value in sys.argv[1:]:
    register_known_secret(value)
sys.stdout.write(Redactor(salt="s").redact_text(sys.stdin.read()))
"""
_CHILD_ORDER = """
import sys
from ildottore.redactor import _known_secrets, register_known_secret
for value in sys.argv[1:]:
    register_known_secret(value)
sys.stdout.write(repr(_known_secrets()))
"""


def _in_a_process(child: str, text: str, credentials: tuple[str, ...], seed: int) -> str:
    # The child imports the same source tree as this test, whatever the installed package is.
    source = str(Path(redactor_mod.__file__).resolve().parents[1])
    env = {
        **os.environ,
        "PYTHONHASHSEED": str(seed),
        "PYTHONPATH": os.pathsep.join(filter(None, (source, os.environ.get("PYTHONPATH")))),
    }
    return subprocess.run(  # noqa: S603 - our own interpreter, a fixed snippet
        [sys.executable, "-c", child, *credentials],
        input=text,
        capture_output=True,
        text=True,
        check=True,
        env=env,
    ).stdout


@pytest.mark.parametrize(
    ("text", "credentials"),
    [
        (_PEM, ("aaaaaaaa1111", "bbbbbbbb2222")),
        ("key 12345678ab87654321 end", ("12345678ab", "ab87654321")),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_the_redaction_does_not_depend_on_the_hash_seed(
    text: str, credentials: tuple[str, ...]
) -> None:
    """Twelve seeds split six and six on main for the key, seven and five for the overlap."""

    for value in credentials:
        register_known_secret(value)
    expected = Redactor(salt=_SALT).redact_text(text)
    outputs = {_in_a_process(_CHILD, text, credentials, seed) for seed in range(12)}
    assert outputs == {expected}


def test_the_registered_credentials_are_tried_in_one_order_whatever_the_hash_seed() -> None:
    """Longest first, then by value; a set's order decided between two of one length."""

    credentials = ("aaaaaaaa1111", "bbbbbbbb2222", "cccccccc3333", "dddd4444")
    orders = {_in_a_process(_CHILD_ORDER, "", credentials, seed) for seed in range(12)}
    assert orders == {repr([*credentials[:3], credentials[3]])}
