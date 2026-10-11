"""The documented key formats and the hex and UUID shapes are masked whatever their entropy (A-78).

Pre-merge security audit of 2026-10-11, MEDIUM 4. Only ``sk-``, ``ghp_``, ``AKIA`` and ``xox``
had a rule of their own; ``sk-ant-``, ``sk-proj-`` (whose ``-`` cut the ``sk-`` rule),
``github_pat_``, ``AIza``, ``glpat-`` and ``hf_`` rested on the entropy fallback, so a body of
low entropy (a repeated pattern) was printed, and a key glued to a run of padding was diluted
below the threshold: `_` written 30 times before it printed 155 of 200 ``ghp_`` tokens and every
``AKIA``, ``glpat-`` and ``hf_`` one, 20 `=` on either side every ``AIza``, ``glpat-`` and
``hf_`` one, 20 `-` before every ``glpat-`` one (``\\b`` refused a key after `_`, a word
character). Random tokens with no prefix were printed too: 74.7% of 32-hex ones (an Azure key),
47.5% of 40-hex, 5.5% of 64-hex and 47.7% of v4 UUIDs.

The values here are built from pieces, so no source line holds a whole key a secret scanner
would stop a push on.
"""

from __future__ import annotations

import math
import random
import re
import string
import uuid
from collections.abc import Callable

import pytest

from ildottore.redactor import Redactor, register_known_secret

_RNG = random.Random(78)  # noqa: S311 - reproducible test data, not a secret
_ALNUM = string.ascii_letters + string.digits
_URLSAFE = _ALNUM + "_-"
_UPPERDIG = string.ascii_uppercase + string.digits
_HEX = "0123456789abcdef"


def _p(*parts: str) -> str:
    return "".join(parts)


def _rnd(alphabet: str, n: int) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


#: (mask type, prefix, body): a body as the provider documents it, random.
FORMATS: list[tuple[str, str, Callable[[], str]]] = [
    ("anthropic_key", _p("sk", "-ant-", "api03-"), lambda: _rnd(_URLSAFE, 93) + "AA"),
    ("anthropic_key", _p("sk", "-ant-", "admin01-"), lambda: _rnd(_URLSAFE, 93) + "AA"),
    ("openai_key", _p("sk", "-"), lambda: _rnd(_ALNUM, 48)),
    ("openai_key", _p("sk", "-proj-"), lambda: _rnd(_URLSAFE, 156)),
    ("openai_key", _p("sk", "-svcacct-"), lambda: _rnd(_URLSAFE, 156)),
    ("openai_key", _p("sk", "-admin-"), lambda: _rnd(_URLSAFE, 120)),
    ("openai_key", _p("sk", "-None-"), lambda: _rnd(_URLSAFE, 48)),
    ("github_token", _p("gh", "p_"), lambda: _rnd(_ALNUM, 36)),
    ("github_token", _p("gh", "o_"), lambda: _rnd(_ALNUM, 36)),
    ("github_token", _p("gh", "u_"), lambda: _rnd(_ALNUM, 36)),
    ("github_token", _p("gh", "s_"), lambda: _rnd(_ALNUM, 36)),
    ("github_token", _p("gh", "r_"), lambda: _rnd(_ALNUM, 36)),
    (
        "github_token",
        _p("github", "_pat_"),
        lambda: "11" + _rnd(_UPPERDIG, 20) + "_" + _rnd(_ALNUM, 59),
    ),
    ("gitlab_token", _p("gl", "pat-"), lambda: _rnd(_URLSAFE, 20)),
    ("gitlab_token", _p("gl", "dt-"), lambda: _rnd(_URLSAFE, 20)),
    ("gitlab_token", _p("gl", "rt-"), lambda: _rnd(_URLSAFE, 20)),
    ("gitlab_token", _p("gl", "rtr-"), lambda: _rnd(_URLSAFE, 20)),
    ("gitlab_token", _p("gl", "cbt-"), lambda: _rnd(_URLSAFE, 20)),
    ("gitlab_token", _p("gl", "ptt-"), lambda: _rnd(_URLSAFE, 20)),
    ("gitlab_token", _p("gl", "ft-"), lambda: _rnd(_URLSAFE, 20)),
    ("gitlab_token", _p("gl", "oas-"), lambda: _rnd(_URLSAFE, 64)),
    ("gitlab_token", _p("gl", "agent-"), lambda: _rnd(_URLSAFE, 50)),
    ("aws_access_key", _p("AK", "IA"), lambda: _rnd(_UPPERDIG, 16)),
    ("aws_access_key", _p("AS", "IA"), lambda: _rnd(_UPPERDIG, 16)),
    ("aws_access_key", _p("AB", "IA"), lambda: _rnd(_UPPERDIG, 16)),
    ("aws_access_key", _p("AC", "CA"), lambda: _rnd(_UPPERDIG, 16)),
    ("google_api_key", _p("AI", "za"), lambda: "Sy" + _rnd(_URLSAFE, 33)),
    ("huggingface_token", _p("hf", "_"), lambda: _rnd(string.ascii_letters, 34)),
    (
        "slack_token",
        _p("xo", "xb-"),
        lambda: _rnd(string.digits, 12) + "-" + _rnd(string.digits, 13) + "-" + _rnd(_ALNUM, 24),
    ),
    ("slack_token", _p("xa", "pp-"), lambda: "1-A" + _rnd(_UPPERDIG, 10) + "-" + _rnd(_HEX, 64)),
    ("slack_token", _p("xo", "xe.xoxp-"), lambda: "1-" + _rnd(_ALNUM, 40)),
    ("slack_token", _p("xo", "xe-"), lambda: "1-" + _rnd(_ALNUM, 40)),
    ("slack_token", _p("xw", "fp-"), lambda: _rnd(_ALNUM, 30)),
    ("stripe_key", _p("sk", "_live_"), lambda: _rnd(_ALNUM, 99)),
    ("stripe_key", _p("sk", "_test_"), lambda: _rnd(_ALNUM, 24)),
    ("stripe_key", _p("rk", "_live_"), lambda: _rnd(_ALNUM, 99)),
    ("stripe_key", _p("wh", "sec_"), lambda: _rnd(_ALNUM, 32)),
    ("npm_token", _p("np", "m_"), lambda: _rnd(_ALNUM, 36)),
    ("pypi_token", _p("py", "pi-"), lambda: "AgEIcHlwaS5vcmc" + _rnd(_URLSAFE, 150)),
]

#: Where a key is written: alone, in prose and config, and glued to padding or a word.
CONTEXTS = {
    "bare": "{s}",
    "sentence": "The key is {s}.",
    "env": "API_KEY={s}",
    "json": '{{"api_key": "{s}"}}',
    "bearer": "Authorization: Bearer {s}",
    "underscores_before": "_" * 30 + "{s}",
    "equals_around": "=" * 20 + "{s}" + "=" * 20,
    "dashes_before": "-" * 20 + "{s}",
    "word_underscore_before": "x_{s}",
    "underscore_word_after": "{s}_x",
    "dilute": "a" * 120 + "-{s}-" + "a" * 120,
    "query": "https://api.example.test/v1/x?key={s}&a=1",
}


def _leaks(out: str, body: str) -> bool:
    """True when 8 consecutive characters of ``body`` survive (the auditor's measure)."""

    return any(body[i : i + 8] in out for i in range(len(body) - 7))


@pytest.mark.parametrize(("kind", "prefix", "body"), FORMATS, ids=[f[1] for f in FORMATS])
@pytest.mark.parametrize("context", sorted(CONTEXTS))
def test_a_documented_key_is_masked_with_its_type_in_every_context(
    kind: str, prefix: str, body: Callable[[], str], context: str
) -> None:
    redactor = Redactor(salt="s")
    for _ in range(5):
        private = body()
        out = redactor.redact_text(CONTEXTS[context].format(s=prefix + private))
        assert not _leaks(out, private), out
        # Its own type: the late pattern's, or the entropy rule's mask of its token, typed by it.
        # After a label, the labelled rule's, as on main; a Slack body's digit groups are a phone
        # number to that rule, which runs first, as on main.
        typed = {kind} | ({"labeled_secret"} if context in LABELLED else set())
        if prefix.startswith("xoxb-"):
            typed |= {"phone", "high_entropy"}
        assert any(f"«REDACTED:{t}" in out for t in typed), out
        assert redactor.redact_text(out) == out


#: The contexts that put a label (`API_KEY=`, `"api_key": `) before the key.
LABELLED = frozenset({"env", "json"})


LOW_ENTROPY = {
    "a*": lambda n: "a" * n,
    "ab*": lambda n: ("ab" * n)[:n],
    "Ab1*": lambda n: ("Ab1" * n)[:n],
    "A*": lambda n: "A" * n,
    "chunk6": lambda n: ("Zq8LmP" * n)[:n],
}
#: Body lengths as documented, and the prefix of each format family.
LOW_ENTROPY_FORMATS = [
    ("anthropic_key", _p("sk", "-ant-", "api03-"), 95),
    ("openai_key", _p("sk", "-proj-"), 156),
    ("openai_key", _p("sk", "-"), 48),
    ("github_token", _p("gh", "p_"), 36),
    ("github_token", _p("github", "_pat_"), 82),
    ("gitlab_token", _p("gl", "pat-"), 20),
    ("aws_access_key", _p("AK", "IA"), 16),
    ("google_api_key", _p("AI", "za"), 35),
    ("huggingface_token", _p("hf", "_"), 34),
    ("stripe_key", _p("sk", "_live_"), 24),
    ("npm_token", _p("np", "m_"), 36),
]


@pytest.mark.parametrize(
    ("kind", "prefix", "length"), LOW_ENTROPY_FORMATS, ids=[f[1] for f in LOW_ENTROPY_FORMATS]
)
@pytest.mark.parametrize("shape", sorted(LOW_ENTROPY))
def test_a_documented_key_with_a_low_entropy_body_is_masked(
    kind: str, prefix: str, length: int, shape: str
) -> None:
    """The entropy rule passed a repeated body: ``sk-proj-`` and ``a`` written 156 times."""

    private = LOW_ENTROPY[shape](length)
    if kind == "aws_access_key" and not private.isupper():
        private = private.upper()
    for text in (prefix + private, f"KEY {prefix}{private}.", f'{{"k": "{prefix}{private}"}}'):
        out = Redactor(salt="s").redact_text(text)
        assert f"«REDACTED:{kind}:" in out, out
        assert private not in out


@pytest.mark.parametrize(
    "text",
    [
        "scikit-learn and sk-learn are not keys",
        "a ghp_ token, a glpat- token and an hf_ token",
        "hf_hub_download(repo_id) and npm_config_cache",
        "pypi-simple-index and the xoxb- prefix",
        "ASIAPACIFIC is a region code",
        "sk_live_ is Stripe's live-mode prefix",
        "run-abc123def456 halted",
        "AG-TOOLCHAIN-EXFIL-001 and qwen2.5-coder-32b-instruct",
        "the sha deadbeef1234 is short",
    ],
)
def test_a_prefix_without_a_key_after_it_is_left_as_written(text: str) -> None:
    assert Redactor(salt="s").redact_text(text) == text


# --- the hex and UUID shapes ------------------------------------------------------------


def _hex(n: int) -> str:
    return _rnd(_HEX, n)


@pytest.mark.parametrize(
    ("make", "kind"),
    [
        (lambda: _hex(32), "hex_token"),
        (lambda: _hex(40), "hex_token"),
        (lambda: _hex(64), "hex_token"),
        (lambda: _hex(32).upper(), "hex_token"),
        (lambda: "0x" + _hex(64), "hex_token"),
        (lambda: str(uuid.UUID(int=_RNG.getrandbits(128), version=4)), "uuid"),
        (lambda: str(uuid.UUID(int=_RNG.getrandbits(128), version=4)).upper(), "uuid"),
        (lambda: str(uuid.UUID(int=_RNG.getrandbits(128), version=1)), "uuid"),
    ],
    ids=["hex32", "hex40", "hex64", "HEX32", "0x-hex64", "uuid4", "UUID4", "uuid1"],
)
def test_every_random_hex_key_and_uuid_is_masked(make: Callable[[], str], kind: str) -> None:
    """Every draw, where the entropy rule alone printed up to three in four (MEDIUM 4)."""

    redactor = Redactor(salt="s")
    for _ in range(300):
        value = make()
        for text in (value, f"key={value}", f'"{value}"', f"Bearer {value}", f"x_{value}_y"):
            out = redactor.redact_text(text)
            assert value not in out, out
            assert not _leaks(out, value.removeprefix("0x")), out
            # Its own type, or the entropy rule's when that one took the whole token first (or
            # the IBAN rule's, for 32 to 34 upper-case digits starting with two letters).
            typed = (kind, "high_entropy:", "iban»")
            assert any(f"«REDACTED:{t}" in out for t in typed), out


@pytest.mark.parametrize(
    "value",
    [
        "deadbeef" * 4,  # 32 hex digits at 3 bits/char
        "0123456789abcdef" * 2,
        "a" * 40,
        "ab" * 32,
        "00000000-0000-4000-8000-000000000000",
        "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
    ],
)
def test_a_low_entropy_hex_run_or_uuid_is_masked(value: str) -> None:
    out = Redactor(salt="s").redact_text(f"value {value} here")
    assert value not in out
    assert "«REDACTED:" in out


def test_a_uuid_in_a_url_path_is_masked_and_the_path_kept() -> None:
    """A path is exempt from the entropy rule by its shape, not the UUID inside it."""

    value = "3f2a1b4c-5d6e-4f80-9a1b-2c3d4e5f6071"
    out = Redactor(salt="s").redact_text(f"GET /v1/threads/{value}/messages")
    assert out.startswith("GET /v1/threads/«REDACTED:uuid:")
    assert out.endswith("»/messages")


def test_the_two_shapes_have_their_own_types_and_corroborate() -> None:
    redactor = Redactor(salt="s")
    key = "deadbeef" * 4
    one = redactor.redact_text(f"{key} and {key}")
    assert one.count("«REDACTED:hex_token:") == 2
    assert len(set(one.split(" and "))) == 1


@pytest.mark.parametrize(
    "text",
    [
        "run-abc123def456",  # a run id: 12 hex digits
        "the sha deadbeef1234",
        "spec AG-TOOLCHAIN-EXFIL-001",
        # 31 hex digits are under the floor (a low-entropy run, which the rule passes too).
        "deadbeef" * 3 + "deadbee",
    ],
)
def test_short_hex_and_identifiers_are_left_as_written(text: str) -> None:
    assert Redactor(salt="s").redact_text(text) == text


def test_a_hex_run_glued_to_a_letter_is_judged_as_one_token() -> None:
    """``abc...g`` is no hex run: the whole token is the entropy rule's, as before."""

    token = "deadbeef" * 4 + "g"
    assert Redactor(salt="s").redact_text(token) == token  # 3 bits/char: under the threshold


@pytest.mark.parametrize(
    "redactor",
    [
        Redactor(salt="s").without_entropy(),
        Redactor(salt="s", entropy_threshold=math.inf),
    ],
    ids=["without_entropy", "infinite_threshold"],
)
def test_a_redactor_without_the_entropy_rule_leaves_a_hex_run(redactor: Redactor) -> None:
    """The hex run belongs to the fallback: what keeps a value out of it keeps it out of this.

    The CLI keeps the digests it computed out of the fallback, and a model name keeps its form.
    A UUID is a pattern, run before the phone rule, which cut it: it is masked here too.
    """

    hex_run = "deadbeef" * 8
    assert redactor.redact_text(f"x {hex_run} y") == f"x {hex_run} y"
    out = redactor.redact_text("x 3f2a1b4c-5d6e-4f80-9a1b-2c3d4e5f6071 y")
    assert out.startswith("x «REDACTED:uuid:") and out.endswith("» y")


def test_a_redactor_with_only_the_entropy_rule_masks_a_hex_run() -> None:
    """The CLI's second redactor (``Redactor(patterns=[])``) is the fallback alone."""

    out = Redactor(salt="s", patterns=[]).redact_text("x " + "deadbeef" * 8 + " y")
    assert out.startswith("x «REDACTED:hex_token:") and out.endswith("» y")


@pytest.mark.parametrize(
    "uuid_value",
    [
        "b3dd0f36-6819-4748-a1de-4b44fa4b4790",  # two digit-only groups, a phone to that rule
        "12345678-1234-4123-8123-123456789012",  # digits only, a card or a phone
        "B693CB02-41CC-4120-8660-0B87DFC81177",
    ],
)
def test_a_uuid_with_digit_only_groups_is_masked_whole(uuid_value: str) -> None:
    """The phone rule read ``-6819-4748-`` as a number and left the rest of the UUID readable."""

    out = Redactor(salt="s").redact_text(f"id {uuid_value} ok")
    assert out.startswith("id «REDACTED:uuid:") and out.endswith("» ok"), out


@pytest.mark.parametrize(
    "kind",
    [
        *sorted({f[0] for f in FORMATS}),
        "hex_token",
        "uuid",
    ],
)
def test_the_new_masks_are_kept_as_they_are(kind: str) -> None:
    redactor = Redactor(salt="s")
    for mask in (f"«REDACTED:{kind}»", f"«REDACTED:{kind}:0123abcd»"):
        assert redactor.redact_text(f"a {mask} b") == f"a {mask} b"


@pytest.mark.usefixtures("no_known_secrets")
def test_a_hex_run_and_a_uuid_after_a_labelled_url_are_masked() -> None:
    """The entropy rule has a second home, after a URL mask that took a labelled value's head."""

    register_known_secret("Adm1n@2026")
    text = (
        "redis://ops:Adm1n@2026-db:6379,password=Secr3t@Value99xyz then "
        + "deadbeef" * 4
        + " and 3f2a1b4c-5d6e-4f80-9a1b-2c3d4e5f6071"
    )
    out = Redactor(salt="s").redact_text(text)
    assert "deadbeef" not in out
    assert "3f2a1b4c" not in out
    assert "Value99xyz" not in out
    assert "«REDACTED:hex_token:" in out and "«REDACTED:uuid:" in out


# --- the late pass only adds to what the rules before it masked ----------------------------
# Run before the labelled and the entropy rules, the key formats and the UUID left readable what
# those rules had masked (pre-commit differential fuzz against main's redactor, 20,000 texts:
# 5,120 showed text main masks, 1,662 of them 8 characters or more of a planted secret).


def test_a_key_glued_to_a_word_is_masked_with_its_token_and_typed() -> None:
    """``x_<key>`` was the entropy rule's whole token on main; the key alone left ``x_``."""

    key = _p("sk", "-proj-") + _rnd(_URLSAFE, 156)
    out = Redactor(salt="s").redact_text(f"see x_{key}-tail here")
    assert out.startswith("see «REDACTED:openai_key:") and out.endswith("» here"), out


def test_a_label_glued_after_a_greedy_key_still_masks_its_value() -> None:
    """``AIza`` takes `-` in its body: run first, it took `-api` and the label was lost."""

    key = _p("AI", "za") + "Sy" + _rnd(_URLSAFE, 33)
    out = Redactor(salt="s").redact_text(f"{key}-x-api key : Zq8w@Secret_value end")
    assert "Zq8w" not in out and "Secret_value" not in out, out


def test_a_uuid_as_the_user_of_an_address_is_masked_with_the_address() -> None:
    out = Redactor(salt="s").redact_text("mail 3f2a1b4c-5d6e-4f80-9a1b-2c3d4e5f6071@example.com ok")
    assert out == "mail «REDACTED:email» ok"


@pytest.mark.parametrize("glue", ["_", "-", "=", "/", "_id_"])
@pytest.mark.parametrize("after", [True, False])
def test_a_secret_glued_to_a_uuid_with_number_groups_stays_masked(glue: str, after: bool) -> None:
    """Main cut such a UUID at its numbers and masked the piece holding the secret whole."""

    redactor = Redactor(salt="s")
    for _ in range(200):
        value = f"{_hex(8)}-{_hex(4)}-{_rnd(string.digits, 4)}-{_rnd(string.digits, 4)}-{_hex(12)}"
        secret = _rnd(_ALNUM, 20)
        text = f"x {value}{glue}{secret} y" if after else f"x {secret}{glue}{value} y"
        out = redactor.redact_text(text)
        assert value not in out and secret[:8] not in out and secret[-8:] not in out, out


@pytest.mark.parametrize(
    "text",
    [
        # A labelled phone number runs on through a line break into a UUID's first digit, and
        # the card rule, which runs first, had left the UUID's last two groups alone.
        "tel +34 600 123 456\n 6f71e03a-8980-6909-1471-288481829900. ok",
        # A phone number written right before a UUID that starts with digits.
        "call 555 123 4567 36184319-d792-4451-a196-ea92ae3d9a2d/redis ok",
        "+41494259-9176-5907-a0b4-819434834930 ok",
    ],
)
def test_a_number_running_into_a_uuid_leaves_no_part_of_either(text: str) -> None:
    """The number rules leave a UUID whole (``_number_mask``); what lies outside it is masked."""

    out = Redactor(salt="s").redact_text(text)
    uuid_text = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text)
    assert uuid_text is not None
    value = uuid_text.group(0)
    for group in value.split("-"):
        assert group not in out, out
    assert "«REDACTED:uuid:" in out, out
    for number in ("600 123 456", "555 123 4567", "+4149"):
        assert number not in out, out
