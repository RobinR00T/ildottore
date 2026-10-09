"""The redactor and the evaluators on hostile text (2026-10-06).

A target controls the text they read. Defects already on main, found by the audits of the
labelled-number block and of this one:
- the stash token that keeps a mask out of the next patterns' reach could be forged by adjacency
  (`«a»«b»0«c»` came back as `«a»«a»1` and NUL characters, changing on every pass, which the
  evidence store treats as a reason to abort the campaign);
- a mask the target wrote was kept as it was, with the operator's key inside it;
- `mask_value` returned a value raw when it held a character the redactor rewrites;
- the phone, email and JWT rules, `secret_shape`'s JWT rule, the backtick rule of `tool_call`
  and `pii_detector`'s phone check were quadratic.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from ildottore import redactor as redactor_mod
from ildottore.evaluators.base import mask_value
from ildottore.evaluators.pii_detector import _detect
from ildottore.evaluators.secret_shape import _detect as _detect_secrets
from ildottore.evaluators.tool_call import _INJECTION_RE
from ildottore.redactor import Redactor, register_known_secret


@pytest.mark.parametrize(
    "text",
    [
        "«REDACTED:a»«REDACTED:b»0«REDACTED:c»",
        "«REDACTED:x»12«REDACTED:y»3«REDACTED:z»",
        "«REDACTED:card»0" * 50,
        "\x00«REDACTED:a»\x01\x00«REDACTED:b»\x01",  # forged delimiters are made visible
    ],
)
def test_echoed_masks_are_kept_as_they_are_and_redaction_is_idempotent(text: str) -> None:
    redactor = Redactor(salt="s")
    once = redactor.redact_text(text)
    assert "\x00" not in once and "\x01" not in once
    assert redactor.redact_text(once) == once
    expected = text.replace("\x00", "\u2400").replace("\x01", "\u2401")
    assert once == expected, "nothing in the input needed masking"


@pytest.mark.usefixtures("no_known_secrets")
def test_a_registered_credential_next_to_echoed_masks_keeps_every_mask() -> None:
    register_known_secret("KK0Kk1234567890")
    out = Redactor(salt="s").redact_text("KK0Kk1234567890 «REDACTED:x»0«REDACTED:y»")
    assert out.endswith(" «REDACTED:x»0«REDACTED:y»")
    assert "KK0Kk1234567890" not in out and "\x00" not in out


@pytest.mark.parametrize(
    ("value", "masked_as"),
    [
        ("gH7_Ab12Cd34Ef56Gh78Ij90Kl", "«REDACTED:credential:"),  # registered below
        ("AKIAIOSFODNN7EXAMPLE", "«REDACTED:aws_access_key:"),
        (
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "«REDACTED:high_entropy:",
        ),
    ],
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_mask_written_by_the_target_does_not_hide_what_it_wraps(
    value: str, masked_as: str
) -> None:
    register_known_secret("gH7_Ab12Cd34Ef56Gh78Ij90Kl")
    redactor = Redactor(salt="s")
    for forged in (f"«REDACTED:{value}»", f"«REDACTED:{value}:0123abcd»"):
        out = redactor.redact_text(f"key {forged} end")
        assert value not in out and masked_as in out
        assert redactor.redact_text(out) == out


@pytest.mark.parametrize(
    ("text", "secret", "masked_as"),
    [
        ("password: «REDACTED:Hunter2Hunter2»", "Hunter2Hunter2", "labeled_secret"),
        ("the api key is «REDACTED:Zx9Qw2Lm7Pk4»", "Zx9Qw2Lm7Pk4", "labeled_secret"),
        ("secret=«REDACTED:Tr0ub4dor_3»", "Tr0ub4dor_3", "labeled_secret"),
        ("https://admin:«REDACTED:S3cretPass»@db.local/x", "S3cretPass", "url_password"),
    ],
)
def test_a_forged_mask_is_read_with_the_text_around_it(
    text: str, secret: str, masked_as: str
) -> None:
    """Checking the type alone kept these: only the label or the URL marks them secret."""

    redactor = Redactor(salt="s")
    out = redactor.redact_text(text)
    assert secret not in out and f"«REDACTED:{masked_as}" in out
    assert redactor.redact_text(out) == out


def test_every_mask_type_the_tool_writes_is_kept_as_written() -> None:
    """A type missing from the list is read as text: its masks would be masked again."""

    import re
    from pathlib import Path

    src = Path(redactor_mod.__file__).parent
    written: set[str] = set()
    for path in src.rglob("*.py"):
        code = path.read_text(encoding="utf-8")
        written |= set(re.findall(r'type_hint="(\w+)"', code))
        written |= set(re.findall(r'PIIHit\("(\w+)"', code))
        written |= set(re.findall(r'SecretShapeRule\(\s*"(\w+)"', code))
        written |= set(re.findall(r'Pattern\(\s*"(\w+)"', code))
        written |= set(re.findall(r'_MASK_TEMPLATE(?:_HASHED)?\.format\(type="(\w+)"', code))
    assert len(written) >= 15
    kept = redactor_mod._OWN_MASK_TYPES | {p.type for p in redactor_mod._default_patterns()}
    assert written <= kept, sorted(written - kept)


@pytest.mark.parametrize(
    "kind",
    [
        # The types the redactor and the evaluators write (`mask_value`'s type hints).
        "credential",
        "url_password",
        "labeled_secret",
        "high_entropy",
        "email",
        "phone",
        "card",
        "iban",
        "ipv4",
        "jwt",
        "ip",
        "national_id",
        "canary",
        "shared_line",
        "tool_arg_injection",
        "private_key",
    ],
)
def test_the_masks_the_tool_writes_are_kept_as_they_are(kind: str) -> None:
    redactor = Redactor(salt="s")
    for mask in (f"«REDACTED:{kind}»", f"«REDACTED:{kind}:0123abcd»"):
        assert redactor.redact_text(f"a {mask} b") == f"a {mask} b"


@pytest.mark.usefixtures("no_known_secrets")
def test_a_registered_credential_named_like_a_mask_type_does_not_nest_the_mask() -> None:
    register_known_secret("credential")
    redactor = Redactor(salt="s")
    once = redactor.redact_text("a «REDACTED:credential:0123abcd» b")
    assert once == "a «REDACTED:credential:0123abcd» b"


# No value here can appear in a mask (its digest is hex): `ab` did, 2.7% of the time.
@pytest.mark.parametrize("value", ["a shared line\x01", "\x00rm -rf /", "xyz\x00\x01"])
def test_mask_value_never_returns_a_value_holding_a_rewritten_character(value: str) -> None:
    out = mask_value(value, type_hint="shared_line")
    assert out.startswith("«REDACTED:shared_line:") and value.strip("\x00\x01") not in out


@pytest.mark.parametrize(
    ("text", "masked_as"),
    [
        ("AKIA\x00IOSFODNN7EXAMPLE", "«REDACTED:aws_access_key:"),
        ("card 4111\x001111\x001111\x001111", "«REDACTED:card»"),
        ("bob\x00@corp.io", "«REDACTED:email»"),
        # Joined, these are no email and no phone (`bob@corp.io_`); apart, they are.
        ("bob@corp.io\x00_", "«REDACTED:email»"),
        ("call 600123456\x00x", "«REDACTED:phone»"),
        # A key read as UTF-16 with Latin-1: a NUL after every character.
        ("\x00".join("sk-" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7") + "\x00", "«REDACTED:openai_key:"),
    ],
)
def test_a_secret_split_by_a_stash_delimiter_is_still_masked(text: str, masked_as: str) -> None:
    """Writing the delimiters as `␀` kept these apart and in clear (pre-merge audit)."""

    redactor = Redactor(salt="s")
    out = redactor.redact_text(text)
    assert masked_as in out and "\x00" not in out
    assert redactor.redact_text(out) == out


def test_two_names_that_differ_by_a_stash_delimiter_stay_two() -> None:
    """Dropping `\\x01` made `cmd` and `cmd\\x01` one key in the stored evidence."""

    redactor = Redactor(salt="s")
    keys = {redactor.redact_text(k) for k in ("cmd", "cmd\x01", "cmd\x00", "cmd\x00\x01")}
    assert len(keys) == 4


_HOSTILE = {
    "tel and 1- (labelled phone)": "tel" + "1-" * 50000,
    "a. (email)": "a." * 50000,
    "a@b.b. (email domain)": "a@" + "b." * 50000,
    "1. 2. 3. (phone)": "1. 2. 3. " * 11000,
    "-1. (phone)": "-1." * 33333,
    "eyJ- (jwt)": "eyJ-" * 25000,
    "20,000 echoed masks": "«REDACTED:card»0" * 20000,
    "20,000 forged masks": "«REDACTED:kind_a»0" * 20000,
    "emails and phones": " ".join(f"u{i}@example.com +34 600 {i:06d}" for i in range(12000)),
}


@pytest.mark.parametrize("text", list(_HOSTILE.values()), ids=list(_HOSTILE))
def test_hostile_text_is_redacted_and_scanned_in_linear_time(text: str) -> None:
    """Main took 3.3 to 21 s on each of these; now 0.06 s or less."""

    started = time.perf_counter()
    Redactor(salt="s").redact_text(text)
    _detect(text)
    _detect_secrets(text)
    assert time.perf_counter() - started < 1.5


def test_an_unclosed_backtick_in_a_tool_argument_is_scanned_in_linear_time() -> None:
    started = time.perf_counter()
    assert _INJECTION_RE.search("`" + "a" * 400000) is None
    assert time.perf_counter() - started < 1.5
    assert _INJECTION_RE.search("run `cat /etc/passwd` now") is not None
    assert _INJECTION_RE.search("`1 + 2`") is None  # no letter: arithmetic, not a command


@pytest.mark.parametrize(
    ("text", "email"),
    [
        ("mail me at jordan.testfile@example.com today", "jordan.testfile@example.com"),
        ("(a+b_c-d%e@sub.example.org)", "a+b_c-d%e@sub.example.org"),
    ],
)
def test_emails_are_still_found(text: str, email: str) -> None:
    assert email not in Redactor(salt="s").redact_text(text)
    assert email in {h.value for h in _detect(text)}


def test_emails_glued_to_each_other_are_all_found() -> None:
    """The first fix (a match only where a run starts) left the second one in clear."""

    text = "ann_1@acme.com.bob_2@acme.com.cat_3@acme.com.dan_4@acme.com"
    assert Redactor(salt="s").redact_text(text) == "«REDACTED:email»" * 4
    glued = "jane.doe@acme.com-bob_roe@acme.com"
    assert {h.value for h in _detect(glued)} == {"jane.doe@acme.com", "-bob_roe@acme.com"}


def test_a_jwt_after_a_dash_is_still_masked() -> None:
    jwt = "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4fw"
    out = Redactor(salt="s").redact_text(f"x-{jwt} and eyJ-eyJ-{jwt}")
    assert jwt not in out and out.count("«REDACTED:jwt:") == 2


def test_a_phone_inside_an_email_is_that_email_and_a_repeated_number_is_a_phone() -> None:
    kinds = [(h.kind, h.value) for h in _detect("write to 600123456@example.com")]
    assert kinds == [("email", "600123456@example.com")]
    # The same digits elsewhere were skipped when the check compared values.
    kinds = [(h.kind, h.value) for h in _detect("600123456@example.com or 600123456")]
    assert ("phone", "600123456") in kinds


@pytest.mark.usefixtures("no_known_secrets")
def test_a_registered_credential_written_as_a_digest_is_masked() -> None:
    """A mask of a type the tool writes kept a registered 8-hex credential as its digest."""

    register_known_secret("deadbeef")
    redactor = Redactor(salt="s")
    out = redactor.redact_text("pin «REDACTED:card:deadbeef»")
    assert "deadbeef" not in out and "«REDACTED:credential:" in out
    assert redactor.redact_text(out) == out
    assert redactor.redact_text("«REDACTED:card:0123abcd»") == "«REDACTED:card:0123abcd»"


def test_evidence_keys_that_mask_to_one_name_are_all_kept(tmp_path: Path) -> None:
    """`a@x.io` and `b@y.io` both read `«REDACTED:email»`: the second replaced the first."""

    from ildottore.store.evidence_fs import FsEvidenceStore

    store = FsEvidenceStore(tmp_path, redactor=Redactor(salt="s"))
    masked = store._mask_keys({"a@x.io": 1, "b@y.io": 2, "plain": {"c@z.io": 3, "d@w.io": 4}})
    assert masked == {
        "«REDACTED:email»": 1,
        "«REDACTED:email», #2": 2,
        "plain": {"«REDACTED:email»": 3, "«REDACTED:email», #2": 4},
    }
    assert store._mask_keys(masked) == masked


def test_numbered_evidence_keys_pass_the_leak_guard(tmp_path: Path) -> None:
    """` (2)` after a date made a phone, and the guard refused the reply (abort)."""

    from ildottore.shared.models import ModelResponse
    from ildottore.store.evidence_fs import FsEvidenceStore
    from tests.store.conftest import make_attempt

    store = FsEvidenceStore(tmp_path, redactor=Redactor(salt="s"))
    args = {f"{who}@x.io {tail}": n for n, who in enumerate("abc") for tail in ("2026-10-06",)}
    args |= {"a@x.io ext 555-0142": 7, "b@x.io ext 555-0142": 8, "c@x.io 123456": 9}
    # A label and a value it refuses at the end of a string: `, #2` ended that (pre-merge audit).
    args |= {f"{w}@x.io {tail}": 10 for w in "ab" for tail in ("password: Secret", "token Tokens")}
    args |= {f"{w}@x.io api key is SECRETS": 11 for w in "ab"}
    attempt = make_attempt().model_copy(
        update={"response": ModelResponse(text="ok", tool_calls=[{"name": "f", "arguments": args}])}
    )
    ref = store.put("run-1", attempt)
    assert ref.sha256 is not None


def test_ten_thousand_keys_after_a_label_word_pass_the_leak_guard(tmp_path: Path) -> None:
    """` #10000` after `token` was a labelled secret, and the guard refused the reply."""

    from ildottore.shared.models import ModelResponse
    from ildottore.store.evidence_fs import FsEvidenceStore
    from tests.store.conftest import make_attempt

    store = FsEvidenceStore(tmp_path, redactor=Redactor(salt="s"))
    for label in ("token", "password:", "api key is", "secret ="):
        args = {f"u{i}@x.io {label}": i for i in range(10001)}
        response = ModelResponse(text="ok", tool_calls=[{"name": "f", "arguments": args}])
        assert store.put("run-1", make_attempt().model_copy(update={"response": response}))


def test_numbering_that_redaction_swallows_is_refused_not_looped(tmp_path: Path) -> None:
    """From 10^8 the number reads as a phone; no reply holds that many keys, but no loop."""

    from ildottore.store.evidence_fs import FsEvidenceStore, RedactionLeakError

    class SwallowsNumbers(Redactor):
        def redact_text(self, text: str) -> str:  # every key masks to one name, every number
            return "«REDACTED:email», #«REDACTED:phone»" if ", #" in text else "«REDACTED:email»"

    store = FsEvidenceStore(tmp_path, redactor=SwallowsNumbers(salt="s"))
    with pytest.raises(RedactionLeakError, match="could not be told apart"):
        store._mask_keys({"a@x.io": 1, "b@x.io": 2, "c@x.io": 3})


def test_many_evidence_keys_that_collide_are_numbered_in_linear_time(tmp_path: Path) -> None:
    from ildottore.store.evidence_fs import FsEvidenceStore

    store = FsEvidenceStore(tmp_path, redactor=Redactor(salt="s"))
    # 24,000 keys: 0.55 s here, 1.6 s under a CI-like coverage tracer; counting each base from
    # 1 again took 31 s (quadratic), so 15 s separates the two on a slower runner too.
    keys = {f"user{i}@x.io": i for i in range(24000)}
    started = time.perf_counter()
    masked = store._mask_keys(keys)
    assert time.perf_counter() - started < 15.0 and len(masked) == 24000


def test_the_skip_branches_take_only_long_runs() -> None:
    """Unbounded, they matched every word of a clean text, a callback each (+31% on main)."""

    from ildottore.redactor import EMAIL, skipped

    phone = next(p for p in redactor_mod._default_patterns() if p.type == "phone").regex
    assert EMAIL.search("plain words and v3 run ids") is None
    assert phone.search("call 12 34 or 555-0142") is None
    long_run = EMAIL.search("x" * 64)
    assert long_run is not None and skipped(long_run)
    digits = phone.search("1. " * 22)
    assert digits is not None and skipped(digits)


@pytest.mark.parametrize("text", ["a" * 63 + ".", "1 " * 31 + "1.", "x" * 64])
def test_runs_around_the_skip_length_are_scanned_as_before(text: str) -> None:
    """The `skip` branch takes runs of 64 or more only; around that length nothing changes."""

    redactor = Redactor(salt="s")
    for probe in (text, text + "@corp.io", "+34 " + text, text + " bob@corp.io"):
        out = redactor.redact_text(probe)
        assert redactor.redact_text(out) == out
    assert "bob@corp.io" not in redactor.redact_text(text + " bob@corp.io")
