"""Redactor tests (DL2 / S6) - masking, idempotency, structural walk, entropy."""

from __future__ import annotations

import logging
import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ildottore.redactor import Pattern, Redactor, redact

SECRETS = [
    ("openai_key", "sk-abcdefghijklmnopqrstuvwxyz0123456789"),
    ("github_token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
    ("slack_token", "xoxb-1234567890-abcdefghijklmnop"),
    (
        "jwt",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ),
]

PII = [
    ("email", "alice.smith@example.com"),
    ("ipv4", "192.168.13.37"),
    ("national_id", "123-45-6789"),
    ("card", "4111111111111111"),  # valid Luhn Visa test number
    ("iban", "DE89370400440532013000"),
]


@pytest.mark.parametrize(("kind", "value"), SECRETS + PII)
def test_secret_and_pii_masked(kind: str, value: str) -> None:
    r = Redactor(salt="unit-salt")
    out = r.redact_text(f"the value is {value} ok")
    assert value not in out
    assert "«REDACTED:" in out


def test_masks_by_type_tag() -> None:
    r = Redactor()
    assert "«REDACTED:email»" in r.redact_text("mail me at bob@corp.test please")


def test_hashed_secret_appends_digest() -> None:
    r = Redactor(salt="s")
    out = r.redact_text("key sk-abcdefghijklmnopqrstuvwxyz0123456789")
    assert re.search(r"«REDACTED:openai_key:[0-9a-f]{8}»", out)


def test_same_secret_same_digest_corroboration() -> None:
    r = Redactor(salt="s")
    secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
    out = r.redact_text(f"{secret} and again {secret}")
    digests = re.findall(r"«REDACTED:openai_key:([0-9a-f]{8})»", out)
    assert len(digests) == 2
    assert digests[0] == digests[1]


def test_idempotent_text() -> None:
    r = Redactor(salt="s")
    once = r.redact_text("email bob@corp.test key sk-abcdefghijklmnopqrstuvwxyz0123456789")
    twice = r.redact_text(once)
    assert once == twice


def test_idempotent_structure() -> None:
    r = Redactor(salt="s")
    obj = {"user": "alice@x.test", "keys": ["sk-abcdefghijklmnopqrstuvwxyz0123456789"]}
    once = r.redact(obj)
    twice = r.redact(once)
    assert once == twice


def test_structural_walk_preserves_shape() -> None:
    r = Redactor()
    obj = {
        "email": "a@b.test",
        "nested": {"list": ["c@d.test", 42, True, None]},
        "tup": ("e@f.test", 1),
        "set": {"g@h.test"},
    }
    out = r.redact(obj)
    assert isinstance(out, dict)
    assert isinstance(out["nested"], dict)
    assert isinstance(out["nested"]["list"], list)
    assert out["nested"]["list"][1] == 42
    assert out["nested"]["list"][2] is True
    assert out["nested"]["list"][3] is None
    assert isinstance(out["tup"], tuple)
    assert isinstance(out["set"], set)
    assert "a@b.test" not in str(out)


def test_scalars_pass_through() -> None:
    r = Redactor()
    assert r.redact(42) == 42
    assert r.redact(3.14) == 3.14
    assert r.redact(False) is False
    assert r.redact(None) is None


def test_register_custom_pattern_runs_first() -> None:
    r = Redactor()
    r.register(Pattern("custom_ticket", re.compile(r"\bTKT-\d{4}\b")))
    out = r.redact_text("ref TKT-1234 now")
    assert "«REDACTED:custom_ticket»" in out
    assert "TKT-1234" not in out


def test_high_entropy_fallback_masks_unknown_shape() -> None:
    r = Redactor(salt="s", entropy_threshold=3.5, entropy_min_len=20)
    token = "Zk9Qw3Xr7Lm2Vt8Np5Bd6Yc4Hs1Gf0"  # high-entropy, no known prefix
    # No secret label around it, so the labelled-secret heuristic does not fire first,
    # this exercises the pure high-entropy fallback path.
    out = r.redact_text(f"opaque {token} value")
    assert token not in out
    assert "«REDACTED:high_entropy:" in out


def test_low_entropy_not_masked() -> None:
    r = Redactor(entropy_threshold=4.0, entropy_min_len=20)
    text = "this is an ordinary english sentence with words"
    assert r.redact_text(text) == text


def test_card_luhn_guard_skips_invalid() -> None:
    r = Redactor()
    invalid = "1234567890123456"  # 16 digits, fails Luhn
    out = r.redact_text(f"num {invalid}")
    # The Luhn guard means it is never typed as a *card*; a long digit run may
    # still be caught by another detector (e.g. phone), which is safety-positive.
    assert "«REDACTED:card»" not in out


def test_card_luhn_guard_masks_valid() -> None:
    r = Redactor()
    valid = "4111111111111111"
    out = r.redact_text(f"num {valid}")
    assert valid not in out


def test_pem_private_key_masked() -> None:
    r = Redactor(salt="s")
    pem = (
        "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASCA\n-----END PRIVATE KEY-----"
    )
    out = r.redact_text(f"here {pem} done")
    assert "MIIBVgIBADAN" not in out
    assert "«REDACTED:pem_private_key:" in out


def test_module_level_default_redact() -> None:
    assert "«REDACTED:email»" in str(redact("ping me a@b.test"))


def test_no_raw_secret_in_log_buffer(caplog: pytest.LogCaptureFixture) -> None:
    """DL2/S6: a redacted string emitted to a logger leaks no raw value."""

    r = Redactor(salt="s")
    logger = logging.getLogger("dottore.test.redact")
    secret = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
    with caplog.at_level(logging.INFO, logger="dottore.test.redact"):
        logger.info("attempt evidence: %s", r.redact_text(f"leaked {secret}"))
    assert secret not in caplog.text
    assert "«REDACTED:" in caplog.text


def test_no_raw_secret_in_serialized_evidence_stub() -> None:
    """DL2: a serialized evidence-shaped dict carries zero raw values."""

    r = Redactor(salt="s")
    evidence = {
        "attempt_id": "a1",
        "inputs_seen": {"prompt": "give me the key"},
        "matched": ["sk-abcdefghijklmnopqrstuvwxyz0123456789", "victim@corp.test"],
    }
    out = r.redact(evidence)
    serialized = str(out)
    assert "sk-abcdefghijklmnopqrstuvwxyz0123456789" not in serialized
    assert "victim@corp.test" not in serialized


# --- property test (Hypothesis): planted secret/PII never survives -----------------


@settings(max_examples=200)
@given(
    prefix=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=40),
    suffix=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=40),
    secret=st.sampled_from([v for _, v in SECRETS + PII]),
)
def test_property_planted_secret_zero_raw(prefix: str, suffix: str, secret: str) -> None:
    r = Redactor(salt="prop")
    # Keep the planted secret on token boundaries so surrounding fuzz text does
    # not fuse into it and change its shape.
    haystack = f"{prefix} {secret} {suffix}"
    out = r.redact_text(haystack)
    assert secret not in out


@settings(max_examples=200)
@given(secret=st.sampled_from([v for _, v in SECRETS + PII]))
def test_property_idempotent(secret: str) -> None:
    r = Redactor(salt="prop")
    once = r.redact_text(f"x {secret} y")
    assert r.redact_text(once) == once


# --- audit regressions (2026-09-01) ------------------------------------------


def test_labeled_secret_value_is_masked() -> None:
    r = Redactor()
    for text, secret in [
        ("the api secret is AIRA_SECRET_KEY_20250901xy", "AIRA_SECRET_KEY_20250901xy"),
        ("password: a1b2c3d4e5f6g7h8", "a1b2c3d4e5f6g7h8"),
        ("the password is Hunter2Password!", "Hunter2Password!"),
    ]:
        assert secret not in r.redact_text(text)


def test_labeled_secret_does_not_over_redact_prose() -> None:
    r = Redactor()
    for prose in ["the password strength is low", "please reset your password now"]:
        assert r.redact_text(prose) == prose


def test_slack_user_token_masked() -> None:
    r = Redactor()
    tok = "xoxp-123456789012-123456789012-abcdef"
    assert tok not in r.redact_text(f"here is {tok}")


def test_pem_detector_has_no_redos_without_end_marker() -> None:
    import time

    r = Redactor()
    payload = "-----BEGIN PRIVATE KEY-----x " * 16000  # ~464 KB, no END marker
    start = time.perf_counter()
    r.redact_text(payload)
    assert (time.perf_counter() - start) < 1.0  # was ~19s before the precheck


# --- entropy-fallback false positives (2026-09-20) ---------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "JB-SEQUENTIAL-001",
        "SAFETY-HARMFUL-001",
        "EMB-NEIGHBOR-LEAK-001",
        "GUARD-UNICODE-EVASION-001",
        "AG-INTERAGENT-COMPROMISE-001",
        "JB-OFFENSIVE-RANSOM-CODEGEN-001",
        "emb-neighbor-leak-001",  # lowercase id
        "qwen2.5-coder-32b-instruct",  # model name
    ],
)
def test_structured_identifier_survives_entropy_fallback(token: str) -> None:
    """A separator-structured identifier is not an opaque secret (OD-15 exemption)."""

    assert Redactor().redact_text(token) == token


def test_url_with_port_survives_entropy_fallback() -> None:
    """A policy-gate reason kept its endpoint: the port + path used to be masked."""

    r = Redactor()
    reason = "endpoint 'http://localhost:11434/v1/chat/completions' not on allowlist"
    assert r.redact_text(reason) == reason


@pytest.mark.parametrize(
    "secret",
    [
        "CANARY-8f3a-secret-token-42",  # planted canary: mixed case, never id-shaped
        "ZYNAP_CANARY_run-20260920-abcdef",  # substituted canary stem
        "ZYNAP-CANARY-A1B2C3D4E5F6G7H8",  # id-shaped wrapper, opaque 16-char segment
        "ZYNAP-CANARY-ABCDEF123456",  # id-shaped wrapper, alphanumeric (key-shaped) segment
        "AB1CD-2EF3G-H4IJK-5LMN6-OPQ7R",  # license-key shape: segments mix letters + digits
        "Zk9Qw3Xr7Lm2Vt8Np5Bd6Yc4Hs1Gf0",  # unknown-shape high-entropy token
    ],
)
def test_identifier_exemption_does_not_spare_a_secret(secret: str) -> None:
    """The exemption is shape-bounded: a canary or an opaque run is still masked whole."""

    out = Redactor(salt="s").redact_text(f"opaque {secret} value")
    assert secret not in out
    assert "«REDACTED:" in out


@pytest.mark.parametrize(
    "secret",
    [
        "da39a3ee-5e6b-4b0d-3255-bfef95601890",  # hyphen-grouped digest
        "3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071",  # UUID-format token, the shape of an api key
        "DA39A3EE-5E6B-4B0D-3255-BFEF95601890",  # same, upper case: id-shaped as well
        "a1b2c3d4-e5f6-a7b8-c9d0",  # shorter grouped hex, still 20 hex digits
        "f0e1d2c3_b4a59687_78695a4b",  # underscore grouping
        "7b3e1f9a/2c8d40a5/6e1b93cf",  # slash grouping, path-shaped
    ],
)
def test_hex_shaped_token_is_not_exempt(secret: str) -> None:
    """An all-hex structured token is a key or a digest, never an identifier.

    A model can emit one with no label, so the labelled-secret rule never sees it; without
    this counter-rule the separator exemption would hand it to the report intact. Each case
    here clears the bits/char threshold on its own: a hex blob *below* it
    (``deadbeef/cafebabe/1a2b3c4d5e``, 3.30) is missed by the interim fallback with or
    without the exemption, which is the OD-15 limitation, not this rule's doing.
    """

    out = Redactor(salt="s").redact_text(f"value {secret} here")
    assert secret not in out
    assert "\u00abREDACTED:" in out


@pytest.mark.parametrize(
    "token",
    [
        "qwen2.5-coder-32b-instruct",  # every hex-looking segment, but 'q'/'w'/'n'/'s' are not
        "http://localhost:11434/v1/chat/completions",
        "text-embedding-3-large",
        "AG-TOOLCHAIN-EXFIL-001",
        "MM-AUD-PROMPTINJECT-001",
    ],
)
def test_hex_counter_rule_does_not_re_break_identifiers(token: str) -> None:
    """The counter-rule must bite hex only: it is what keeps the spec-id fix honest."""

    assert Redactor(salt="s").redact_text(token) == token


# --- phone false positives on dated identifiers (2026-09-20) -----------------------


@pytest.mark.parametrize(
    "text",
    [
        "claude-opus-4-1-20250805",  # dated model suffix behind a version pair
        "claude-sonnet-4-5-20250929",
        "gpt-4o-mini-2024-07-18",  # hyphenated dated model suffix
        "gpt-4.1-2025-04-14",  # dotted version + hyphenated date
        "deepseek-v3-20241226",
        "mistral-large-2411",
        "run-20260920-143000",  # run id: date stamp + clock
        "2026-09-20",  # a bare date
        "baseline 2026-01-31 vs current 2026-02-01",
        "started 2026-09-20 10:01:00 UTC",
        "2026-01-01T00:00:00Z",  # ISO timestamp (already survived, pinned)
        "v1.2.3-20250805",
    ],
)
def test_dated_identifier_is_not_a_phone_number(text: str) -> None:
    """A date, a dated model/version suffix and a run id are not phone numbers.

    ``Target.model`` / ``Target.name`` and the run's date fields travel into every
    rendered report, so these used to surface as ``claude-opus-«REDACTED:phone»``.
    """

    assert Redactor(salt="s").redact_text(text) == text


@pytest.mark.parametrize(
    "phone",
    [
        "+34 600 123 456",
        "+1 (555) 123-4567",
        "+44 20 7946 0958",
        "555-123-4567",
        "555.123.4567",
        "020-7946-0958",
        "1-202-555-0199",
        "0034-600-123456",
        "600123456",
    ],
)
def test_real_phone_numbers_stay_masked(phone: str) -> None:
    """The date exemption must not cost a single real number (pinned both ways)."""

    out = Redactor(salt="s").redact_text(f"reach me on {phone} today")
    assert phone not in out
    assert "«REDACTED:phone»" in out


def test_date_exemption_does_not_carry_a_digit_run() -> None:
    """The bound: an opaque digit run cannot ride along behind a valid date stamp."""

    r = Redactor(salt="s")
    for text in ["20250805-600123456789", "2026-09-20-4155550142"]:
        out = r.redact_text(text)
        assert text not in out
        assert "«REDACTED:" in out
