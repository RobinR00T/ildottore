"""Redactor tests (DL2 / S6) — masking, idempotency, structural walk, entropy."""

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
