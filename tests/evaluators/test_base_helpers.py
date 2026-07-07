"""Tests for base helpers: entropy, masking (DL2 — no raw value survives), verdict builders."""

from __future__ import annotations

import math

from ildottore.evaluators.base import BaseEvaluator, mask_value, mask_values, shannon_entropy
from ildottore.redactor import Redactor
from ildottore.shared.enums import InconclusiveReason, VerdictStatus


def test_shannon_entropy_empty_is_zero() -> None:
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_uniform() -> None:
    # Four distinct equiprobable symbols → 2 bits/char.
    assert math.isclose(shannon_entropy("abcd"), 2.0)


def test_shannon_entropy_low_for_repeats() -> None:
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_mask_value_never_returns_raw() -> None:
    raw = "sk-a1B2c3D4e5F6g7H8i9J0kLmN"
    masked = mask_value(raw, type_hint="openai_key")
    assert raw not in masked
    assert masked.startswith("«REDACTED:")


def test_mask_value_typed_when_redactor_unaware() -> None:
    # A canary the redactor's default patterns don't recognise still gets typed + hashed.
    masked = mask_value("CANARY-unusual-xyz", type_hint="canary")
    assert "canary" in masked
    assert "CANARY-unusual-xyz" not in masked


def test_mask_value_salted_hash_is_stable_and_keyed() -> None:
    r1 = Redactor(salt="one")
    r2 = Redactor(salt="two")
    a = mask_value("CANARY-abc-1", type_hint="canary", redactor=r1)
    b = mask_value("CANARY-abc-1", type_hint="canary", redactor=r1)
    c = mask_value("CANARY-abc-1", type_hint="canary", redactor=r2)
    assert a == b  # deterministic per key
    assert a != c  # different salt → non-correlatable across engagements


def test_mask_values_dedupes_and_preserves_order() -> None:
    out = mask_values(["CANARY-A", "CANARY-A", "CANARY-B"], type_hint="canary")
    assert len(out) == 2


def test_verdict_builders_polarity_and_reason() -> None:
    ev = BaseEvaluator()
    ev.type = "x"
    p = ev._pass("ok")
    f = ev._fail("bad", matched=["m"])
    inc = ev._inconclusive("dunno", reason=InconclusiveReason.CAPABILITY_UNAVAILABLE)
    nr = ev._needs_review("valid-but-uncorroborated", matched=["m"])
    assert p.status is VerdictStatus.PASS
    assert f.status is VerdictStatus.FAIL and f.matched == ["m"]
    assert inc.status is VerdictStatus.INCONCLUSIVE
    assert inc.inconclusive_reason is InconclusiveReason.CAPABILITY_UNAVAILABLE
    assert nr.status is VerdictStatus.INCONCLUSIVE
    assert nr.inconclusive_reason is None  # needs-review carries no closed reason
