"""A mask of a type A-78 added is kept only when this process wrote it (u01 A-78, audit L3).

A mask is kept as written when its type is one the tool writes, so a second pass, the evidence
store's check and a report leave the tool's own masks alone. A target can write one too, and a
kept mask ends a labelled value: `password: «REDACTED:high_entropy»<secret>` showed the secret
before A-78, and A-78 added nine types that did the same (`password: «REDACTED:uuid»<secret>`,
83 of 93 regressions in the audit's mixed fuzz). A mask of one of those types is now kept only
when this process wrote it; any other is read as text, as the redactor before A-78 read it.
"""

from __future__ import annotations

import pytest

from ildottore import redactor as redactor_mod
from ildottore.redactor import Redactor

_NEW = (
    "hex_token",
    "uuid",
    "anthropic_key",
    "gitlab_token",
    "google_api_key",
    "huggingface_token",
    "stripe_key",
    "npm_token",
    "pypi_token",
)


def test_the_types_a78_added_are_the_nine() -> None:
    assert set(redactor_mod._LATE_MASK_TYPES) == set(_NEW)


@pytest.mark.parametrize("kind", _NEW)
@pytest.mark.parametrize("digest", ["", ":1a2b3c4d"])
def test_a_mask_a_target_writes_is_read_as_text(kind: str, digest: str) -> None:
    out = Redactor(salt="s").redact_text(f"password: «REDACTED:{kind}{digest}»Summer2026x")
    assert "Summer2026x" not in out
    assert out.startswith("password: «REDACTED:labeled_secret:")


@pytest.mark.parametrize(
    "secret",
    [
        "6a1f0c2e-91b4-4d7a-8e3b-2f5c9d0a7b14",
        "0123456789abcdef0123456789abcdef",
        "sk-ant-api03-" + "Ab1" * 30,
        "glpat-" + "x1Y2z3W4v5U6t7S8r9Q0",
        "hf_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3h",
    ],
)
def test_its_own_masks_are_kept_by_a_second_pass(secret: str) -> None:
    redactor = Redactor(salt="s")
    for text in (f"x {secret} y", f"ws://{secret}@h/v1", f"note: {secret}_tail"):
        once = redactor.redact_text(text)
        assert secret not in once
        assert redactor.redact_text(once) == once, once
        assert Redactor(salt="other").redact_text(once) == once, once


def test_a_mask_of_an_older_type_is_kept_as_before() -> None:
    # The class predates A-78 for the types the tool wrote before it: unchanged here.
    text = "password: «REDACTED:high_entropy»Summer2026x"
    assert Redactor(salt="s").redact_text(text) == text


def test_the_record_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(redactor_mod, "_EMITTED_CAP", 4)
    monkeypatch.setattr(redactor_mod, "_EMITTED", [set(), set()])
    redactor = Redactor(salt="s")
    for n in range(20):
        redactor.redact_text(f"x {n:032x} y")
    assert all(len(generation) <= 4 for generation in redactor_mod._EMITTED)
    last = redactor.redact_text(f"x {19:032x} y")
    assert redactor.redact_text(last) == last  # the last ones written are still kept
