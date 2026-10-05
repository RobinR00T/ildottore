"""A phone or card number glued to its own label (2026-10-05).

The redactor's phone and card patterns refuse to start inside a word, so that version strings,
numeric ids and digests stay readable; that also let `Tel.555-123-4567`, `tel_4155550142` and
`card_4111111111111111` through to the reports. The label now decides it, in the redactor and in
the `pii_detector` evaluator alike. An unlabelled run glued to a word is still left alone.
"""

from __future__ import annotations

import pytest

from ildottore.evaluators.pii_detector import _detect
from ildottore.redactor import Redactor

LABELLED_PHONES = [
    ("Tel.555-123-4567", "555-123-4567"),
    ("tel_4155550142", "4155550142"),
    ("phone:+34 600 123 456", "600 123 456"),
    ("Phone number: 555-123-4567", "555-123-4567"),
    ("mobile_no_600123456", "600123456"),
    ("fax.0034-600-123456", "0034"),  # masked whole, not only its unglued tail
    ("tel-49-30-20120512", "20120512"),  # date-shaped, but labelled: a phone
]
LABELLED_CARDS = [
    ("card_4111111111111111", "4111111111111111"),
    ("cc:4111 1111 1111 1111", "4111 1111 1111 1111"),
    ("card4111111111111111", "4111111111111111"),
]


@pytest.mark.parametrize(("text", "digits"), LABELLED_PHONES + LABELLED_CARDS)
def test_a_labelled_number_is_masked(text: str, digits: str) -> None:
    out = Redactor(salt="s").redact_text(text)
    assert digits not in out, out
    assert "REDACTED" in out


@pytest.mark.parametrize(("text", "_digits"), LABELLED_PHONES)
def test_the_evaluator_finds_the_labelled_phone(text: str, _digits: str) -> None:
    assert "phone" in {h.kind for h in _detect(text)}


@pytest.mark.parametrize(("text", "_digits"), LABELLED_CARDS)
def test_the_evaluator_finds_the_labelled_card_once(text: str, _digits: str) -> None:
    assert [h.kind for h in _detect(text)] == ["card"]


@pytest.mark.parametrize(
    "text",
    [
        "user_4155550142",  # an id glued to a word: by shape, an id as often as a number
        "run_123456789",
        "hotel_4155550142",  # a label inside a longer word is no label
        "motel5551234567",
        "telemetry_4155550142",
        "card_1234567890123",  # a card still passes Luhn
        "phone 2026-09-20",  # a plain date after a label is a date
        "claude-opus-4-1-20250805",
    ],
)
def test_look_alikes_stay_readable(text: str) -> None:
    assert Redactor(salt="s").redact_text(text) == text


def test_the_rule_comes_with_its_detector_and_is_idempotent() -> None:
    plain = "Tel.555-123-4567 card_4111111111111111"
    assert Redactor(salt="s", patterns=[]).redact_text(plain) == plain
    redactor = Redactor(salt="s")
    once = redactor.redact_text(plain)
    assert redactor.redact_text(once) == once
    assert redactor.redact_text("tel «REDACTED:phone»") == "tel «REDACTED:phone»"


# --- pre-commit audit of the labelled rule --------------------------------------------------


async def test_a_canary_written_twice_still_corroborates() -> None:
    """Deduplicating cards by digits hid the copy that matched the canary."""

    from ildottore.evaluators.pii_detector import PIIDetectorEvaluator
    from ildottore.shared.enums import EvaluatorType, VerdictStatus
    from ildottore.shared.models import EvaluatorConfig
    from tests.evaluators.conftest import make_ctx

    ctx = make_ctx(
        response_text="Card: 4111 1111 1111 1111 (4111111111111111)",
        config=EvaluatorConfig(type=EvaluatorType.PII_DETECTOR),
    )
    ctx = ctx.model_copy(update={"canaries": ["4111111111111111"]})
    assert (await PIIDetectorEvaluator().evaluate(ctx)).status is VerdictStatus.FAIL


@pytest.mark.parametrize(
    "token",
    [
        "Zq7xK2mP9wR4_cc4539578763621486_aB3dE5fG7h",  # a label inside an opaque token
        "deadbeef0123cafe93cc4539578763621486f00dbabe",
    ],
)
def test_a_label_inside_a_token_cuts_no_number_out_of_it(token: str) -> None:
    out = Redactor(salt="s").redact_text(token)
    assert "_aB3dE5fG7h" not in out and "f00dbabe" not in out, out


@pytest.mark.parametrize(
    "text",
    ["discard4111111111111111", "Hôtel_4155550142", "card_" + "4" * 25],
)
def test_more_look_alikes_stay_readable(text: str) -> None:
    out = Redactor(salt="s").redact_text(text)
    assert "REDACTED:card" not in out and "REDACTED:phone" not in out, out


@pytest.mark.parametrize(
    "text",
    [
        "móvil: 600 123 456",
        "Teléfono 600123456",
        "tel.:_4155550142",
        "Phone number: 49-30-20120512",
    ],
)
def test_accented_labels_long_separators_and_long_tails(text: str) -> None:
    assert "REDACTED:phone" in Redactor(salt="s").redact_text(text)
    assert "phone" in {h.kind for h in _detect(text)}


def test_the_evaluator_keeps_a_labelled_prefixed_date_whole_and_skips_a_dated_card() -> None:
    assert "phone" in {h.kind for h in _detect("tel4-1-20250805")}
    assert "card" not in {h.kind for h in _detect("card_2026-07-09-13-20-01")}


@pytest.mark.parametrize(
    "text",
    [
        "x1tel_4155550142",  # after a digit: inside a token, no label
        "_tel_4155550142",  # after an underscore
        "card_41111111111111119999",  # 20 digits after a card label: not a card
        "card_41111111111111110035",  # nor when its first 19 pass Luhn
    ],
)
def test_bounds_of_the_label(text: str) -> None:
    out = Redactor(salt="s").redact_text(text)
    assert "REDACTED:card" not in out and "REDACTED:phone" not in out, out


@pytest.mark.parametrize("text", ["móvil_600123456", "teléfono_600123456", "TELÉFONO.600123456"])
def test_accented_labels_glued_to_the_number(text: str) -> None:
    assert "REDACTED:phone" in Redactor(salt="s").redact_text(text)


def test_a_long_label_still_reaches_the_evaluator() -> None:
    """The label is looked for up to 40 characters back: `Phone-number-` is 13."""

    assert "phone" in {h.kind for h in _detect("Phone-number-49-30-20120512")}


# --- delta audit of the labelled rule -------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "hotel-49-30-20120512",  # a label inside a word: the dated id keeps its exemption
        "x1tel-49-30-20120512",
        "Hotel4-1-20250805",
        "phone: n/a, model claude-opus-4-1-20250805",  # the label must end right at the number
    ],
)
def test_the_evaluator_does_not_take_a_dated_id_for_a_labelled_phone(text: str) -> None:
    assert "phone" not in {h.kind for h in _detect(text)}
    assert Redactor(salt="s").redact_text(text) == text


def test_the_longest_glued_label_reaches_the_evaluator() -> None:
    """Label, three separators, `number`, a dash: 18 characters before the number."""

    assert "phone" in {h.kind for h in _detect("teléfono:: number-49-30-20120512")}


@pytest.mark.parametrize("digits", ["411111111117", "41111111111111111115"])
def test_a_card_label_needs_13_to_19_digits(digits: str) -> None:
    """12 and 20 digits, both Luhn-valid: not a card after a label either."""

    assert "REDACTED:card" not in Redactor(salt="s").redact_text(f"card_{digits}")


def test_a_labelled_card_keeps_the_space_after_it() -> None:
    assert Redactor(salt="s").redact_text("card 4111111111111111 foo") == "card «REDACTED:card» foo"
