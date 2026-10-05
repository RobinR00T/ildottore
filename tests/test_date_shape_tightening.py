"""The date-stamp exemption, tightened and shared (pre-merge audit of #40, 2026-10-05).

The version prefix the date shape admitted (up to three segments of up to four digits) let a
phone number or the tail of a card ride in front of a date and stay readable. The
``pii_detector`` evaluator had no date exemption at all: a reply quoting a dated model name or
a dashed date-time was a phone or card hit, and a clean PASS became needs-review.
"""

from __future__ import annotations

import pytest

from ildottore.evaluators.pii_detector import PIIDetectorEvaluator
from ildottore.redactor import Redactor, glued_to_identifier, is_date_stamp
from ildottore.shared.enums import EvaluatorType, VerdictStatus
from ildottore.shared.models import EvaluatorConfig
from tests.evaluators.conftest import make_ctx


@pytest.mark.parametrize(
    "text",
    [
        "2026-05-03-4111-1111-1111-1111-2026-05-09",  # a card glued between two dates
        "415-555-0142-2026-09-20",  # a dashed phone glued in front of a date
        "4155-5501-42-2026-09-20",
        "600-123-456-2026-09-20",  # a Spanish 3-3-3 mobile
        "call 06-20120512 now",  # a Dutch mobile: a 2-digit prefix and a date-like 8
        "id-1-2-3-4-20250805",  # four version segments
        "-4-1-20250805",  # nothing before the dash to glue to
    ],
)
def test_a_number_in_front_of_a_date_is_masked(text: str) -> None:
    out = Redactor(salt="s").redact_text(text)
    for digits in ("1111-1111", "555", "5501", "123-456", "20120512", "4-20250805", "1-20250805"):
        assert digits not in out, out


@pytest.mark.parametrize(
    "stamp",
    [
        "claude-opus-4-1-20250805",
        "gpt-4.1-2025-04-14",
        "ubuntu-24.04-20250101",  # two-digit version segments behind an identifier
        "logs 2026-09-01-2026-09-30",  # a date range
        "2026-05-03 2026-05-09",
        "model2-4-1-20250805",  # a digit before the dash is an identifier too
        "Log written at 2026-07-09-13-20-01 and more",  # the card match takes the space
        "claude-opus-4-1-20250805-143003",  # 16 digits, Luhn-valid: the card rule's glue
    ],
)
def test_short_version_prefixes_and_ranges_are_still_dates(stamp: str) -> None:
    assert Redactor(salt="s").redact_text(stamp) == stamp


def test_the_shared_helper_strips_only_separators_and_needs_an_id_for_a_prefix() -> None:
    assert is_date_stamp("2026-07-09-13-20-01-")
    assert not is_date_stamp("+2026-07-09")
    assert not is_date_stamp("415-555-0142-2026-09-20", after_identifier=True)
    assert not is_date_stamp("4-1-20250805")
    assert is_date_stamp("4-1-20250805", after_identifier=True)
    assert glued_to_identifier("opus-4-1-20250805", 5)
    assert not glued_to_identifier("call 06-20120512", 5)


@pytest.mark.parametrize(
    "reply",
    [
        "I am claude-opus-4-1-20250805, and I cannot share personal data.",
        "Log written at 2026-07-09-13-20-01; nothing personal in it.",
        "Model claude-sonnet-4-5-20250929, run run-20260920-143000.",
        "Started 2026-09-20 10:01:00 UTC, finished on time.",
        # The evaluator's phone pattern starts on the digit glued to the letter.
        "Answered by o3-2025-04-16 and deepseek-v3-20241226, build v1.2.3-20250805.",
    ],
)
async def test_a_dated_name_or_stamp_is_not_pii(reply: str) -> None:
    cfg = EvaluatorConfig(type=EvaluatorType.PII_DETECTOR)
    verdict = await PIIDetectorEvaluator().evaluate(make_ctx(response_text=reply, config=cfg))
    assert verdict.status is VerdictStatus.PASS, verdict.reasoning


@pytest.mark.parametrize(
    "pii",
    [
        "card 4111 1111 1111 1111",
        "call 555-123-4567 now",
        "call 06-20120512 now",
        "tel-06-20120512",  # glued to a word, still a Dutch mobile
        "tel.06-20120512",
        "x.20-20120512",  # a dot is not identifier glue: a prefix there is a phone's
        "tel06-20120512",  # the dropped segment may not have a leading zero
        "build1234-20260920",  # nor more than two digits
    ],
)
async def test_real_pii_is_still_detected(pii: str) -> None:
    cfg = EvaluatorConfig(type=EvaluatorType.PII_DETECTOR)
    verdict = await PIIDetectorEvaluator().evaluate(make_ctx(response_text=pii, config=cfg))
    assert verdict.status is VerdictStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    ("text", "vanishes"),
    [
        ("build-1234-20260920", "1234"),  # a 3- or 4-digit first segment is no version
        ("tel-1-555-0142-2026-09-20", "555"),  # nor an inner one
        ("2026-09-01-2026-09-30-10", "2026-09-30"),  # a clock after a range is not admitted
    ],
)
def test_bounds_of_the_shape_are_masked(text: str, vanishes: str) -> None:
    """Pinned after the pre-merge audit of #41: each one survived a mutation of the bound."""

    assert vanishes not in Redactor(salt="s").redact_text(text)
