"""A budget halt's figures survive the redactor that masks every surface showing them.

The halt reason is redacted before the terminal and every report see it (SEC-01), and a bare
figure of nine characters or more reads as a phone number to the redactor (a Luhn-valid one of
13 to 19 digits as a card). So the reason printed ``attempted «REDACTED:phone»`` for exactly the
figure that stopped the run: any stop on the default 1,800 s wall ceiling (``1800.123456``),
any token figure past 99,999,999 and any ceiling the operator set that high.
"""

from __future__ import annotations

import itertools
import re
from decimal import Decimal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ildottore.core.budgets import BudgetExhausted
from ildottore.core.runner import CampaignRunner
from ildottore.reporting import default_redactor
from ildottore.shared.models import PlanBudgets

from .conftest import (
    VULNERABLE_RESPONSE,
    make_policy_engine,
    make_scenario,
    make_spec,
    make_target,
    mock_adapter_factory,
    no_sleep,
)

_REDACTOR = default_redactor()

# axis, limit, attempted, the limit as printed, the attempted figure as printed
_CASES = [
    # A target reporting 2**53 tokens: the figure of the audit finding.
    ("max_tokens", 500_000, 2**53, "500,000", "9,007,199,254,740,992"),
    # An operator ceiling of a billion: the LIMIT was masked too.
    ("max_tokens", 1_000_000_000, 1_000_000_513, "1,000,000,000", "1,000,000,513"),
    # Luhn-valid, so the card rule took it before the phone rule could.
    ("max_tokens", 500_000, 4_111_111_111_111_111, "500,000", "4,111,111,111,111,111"),
    # The default wall ceiling: every stop on it printed a masked elapsed time. Seconds keep
    # three decimals, rounded up for the figure that crossed the ceiling.
    ("max_wall_s", 1_800, 1800.123456, "1,800", "1,800.124"),
    ("max_wall_s", 10, 10.123456, "10", "10.124"),
    # Rounded to the nearest, this read "attempted 1,800.000 would exceed limit 1,800".
    ("max_wall_s", 1_800, 1800.0004, "1,800", "1,800.001"),
    # Past any real spend: a magnitude, so a hostile figure cannot fill the line.
    ("max_tokens", 500_000, 10**18, "500,000", "1.000e+18"),
    ("max_tokens", 500_000, 10**300, "500,000", "1.000e+300"),
    # A magnitude rounds away from the ceiling too: the ceiling down, the figure up, so one
    # past a ceiling of 10**18 does not print as equal to it.
    ("max_tokens", 10**18, 10**18 + 1, "1.000e+18", "1.001e+18"),
    ("max_tokens", 2 * 10**18 - 1, 2 * 10**18, "1.999e+18", "2.000e+18"),
    ("max_tokens", 500_000, 99_995 * 10**14 + 1, "500,000", "1.000e+19"),
]


@pytest.mark.parametrize(("axis", "limit", "attempted", "shown_limit", "shown_attempted"), _CASES)
def test_the_halt_message_keeps_its_figures_through_the_redactor(
    axis: str, limit: int, attempted: float, shown_limit: str, shown_attempted: str
) -> None:
    exc = BudgetExhausted(axis, limit, attempted)
    message = str(exc)

    assert _REDACTOR.redact_text(message) == message
    assert f"attempted {shown_attempted} would exceed limit {shown_limit}" in message
    assert exc.figures == f"limit {shown_limit}, attempted {shown_attempted}"
    assert _REDACTOR.redact_text(exc.figures) == exc.figures
    # Only the text changes: the numbers a caller reads off the exception are the same.
    assert (exc.axis, exc.limit, exc.attempted) == (axis, limit, attempted)


@given(
    limit=st.integers(min_value=0, max_value=10**18 - 1),
    attempted=st.integers(min_value=0, max_value=10**18 - 1),
)
def test_no_count_reads_as_personal_data(limit: int, attempted: int) -> None:
    exc = BudgetExhausted("max_tokens", limit, attempted)
    assert _REDACTOR.redact_text(str(exc)) == str(exc)
    assert _REDACTOR.redact_text(exc.figures) == exc.figures
    # Grouped, not rounded: the exact count is still there for the operator to read.
    assert exc.figures == f"limit {limit:,}, attempted {attempted:,}"


@given(
    limit=st.integers(min_value=0, max_value=10**9),
    attempted=st.floats(min_value=0, max_value=1e15, allow_nan=False, allow_infinity=False),
)
def test_no_elapsed_time_reads_as_personal_data(limit: int, attempted: float) -> None:
    exc = BudgetExhausted("max_wall_s", limit, attempted)
    assert _REDACTOR.redact_text(str(exc)) == str(exc)
    assert _REDACTOR.redact_text(exc.figures) == exc.figures


_NUMBER = st.one_of(
    st.integers(min_value=0, max_value=10**40),
    st.floats(min_value=0, max_value=1e30, allow_nan=False, allow_infinity=False),
)


def _read(figure: str) -> Decimal:
    return Decimal(figure.replace(",", ""))


@given(limit=_NUMBER, attempted=_NUMBER)
def test_a_shortened_figure_is_rounded_away_from_the_ceiling(
    limit: float, attempted: float
) -> None:
    shown = re.fullmatch(
        r"limit (\S+), attempted (\S+)", BudgetExhausted("max_tokens", limit, attempted).figures
    )
    assert shown is not None
    shown_limit, shown_attempted = (_read(figure) for figure in shown.groups())

    assert shown_limit <= Decimal(limit)
    assert shown_attempted >= Decimal(attempted)
    if attempted > limit:
        # A crossed ceiling never reads as one that was not crossed.
        assert shown_attempted > shown_limit


def test_a_count_past_the_int_to_str_limit_still_builds_the_message() -> None:
    """``str`` refuses an int of more than 4,300 digits (Python 3.11+), and the f-string that
    built this message did the same: the exception meant to halt the run raised ``ValueError``
    from its own constructor. ``dottore run`` does not get this far today (it fails first while
    storing the spend), but the exception has to build for any int it is given."""

    exc = BudgetExhausted("max_tokens", 500_000, int("9" * 4300) + 513)
    assert "attempted 1.001e+4300 would exceed limit 500,000" in str(exc)


def test_a_real_phone_number_beside_the_figures_is_still_masked() -> None:
    """The fix is in how the figures are written, not an exemption: the redactor still reads
    the whole reason, so a phone number that reaches it (a target id, the message of an aborted
    run) is masked as before, and the figures beside it are kept."""

    exc = BudgetExhausted("max_tokens", 500_000, 2**53)
    reason = f"budget ceiling reached on 'max_tokens' ({exc.figures}); call +1 415 555 0134"

    masked = _REDACTOR.redact_text(reason)

    assert "415 555 0134" not in masked
    assert "REDACTED:phone" in masked
    assert exc.figures in masked


async def test_a_stop_on_the_wall_ceiling_names_an_elapsed_time_the_redactor_keeps(
    evaluators, mutators, scorer, stores
) -> None:
    # The ledger opens at 0.0; every later read is 1,800.123456 s in, past the 1,800 s default.
    reads = itertools.chain([0.0], itertools.repeat(1800.123456))
    evidence, runs = stores
    budgets = PlanBudgets(max_wall_s=1_800)
    runner = CampaignRunner(
        policy=make_policy_engine(),
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=mock_adapter_factory(make_scenario(VULNERABLE_RESPONSE)),
        endpoint_for=lambda _t, _s: "https://api.example.test/v1/chat",
        n=2,
        sleep=no_sleep,
        now=lambda: 0.0,
        wall_clock=lambda: next(reads),
    )

    result = await runner.run(
        run_id="r-wall", target=make_target(), specs=[make_spec()], budgets=budgets
    )

    assert result.status == "budget_exhausted"
    assert result.status_reason is not None
    assert "on 'max_wall_s' (limit 1,800, attempted 1,800.124)" in result.status_reason
    assert _REDACTOR.redact_text(result.status_reason) == result.status_reason
