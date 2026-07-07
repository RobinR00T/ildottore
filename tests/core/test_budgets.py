"""Budget-ledger tests: hard caps on every axis, no self-DoS (contract §7)."""

from __future__ import annotations

import threading

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ildottore.core.budgets import BudgetExhausted, BudgetLedger
from ildottore.shared.models import PlanBudgets

from .conftest import FakeClock


def test_unbounded_axes_never_raise() -> None:
    ledger = BudgetLedger()
    for _ in range(1000):
        ledger.debit_request(tokens=100)
        ledger.debit_attempt()
    snap = ledger.snapshot()
    assert snap.requests == 1000
    assert snap.attempts == 1000
    assert snap.tokens == 100_000


def test_request_ceiling_is_hard() -> None:
    ledger = BudgetLedger(max_requests=3)
    for _ in range(3):
        ledger.debit_request()
    with pytest.raises(BudgetExhausted) as exc:
        ledger.debit_request()
    assert exc.value.axis == "max_requests"
    # The refused debit did NOT commit — still exactly 3 requests.
    assert ledger.snapshot().requests == 3


def test_token_ceiling_is_hard_and_atomic() -> None:
    ledger = BudgetLedger(max_tokens=100)
    ledger.debit_request(tokens=60)
    with pytest.raises(BudgetExhausted) as exc:
        ledger.debit_request(tokens=50)  # would be 110 > 100
    assert exc.value.axis == "max_tokens"
    # Neither the request nor the tokens committed (checked-then-applied).
    snap = ledger.snapshot()
    assert snap.tokens == 60
    assert snap.requests == 1


def test_attempt_ceiling_is_hard() -> None:
    ledger = BudgetLedger(max_attempts=2)
    ledger.debit_attempt()
    ledger.debit_attempt()
    with pytest.raises(BudgetExhausted) as exc:
        ledger.debit_attempt()
    assert exc.value.axis == "max_attempts"


def test_wall_clock_ceiling_with_injected_clock() -> None:
    clock = FakeClock()
    ledger = BudgetLedger(max_wall_s=10, time_source=clock)
    ledger.debit_request()  # t=0, ok
    clock.advance(11)
    with pytest.raises(BudgetExhausted) as exc:
        ledger.check_wall()
    assert exc.value.axis == "max_wall_s"


def test_add_tokens_reconciliation_can_breach() -> None:
    ledger = BudgetLedger(max_tokens=50)
    ledger.debit_request(tokens=10)
    with pytest.raises(BudgetExhausted):
        ledger.add_tokens(45)  # 10 + 45 = 55 > 50
    assert ledger.snapshot().tokens == 10


def test_check_wall_noop_when_unbounded() -> None:
    ledger = BudgetLedger()  # no wall ceiling
    ledger.check_wall()  # must not raise
    ledger.debit_request()


def test_add_tokens_negative_rejected() -> None:
    ledger = BudgetLedger()
    with pytest.raises(ValueError, match="tokens"):
        ledger.add_tokens(-1)


def test_from_plan_budgets_maps_all_axes() -> None:
    budgets = PlanBudgets(max_tokens=1, max_requests=2, max_wall_s=3, max_attempts=4)
    ledger = BudgetLedger.from_plan_budgets(budgets)
    snap = ledger.snapshot()
    assert (snap.max_tokens, snap.max_requests, snap.max_wall_s, snap.max_attempts) == (1, 2, 3, 4)


def test_negative_ceiling_rejected() -> None:
    with pytest.raises(ValueError, match="max_requests"):
        BudgetLedger(max_requests=-1)


def test_negative_token_debit_rejected() -> None:
    ledger = BudgetLedger()
    with pytest.raises(ValueError, match="tokens"):
        ledger.debit_request(tokens=-5)


def test_concurrent_debits_never_exceed_ceiling() -> None:
    """Property-ish: many threads racing a small ceiling never over-spend."""

    ceiling = 50
    ledger = BudgetLedger(max_requests=ceiling)
    granted = 0
    lock = threading.Lock()

    def worker() -> None:
        nonlocal granted
        for _ in range(20):
            try:
                ledger.debit_request()
            except BudgetExhausted:
                return
            with lock:
                granted += 1

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # No more than the ceiling was ever granted, and the ledger agrees.
    assert granted == ceiling
    assert ledger.snapshot().requests == ceiling


@given(
    max_requests=st.integers(min_value=0, max_value=200),
    debits=st.integers(min_value=0, max_value=400),
)
def test_property_request_axis_never_exceeds_ceiling(max_requests: int, debits: int) -> None:
    ledger = BudgetLedger(max_requests=max_requests)
    granted = 0
    for _ in range(debits):
        try:
            ledger.debit_request()
        except BudgetExhausted:
            break
        granted += 1
    assert granted <= max_requests
    assert ledger.snapshot().requests <= max_requests


@given(
    max_tokens=st.integers(min_value=0, max_value=1000),
    chunk=st.integers(min_value=1, max_value=50),
    count=st.integers(min_value=0, max_value=100),
)
def test_property_token_axis_never_exceeds_ceiling(max_tokens: int, chunk: int, count: int) -> None:
    ledger = BudgetLedger(max_tokens=max_tokens)
    for _ in range(count):
        try:
            ledger.debit_request(tokens=chunk)
        except BudgetExhausted:
            break
    assert ledger.snapshot().tokens <= max_tokens
