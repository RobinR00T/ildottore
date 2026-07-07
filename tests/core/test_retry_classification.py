"""Env-vs-product classification + retry/backoff/timeout (contract §7)."""

from __future__ import annotations

import asyncio

import pytest

from ildottore.core.budgets import BudgetExhausted, BudgetLedger
from ildottore.core.execute import (
    RetryPolicy,
    default_is_env_error,
    execute_attempt,
)
from ildottore.shared.models import ModelRequest, ModelResponse, Sampling

from .conftest import no_sleep


class _EnvError(Exception):
    is_env_error = True


class _ProductError(Exception):
    is_env_error = False


class _RateLimitError(Exception):
    """Recognized by class-name convention (no marker attribute)."""


class FlakyAdapter:
    """Fails with an env error ``fail_times`` then returns ``response``."""

    id = "flaky"

    def __init__(self, response: ModelResponse, *, fail_times: int, exc: Exception) -> None:
        self._response = response
        self._fail_times = fail_times
        self._exc = exc
        self.calls = 0

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.calls += 1
        if self.calls <= self._fail_times:
            raise self._exc
        return self._response

    def capabilities(self):  # pragma: no cover - not used here
        from ildottore.shared.models import Capabilities

        return Capabilities()


def _req() -> ModelRequest:
    return ModelRequest(prompt="hi", sampling=Sampling(temperature=0.0))


def _resp(text: str = "ok") -> ModelResponse:
    return ModelResponse(text=text)


# --- classification ----------------------------------------------------------


def test_default_classifier_marker_attribute() -> None:
    assert default_is_env_error(_EnvError()) is True
    assert default_is_env_error(_ProductError()) is False


def test_default_classifier_timeout_is_env() -> None:
    assert default_is_env_error(TimeoutError()) is True
    assert default_is_env_error(TimeoutError()) is True


def test_default_classifier_name_convention() -> None:
    assert default_is_env_error(_RateLimitError()) is True


# --- retry then succeed ------------------------------------------------------


async def test_env_error_retried_then_success() -> None:
    adapter = FlakyAdapter(_resp("recovered"), fail_times=2, exc=_EnvError())
    ledger = BudgetLedger()
    result = await execute_attempt(
        adapter,
        _req(),
        attempt_id="a1",
        spec_id="S-1",
        mutation="identity",
        sampling=Sampling(temperature=0.0),
        ledger=ledger,
        retry=RetryPolicy(max_retries=3, base_delay_s=0.0),
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    assert result.env_error is False
    assert result.retries == 2
    assert result.attempt.response is not None
    assert result.attempt.response.text == "recovered"
    # 3 sends were debited (2 fails + 1 success).
    assert ledger.snapshot().requests == 3


async def test_env_error_exhausts_retries_to_inconclusive() -> None:
    adapter = FlakyAdapter(_resp(), fail_times=10, exc=_EnvError())
    ledger = BudgetLedger()
    result = await execute_attempt(
        adapter,
        _req(),
        attempt_id="a1",
        spec_id="S-1",
        mutation="identity",
        sampling=None,
        ledger=ledger,
        retry=RetryPolicy(max_retries=2, base_delay_s=0.0),
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    assert result.env_error is True
    assert result.attempt.response is None
    assert result.attempt.error is not None
    assert len(result.errors) == 3  # first send + 2 retries


async def test_product_error_propagates_not_masked() -> None:
    adapter = FlakyAdapter(_resp(), fail_times=10, exc=_ProductError("boom"))
    ledger = BudgetLedger()
    with pytest.raises(_ProductError):
        await execute_attempt(
            adapter,
            _req(),
            attempt_id="a1",
            spec_id="S-1",
            mutation="identity",
            sampling=None,
            ledger=ledger,
            retry=RetryPolicy(max_retries=3, base_delay_s=0.0),
            sleep=no_sleep,
            now=lambda: 0.0,
        )


async def test_timeout_is_env_error() -> None:
    class SlowAdapter:
        id = "slow"

        async def send(self, request: ModelRequest) -> ModelResponse:
            await asyncio.sleep(10)
            return _resp()  # pragma: no cover

        def capabilities(self):  # pragma: no cover
            from ildottore.shared.models import Capabilities

            return Capabilities()

    ledger = BudgetLedger()
    result = await execute_attempt(
        SlowAdapter(),
        _req(),
        attempt_id="a1",
        spec_id="S-1",
        mutation="identity",
        sampling=None,
        ledger=ledger,
        retry=RetryPolicy(max_retries=1, base_delay_s=0.0),
        timeout_s=0.01,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    assert result.env_error is True


async def test_budget_breach_during_send_propagates() -> None:
    adapter = FlakyAdapter(_resp(), fail_times=0, exc=_EnvError())
    ledger = BudgetLedger(max_requests=0)  # first debit breaches immediately
    with pytest.raises(BudgetExhausted):
        await execute_attempt(
            adapter,
            _req(),
            attempt_id="a1",
            spec_id="S-1",
            mutation="identity",
            sampling=None,
            ledger=ledger,
            sleep=no_sleep,
            now=lambda: 0.0,
        )


async def test_response_token_usage_reconciled() -> None:
    adapter = FlakyAdapter(
        ModelResponse(text="ok", usage={"total_tokens": 42}), fail_times=0, exc=_EnvError()
    )
    ledger = BudgetLedger(max_tokens=100)
    await execute_attempt(
        adapter,
        _req(),
        attempt_id="a1",
        spec_id="S-1",
        mutation="identity",
        sampling=None,
        ledger=ledger,
        sleep=no_sleep,
        now=lambda: 0.0,
    )
    assert ledger.snapshot().tokens == 42


def test_retry_backoff_schedule_is_capped() -> None:
    policy = RetryPolicy(base_delay_s=1.0, multiplier=2.0, max_delay_s=5.0)
    assert policy.delay_for(0) == 1.0
    assert policy.delay_for(1) == 2.0
    assert policy.delay_for(2) == 4.0
    assert policy.delay_for(3) == 5.0  # capped
