"""Multi-turn conversation execution: a pinned attacker ladder (u08 multi-turn).

The single-turn path (:func:`~ildottore.core.reproduce.reproduce` +
:func:`~ildottore.core.execute.execute_attempt`) sends one request and evaluates one
response. A whole class of real attacks (Crescendo, Linear/PAIR-style refinement,
Sequential decomposition, Bad-Likert-Judge) only succeeds **across turns**: an opening
turn that reads benign, then an escalation that exploits the context the earlier turns
established.

:func:`execute_conversation` runs one such conversation:

* the attacker turns are the spec's **pinned** ``attack.turns`` list, a scripted ladder,
  never LLM-generated, so the run stays reproducible (the product thesis, ``docs/01 §5``);
* each turn threads the prior assistant replies back as ``messages`` history, so turn N
  sees the real dialogue that led to it;
* per-turn sends reuse :func:`execute_attempt` (retry/backoff/timeout + per-send budget
  debit), so a multi-turn attack cannot self-DoS and env errors stay ``inconclusive``;
* the returned :class:`~ildottore.core.execute.AttemptResult` carries **one** aggregate
  :class:`Attempt` whose ``request.messages`` is the full transcript and whose ``response``
  is the **final** assistant turn, the one the evaluator arbitrates (the exploit either
  surfaced by the last turn or the target held). Intermediate turns live in the transcript
  for evidence; they are not separately scored.

Determinism: against the deterministic :class:`~ildottore.adapters.mock.MockTarget` every
turn pins ``mock_attempt`` to its turn index, so N repro conversations replay the identical
ladder, byte-stable evidence (contract §7). A real over-the-wire adapter ignores the pin.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from ildottore.core.budgets import BudgetLedger
from ildottore.core.execute import AttemptResult, RetryPolicy, default_is_env_error, execute_attempt
from ildottore.core.reproduce import DEFAULT_N, attempt_id_for
from ildottore.shared.models import Attempt, JsonDict, ModelRequest, ModelResponse, Sampling
from ildottore.shared.protocols import TargetAdapter

__all__ = [
    "execute_conversation",
    "reproduce_conversation",
]

#: Request metadata key the deterministic mock (u03) reads to pin its sequence index.
_MOCK_ATTEMPT_KEY = "mock_attempt"


def _turn_request(
    messages: list[JsonDict],
    *,
    system_prompt: str | None,
    sampling: Sampling | None,
    turn_index: int,
    attempt_id: str,
) -> ModelRequest:
    """Build the request for one turn: the accumulated history + a pinned mock index."""

    return ModelRequest(
        messages=list(messages),
        system_prompt=system_prompt,
        sampling=sampling,
        metadata={
            _MOCK_ATTEMPT_KEY: turn_index,
            "turn_index": turn_index,
            "conversation": attempt_id,
        },
    )


def _aggregate_attempt(
    *,
    attempt_id: str,
    spec_id: str,
    mutation: str,
    messages: list[JsonDict],
    system_prompt: str | None,
    sampling: Sampling | None,
    response: ModelResponse | None,
    latency_ms: float | None,
    error: str | None,
) -> Attempt:
    """Assemble the single conversation-level :class:`Attempt` (transcript + final reply)."""

    return Attempt(
        attempt_id=attempt_id,
        spec_id=spec_id,
        mutation=mutation,
        request=ModelRequest(
            messages=list(messages),
            system_prompt=system_prompt,
            sampling=sampling,
            metadata={"turns": len([m for m in messages if m.get("role") == "user"])},
        ),
        response=response,
        sampling=sampling,
        latency_ms=latency_ms,
        error=error,
    )


async def execute_conversation(
    adapter: TargetAdapter,
    turns: list[str],
    *,
    attempt_id: str,
    spec_id: str,
    mutation: str,
    sampling: Sampling | None,
    ledger: BudgetLedger,
    system_prompt: str | None = None,
    mutate_turn: Callable[[str], str] | None = None,
    retry: RetryPolicy | None = None,
    timeout_s: float | None = None,
    is_env_error: Callable[[BaseException], bool] = default_is_env_error,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    now: Callable[[], float] | None = None,
) -> AttemptResult:
    """Run one multi-turn conversation and return one aggregate :class:`AttemptResult`.

    Threads each attacker turn (optionally mutated by ``mutate_turn``) with the prior
    assistant replies as ``messages`` history, sending each through
    :func:`execute_attempt`. The aggregate attempt's ``response`` is the **final** turn's
    reply (what the evaluator scores) and its ``request.messages`` is the full transcript.

    An env error on **any** turn aborts the conversation and returns an ``env_error``
    result whose attempt has ``response=None`` (the runner records ``inconclusive``, never
    a fabricated fail from a half-finished dialogue).
    """

    messages: list[JsonDict] = []
    last_response: ModelResponse | None = None
    total_latency = 0.0
    saw_latency = False

    for turn_index, raw_turn in enumerate(turns):
        user_text = mutate_turn(raw_turn) if mutate_turn is not None else raw_turn
        messages.append({"role": "user", "content": user_text})
        request = _turn_request(
            messages,
            system_prompt=system_prompt,
            sampling=sampling,
            turn_index=turn_index,
            attempt_id=attempt_id,
        )
        result = await execute_attempt(
            adapter,
            request,
            attempt_id=f"{attempt_id}@t{turn_index}",
            spec_id=spec_id,
            mutation=mutation,
            sampling=sampling,
            ledger=ledger,
            retry=retry,
            timeout_s=timeout_s,
            is_env_error=is_env_error,
            sleep=sleep,
            now=now,
        )
        response = result.attempt.response
        if result.env_error or response is None:
            aborted = _aggregate_attempt(
                attempt_id=attempt_id,
                spec_id=spec_id,
                mutation=mutation,
                messages=messages,
                system_prompt=system_prompt,
                sampling=sampling,
                response=None,
                latency_ms=None,
                error=result.attempt.error or "conversation aborted after an environment error",
            )
            return AttemptResult(
                attempt=aborted,
                env_error=True,
                retries=result.retries,
                errors=result.errors,
            )

        last_response = response
        if result.attempt.latency_ms is not None:
            total_latency += result.attempt.latency_ms
            saw_latency = True
        # Thread the assistant reply into the history so the next turn sees it. Only carry
        # ``tool_calls`` when the turn actually made some (an empty list is a provider-foreign
        # field that some Messages APIs reject; adapters also project to their own shape).
        assistant_msg: JsonDict = {"role": "assistant", "content": response.text}
        if response.tool_calls:
            assistant_msg["tool_calls"] = [dict(call) for call in response.tool_calls]
        messages.append(assistant_msg)

    final = _aggregate_attempt(
        attempt_id=attempt_id,
        spec_id=spec_id,
        mutation=mutation,
        messages=messages,
        system_prompt=system_prompt,
        sampling=sampling,
        response=last_response,
        latency_ms=total_latency if saw_latency else None,
        error=None,
    )
    return AttemptResult(attempt=final, env_error=False, retries=0, errors=[])


async def reproduce_conversation(
    adapter: TargetAdapter,
    turns: list[str],
    *,
    spec_id: str,
    mutation: str,
    sampling: Sampling | None,
    ledger: BudgetLedger,
    n: int = DEFAULT_N,
    system_prompt: str | None = None,
    mutate_turn: Callable[[str], str] | None = None,
    retry: RetryPolicy | None = None,
    timeout_s: float | None = None,
    is_env_error: Callable[[BaseException], bool] = default_is_env_error,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    now: Callable[[], float] | None = None,
    completed: set[str] | None = None,
) -> list[AttemptResult]:
    """Execute the pinned conversation ``n`` times (repro), one aggregate attempt each.

    Mirrors :func:`~ildottore.core.reproduce.reproduce` for the multi-turn path: one
    ``debit_attempt`` per conversation (each turn additionally debits a request inside
    :func:`execute_attempt`), stable ``attempt_id`` per run so resume skips completed
    conversations, and results returned in order. Against the deterministic mock all ``n``
    conversations are byte-identical; against a real target they measure repro honestly.
    """

    if n < 1:
        raise ValueError("n must be >= 1")
    results: list[AttemptResult] = []
    for run_index in range(n):
        attempt_id = attempt_id_for(spec_id, mutation, run_index)
        if completed is not None and attempt_id in completed:
            continue
        ledger.debit_attempt()
        result = await execute_conversation(
            adapter,
            turns,
            attempt_id=attempt_id,
            spec_id=spec_id,
            mutation=mutation,
            sampling=sampling,
            ledger=ledger,
            system_prompt=system_prompt,
            mutate_turn=mutate_turn,
            retry=retry,
            timeout_s=timeout_s,
            is_env_error=is_env_error,
            sleep=sleep,
            now=now,
        )
        results.append(result)
    return results
