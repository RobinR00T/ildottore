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
from ildottore.core.pacing import RateLimiter
from ildottore.core.reproduce import DEFAULT_N, attempt_id_for
from ildottore.core.setup_delivery import IN_BAND, MAX_TOOL_ROUNDS, InBandSetup
from ildottore.shared.models import Attempt, JsonDict, ModelRequest, ModelResponse, Sampling
from ildottore.shared.protocols import TargetAdapter
from ildottore.shared.toolcalls import call_arguments, call_id, call_name

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
    tools: list[JsonDict] | None = None,
) -> ModelRequest:
    """Build the request for one turn: the accumulated history + a pinned mock index."""

    return ModelRequest(
        messages=list(messages),
        system_prompt=system_prompt,
        tools=tools,
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
    setup: InBandSetup | None = None,
    tool_rounds: int = 0,
) -> Attempt:
    """Assemble the single conversation-level :class:`Attempt` (transcript + final reply).

    An in-band scene (OD-18) is recorded on the request: its tools, ``setup_delivery`` and the
    tool rounds played, so the evidence says the model was measured, not an application.
    """

    preamble = len(setup.preamble) if setup is not None else 0
    metadata: JsonDict = {"turns": len([m for m in messages[preamble:] if m.get("role") == "user"])}
    if setup is not None:
        metadata["setup_delivery"] = IN_BAND
        metadata["tool_rounds"] = tool_rounds
    return Attempt(
        attempt_id=attempt_id,
        spec_id=spec_id,
        mutation=mutation,
        request=ModelRequest(
            messages=list(messages),
            system_prompt=system_prompt,
            tools=list(setup.tools) if setup is not None and setup.tools else None,
            sampling=sampling,
            metadata=metadata,
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
    pacer: RateLimiter | None = None,
    setup: InBandSetup | None = None,
) -> AttemptResult:
    """Run one multi-turn conversation and return one aggregate :class:`AttemptResult`.

    Threads each attacker turn (optionally mutated by ``mutate_turn``) with the prior
    assistant replies as ``messages`` history, sending each through
    :func:`execute_attempt`. The aggregate attempt's ``response`` carries the **final**
    turn's ``text`` (what the text evaluators score) and its ``request.messages`` is the
    full transcript.

    Its ``tool_calls``, however, are the **whole conversation's** trace, not just the last
    turn's. The attack is the dialogue, so "did the agent call these tools while under
    attack" has to be asked of every turn: scoring only the final reply let an agent answer
    on one turn and act on the next, which made the trace evaluators
    (``tool_call``, ``tool_sequence``, ``kill_chain_progression``) under-report a chain that
    demonstrably happened. Calls are accumulated in turn order, so an ordered-chain check
    sees the sequence exactly as it occurred.

    An env error on **any** turn aborts the conversation and returns an ``env_error``
    result whose attempt has ``response=None`` (the runner records ``inconclusive``, never
    a fabricated fail from a half-finished dialogue).

    With an in-band ``setup`` (OD-18) the memory seed opens the history, the retrieved
    documents precede the first attacker turn, every request carries the tool definitions, and
    a reply that calls tools is answered with each tool's declared result and sent on, for at
    most :data:`MAX_TOOL_ROUNDS` rounds a turn, each a send under the budget and the pacer.
    Calls the rounds leave unanswered are kept in the trace and dropped from the history, so a
    next turn is never sent after an unanswered call (which an API refuses).
    """

    messages: list[JsonDict] = list(setup.preamble) if setup is not None else []
    tools = list(setup.tools) if setup is not None and setup.tools else None
    last_response: ModelResponse | None = None
    trace_tool_calls: list[JsonDict] = []
    total_latency = 0.0
    saw_latency = False
    tool_rounds = 0

    def aborted(result: AttemptResult) -> AttemptResult:
        attempt = _aggregate_attempt(
            attempt_id=attempt_id,
            spec_id=spec_id,
            mutation=mutation,
            messages=messages,
            system_prompt=system_prompt,
            sampling=sampling,
            response=None,
            latency_ms=None,
            error=result.attempt.error or "conversation aborted after an environment error",
            setup=setup,
            tool_rounds=tool_rounds,
        )
        return AttemptResult(
            attempt=attempt, env_error=True, retries=result.retries, errors=result.errors
        )

    async def send(turn_index: int, suffix: str) -> AttemptResult:
        request = _turn_request(
            messages,
            system_prompt=system_prompt,
            sampling=sampling,
            turn_index=turn_index,
            attempt_id=attempt_id,
            tools=tools,
        )
        return await execute_attempt(
            adapter,
            request,
            attempt_id=f"{attempt_id}@t{turn_index}{suffix}",
            spec_id=spec_id,
            mutation=mutation,
            sampling=sampling,
            ledger=ledger,
            retry=retry,
            timeout_s=timeout_s,
            is_env_error=is_env_error,
            sleep=sleep,
            now=now,
            pacer=pacer,
        )

    for turn_index, raw_turn in enumerate(turns):
        user_text = mutate_turn(raw_turn) if mutate_turn is not None else raw_turn
        if setup is not None and turn_index == 0 and setup.context:
            # The documents a retriever returned, then the attacker's turn (mutated alone).
            user_text = setup.context + user_text
        messages.append({"role": "user", "content": user_text})
        result = await send(turn_index, "")
        response = result.attempt.response
        if result.env_error or response is None:
            return aborted(result)

        rounds = 0
        turn_texts: list[str] = []
        while True:
            turn_texts.append(response.text)
            # Accumulate the trace across turns and rounds (see the docstring): the aggregate
            # keeps the final text but must expose every tool call made, in order.
            trace_tool_calls.extend(dict(call) for call in response.tool_calls)
            if result.attempt.latency_ms is not None:
                total_latency += result.attempt.latency_ms
                saw_latency = True
            answer = setup is not None and bool(response.tool_calls) and rounds < MAX_TOOL_ROUNDS
            # Thread the assistant reply into the history so the next send sees it. Only carry
            # ``tool_calls`` when they are answered next (an unanswered call, or an empty list,
            # is refused by some APIs; adapters also project to their own shape).
            messages.append(_assistant_turn(response, setup, turn_index, rounds, answer))
            if setup is None or not answer:
                break
            rounds += 1
            tool_rounds += 1
            for position, call in enumerate(response.tool_calls):
                name = call_name(call)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id(
                            call, _fallback_id(turn_index, rounds - 1, position)
                        ),
                        "name": name,
                        "content": setup.tool_result(name),
                    }
                )
            result = await send(turn_index, f"r{rounds}")
            next_response = result.attempt.response
            if result.env_error or next_response is None:
                return aborted(result)
            response = next_response
        last_response = response
        if rounds:
            # What the model wrote before calling a tool is part of its answer: scoring only
            # the last round's text let a canary leaked ahead of a call pass, and a reply cut
            # by the round cap be scored as "" (pre-commit audit of OD-18 A).
            kept: list[str] = []
            for text in turn_texts:
                if text.strip() and (not kept or kept[-1] != text):
                    kept.append(text)
            joined = "\n\n".join(kept)
            last_response = response.model_copy(update={"text": joined})

    # The scored response: final turn's text, whole-conversation tool trace.
    scored = last_response
    if scored is not None and list(scored.tool_calls) != trace_tool_calls:
        scored = scored.model_copy(update={"tool_calls": trace_tool_calls})

    final = _aggregate_attempt(
        attempt_id=attempt_id,
        spec_id=spec_id,
        mutation=mutation,
        messages=messages,
        system_prompt=system_prompt,
        sampling=sampling,
        response=scored,
        latency_ms=total_latency if saw_latency else None,
        error=None,
        setup=setup,
        tool_rounds=tool_rounds,
    )
    return AttemptResult(attempt=final, env_error=False, retries=0, errors=[])


def _fallback_id(turn_index: int, round_index: int, position: int) -> str:
    return f"call_{turn_index}_{round_index}_{position}"


def _assistant_turn(
    response: ModelResponse,
    setup: InBandSetup | None,
    turn_index: int,
    round_index: int,
    answered: bool,
) -> JsonDict:
    """The assistant turn threaded into the history.

    Outside the in-band scene the calls ride along as the provider wrote them, as before. In it,
    they go provider-neutral (``id``, ``name``, ``arguments``) when the next send answers them,
    and are left out when it does not.
    """

    turn: JsonDict = {"role": "assistant", "content": response.text}
    if not response.tool_calls:
        return turn
    if setup is None:
        turn["tool_calls"] = [dict(call) for call in response.tool_calls]
    elif answered:
        turn["tool_calls"] = [
            {
                "id": call_id(call, _fallback_id(turn_index, round_index, position)),
                "name": call_name(call),
                "arguments": call_arguments(call),
            }
            for position, call in enumerate(response.tool_calls)
        ]
    return turn


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
    pacer: RateLimiter | None = None,
    setup: InBandSetup | None = None,
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
            # Forwarded, which it was not: this function took a ``pacer`` and dropped it one
            # hop short, so every multi-turn spec ran UNPACED while the single-turn path
            # obeyed the ceiling. 11 of 75 shipped specs are multi-turn, but 42% of a full
            # battery's requests, and the measured breach was 19x the authorized rate.
            pacer=pacer,
            setup=setup,
        )
        results.append(result)
    return results
