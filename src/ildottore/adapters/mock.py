"""Deterministic, offline :class:`MockTarget` (u03, contract §5 step 1).

:class:`MockTarget` is a **pure** :class:`~ildottore.shared.protocols.TargetAdapter`:
given a fixture's canned response(s) it returns the declared
:class:`~ildottore.shared.models.ModelResponse` with **zero I/O and no clock/RNG**
— identical bytes on every call (contract §4 KEEP, §7 determinism). It is the
scanner-side stand-in that makes every attack spec's fixtures replayable in CI so
the golden harness (:mod:`ildottore.testing.golden`) can prove detection accuracy
offline.

Design constraints (contract §4/§8, ``docs/07 §2``):

* **No network, no clock, no RNG, no filesystem.** This module imports nothing
  from ``httpx``/``socket``/``requests``/``urllib``/``time``/``random``. A
  network import here fails CI (the no-network acceptance test asserts it via AST).
* **No matching logic.** The target does not interpret the attack; it replays
  exactly what the fixture author declared, selected by ``scenario`` key only.
* **Capability honesty.** :meth:`MockTarget.capabilities` reflects the fixture's
  declared capabilities so a spec needing an absent capability yields
  ``inconclusive: capability_unavailable`` downstream, never a fabricated pass.
* **Sequence replay.** A multi-response fixture (N-run repro) replays a declared
  sequence, cycling deterministically by attempt index — no drift.

The concrete provider adapters (openai/anthropic/rest) are u04 and are **not**
imported here; ``MockTarget`` implements the protocol structurally.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ildottore.shared.models import (
    Capabilities,
    FixtureCase,
    JsonDict,
    ModelRequest,
    ModelResponse,
    TokenLogprob,
)

__all__ = [
    "BARE_RESPONSE",
    "MockScenario",
    "MockTarget",
    "bare_scenario",
]

#: The canned answer a *bare* mock returns when no fixture scenario is selected. It
#: is deliberately generic — it matches neither a spec's ``vulnerable`` nor its
#: ``hardened`` fixture, so every evaluator abstains and the run stays
#: ``inconclusive`` (the current default behavior, made explicit). Selecting the
#: ``vulnerable`` / ``hardened`` scenario replays the spec's own fixtures instead.
BARE_RESPONSE = "(mock target: no scenario configured — bare canned response)"


class MockScenario(BaseModel):
    """A single canned scenario for :class:`MockTarget` (u03-owned input shape).

    This is the offline-replay envelope the mock consumes. It is a superset of the
    schema-mirrored :class:`~ildottore.shared.models.FixtureCase` (which carries
    only ``response``/``tool_calls``): it additionally lets a fixture declare a
    **response sequence** (``response: list[str]`` per contract §6, for N-run
    repro), ``logprobs`` (so ``logprob_membership`` specs are exercisable offline,
    ADR-0005) and the target ``capabilities`` it emulates (capability honesty).

    Construct directly, or from a spec's ``FixtureCase`` via :meth:`from_fixture`.
    Frozen so a scenario cannot mutate between replays (determinism).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # A single response, or an ordered sequence cycled by attempt index (contract §6).
    response: str | list[str]
    tool_calls: list[JsonDict] = Field(default_factory=list)
    logprobs: list[TokenLogprob] | None = None
    finish_reason: str | None = None
    capabilities: Capabilities = Field(default_factory=Capabilities)

    def model_post_init(self, _context: object) -> None:
        if isinstance(self.response, list) and len(self.response) == 0:
            raise ValueError("MockScenario.response sequence must be non-empty")

    @classmethod
    def from_fixture(
        cls,
        fixture: FixtureCase,
        *,
        logprobs: list[TokenLogprob] | None = None,
        capabilities: Capabilities | None = None,
        finish_reason: str | None = None,
    ) -> MockScenario:
        """Build a scenario from a schema :class:`FixtureCase`.

        ``FixtureCase`` carries no logprobs/capabilities (they are not in the
        author-facing schema), so the harness supplies them out-of-band when a
        spec needs them (e.g. ``logprob_membership``). Everything else is copied
        verbatim — the mock never re-interprets the fixture (contract §4 KEEP).
        """

        return cls(
            response=fixture.response,
            tool_calls=list(fixture.tool_calls or []),
            logprobs=logprobs,
            capabilities=capabilities if capabilities is not None else Capabilities(),
            finish_reason=finish_reason,
        )

    @classmethod
    def bare(cls, *, capabilities: Capabilities | None = None) -> MockScenario:
        """A *bare* scenario: one generic canned response, no fixture, no tool calls.

        Neither fixture pattern matches :data:`BARE_RESPONSE`, so a run against a bare
        mock yields ``inconclusive`` for every spec — the honest default when no
        scenario is chosen (no fabricated pass, no fabricated fail).
        """

        return cls(
            response=BARE_RESPONSE,
            capabilities=capabilities if capabilities is not None else Capabilities(),
        )

    def _responses(self) -> list[str]:
        """The response sequence as a list (a single string is a length-1 sequence)."""

        if isinstance(self.response, str):
            return [self.response]
        return list(self.response)

    def response_for(self, attempt: int) -> str:
        """The response text for ``attempt`` (0-indexed), cycling deterministically.

        A single-string scenario returns that string for every attempt; a sequence
        cycles by ``attempt % len(sequence)`` so N-run repros never drift.
        """

        seq = self._responses()
        return seq[attempt % len(seq)]


class MockTarget:
    """Deterministic offline :class:`~ildottore.shared.protocols.TargetAdapter`.

    ``MockTarget(scenario, ...)`` replays ``scenario``'s canned response(s). Each
    :meth:`send` returns a fully-populated :class:`ModelResponse`; the attempt
    index (advanced per call, or supplied explicitly via the request metadata key
    ``mock_attempt``) selects the sequence element for N-run repro.

    Pure: no I/O, no clock, no RNG. Two ``MockTarget``\\ s built from the same
    scenario return byte-identical responses at the same attempt index.
    """

    id: str

    _METADATA_ATTEMPT_KEY = "mock_attempt"

    def __init__(self, scenario: MockScenario, *, id: str = "mock") -> None:
        self._scenario = scenario
        self.id = id
        # Deterministic internal cursor for sequence replay when the caller does
        # not pin an explicit attempt index. Not a clock/RNG — a plain counter.
        self._cursor = 0

    @property
    def scenario(self) -> MockScenario:
        """The canned scenario this target replays (read-only)."""

        return self._scenario

    def capabilities(self) -> Capabilities:
        """The declared capabilities of the emulated target (capability honesty)."""

        return self._scenario.capabilities

    def reset(self) -> None:
        """Reset the internal sequence cursor to 0 (deterministic re-run)."""

        self._cursor = 0

    def _attempt_index(self, request: ModelRequest) -> int:
        """Resolve the attempt index: explicit ``mock_attempt`` metadata, else cursor.

        Pinning the index makes :meth:`send` a pure function of ``(scenario, index)``
        — the property test relies on this to prove byte-identity. Without a pin the
        cursor advances so repeated sends walk a declared sequence in order.
        """

        meta = request.metadata or {}
        pinned = meta.get(self._METADATA_ATTEMPT_KEY)
        if isinstance(pinned, int) and not isinstance(pinned, bool):
            if pinned < 0:
                raise ValueError("mock_attempt must be non-negative")
            return pinned
        index = self._cursor
        self._cursor += 1
        return index

    def _build_response(self, attempt: int) -> ModelResponse:
        """Assemble the canned :class:`ModelResponse` for ``attempt`` (pure)."""

        scenario = self._scenario
        return ModelResponse(
            text=scenario.response_for(attempt),
            # Copy so a caller mutating the returned list cannot poison replays.
            tool_calls=[dict(call) for call in scenario.tool_calls],
            logprobs=(
                None if scenario.logprobs is None else [lp.model_copy() for lp in scenario.logprobs]
            ),
            finish_reason=scenario.finish_reason,
        )

    async def send(self, request: ModelRequest) -> ModelResponse:
        """Return the canned response for this request's attempt index.

        ``async`` only to satisfy the :class:`TargetAdapter` protocol; the body
        performs **no** awaits, no I/O, no clock read (contract §4 KEEP).
        """

        attempt = self._attempt_index(request)
        return self._build_response(attempt)


def bare_scenario(*, capabilities: Capabilities | None = None) -> MockScenario:
    """Module-level alias for :meth:`MockScenario.bare` (composition-root convenience)."""

    return MockScenario.bare(capabilities=capabilities)
