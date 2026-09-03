"""nmap-style flag primitives: the ``-T`` timing template + suite-alias map (contract §5.1).

``core`` never sees these - they are CLI-local value objects the commands resolve
*before* handing concrete numbers to the engine. Two golden-tested tables live here
(contract §7):

* :data:`TIMING_TEMPLATES` - ``-T0..-T5`` → ``{rate_rps, concurrency, timeout_s}``.
  Explicit ``--rate/--concurrency/--timeout`` override the template (see
  :func:`resolve_timing`).
* :data:`SUITE_ALIASES` - the friendly ``owasp:llm`` ⇄ registered suite id
  (``owasp-llm-top10``) mapping from ``docs/09 §2``.

Everything here is a pure function of its inputs (no I/O), so the CLI-map and
timing golden tests are deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

__all__ = [
    "DEFAULT_TEMPLATE",
    "SUITE_ALIASES",
    "TIMING_TEMPLATES",
    "Timing",
    "resolve_suite_id",
    "resolve_timing",
    "timing_for_template",
]


@dataclass(frozen=True)
class Timing:
    """Concrete rate/concurrency/timeout the engine consumes."""

    rate_rps: float
    concurrency: int
    timeout_s: float


#: ``-T0..-T5`` → concrete timing (documented in the contract §4 KEEP / ``docs/09``).
#: T3 is the default "polite but productive" profile; T0 is a slow single-flight
#: minimum battery, T5 is maximum aggression.
TIMING_TEMPLATES: dict[int, Timing] = {
    0: Timing(rate_rps=0.5, concurrency=1, timeout_s=120.0),
    1: Timing(rate_rps=1.0, concurrency=1, timeout_s=90.0),
    2: Timing(rate_rps=2.0, concurrency=2, timeout_s=60.0),
    3: Timing(rate_rps=5.0, concurrency=4, timeout_s=45.0),
    4: Timing(rate_rps=10.0, concurrency=8, timeout_s=30.0),
    5: Timing(rate_rps=20.0, concurrency=16, timeout_s=20.0),
}

#: Default timing template when ``-T`` is not given (``docs/09 §2`` - "default T3").
DEFAULT_TEMPLATE = 3

#: Friendly suite aliases → the id the registry stores (``docs/09 §2``).
SUITE_ALIASES: dict[str, str] = {
    "owasp:llm": "owasp-llm-top10",
    "mitre:atlas": "mitre-atlas",
    "nist:ai": "nist-ai-rmf",
    "eu:ai-act": "eu-ai-act",
    "dora": "dora",
    "iso:42001": "iso-42001",
    "agentic": "agentic-extortion",
    "baseline": "owasp-llm-top10",
    "quick": "quick",
}


def timing_for_template(template: int) -> Timing:
    """Return the timing profile for ``-T<template>`` (raises on out-of-range)."""

    try:
        return TIMING_TEMPLATES[template]
    except KeyError:
        raise ValueError(
            f"invalid -T template {template!r}; expected 0..{max(TIMING_TEMPLATES)}"
        ) from None


def resolve_timing(
    template: int = DEFAULT_TEMPLATE,
    *,
    rate: float | None = None,
    concurrency: int | None = None,
    timeout_s: float | None = None,
) -> Timing:
    """Resolve the effective timing: template defaults, explicit flags override.

    Any of ``rate``/``concurrency``/``timeout_s`` given on the command line wins over
    the ``-T`` template value for that one field (contract §4 KEEP, §7 golden).
    """

    base = timing_for_template(template)
    return replace(
        base,
        rate_rps=rate if rate is not None else base.rate_rps,
        concurrency=concurrency if concurrency is not None else base.concurrency,
        timeout_s=timeout_s if timeout_s is not None else base.timeout_s,
    )


def resolve_suite_id(name: str) -> str:
    """Map a friendly suite alias to the registered suite id (identity if unknown).

    ``owasp:llm`` → ``owasp-llm-top10``; an already-canonical id passes through so a
    user can name the registered id directly.
    """

    return SUITE_ALIASES.get(name.strip(), name.strip())
