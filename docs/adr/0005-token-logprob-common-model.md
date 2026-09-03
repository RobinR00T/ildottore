# ADR-0005 - Common `TokenLogprob` model across adapters (OD-1)

- **Status:** Accepted
- **Date:** 2026-07-07

## Context
Membership inference and confidence side-channels (`docs/11`) need token logprobs, but providers
expose them differently (OpenAI `logprobs.content[].logprob` + top_logprobs; Anthropic differs;
many REST targets none). Unit u04 (adapters) and u06 (evaluators) must agree on one shape.

## Decision
`shared.models` defines a provider-neutral `TokenLogprob{token: str, logprob: float,
top: list[tuple[str, float]] | None}` and `ModelResponse.logprobs: list[TokenLogprob] | None`.
Adapters map their provider format into this; `Capabilities.logprobs` reports availability.
Absent ⇒ `None` ⇒ `logprob_membership` returns `inconclusive: capability_unavailable`.

## Consequences
- (+) Evaluators code against one shape; adapters own the mapping.
- (−) Some provider-specific richness (e.g. byte offsets) is dropped in MVP‑1; revisit if needed.
