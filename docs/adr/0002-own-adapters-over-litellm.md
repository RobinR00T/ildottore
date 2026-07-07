# ADR-0002 — Own thin adapters over a normalization layer (LiteLLM)

- **Status:** Accepted
- **Date:** 2026-07-07

## Context
v0.1 suggested "LiteLLM or own adapters" for LLM access. LiteLLM is convenient but normalizes
requests/responses across providers, which for a *security* tool hides exactly the bytes we
need to control and observe (system-prompt placement, message roles, tool schemas, sampling
params, provider-specific fields, raw response).

## Decision
The core abstraction is our own `TargetAdapter` protocol. Each provider (OpenAI, Anthropic,
generic REST) gets a thin adapter that we fully control and contract-test with recorded
cassettes. LiteLLM may be wrapped as *one optional adapter* for breadth, but is never the core
abstraction.

## Consequences
- (+) Byte-exact control, precise evidence, per-provider capability reporting (e.g. `seed`).
- (−) We maintain a small amount of per-provider code. Mitigated by the generic REST adapter
  covering the long tail and by contract tests.
