# u04-target-adapters.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/01`
(§2-§3, §5-§6) + `docs/adr/0002` + `docs/adr/0005` + `docs/10` + `shared/` before implementing.
**HARD unit** — byte-exact provider control is the whole point (ADR-0002).

## §1 Scope & ownership
- **OWNS:** `src/ildottore/adapters/` — `base.py` (shared plumbing: allowlist enforcement,
  retry/timeout, logprob mapping helpers, capability probing), `openai.py`, `anthropic.py`,
  `rest.py` (generic REST, long-tail per ADR-0002).
- **MUST NOT touch:** `shared/`, `policy/`, `evaluators/`, `core/`, `fingerprint/`, `scoring/`,
  `store/`, any spec/suite YAML. `adapters/mock.py` is u03's — do not create it here.

## §2 Intended behavior
Turn a provider-neutral `ModelRequest` into a `ModelResponse` over the wire, byte-faithfully, and
report per-provider `Capabilities`. Each adapter: (a) enforces the endpoint **allowlist** before
any egress (default-deny, host + path-prefix) — out-of-scope ⇒ refuse, never send; (b) sends with
pinned sampling params (temperature, top_p, `seed` where supported), preserving system-prompt
placement and message roles verbatim; (c) captures token logprobs into the common `TokenLogprob`
shape when the provider exposes them (ADR-0005); (d) maps provider errors to env-error (retry/skip)
vs product-defect (raise) per `AGENTS.md §2`; (e) surfaces raw request/response ids + full sampling
config for reproducibility (`docs/01 §5`). No normalization layer hides the bytes (ADR-0002).

## §3 Dependencies & interface contracts
- Implements `shared.protocols.TargetAdapter` (`id: str`, `async send(ModelRequest)->ModelResponse`,
  `capabilities()->Capabilities`). Deps: **u00** (models/protocols), **u01** (allowlist/scope +
  redactor). Consumes `shared.models.{ModelRequest, ModelResponse, Capabilities, TokenLogprob,
  Target}`; these are the stable interface registry (`docs/01 §3`, `00-INDEX`) — do not alter them.
- Calls providers via **`httpx`** only (no vendor SDKs — ADR-0002). Reads endpoint allowlist and
  auth-identity resolution from u01's policy engine; secrets sourced from env/vault, never logged.
- `Capabilities` MUST report all eight flags: `tools, rag, memory, streaming, seed, logprobs,
  multi_identity, multimodal`. A target may expose ≥2 auth identities (`multi_identity`, `docs/01 §6`).

## §4 Known constraints — KEEP / DECIDE
- KEEP: allowlist check happens **in `base.py` before the httpx call** — unbypassable by subclasses.
- KEEP: `logprobs` absent ⇒ `ModelResponse.logprobs = None` (not `[]`) so `logprob_membership`
  returns `inconclusive: capability_unavailable` (ADR-0005). `seed` unsupported ⇒ record best-effort
  determinism, do not fake a seed.
- KEEP: NO live keys in CI — every provider path is contract-tested with recorded **respx** cassettes.
- KEEP: capabilities are **static per adapter+config** (declared), not inferred by probing at send
  time; live capability probing belongs to u09 fingerprint, not here.
- DECIDE (OD-1, ADR-0005 Accepted): OpenAI `logprobs.content[].logprob`+`top_logprobs` vs Anthropic
  shape → both map into `TokenLogprob{token, logprob, top}`. Byte-offset richness dropped in MVP-1.

## §5 Implementation plan (each step its own commit, green before next)
1. `base.py`: allowlist gate (host+path-prefix, default-deny), retry/timeout/backoff, env-vs-product
   error classification, `_map_logprobs` helper, redactor hookup, `Capabilities` scaffolding.
2. `openai.py`: chat/completions over httpx; `seed`+`logprobs`+`top_logprobs`; map to `TokenLogprob`;
   capabilities (tools/json/vision/streaming/seed/logprobs = true, subject to config).
3. `anthropic.py`: messages API; role/system-block placement verbatim; logprob mapping (per provider
   support); `stop_reason` vocab preserved; capabilities.
4. `rest.py`: generic REST via a declarative request/response JSONPath template (long-tail); usually
   `logprobs=None`, `seed=False`; capabilities driven by template config.

## §6 Data/wire shapes
- `TokenLogprob = {token: str, logprob: float, top: list[tuple[str,float]] | None}` (ADR-0005).
- `ModelResponse` carries: `text`, `raw` (provider raw, redacted), `logprobs: list[TokenLogprob]|None`,
  `finish_reason`/`stop_reason`, provider request/response ids, echoed sampling config.
- `Capabilities = {tools, rag, memory, streaming, seed, logprobs, multi_identity, multimodal: bool}`
  (+ `max_context_tokens: int|None`). All must validate vs `schemas/`.
- Cassettes live under `tests/fixtures/cassettes/{openai,anthropic,rest}/*.yaml` (respx recordings,
  keys scrubbed). Secrets in requests masked via u01 redactor before any log/evidence write.

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/adapters -q` green; coverage ≥ 90% for `src/ildottore/adapters/`. **Zero live network
  calls** in the suite (respx asserts all httpx traffic is mocked; `pytest --forked`/no-net gate).
- **Allowlist gate:** table-test proves an off-allowlist host AND off-prefix path each raise
  `EndpointNotAllowed` **before** any httpx request is issued (respx registers 0 calls on refusal).
- **Logprob mapping (golden):** OpenAI + Anthropic cassettes → assert exact `TokenLogprob` lists vs
  golden JSON in `tests/fixtures/golden/logprobs/`; a no-logprob cassette ⇒ `logprobs is None`.
- **Capabilities:** each adapter reports all eight bool flags; parametrized snapshot per provider.
- **Error classification:** 429/503/timeout cassettes ⇒ retry-then-skip (env); a malformed-schema
  200 ⇒ raise (product defect). No defect masked as flake.
- `ruff check`, `ruff format --check`, `mypy src/ildottore/adapters` clean; `lint-imports` green
  (adapters import only `shared` + u01 interfaces + httpx — never evaluators/core, `docs/01 §2`).

## §8 Out of scope / forbidden
- MUST NOT import or call vendor SDKs (`openai`, `anthropic` packages) — httpx only (ADR-0002).
- MUST NOT use LiteLLM as the core abstraction (optional wrapped adapter is MVP-2+, not here).
- MUST NOT print/commit secrets or store raw auth headers; redactor-masked evidence only.
- MUST NOT implement evaluation (u06), scoring (u07), fingerprint probing (u09), or the mock
  adapter (u03). MUST NOT bypass the allowlist for "convenience" test hosts.
- Not its call: signature-DB/probing (u09) · scope-signing scheme (OD-2, u01).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-1** (ADR-0005 Accepted): Anthropic logprob availability/shape — if the provider exposes no
  usable per-token logprobs in MVP-1, `anthropic.py` reports `logprobs=False` and returns `None`;
  confirm this is acceptable vs deferring membership-inference on Anthropic targets to MVP-2.
- REST auth-injection surface (header vs query vs body-templated token): propose header-only default
  in MVP-1 to shrink the secret-leak surface — needs sign-off.
