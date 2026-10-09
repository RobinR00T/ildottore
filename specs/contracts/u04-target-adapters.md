# u04-target-adapters.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/01`
(§2-§3, §5-§6) + `docs/adr/0002` + `docs/adr/0005` + `docs/10` + `shared/` before implementing.
**HARD unit**: byte-exact provider control is the whole point (ADR-0002).

## §1 Scope & ownership
- **OWNS:** `src/ildottore/adapters/`: `base.py` (shared plumbing: allowlist enforcement,
  retry/timeout, logprob mapping helpers, capability probing), `openai.py`, `anthropic.py`,
  `rest.py` (generic REST, long-tail per ADR-0002), `mcp.py` (read-only MCP discovery) and
  `websocket.py` (a template-driven JSON-over-WebSocket chat client, 2026-10-07: the wire
  shape comes from the target file's `websocket:` block, the gate runs before the socket is
  dialled, redirects at the upgrade are never followed, every frame is recorded with the
  credential as `{{token}}`, one connection per conversation, a turn bounded in time, bytes and
  frames; `tests/adapters/test_websocket.py` against a loopback server).
- **MUST NOT touch:** `shared/`, `policy/`, `evaluators/`, `core/`, `fingerprint/`, `scoring/`,
  `store/`, any spec/suite YAML. `adapters/mock.py` is u03's: do not create it here.

## §2 Intended behavior
Turn a provider-neutral `ModelRequest` into a `ModelResponse` over the wire, byte-faithfully, and
report per-provider `Capabilities`. Each adapter: (a) enforces the endpoint **allowlist** before
any egress (default-deny, host + path-prefix): out-of-scope ⇒ refuse, never send; (b) sends with
pinned sampling params (temperature, top_p, `seed` where supported), preserving system-prompt
placement and message roles verbatim; (c) captures token logprobs into the common `TokenLogprob`
shape when the provider exposes them (ADR-0005); (d) maps provider errors to env-error (retry/skip)
vs product-defect (raise) per `AGENTS.md §2`; (e) surfaces raw request/response ids + full sampling
config for reproducibility (`docs/01 §5`). No normalization layer hides the bytes (ADR-0002).

## §3 Dependencies & interface contracts
- Implements `shared.protocols.TargetAdapter` (`id: str`, `async send(ModelRequest)->ModelResponse`,
  `capabilities()->Capabilities`). Deps: **u00** (models/protocols), **u01** (allowlist/scope +
  redactor). Consumes `shared.models.{ModelRequest, ModelResponse, Capabilities, TokenLogprob,
  Target}`; these are the stable interface registry (`docs/01 §3`, `00-INDEX`): do not alter them.
- Calls providers via **`httpx`** only (no vendor SDKs: ADR-0002). Reads endpoint allowlist and
  auth-identity resolution from u01's policy engine; secrets sourced from env/vault, never logged.
- `Capabilities` MUST report all eight flags: `tools, rag, memory, streaming, seed, logprobs,
  multi_identity, multimodal`. A target may expose ≥2 auth identities (`multi_identity`, `docs/01 §6`).

## §4 Known constraints: KEEP / DECIDE
- KEEP: allowlist check happens **in `base.py` before the httpx call**: unbypassable by subclasses.
- KEEP: `logprobs` absent ⇒ `ModelResponse.logprobs = None` (not `[]`) so `logprob_membership`
  returns `inconclusive: capability_unavailable` (ADR-0005). `seed` unsupported ⇒ record best-effort
  determinism, do not fake a seed.
- KEEP: NO live keys in CI: every provider path is contract-tested with recorded **respx** cassettes.
- KEEP (as built, SEC-07 and 2026-10-04): every body read over the wire goes through
  `base.read_capped`: 4 MiB (`MAX_RESPONSE_BYTES`), checked per chunk. The body is read raw and
  `gzip`/`deflate` are decoded there with a bounded `zlib` call, so a compression bomb never
  inflates past the cap (httpx inflated each network chunk whole first: a 200 KB gzip reply
  allocated about 150 MB); the compressed bytes are capped too. Every request sends
  `Accept-Encoding: gzip, deflate` (`base.ACCEPT_ENCODING`), so httpx never offers `br` or
  `zstd` it cannot hand to the cap. Any other `Content-Encoding`, or a corrupt or truncated
  body, is `ResponseUndecodable` on a 2xx; an error status keeps its status classification
  with an empty body. Both errors are environment failures with `retryable = False`. The MCP
  adapter's `notifications/initialized` reply is streamed and never read.
- KEEP (as built, 2026-10-07): every reply is parsed through `shared.nesting.bounded_loads`
  (the base adapter's body, the MCP adapter's JSON body, SSE `data:` event and stdio line),
  which refuses a text whose brackets nest deeper than 100 levels (`MAX_DEPTH`, objects and
  arrays outside strings; a provider's reply nests about 10). The depth is read from the text
  before it is parsed, so the parser never recurses past it and the verdict does not depend on
  the Python version (20,000 unclosed `[` were "not JSON" on 3.14 and a stack overflow on 3.12):
  brackets that balance and nest past the limit are too deep whether or not the rest is valid
  JSON, brackets that do not balance are not JSON (refused unparsed). The measure is linear: its
  string pattern cannot fail once it has seen a quote (one that could took 38 s for 160 KB). An
  MCP stdio reply line may be 4 MiB (`MAX_RESPONSE_BYTES`, asyncio's default was 64 KiB), and so
  may all one request reads, its stray lines and its reply together (each line's ending newline
  not counted); past either it is `ResponseTooLarge`. A tool call's
  arguments carried as a JSON string are measured too, unless they do not balance (they read as
  no arguments, as before)
  (`shared.toolcalls.check_argument_nesting`), since the reply's parse never opens them. The
  refusal is `ResponseTooDeep`, an environment failure with `retryable = False`: the attempt is
  inconclusive and the campaign goes on. Found 2026-10-07: `json.loads` raises
  `RecursionError`, not a `ValueError`, so one 400 KB reply of `[` escaped the malformed-body
  handler and the runner aborted the campaign; and a reply the parser accepts aborted it too,
  300 levels (about 600 bytes) overflowing pydantic's serializer when the evidence was written.
  A body that is not JSON keeps the product-defect rule of §7 (open decision OD-21). A refused
  reply during the `-sV`/`-A` probe pass (u09) still stops the run before the attack.
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
- `Capabilities = {tools, rag, memory, streaming, seed, logprobs, multi_identity, multimodal,
  audio: bool}` (as built, `shared/models.py`: nine flags, `audio` added with the audio carrier,
  and no `max_context_tokens` field). All must validate vs `schemas/`.
- Cassettes live under `tests/adapters/cassettes/{openai,anthropic,rest}/`. (As built they are
  hand-written `{status_code, json}` response bodies served by `respx`, not recordings of real
  traffic, so there is no key to scrub; the MCP adapter's tests stub JSON-RPC inline.) Secrets
  in requests masked via u01 redactor before any log/evidence write.

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/adapters -q` green; coverage ≥ 90% for `src/ildottore/adapters/`. **Zero live network
  calls** in the suite (respx asserts all httpx traffic is mocked; `pytest --forked`/no-net gate).
- **Allowlist gate:** table-test proves an off-allowlist host AND off-prefix path each raise
  `EndpointNotAllowed` **before** any httpx request is issued (respx registers 0 calls on refusal).
- **Logprob mapping (golden):** OpenAI + Anthropic cassettes → assert exact `TokenLogprob` lists vs
  golden JSON in `tests/adapters/golden/logprobs/`; a no-logprob cassette ⇒ `logprobs is None`.
- **Capabilities:** each adapter reports every bool flag (nine as built); parametrized snapshot per provider.
- **Error classification:** 429/503/timeout cassettes ⇒ retry-then-skip (env); a malformed-schema
  200 ⇒ raise (product defect). No defect masked as flake. A 200 whose brackets balance and nest
  deeper than `MAX_DEPTH` (past the parser's stack included), in the body or in a tool call's
  string arguments, ⇒ `ResponseTooDeep` (env, sent once), for every adapter and the MCP transports
  (a body whose brackets do not balance follows the product-defect rule, OD-21, except over MCP
  stdio, where the line is skipped as stray output; tool-call arguments that do not balance read
  as no arguments)
  (`tests/adapters/test_deep_replies.py`); through the CLI, one such reply fails its attempt
  and every other spec runs (`tests/cli/test_hostile_nesting.py`).
- `ruff check`, `ruff format --check`, `mypy src/ildottore/adapters` clean; `lint-imports` green
  (adapters import only `shared` + u01 interfaces + httpx: never evaluators/core, `docs/01 §2`).

## §8 Out of scope / forbidden
- MUST NOT import or call vendor SDKs (`openai`, `anthropic` packages): httpx only (ADR-0002).
- MUST NOT use LiteLLM as the core abstraction (optional wrapped adapter is MVP-2+, not here).
- MUST NOT print/commit secrets or store raw auth headers; redactor-masked evidence only.
- MUST NOT implement evaluation (u06), scoring (u07), fingerprint probing (u09), or the mock
  adapter (u03). MUST NOT bypass the allowlist for "convenience" test hosts.
- Not its call: signature-DB/probing (u09) · scope-signing scheme (OD-2, u01).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-1** (ADR-0005 Accepted): Anthropic logprob availability/shape: if the provider exposes no
  usable per-token logprobs in MVP-1, `anthropic.py` reports `logprobs=False` and returns `None`;
  confirm this is acceptable vs deferring membership-inference on Anthropic targets to MVP-2.
- REST auth-injection surface (header vs query vs body-templated token): propose header-only default
  in MVP-1 to shrink the secret-leak surface: needs sign-off.
- **OD-30** (WebSocket, 2026-10-07): the frame transcript lives in `ModelResponse.raw_ids["websocket"]`
  rather than in a dedicated field. A `transcript` field on the frozen u00 `ModelResponse` would be
  the honest shape, but it changes every stored attempt's dump and the report snapshots; the
  nested value is skipped by the fingerprint's envelope layer. Decide whether to add the field.
- **OD-31** (WebSocket): `session.one_query_in_flight: false` is refused. Several concurrent queries
  on one socket need a correlation id in the templates and in the reply frames; whether that is
  wanted, and how a target declares it, is the owner's call.
- **OD-32** (WebSocket): a reconnect is attempted only before a query is on the wire. A connection
  closed mid-turn is an environment error the runner retries and debits; the adapter never resends a
  query on its own, so no send escapes the ledger. A later turn of a multi-turn attempt whose
  connection is gone is inconclusive, never a silent new session. Whether a stateless server
  (`{{messages}}` in the template) should be allowed to reconnect mid-conversation is open.
- **OD-33** (WebSocket): `dottore fleet` infers `rest` from a `wss://` endpoint and writes no
  `websocket:` block, so a WebSocket target is declared by hand today. Whether a fleet entry should
  carry the block is open.

- **OD-21** (open, 2026-10-07): a 200 whose body is not JSON (brackets that do not balance
  included; or not the provider's shape; or JSON with an integer of more than 4,300 digits,
  which Python refuses to read) is
  `AdapterProductError`, and the runner aborts the campaign on it (F5), so one hostile reply of
  `<html>` still stops a scan, where a reply nested too deeply now fails only its attempt.
  Measured with `dottore run` against a local stub: exit 3, "aborted on AdapterProductError", 1
  request sent. Decide whether a malformed success body fails its attempt (inconclusive, as
  `ResponseTooDeep`) or keeps stopping the campaign (a misconfigured endpoint is then caught at
  the first request instead of after the whole battery). A non-retryable 4xx is not in question.
