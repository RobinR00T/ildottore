# u04-target-adapters.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/01`
(§2-§3, §5-§6) + `docs/adr/0002` + `docs/adr/0005` + `docs/10` + `shared/` before implementing.
**HARD unit**: byte-exact provider control is the whole point (ADR-0002).

## §1 Scope & ownership
- **OWNS:** `src/ildottore/adapters/`: `base.py` (shared plumbing: allowlist enforcement,
  retry/timeout, logprob mapping helpers, capability probing), `openai.py`, `anthropic.py`,
  `rest.py` (generic REST, long-tail per ADR-0002).
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
- **A-39 A reply's logprob figure is read only when a model could produce it (added 2026-10-07).**
  A logprob is `log p` of a probability in (0, 1]: a finite number at or below zero. A JSON number
  has no bound, and `map_logprobs` passed every figure to `float()`: a 400-digit integer raised
  `OverflowError` and a list or an object `TypeError`, neither of which the CLI catches, so
  `dottore fingerprint` and `run -sV` exited 1 (the code CI reads as findings below `--fail-on`)
  with a traceback and no report, and plain `run` and `fleet --run` aborted the campaign with exit
  3; a string that is not a number raised `ValueError` (exit 3), and a `top_logprobs` that was a
  number or a bool, or a null alternative in the map shape, `TypeError`. The OpenAI adapter asks
  for logprobs on every request, the `--judge` model's included, so every spec was exposed, though
  the `-sV` probes read no logprob at all. A positive token figure (0.5, 1e300, or `true`, read as
  1.0) scored `DL-MEMORIZE-DIVERGENCE-001` as "likely memorized" (exit 1), and a NaN or an
  infinity went into the report and the evidence as a bare `NaN` or `Infinity` token, which is not
  JSON (code audit of `fix/usage-figure-overflow`, F1, F2, F4, F5). A figure is now read through
  `shared.logprobs.readable_logprob`: a JSON number that converts to a finite float at or below
  zero, `0` included; a bool is not one, nor is a string that spells one (`float()` read those
  before: `"-0.5"` was believed, `"1"` scored "likely memorized" and `"nan"` wrote a bare `NaN`).
  A block in which any entry's own figure is not readable, whether or not the entry names its
  token, is `None`, read as no block: the attempt and every evaluator of its text go on, and
  `logprob_membership` is `inconclusive: capability_unavailable` (the whole block, not only the
  entry: OD-24; an entry with no token is still skipped, but after its figure is read, or a
  positive one beside four confident tokens let the rest be scored: delta audit). An alternative
  whose figure is not readable costs its token the alternatives (`top` is `None`) and nothing
  else, since no alternative is ever scored (the first version voided the whole block, and
  confident tokens with one bad alternative lost their "likely memorized": pre-commit audit). A
  null figure is still skipped as absent, a token's and an alternative's in both `top_logprobs`
  shapes, and a `top_logprobs` of neither shape is no alternatives. `logprob_membership` checks
  the figures it scores with the same predicate, so an adapter that builds its own `TokenLogprob`
  (a plugin, the mock) cannot get an impossible one scored either. Not claimed: the evidence does
  not say a block was unreadable rather than absent (`logprobs: null` both ways, OD-24); such an
  adapter's own figures still reach the evidence as it built them (a NaN there is still written as
  a bare token); a run halted before this change and resumed after it keeps what its stored
  attempts carry (a positive figure's "likely memorized", a NaN that makes the report not JSON),
  since a resume adopts stored verdicts; a figure a model can produce is believed, so a target can
  still send confident logprobs and be scored "likely memorized", as before, and absurd but finite
  ones (two of `-1.7e308`) make the mean NLL infinite, read as "no memorization signal"; a token
  is read with `str()`, unchecked (a lone surrogate there, or in the reply's text, still aborts
  `run` with exit 3 on `UnicodeEncodeError`, open; and a token, or an alternative's token, nested
  about 100,000 levels deep still overflows `str()` with `RecursionError`, so `fingerprint` and
  `run -sV` exit 1 and `run` exits 3, as on main, which the depth cap of `fix/target-deep-json`
  turns into `ResponseTooDeep`: pre-merge audit). `tests/cli/test_logprob_figures.py` (through the
  CLI: `fingerprint`, `run`, `run -sV` and the membership spec, both directions, the text still
  judged), `tests/adapters/test_base.py`, `tests/evaluators/test_data_leak.py`,
  `tests/shared/test_logprobs.py`.
- **Capabilities:** each adapter reports every bool flag (nine as built); parametrized snapshot per provider.
- **Error classification:** 429/503/timeout cassettes ⇒ retry-then-skip (env); a malformed-schema
  200 ⇒ raise (product defect). No defect masked as flake.
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
- **OD-24** (open, built reversibly 2026-10-07, A-39): what a logprob block with one figure no
  model produces reads as. Built: when the figure is a token's own, the whole block is `None`, as
  if the reply carried none, so nothing is scored from it; when it is an alternative's, only that
  token's alternatives are dropped (no alternative is scored). The other choice for a token
  figure, dropping only the bad entries as a null one is dropped, scores the rest as if it were
  the reply: four confident tokens with one positive figure among them then read "likely
  memorized". Also decided here, and the owner's to confirm: a positive figure counts as
  impossible (`log p` is never above 0, and a gateway that writes probabilities into the field
  is caught). Not measured: whether a provider sends rounding-level positive figures (`2e-07`);
  if one does in a token's own figure, its membership spec is inconclusive, with nothing in the
  evidence saying why (in an alternative it costs only that token's alternatives). Also the
  owner's: an entry that is not an object (a list such as `["a", 0.9]`, a string, a number) or
  that carries no figure is skipped and the rest is scored, as on main, though the whole-block
  reasoning applies to it too (pre-merge audit). Open:
  whether the evidence should say a block was unreadable rather than absent, which needs an
  additive field on `ModelResponse` (u00).
- REST auth-injection surface (header vs query vs body-templated token): propose header-only default
  in MVP-1 to shrink the secret-leak surface: needs sign-off.
