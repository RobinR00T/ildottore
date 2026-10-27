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
  frames; `tests/adapters/test_websocket.py` against a loopback server), and `comprehending.py`
  (the offline target that decodes what it is sent, test support for `-sV`; recorded
  2026-10-12), and `isolation.py` (the container a stdio MCP server may run in, A-104).
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
config for reproducibility (`docs/01 §5`). No normalization layer hides the bytes (ADR-0002),
with one exception: a lone surrogate, half a character no UTF-8 writer can hold, reads as U+FFFD
where the reply is parsed (§7 A-47); and, as before A-47, any invalid UTF-8 in an MCP SSE stream
reads as U+FFFD, since httpx decodes the stream as text.

## §3 Dependencies & interface contracts
- Implements `shared.protocols.TargetAdapter` (`id: str`, `async send(ModelRequest)->ModelResponse`,
  `capabilities()->Capabilities`). Deps: **u00** (models/protocols), **u01** (allowlist/scope +
  redactor). Consumes `shared.models.{ModelRequest, ModelResponse, Capabilities, TokenLogprob,
  Target}`; these are the stable interface registry (`docs/01 §3`, `00-INDEX`): do not alter them.
- Calls providers via **`httpx`** only (no vendor SDKs: ADR-0002). Reads endpoint allowlist and
  auth-identity resolution from u01's policy engine; secrets sourced from env/vault, never logged.
- `Capabilities` MUST report all eight flags: `tools, rag, memory, streaming, seed, logprobs,
  multi_identity, multimodal`. A target may expose ≥2
  auth identities (`multi_identity`, `docs/01 §6`).

## §4 Known constraints: KEEP / DECIDE
- KEEP: allowlist check happens **in `base.py` before the httpx call**: unbypassable by subclasses.
- KEEP: `logprobs` absent ⇒ `ModelResponse.logprobs = None` (not `[]`) so `logprob_membership`
  returns `inconclusive: capability_unavailable` (ADR-0005). `seed` unsupported ⇒ record best-effort
  determinism, do not fake a seed.
- KEEP: NO live keys in CI: every provider path is contract-tested
  with recorded **respx** cassettes.
- KEEP (as built, SEC-07 and 2026-10-04): every body read over the wire goes through
  `base.read_capped`: 4 MiB (`MAX_RESPONSE_BYTES`), checked per chunk. The body is read raw and
  `gzip`/`deflate` are decoded there with a bounded `zlib` call, so a compression bomb never
  inflates past the cap (httpx inflated each network chunk whole first: a 200 KB gzip reply
  allocated about 150 MB); the compressed bytes are capped too. Every request sends
  `Accept-Encoding: gzip, deflate` (`base.ACCEPT_ENCODING`), so httpx never offers `br` or
  `zstd` it cannot hand to the cap. Any other `Content-Encoding`, or a corrupt or truncated
  body, is `ResponseUndecodable` on a 2xx; an error status keeps its status classification
  with an empty body, and so does an error status whose body is over the cap (before PR #68, a
  `401` with a 5 MB body was `ResponseTooLarge`, an inconclusive attempt, where a short one
  stops the run; delta audit of OD-23). Both errors are environment failures with
  `retryable = False`. The MCP
  adapter's `notifications/initialized` reply is streamed and never read.
- KEEP (as built, 2026-10-07): every reply is parsed through `shared.nesting.bounded_loads`
  (the base adapter's body, the MCP adapter's JSON body, SSE `data:` event and stdio line, and each
  WebSocket frame since the pre-merge audit of PR #87, 2026-10-09, where a plain `json.loads` parsed
  it), which refuses a text whose brackets nest deeper than 100 levels (`MAX_DEPTH`, objects and
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
  (`shared.toolcalls.check_argument_nesting`), since the reply's parse never opens them; so are a
  WebSocket frame's tool calls when its block declares `tool_calls_path`. The refusal is
  `ResponseTooDeep`, an environment failure with `retryable = False`: the attempt is inconclusive
  and the campaign goes on. A WebSocket frame has a tighter bound of its own, 64 levels on the
  parsed frame (`MAX_FRAME_DEPTH`: the frame is filed whole in `raw_ids`), refused as
  `WebSocketFrameTooDeep`, a `ResponseTooDeep`; a text frame that is not UTF-8, which the library
  refuses by closing the connection with 1007, is `WebSocketUndecodable`, a `ResponseUndecodable`,
  not retried either (it was retried three times). A close the server starts with 1007 or 1009 says
  the query frame was invalid or too large: it is `WebSocketClosed` with `retryable = False`,
  quoting the server's reason scrubbed and redacted (second pre-merge audit: the library echoes the
  close, which read as this side's overflow, the reason dropped). Found 2026-10-07: `json.loads`
  raises `RecursionError`, not a `ValueError`, so one 400 KB reply of `[` escaped the malformed-body
  handler and the runner aborted the campaign; and a reply the parser accepts aborted it too,
  300 levels (about 600 bytes) overflowing pydantic's serializer when the evidence was written.
  A success body the adapter cannot read (not JSON, brackets that do not balance and an integer
  of more than 4,300 digits included; not an object; not the provider's or the template's shape)
  is `ResponseMalformed` since OD-21 (decided 2026-10-11 under the owner's delegation, revisable):
  an environment failure with `retryable = False` and the marker `malformed_reply = True`, so the
  attempt is inconclusive and the campaign goes on, until its first five replies all are such
  (u08 A-74). A refused
  reply during the `-sV`/`-A` probe pass fails only that probe and the run goes on (u09 §7
  A-35, OD-23), and so does each WebSocket refusal above, a 1007 or 1009 close the server starts
  included, since each is an environment failure with `retryable = False`
  (`tests/cli/test_websocket_target.py`).
- KEEP: capabilities are **static per adapter+config** (declared), not inferred by probing at send
  time; live capability probing belongs to u09 fingerprint, not here.
- DECIDE (OD-1, ADR-0005 Accepted): OpenAI `logprobs.content[].logprob`+`top_logprobs` vs Anthropic
  shape → both map into `TokenLogprob{token, logprob, top}`. Byte-offset richness dropped in MVP-1.

## §5 Implementation plan (each step its own commit, green before next)
1. `base.py`: allowlist gate (host+path-prefix, default-deny), retry/timeout/backoff, env-vs-product
   error classification, `_map_logprobs` helper, redactor hookup, `Capabilities` scaffolding.
2. `openai.py`: chat/completions over httpx; `seed`+`logprobs`+`top_logprobs`; map to
   `TokenLogprob`; capabilities (tools/json/vision/streaming/seed/logprobs =
   true, subject to config).
3. `anthropic.py`: messages API; role/system-block placement verbatim; logprob mapping (per provider
   support); `stop_reason` vocab preserved; capabilities. (Since 2026-10-09, u12 A-66: its
   `sent_sampling` is what of a request's sampling goes out, no `seed` and no `top_p` beside a
   `temperature`, since Anthropic's API reference says Claude 4 models refuse the pair with HTTP
   400 (the reference bundled with the claude-api skill, cached 2026-09-25, not tested live);
   `_build_request` sends it, and the composition root records attempts and probes through it.
   Since the same day, u12 A-68: `sampling_enabled` false (a target that takes no sampling, as
   `MODELS_WITHOUT_SAMPLING` lists Claude Opus 4.7 and later, Sonnet 5, and the Fable and Mythos 5
   families) drops the `temperature` and the `top_p` too; the OpenAI adapter has the same switch
   and its own `sent_sampling`; and a 400 whose JSON error names, as a parameter (`error.param`, a
   quoted token, the first word of the message), a sampling field the request sent is
   `SamplingRefused`, a product error that names the capability to set; the judge re-raises it.)
4. `rest.py`: generic REST via a declarative request/response JSONPath template (long-tail); usually
   `logprobs=None`, `seed=False`; capabilities driven by template config.

## §6 Data/wire shapes
- `TokenLogprob = {token: str, logprob: float, top: list[tuple[str,float]] | None}` (ADR-0005).
- `ModelResponse` carries: `text`, `raw` (provider raw, redacted),
  `logprobs: list[TokenLogprob]|None`, `finish_reason`/`stop_reason`, provider request/response
  ids, echoed sampling config.
- `Capabilities = {tools, rag, memory, streaming, seed, logprobs, multi_identity, multimodal,
  audio: bool}` (as built, `shared/models.py`: nine flags, `audio` added with the audio carrier,
  and no `max_context_tokens` field), and since 2026-10-09 `sampling: bool | None` (u12 A-68:
  `None` is the default rule, not false). All must validate vs `schemas/`.
- Cassettes live under `tests/adapters/cassettes/{openai,anthropic,rest}/`. (As built they are
  hand-written `{status_code, json}` response bodies served by `respx`, not recordings of real
  traffic, so there is no key to scrub; the MCP adapter's tests stub JSON-RPC inline.) Secrets
  in requests masked via u01 redactor before any log/evidence write.

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/adapters -q` green; coverage ≥ 90% for `src/ildottore/adapters/`. **Zero live
  network calls** in the suite (respx asserts all httpx traffic
  is mocked; `pytest --forked`/no-net gate).
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
  is read with `str()`, unchecked (a lone surrogate there, or in the reply's text, reads as U+FFFD
  where the reply is parsed and the attempt is judged, A-47; a token, or an alternative's token,
  nested past 100 levels never reaches `str()`, since its reply is refused where it is parsed as
  `ResponseTooDeep` (§4): that attempt fails and `run` goes on, and in `fingerprint` and `run -sV`
  that probe fails and the pass goes on, as on any reply nested too deeply (u09 A-35; before PR #68
  they stopped with exit 3 and a one-line error); before PR #65 one nested
  about 100,000 levels overflowed `str()` with `RecursionError`, and before PR #79 a lone surrogate
  aborted `run` with exit 3: pre-merge audit). `tests/cli/test_logprob_figures.py` (through the
  CLI: `fingerprint`, `run`, `run -sV` and the membership spec, both directions, the text still
  judged), `tests/adapters/test_base.py`, `tests/evaluators/test_data_leak.py`,
  `tests/shared/test_logprobs.py`.
- **Capabilities:** each adapter reports every bool flag (nine as built);
  parametrized snapshot per provider.
- **Error classification:** 429/503/timeout cassettes ⇒ retry-then-skip (env); a malformed-schema
  200 ⇒ `ResponseMalformed` (env, sent once, since OD-21: see below); a non-retryable 4xx ⇒ raise
  (product defect). No defect masked as flake. A 200 whose brackets balance and nest
  deeper than `MAX_DEPTH` (past the parser's stack included), in the body or in a tool call's
  string arguments, ⇒ `ResponseTooDeep` (env, sent once), for every adapter, the MCP transports
  and a WebSocket frame (`WebSocketFrameTooDeep`, a `ResponseTooDeep`, from 64 levels on the
  parsed frame; `tests/adapters/test_websocket_premerge.py`)
  (a body whose brackets do not balance is a reply that cannot be read, `ResponseMalformed`,
  OD-21, except over MCP stdio, where the line is skipped as stray output; tool-call arguments
  that do not balance read as no arguments)
  (`tests/adapters/test_deep_replies.py`); through the CLI, one such reply fails its attempt
  and every other spec runs (`tests/cli/test_hostile_nesting.py`).
- `ruff check`, `ruff format --check`, `mypy src/ildottore/adapters` clean; `lint-imports` green
  (adapters import only `shared` + u01 interfaces + httpx: never evaluators/core, `docs/01 §2`).
- **A-47 A reply that holds half a character is kept and judged, and nothing that is written or sent
  holds a lone surrogate (added 2026-10-07).** JSON lets a string escape any UTF-16 code unit, so a
  reply can carry a surrogate (U+D800 to U+DFFF) with no partner, escaped or as its raw UTF-8 bytes
  (`ED A0 80`, which `json.loads` decodes with `surrogatepass`), and Python keeps it as a code point
  that no UTF-8 writer accepts. One such reply, in the text, the `id`, the `model` echo, a logprob
  token or alternative, a tool call's name, made `dottore run` exit 3 ("aborted on
  UnicodeEncodeError ... 2 of 2 specs never ran or did not finish", no evidence written: the
  evidence store hashes the encoded payload) and `run -sV` exit 3 with no report (the probe
  evidence); a multi-turn spec sends the reply on in its next request and the `--judge` request
  quotes it, and httpx raised the same error encoding either (the judge received nothing); sqlite
  refuses it too, and pydantic's JSON serializer with `PydanticSerializationError` (first noted on
  main by PR #57 (split credentials); reproduced end to end by the pre-commit audit of
  `fix/hostile-logprob`, 2026-10-07; `dottore fingerprint`, which writes nothing, exited 0). Every
  reply is now made well formed where it is parsed (`shared.wellformed.well_formed_json`: the base
  adapter's body, so OpenAI, Anthropic and the REST template, and the MCP adapter's JSON body, SSE
  `data:` event and stdio line, the last now decoded with `surrogatepass`, the handler `json.loads`
  decodes bytes with: strict decoding skipped a line with the raw bytes as stray output and the call
  timed out; and each WebSocket frame since the pre-merge audit of PR #87, where one frame with an
  escaped half made `run` exit 3 ("aborted on UnicodeEncodeError"), while a text frame holding the
  raw bytes is not UTF-8 and the library refuses it, so that attempt is inconclusive and is not
  retried), and so are a tool call's arguments carried as JSON text, which the reply's parse never
  opens (`shared.toolcalls.call_arguments`, read by the evaluators and the in-band tool loop): a
  lone surrogate reads as U+FFFD, a high half followed by a low half is the character the pair
  encodes, every other character is kept, and keys are treated like values; two keys that read the
  same once replaced keep both values (the replaced one takes the next `, #n`; a key the target
  wrote well formed keeps its name). A first walk only looks, and a reply with no surrogate is
  passed on as it is; one that holds a surrogate is fixed in place, since each caller holds the only
  reference to a fresh parse. The helper lives in `shared/` (u00's package), beside
  `shared/toolcalls.py`, which already serves the adapters and the evaluators; §1 keeps this unit
  out of `shared/`, and the owner signed that off on 2026-10-07. The attempt is evaluated on that
  text, so a leak with half a character before, after or between its words still fails
  (`tests/cli/test_lone_surrogate.py`: 30 of its 37 cases fail on `main` at `a40e596`, all on the
  surrogate, and the other 7, six `fingerprint` cases and a well formed pair, pin what already held;
  `tests/adapters/test_lone_surrogate_replies.py`, 9 of 9 fail there, the raw stdio line on the
  timeout; `tests/shared/test_wellformed.py`). Not claimed: which code unit stood there (the
  evidence shows U+FFFD, as for a U+FFFD the target sent: OD-28), except in a tool call's arguments
  carried as JSON text, which the evidence keeps as the target sent them (the escape, six ASCII
  characters) and only their parse reads as U+FFFD; the same bytes do not read the same on every
  transport (raw `ED A0 80` is one U+FFFD where a body is parsed as bytes and three over an MCP SSE
  stream, which httpx decodes as text first; a CESU-8 pair joins into its character in the first and
  is six U+FFFD in the second); half a character inside a word splits it as a zero-width space does
  today, with the same verdicts (a test pins the parity): `regex_absence` misses a leak split that
  way (`PI-DIRECT-001` is inconclusive and `run` exits 0, where the leak written plainly fails it
  and exits 2), `secret_leakage` misses a split canary and passes, and the spec falls to its other
  evaluators (`SP-LEAK-001` is inconclusive without `--judge` and passes when the judge says
  secure), while a registered credential split that way is masked whole since the fix for split
  credentials (PR #57, merged after this clause) reads U+FFFD as a splitter (u01 A-32), as the owner
  approved on 2026-10-07 for whichever of the two landed second (OD-28); invalid UTF-8 that is not
  an encoded surrogate (one `FF` byte, a
  multibyte character cut short) is still a body that is not JSON, which fails its attempt on the
  base adapter and the MCP JSON body (`ResponseMalformed`, OD-21; it stopped the campaign before),
  while over an MCP SSE stream it reads as U+FFFD and on an MCP stdio
  line the line is skipped and the call times out; the walks visit the whole parsed reply: on 4 MiB
  bodies, one with no surrogate costs about main's peak memory (1.00 to 1.02 times) and 1 to 14
  times its parse in CPU, and a hostile one up to about 42 times its parse in CPU, and most shapes
  no more peak memory than main; the worst is one 4 MiB string holding a half, about 3 times the
  parse's peak (held three times while it is replaced, as in any version), then up to about 2.4
  times for one object of some 250,000 keys that collide once replaced, and up to 1.8 times for many
  distinct long keys holding a half (each original kept for the walk, so a repeated one is renamed
  once); a reply nested past 100 levels never reaches the walk, since `bounded_loads` refuses it
  first (`ResponseTooDeep`, above), and the walk's cost at depth (1.25 times a clean value nested
  116,000 levels, about 2.1 times with a half at the bottom) holds only for a value built otherwise;
  the judge's reasoning, parsed from the judge's text past its adapter, can still hold one, measured
  as harmless because it is neither persisted nor printed (the aggregate verdict writes its own
  reasoning); a spec file whose YAML holds the escape is the operator's input, not a reply, and
  since PR #89 (u02) `dottore lint` refuses it in any field, naming the spec and the field, and
  `run` refuses it when it loads, naming the file (exit 3, nothing sent).
- **A provider's input-filter refusal is a `ProviderFilterBlock`, and only in a documented shape
  (added 2026-10-10, OD-41; the runner's half is u08 A-69).** (d) maps every non-retryable 4xx to
  a product defect, and Azure OpenAI's prompt filter answers a prompt it blocks with one, so the
  first attack it refused stopped the campaign. Read where the bytes are (ADR-0002), and cited in
  the code:
  - Azure OpenAI (`adapters.base.azure_prompt_filter`, in `BaseAdapter`, so the openai, anthropic
    and rest adapters): HTTP 400 and `error.code` exactly `content_filter` (Microsoft Learn,
    "Content filtering for Microsoft Foundry Models (classic)", Scenario 3, read 2026-10-10;
    `innererror.code` `ResponsibleAIPolicyViolation` per the Azure OpenAI REST reference,
    2024-10-21). The message names the status and the path, as an `AdapterStatusError`'s does,
    then `the provider's input filter refused the prompt before the model saw it (error code
    content_filter; filtered: <categories>)`, the categories `innererror.content_filter_result`
    marks `filtered: true` (at most 8, each `[a-z][a-z_]{0,39}`). Neither the provider's message
    nor its inner code is written: the redactor's entropy rule masks
    `ResponsibleAIPolicyViolation`. Read before the sampling question (A-68): this 400 names the
    prompt, not a parameter;
  - Gemini (`RestAdapter._prompt_blocked`, through the `_prompt_blocked` hook every success body
    goes through first): a template whose `text_path` starts at `candidates.`, where the Gemini
    API and Vertex AI put the text (pre-merge audit of `3d739f3`, L3: any template was read, and
    a `promptFeedback` key in a reply that is not Gemini's is not Gemini's block), no text at
    that path, and `promptFeedback.blockReason` `SAFETY`, `OTHER`, `BLOCKLIST` or
    `PROHIBITED_CONTENT` (the Gemini API reference, `PromptFeedback`: "If set, the prompt was
    blocked and no candidates are returned") or `MODEL_ARMOR` or `JAILBREAK` (Vertex AI's REST
    reference, `BlockedReason`, read 2026-10-10, L4); not `IMAGE_SAFETY` (Vertex: a prompt unsafe
    for image generation; the Gemini API: candidates blocked; the two disagree on whether the
    prompt was refused), either spelling of the unspecified value, or a value neither lists,
    which stay the product error they were. The status is the reply's, 200.
  `ProviderFilterBlock` is an `AdapterProductError` (not an `AdapterStatusError`) that carries
  `status_code` and `code`, survives copy and pickle, and sets `blocked_by_provider_filter = True`,
  the structural marker `core.execute` reads, and `retryable = False`. Every other 4xx is the
  `AdapterStatusError` it was: another code at 400, the Azure body at 403 or 422, a body that is
  not JSON or not an object. The MCP adapter (discovery only) and the WebSocket adapter do not
  read it. Not recognised, for want of a documented shape: a Bedrock guardrail intervention (an
  HTTP 200 with `stopReason` `guardrail_intervened`, a reply), OpenAI's `invalid_prompt` 400, and
  Gemini behind its OpenAI-compatible endpoint. Checked by
  `tests/adapters/test_provider_filter_block.py` (52 tests; it does not collect on `92c7b11`);
  `tests/adapters/test_status_error.py` now sends a plain bad request, since the Azure body it
  sent at 400 is a block.
- **A-74 (u08's clause; this unit's half, added 2026-10-11, OD-21) A success reply the adapter
  cannot read is a `ResponseMalformed`, never a product error.** `adapters.base.ResponseMalformed`
  is an `AdapterEnvError` with `is_env_error = True`, `retryable = False` and `malformed_reply =
  True` (the marker `core.execute.is_unreadable_reply` reads), every message ending `; not
  evaluated`, and it survives copy and pickle. Raised for: a 2xx body that is not JSON, through
  `bounded_loads` (brackets that do not balance, an integer of more than 4,300 digits, bytes that
  are not text, an empty body), or whose JSON is not an object (`BaseAdapter`, so openai,
  anthropic and rest); OpenAI's no `choices`, a choice that is not an object, no `message` object,
  `content` that is not a string; Anthropic's no `content` array; a REST template's nothing at
  `text_path` or a text that is not a string (after the Gemini block check, OD-41); a WebSocket
  frame that is binary, not JSON or not an object, and a turn with no text, no tool call and no
  filter's stop at `final_path` (the conversation is dropped, as on every error, and a frame in
  the handshake phase is not re-dialled; a turn with a tool call or a filter's stop and no text is
  a reply with empty text, read after them: raised first, an agent's destructive call was never
  evaluated and a filter's cut was not OD-42's, pre-merge audit of `598f0858`, HIGH 2); an MCP body
  or SSE event that is not JSON, an SSE stream with no `data:` event, and an `initialize` with no
  result object, over HTTP or stdio. What stays a product error: a non-retryable 4xx
  (`AdapterStatusError`, `SamplingRefused`; a `ProviderFilterBlock` is OD-41's blocked attempt), a
  JSON-RPC `error` an MCP server answers, a WebSocket handshake reply that does not satisfy
  `expect`, a refused upgrade, and configuration the adapter cannot send. Since the `-sV` probe
  pass isolates every refused reply by the same marker (u09 A-35), such a probe fails alone, as
  `layer/probe: ResponseMalformed`. The error carries what the attempt keeps for review (pre-merge
  audit of `598f0858`, HIGH 1): `excerpt`, at most 4 KiB (`UNREADABLE_EXCERPT_BYTES`) of the body's
  UTF-8 through the adapter's redactor, read over twice that, cut before a registered credential
  that crosses that cut (`redactor.registered_secrets`) and before a key-shaped token that does
  when its part before the cut is 256 characters or fewer (read in part, neither is recognised:
  up to 15 leading characters of a registered credential survived, verification of `07aa0b3a`,
  LOW 1), redacted, then cut to 4 KiB (`reply_excerpt`, `_clean_cut`); `size`, the body's bytes;
  `advice`, the adapter's `unreadable_advice`, worded for it (openai: an OpenAI chat completions URL
  and `provider: openai`; anthropic: the Messages API; websocket: the block's `text_path`,
  `tool_calls_path` and `final_path`; mcp: an MCP server; a REST template built in Python: its
  `text_path`; a target file's `provider: rest` target, built by `cli.wiring`, the generic
  template's `text` and that a template is the Python API's, never "check the response template",
  which a target file cannot declare: LOW 2). A shape error raised inside `_parse_response` gets the
  body in `_handle_final_response`. A REST template whose `text_path` starts at an index
  (`reads_array_body`, Hugging Face's `0.generated_text`) reads a body that is a JSON array; every
  other adapter and template still refuses one as not an object (LOW 2). Checked by
  `tests/adapters/test_malformed_replies.py` (it does not collect on `6d5f7ae`),
  `tests/adapters/test_rest_array_body.py` and the tests that pinned the old rule, now asserting
  this one (`test_base.py`, `test_openai.py`, `test_anthropic.py`, `test_rest.py`,
  `test_deep_replies.py`, `test_websocket.py`, `test_websocket_premerge.py`,
  `test_provider_filter_block.py`).
- **A-77 (u01's clause; this unit's half, added 2026-10-12, audit of main `de122e26`, HIGH 1) A
  WebSocket transcript names its protocol's fields, and nothing the adapter quotes rebuilds a
  secret from its pieces.** The transcript is `raw_ids["websocket"] = {"frames": [...],
  "protocol_paths": [...]}`: beside the frames (OD-34, unchanged), the dotted paths the target file
  declares as the protocol's (`type_path`, `final_path`, `error_path`, `tool_calls_path`,
  `usage_path`, `model_path`, `id_path`, and the `expect` path of the handshake and of the session
  start), never `text_path` or a path above it. Every other field of a frame received is the
  reply's content, which the redactor joins across the frames field by field (`redact_split`, u01
  A-77), in memory where `redact_ids` builds the record and again at rest and in the reports, which
  read the paths from the transcript without the target file (a transcript stored before them is
  read with the frame type at `type`, the default `type_path`). A secret the server streams in
  deltas was redacted delta by delta and rebuilt from the evidence (an `sk-proj-` key, a registered
  credential and an email in three deltas, measured with the loopback fake chat server). A turn
  with no text quotes its frames received in the excerpt with that content masked as one text
  (`mask_split` over the transcript): the frames were `json.dumps`ed and redacted as one string, so
  each delta was masked alone. `reply_excerpt` reads a JSON body's logprob streams the same way
  (`_split_masked`: OpenAI's `logprobs.content` tokens, their `top_logprobs` shown masked beside a
  masked token, and the `bytes` of every masked token or alternative, which spell it, dropped; an
  event stream's chunk holding one logprob item has the same done to it, its alternatives no
  stream, so its `bytes` no longer spell a key its tokens no longer show), and
  a body streamed as server-sent events when no stream was asked for, masked across the events
  as a transcript is (it is not JSON, so it was quoted as it came, each delta redacted alone,
  pre-merge audit of `c4bd2012`, MEDIUM 3). The stream is read as the format says (WHATWG HTML,
  server-sent events, since the second pre-merge audit, MEDIUM 2): a line ends at CRLF, LF or CR
  only (a raw U+2028 or U+0085 inside an event's JSON no longer splits it), a leading U+FEFF is
  dropped, a blank line ends an event, a line starting with a colon is a comment, a field is what
  precedes the first colon with one space after it dropped, and an event's `data` lines join with
  LF; data that is a JSON object or array is masked field by field across the events (`type`,
  `event`, `object`, `id`, `model`, `created`, `created_at`, `system_fingerprint`, `done` and
  `done_reason` its protocol's fields), and any other data (a bare delta, a JSON string, decoded)
  as the text of one stream. An event of several `data:` lines that make no object or array
  joined (a page of `data:` lines with no blank line between them, which the format reads as one
  event) is read line by line, each line a unit, in the same reading (third pre-merge audit,
  LOW 3: a second reading ran only when the first masked nothing, so a masked event beside such a
  block kept its key). A body of JSON lines is a stream only in a shape known to stream (each line
  Ollama's, a `done` beside a `message` or a `response`, or an OpenAI chunk); any other is records,
  masked string by string as `main` masks it (LOW 2: 181 of 217 clean JSON Lines logs were quoted
  otherwise). Only the head the excerpt can read is read: four times its read extent (twice what
  it keeps plus four times the longest registered credential or 256), cut at a line end, 36 KiB
  with no long credential. A body that fits that head is masked as above. One longer than it has its
  streamed text withheld instead (the owner's decision of 2026-10-13, under the delegation, best
  practice: fail closed, an excerpt may show less than `main`, never more): the excerpt keeps the
  lines `main`'s excerpt of the body shows whole and that are blank, JSON or a `data`, `event`, `id`
  or `retry` field (a comment or a line starting with a space or `=` can take its mask in `main`'s
  excerpt from a label in the text withheld: sixth pre-merge audit, `Tr0ub4dor-and-3` shown in 5 of
  17 forms), with every streamed text value in them emptied (content and delta text, a `response`, a
  message's content, a logprob token and its alternatives, a `data:` line's text; `bytes` and
  Ollama's `context` nulled), and keeps keys, structure, numbers, booleans and the protocol's fields
  above, and a `role`, a `finish_reason`, a `stop_reason` and a `service_tier`, at any depth (an
  event's `delta.type`, a tool call's `id`); its first line says, once, that the text it streams is
  withheld because the reply is longer than the head the excerpt reads. A secret whose pieces cross
  the head's cut is never read whole, so no rule can mask it: masked across the head, what lay near
  the cut moved up into the 4 KiB the excerpt keeps (fourth pre-merge audit, MEDIUM: a URL password
  with symbols showed its beginning at 7 of 31 cuts, a 300-character registered credential at 70 of
  111), and with only the head's first half shown and a stream's open tail left out, a 600-character
  URL password of words still showed 20 to 61 of its characters and a stream that paused past the
  head showed its secret's beginning. Withheld, none shows; a clean body past the head differs from
  `main`'s excerpt only by that text and the notice (240 of 320 in the auditor's eight shapes, the
  six that stream; every event or line shown equals the body's with its text emptied, 20,308
  checked), and one that fits is `main`'s byte for byte (1,498 of 1,498). Only `main`'s whole lines
  are kept since the fifth pre-merge audit: emptied, the lines are short, so the 4 KiB reached lines
  `main`'s never reached, and a secret placed outside the streamed text (comment, `event:` or `id:`
  lines, an event's `id` or `model`) showed 11 of 11 pieces where `main` showed 8; a fixed 4 KiB of
  the body was not enough either, since `main`'s own masks lengthen what it shows (short emails in
  every event: `main` none of 11, 4 KiB 8). The excerpt is read from that head alone (LOW 4: a 4 MiB
  stream of tiny events cost up to 12.8 s, `main` 0.00 s; now under 0.25 s on every shape of the
  audit's `cost3.py`). A masked unit is written again on one `data` line (a text holding LF, on as
  many), JSON in the compact form it had, every other line as it came. A body rewritten (a JSON body
  or a stream) is written with `ensure_ascii` off, as the target wrote it: escaped, a phone or a
  card grouped by U+00A0 or U+202F outside any stream reached the excerpt's redaction as `\u00a0`
  and was shown where `main` masked it (second pre-merge audit, MEDIUM 1), and a WebSocket turn's
  frames are quoted the same way. Not read: what u01 A-77's not-covered list names for the excerpt
  (a line that is no field of the format, pieces in a comment, `event:` or `id:` line, JSON lines in
  another shape, among them). Any other body, or one holding no such stream, is quoted byte for byte
  as before; its `size` is the body's as it came. Checked by
  `tests/adapters/test_split_values_in_replies.py` (its first seven fail on `de122e26`, the three
  event-stream cases on `c4bd2012`, the six grouped-number cases and 12 of the 20 stream shapes on
  `ea13562f`, the log, block and window cases on `74ace451`, on `5dd87b42` the five cases of a
  secret straddling the window's cut or reaching past it from the shown half and an event stream's
  logprobs, on `5646b218` a secret at any offset of a cut stream, a paused stream, and a clean
  stream past the window, on `6d7d990e` a cut excerpt's reach, and on `31cf86bf` the five forms of a
  value after a label in the withheld text).

- **A reply the provider's filter stopped keeps its stop reason, and the REST adapter reads a
  Bedrock guardrail's side (added 2026-10-11, OD-42; the runner's half is u08 A-70).** The stop
  reason is read by `shared.provider_filter` (u08), which the adapters do not duplicate:
  - the OpenAI adapter makes Azure OpenAI's withheld reply (`content: null`, `finish_reason`
    `content_filter`) an empty text with that stop reason, as before; the Anthropic adapter
    passes `stop_reason` `refusal` and its `usage` through, as before (the side is read from
    them, u08);
  - the REST adapter reads the stop at `finish_path` first, and a body with no text at
    `text_path` whose stop is a filter's is a reply with no text and that stop (a Gemini
    candidate stopped with `SAFETY` can come without its text; Vertex AI's reference on
    `FinishReason` `SAFETY`, read 2026-10-11); it was a product error that stopped the campaign.
    `RECITATION` too, since it joined the stops (decided 2026-10-11 under the owner's delegation).
    Any other body with no text stays one until OD-21 (decided 2026-10-11): a
    `ResponseMalformed` now, which fails its attempt (A-74). A template with no `finish_path` reads
    no stop, as before;
  - for a template whose `finish_path` is the Converse root `stopReason`, and a stop of
    `guardrail_intervened`, the adapter reads `trace.guardrail` (present with
    `guardrailConfig.trace: enabled`; the Converse API reference and the user guide, "Include a
    guardrail with the Converse API", read 2026-10-11) into `ModelResponse.filter_side` (u00):
    `output` when an entry of an `outputAssessments` assessment's policies has `action`
    `BLOCKED` or `ANONYMIZED`, else `input` when one of an `inputAssessment` assessment has
    `BLOCKED`, else nothing. The policies read are `contentPolicy.filters`, `topicPolicy.topics`,
    `wordPolicy.customWords` and `managedWordLists`, `sensitiveInformationPolicy.piiEntities` and
    `regexes`, and `contextualGroundingPolicy.filters`, whose action values the API reference
    lists (`BLOCKED | NONE`, and `ANONYMIZED` for the two sensitive-information ones); a value of
    another type is not read. A masked prompt is not a blocked one: a trace that names neither
    side is `filter_side: unknown`, so the evidence tells it from no trace at all (pre-merge audit
    of `a55e953`, L3). The guardrail's message stays the reply's text.
  - **These REST shapes are library-only.** From `dottore`, a target file's `provider: rest` is
    built as `RestTemplate(path=...)`, with the text at `text`, no `finish_path` and no
    `static_body`, and `Target` has no template field: a Bedrock trace, a Gemini `SAFETY`,
    `RECITATION` or `MODEL_ARMOR` stop, and OD-41's Gemini prompt block are read only by a
    `RestTemplate` built in Python (pre-merge audit, M3). A target file's openai, anthropic and
    websocket providers carry their stops as before.
  - The stop words were generic, read whichever adapter carried them (L7): a WebSocket target's
    final frame that held `content_filter`, `refusal` or `safety` at its finish path was read as
    that filter's stop. **Superseded by A-79 below**: each adapter reads its own provider's words.
  Checked by `tests/adapters/test_provider_output_filter.py` (49 tests; it does not collect on
  `6d5f7ae`).

- **A-78 (u01's clause; this unit's half, added 2026-10-11, pre-merge security audit, LOW 6) Every
  adapter refuses a credential shorter than 8 characters before its first request.** The redactor
  masks a registered credential by value only from 8 characters, so a shorter one a target echoes
  reaches the evidence and every report. The WebSocket adapter refused one before any dial (its
  pre-commit audit, F5); the OpenAI, Anthropic and REST adapters (`BaseAdapter.send`) and the MCP
  adapter over HTTP sent it, the resolved `auth_ref` and a password in the endpoint URL alike.
  `adapters.base.refuse_short_credential(id, api_key, url)` runs right after the allowlist gate in
  each of them, the WebSocket adapter's included, and raises `CredentialTooShort` (an
  `AdapterProductError`) with the WebSocket adapter's message: `<id>: the credential is shorter than
  8 characters, which the redactor cannot mask by value; nothing was sent`. A password is checked as
  written and as it reads percent-decoded; an empty one is no credential and passes
  (`https://<token>:@host` sends a user only); a stdio MCP server, which is sent no key, is not
  checked (only the MCP adapter honours `transport: stdio`: on any other provider the field is
  ignored, the key goes over the wire, and the CLI checks it, pre-merge audit of A-78, L4).
  `MIN_CREDENTIAL_LEN` is `redactor.KNOWN_SECRET_MIN_LEN`, re-exported by the WebSocket module. The
  CLI refuses it earlier too (u12). Checked by `tests/adapters/test_short_credentials.py` (39 tests;
  on `de122e26` the file stops at collection, which lacks `MIN_CREDENTIAL_LEN` and
  `refuse_short_credential`, and 19 fail with the two given stand-ins in a copy of the file; the
  test adapters that used the key `k` use one of 10). The no-entropy twin a model name goes through
  (`redact_ids`, `Redactor.without_entropy`) drops the UUID pattern with the entropy rule, so a
  deployment's model name holding one reads as before A-78 for the fingerprint's metadata layer
  (u01's clause, L5).

- **A-79 (this unit's half; the clause is u08's, added 2026-10-11, the amendment to OD-41 and
  OD-42, decided under the owner's delegation, best practice, revisable) A stop is a filter's only
  from the provider that documents it.** A target writes its own stop reason and error body, and
  every adapter read every provider's filter words: an OpenAI-compatible target that answered
  `refusal`, `SAFETY` or `guardrail_intervened`, or a WebSocket target that ended a turn on
  `content_filter`, had its reply read as a filter's cut, and any adapter read Azure's HTTP 400
  `content_filter` as a block (security audit of 2026-10-11, MEDIUM 3). The criterion:
  - every adapter says which stops it honours, `filter_stops` (a `frozenset` of trimmed,
    lower-case words): `BaseAdapter` none; `OpenAIAdapter` `content_filter`; `AnthropicAdapter`
    `refusal`; `RestAdapter` its template's `reads_filter_stops`, which is
    `RestTemplate.filter_stops` when set and otherwise the template's shape: Bedrock's
    (`guardrail_intervened`, `content_filtered`) for a `finish_path` of `stopReason`, Gemini's and
    Vertex AI's (`safety`, `blocklist`, `prohibited_content`, `spii`, `model_armor`, `recitation`)
    for a `text_path` under `candidates.`, none otherwise (a target file's `provider: rest` target
    has the generic template, with no `finish_path`, and reads none); `WebSocketAdapter` its file's
    `response.filter_stops` (u00), none by default. The vocabularies, each sourced, are in
    `shared.filter_stops`; a declaration must name values from them (`documented_stops`), refused
    otherwise, and a WebSocket declaration beside a `final_value` is refused (every turn ends on
    that value);
  - every success reply leaves an adapter through `shared.provider_filter.stop_provenance`
    (`BaseAdapter._checked`; the WebSocket adapter's turn): a stop that is some provider's filter
    word and not one the adapter honours keeps its spelling and gets `ModelResponse.foreign_stop:
    true` (u00), which every reader reads as an ordinary stop (u08). A REST body with no text and
    a foreign stop is a `ResponseMalformed`, and so is a WebSocket turn with no text, no call and
    only an undeclared word; the Bedrock trace is read only beside an honoured
    `guardrail_intervened`;
  - Azure's HTTP 400 `content_filter` is a `ProviderFilterBlock` only from an adapter that
    honours `content_filter` (OpenAI's, or a REST template that declares it); from any other it is
    an `AdapterStatusError`, an undocumented 4xx that stops the campaign, as before OD-41.
    Gemini's `promptFeedback.blockReason` is read only by a template that honours one of Gemini's
    stops (a template in Gemini's shape does, unless its `filter_stops` says otherwise);
  - an `openai` or `anthropic` target file may declare `filter_stops` (u00 `Target`, u12): `[]`
    for an endpoint that speaks the provider's API and has no such filter behind it (not a gateway
    in front of Azure OpenAI, which relays Azure's), or the provider's own word only, checked by
    the `Target` model on every path (`shared.filter_stops.target_filter_stops`). The composition
    root passes it as the adapter's `declared_filter_stops`, which `filter_stops` returns
    intersected with the provider's own words, so a declaration built past the model (by hand, a
    `model_copy`) narrows and never widens them (pre-merge audit of `10cb526b`, LOW): with `[]` no
    Azure 400, and no stop on a reply with text or a tool call, is read as a filter's (pre-merge
    audit of `a55710e9`, LOW 3, best-practice addition);
  - every adapter also says what its provider documents whatever is declared,
    `own_filter_stops`: `BaseAdapter` none (the WebSocket adapter none either), `OpenAIAdapter`
    `content_filter`, `AnthropicAdapter` `refusal`, `RestAdapter` its template's
    `shape_filter_stops` (the shape's, as above). `stop_provenance` never marks a reply with no
    text (`blank_text`: whitespace and the format characters that show and carry nothing, the
    redactor's `EMPTY_FORMAT_RANGES`, so a zero-width space is none, pre-merge audit of
    `e1a8aacf`, LOW 1, and a tag character or a format sign a font draws is text, that of
    `3f7b1254`, LOW) and no tool call that ends on one of them: that
    is the filter's withheld reply, scored as
    without the declaration, never a pass. A gateway in front of Azure relays Azure's empty
    `content_filter`, and the first version marked it foreign under `[]`, so `PI-DIRECT-001`
    passed and the run exited 0 where without the declaration it is `filtered`, exit 3 (pre-merge
    audit of `10cb526b`, MEDIUM). A REST body with no text reads the shape's word too, as `""`;
  - the WebSocket adapter's `unreadable_advice` names `response.filter_stops`: a file written
    before A-79 whose server ends a withheld turn on a filter word gets an unreadable reply for it
    until the word is declared (LOW 2). A withheld turn is one with no tool call and no text
    frame, or only blank ones (`blank_text`), ending on a documented filter word the file does
    not declare: a relay of a streamed Azure reply sends a first delta of `""`, and until the
    pre-merge audit of `e1a8aacf` (MEDIUM 1) only a turn with no text frame at all was
    unreadable, so that one was the model's empty answer and passed, exit 0. A blank turn on a
    declared word is the filter's cut, one on an ordinary stop an empty answer, as before.
  Measured on `de122e26` through the CLI: an `openai` stub answering `JB-ROLEPLAY-001` with
  harmful text and `finish_reason: refusal` gave three cut attempts and exit 0, and gives a
  confirmed fail, exit 2, as the same text with `stop` does; an `anthropic` stub answering every
  attack with Azure's 400 gave six blocked attempts and exit 0, and stops at the first, exit 3.
  Checked by `tests/adapters/test_filter_stop_provenance.py` (54 tests; 52 fail on `de122e26`, the
  two controls pass; 25 fail on `10cb526b`, among them the empty reply on the provider's own word
  under a declaration, from OpenAI, Anthropic and a Gemini template, and an adapter given another
  provider's word; 19 on `e1a8aacf`, among them `blank_text` on 8 strings and a zero-width reply
  through the OpenAI adapter; 11 on `3f7b1254`: `blank_text` on 8 tag and sign strings, the
  three kinds partitioning the redactor's list, the tag reply undeclared and under `[]` and a
  sign under `[]`), `tests/adapters/test_provider_filter_block.py` (59: the Azure 400 from the
  adapters that do not read it, 2 of them failing on `de122e26`) and the WebSocket cases of
  `tests/adapters/test_malformed_replies.py` (42 tests; the blank turn on `""`, `"  "` and a
  zero-width space, 3 failing on `e1a8aacf`, and its control).

- **A-96 (added 2026-10-24): a deployed agent's guard.** A `provider: websocket` target file may
  declare `websocket.guard` (`shared.models.WebSocketGuard`, `adapters/agent_guard.py`), so any AI
  agent reachable over a JSON WebSocket is a target with a profile and no code, held to what that
  deployment needs. Every part is optional; with the block present:
  - the first authentication failure raises `AgentAuthRefused`, a `GuardStop`
    (`AdapterProductError`, not an environment error), so nothing retries it and the runner
    aborts the campaign (exit 3) naming it; a failure is an upgrade answered 401 or 403, a
    handshake reply that does not satisfy `expect`, an error frame whose `auth.code_path` value is
    in `auth.failure_codes` (handshake or turn), and a close, or a silence past
    `response.timeout_seconds`, before the handshake reply;
  - every failure starts `auth.cooldown_seconds` (default 120) in a state file shared by every
    process that scans the endpoint, and a dial inside it is refused (`AgentPacingStop`) with no
    connection; the first three kinds also record the credential's sha256 (never its value, at most
    32 kept) and a later send of it is refused before any dial, so a fresh one is needed;
  - `guard.token` reads the JWT payload unverified before any dial: no JWT, no claim of
    `tenant_claims`, another tenant than `tenant` (a value or a `vars` name), no `exp`, or less than
    `min_lifetime_seconds` of life is refused with no connection; a handshake reply naming another
    tenant at `reply_tenant_path` closes the connection before any query; no message quotes a
    tenant or the credential;
  - `guard.pacing` reserves each query's slot under an exclusive lock on the state file:
    `min_interval_seconds` after the last slot of any process, waited outside the turn timeout;
    a slot that would make more than `max_per_hour` in its hour is refused (`AgentPacingStop`,
    naming when one frees) and reserves nothing;
  - `guard.stop_on_tools`: a name in `names` at `path` (one name or a list), in any frame of a
    turn, an ignored one included, raises `AgentToolStop` and the connection is closed (OD-54);
  - `guard.max_response_bytes` lowers the turn's and the handshake's byte cap, never raises it;
  - `guard.endpoint` requires the endpoint's scheme and exact path.
  The state file is one per endpoint, named by the endpoint's sha256 (the directory lists no host),
  0600 in a 0700 directory under `ILDOTTORE_STATE_DIR`, `$XDG_STATE_HOME/ildottore` or
  `~/.local/state/ildottore`; one that cannot be read starts over. The loader refuses, before any
  send, a scheme or path other than `guard.endpoint`'s, a `guard.token` with no `auth_ref`, a
  `tenant` placeholder not under `vars`, `failure_codes` without `code_path` (or the reverse) and a
  `max_response_bytes` above `MAX_RESPONSE_BYTES`. The guard's paths are kept as protocol fields
  in the transcript (A-77). The block is left out of the target digest (it decides whether and
  when a query goes out, never what answers it), so a run the hourly cap stopped resumes; a target
  without it behaves exactly as before. `--dry-run` prints a `guard:` line and says when the plan
  passes the hourly cap. Judging rules 7 re-pinned (no verdict path touched). Checked by
  `tests/adapters/test_agent_guard.py` (40 tests, against the loopback agent of
  `tests/agent_ws_server.py`) and `tests/cli/test_agent_target.py` (11: the example profile, the
  loader's refusals, the dry-run line, the digest, a guarded campaign, and a run stopped on the first
  auth failure whose next run dials nothing).

- **A-98 (added 2026-10-26): the guard's window, the guard over HTTP, profiles by name.**
  - `guard.window` (`shared.models.WebSocketGuardWindow`): `timezone` (an IANA zone, required),
    `days` (day names or ranges that do not wrap past `sun`), `start` (inclusive), `end`
    (exclusive, `24:00` allowed; an end before the start crosses midnight and belongs to the day it
    opens). The loader refuses a missing or unknown zone, an unknown day, a wrapping range, a start
    equal to its end, and a time YAML read as a number. `AgentGuardState.admit` refuses outside the
    window, and `reserve` refuses at `now` and again at the slot a query is paced to, which is then
    not recorded: `AgentWindowStop`, a `GuardStop`, names the window, the local time and the next
    opening (`next_opening`, within eight days) and says nothing was sent. `--dry-run` names the
    window and, when it is closed now, says a run started now sends nothing and when it opens.
  - `rest.guard` (`shared.models.RestSpec`): a `provider: rest` target (or one with no provider)
    takes the WebSocket guard's block under `rest:`. `GuardKeeper` (`adapters/agent_guard.py`)
    holds the checks both adapters run (endpoint, token, admit, auth failure, error code, reply
    tenant, tools, byte cap); `WebSocketAdapter` delegates to it with no change of behaviour.
    `RestAdapter.send` checks the allowlist, then the keeper, before the base loop; each attempt,
    a retry of a 429 or 5xx included, reserves a slot (`BaseAdapter._before_attempt`, a no-op
    hook by default); `_response_cap` lowers `read_capped`'s cap; `_handle_final_response` reads
    401 and 403 (auth failure, credential refused), a listed `auth.code_path` code in any JSON
    object body, and, on a success, the tenant at `reply_tenant_path` and the tools at
    `stop_on_tools.path` (`AgentTenantMismatch` and `AgentToolStop`: the run stops after that reply,
    which is not read, OD-56). The loader refuses a `rest` block on another provider, a guard
    without an endpoint, a `ws`/`wss` scheme under `rest.guard` (and `http`/`https` under
    `websocket.guard`), and a placeholder in `token.tenant` (a REST target has no `vars`). The block
    is outside the target digest; an absent one hashes as before. No SSE transport exists to guard.
  - Profiles by name (`cli.wiring.resolve_profile`, `profile_dir`): a bare name (charset
    `[A-Za-z0-9._-]`, at most 250 characters, not starting with a dot, no `.yaml`/`.yml` suffix) given to `-t`, a positional
    target, `--judge`, `--scope`, `fleet --judge` or `fingerprint` reads `<name>.yaml` (or `.yml`)
    from `ILDOTTORE_TARGETS_DIR` / `ILDOTTORE_SCOPES_DIR`, else `~/.config/ildottore/targets/` /
    `scopes/`. Anything else is a path, as before. Both suffixes present, a file of that name in the
    working directory as well as a profile, or neither found: refused, exit 3, naming where it
    looked. A directory of that name here does not count as the file.
  `get_path` moved to `adapters/paths.py` (re-exported by `adapters.rest`) so the guard reads
  paths without an import cycle. Judging rules 7 re-pinned (no verdict path touched). Checked by
  `tests/adapters/test_agent_guard_window_rest.py` (26) and `tests/cli/test_rest_guard_profiles.py`
  (20).

- **A-101 (added 2026-10-27): the MCP catalogue, its parameters and its pins (ADR-0015).**
  - The rendering shows each described property of a tool's `inputSchema` under the tool
    (`  - param <path>: <description>`, nested by a dotted path, an array's items with `[]`;
    `_parameter_lines`), so an instruction in a parameter's description reaches the evaluators.
  - `catalogue_fingerprints(tools, resources, prompts)`: the SHA-256 of each entry as advertised
    (canonical JSON, sorted keys, every field), keyed `tool:<name>`, `resource:<name or URI>`,
    `prompt:<name>`; two entries under one key hash together in sorted order. Always in
    `response.raw_ids.mcp_catalogue`, kept readable by `reporting.masking._restore_digests`, which
    also keeps `run.targets[].mcp.pins` readable (masked, the run's report failed its own
    validation and was not written; found running the manual's example).
  - `MCPAdapter.pins` (from the target's `mcp.pins`, `shared.models.McpSpec`: key
    `^(tool|resource|prompt):\S.*$`, value a lowercase SHA-256, at most 10,000): with any, the
    rendering ends in `Pinned catalogue (N pinned): matches`, or `drifted (c changed, u unpinned,
    m missing)` and a line per difference (`_pin_lines`), and `capabilities()` says `mcp_pins`.
  - The loader reads `mcp` for `provider: mcp` only, refuses a malformed pin naming the file, and
    sets `capabilities.mcp_pins` exactly when `mcp.pins` is not empty; declared on a live target it
    is refused (an offline mock may declare it, or pin, only as `vulnerable` or `hardened`, the
    scenarios that replay the spec's fixtures: a canned reply would fail it, OD-16); a fleet entry
    may not declare it. The pins are in
    the target digest; an absent block and a false `mcp_pins` are left out, so a target without
    them hashes as before.
  - `MCP-RUGPULL-001` (u13): `requires: [mcp, mcp_pins]`, `regex_presence` on `matches` and
    `regex_absence` on `drifted`, no judge; in the `mcp` suite. LLM06, not LLM03 (OD-59, decided).
  Still read-only: no `tools/call`. Checked by `tests/adapters/test_mcp.py` (6 added) and
  `tests/cli/test_mcp_rug_pull.py` (15), against a live local server.
- **A-104 (added 2026-10-27): a stdio MCP server may run in a container (ADR-0016).** A
  `provider: mcp`, `transport: stdio` target file may declare `isolation:`
  (`shared.models.IsolationSpec`, `adapters/isolation.py`); any other target is refused the block.
  - The block: `image` (required, `name@sha256:<64 hex>`), `runtime` (`docker` or `podman`,
    default `docker`), `memory` (default `512m`), `cpus` (default `1`, above 0, at most 64), `pids`
    (default `128`, 8 to 4096), `mounts` (at most 16, each `source` and `target`, read-only with no
    way to say otherwise, no two on one target) and `workdir`. A path is absolute, normalized,
    not `/`, with no comma, colon or control character. The loader also refuses a mount whose
    source is not a directory, is written through a symbolic link (the resolved path is named) or
    holds the operator's home directory.
  - `MCPAdapter.isolation`: after the scope authorizes the exact command (unchanged, before
    anything else), `prepare_container` finds the runtime on the server's `PATH` and runs
    `<runtime> image inspect <image>`; no runtime, or a non-zero answer, raises
    `IsolationUnavailable` (`AdapterProductError`: the run aborts, exit 3) and nothing starts.
    Never a fallback to the host. The launch is `container_argv`: `run --rm -i --pull never
    --init --name dottore-mcp-<12 hex> --label dottore.mcp=1 --network none --read-only --tmpfs
    /tmp:rw,noexec,nosuid,nodev,size=64m --cap-drop ALL --security-opt no-new-privileges --user
    65534:65534 --memory M --memory-swap M --cpus C --pids-limit P`, a `--mount
    type=bind,...,readonly` per mount, `--workdir`, then `--entrypoint=<command[0]>`, the image and
    the rest of the command. The container gets no host variable; the runtime's own process gets
    the server's environment and `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`,
    `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`, `CONTAINER_HOST`, `CONTAINERS_CONF` and
    `XDG_RUNTIME_DIR`. After the session, `<runtime> rm -f <name>` runs whatever happened. The
    message names neither the image nor its digest (the redactor masks a digest); it names
    `isolation.image`.
  - The block enters the target digest without `runtime`, `memory`, `cpus` and `pids`; absent, it
    is left out. `--dry-run` prints an `isolation:` line (runtime, image, not pulled, no network,
    read-only root, the limits, the mounts).
  Judging rules 7 re-pinned (no verdict path touched). Checked by
  `tests/adapters/test_mcp_isolation.py` (28: the argv flag by flag, 17 refusals of the block, the
  launch through a stand-in runtime, no image, no runtime, an unauthorized command, a server that
  dies, no block; one real container, opt-in by `DOTTORE_TEST_DOCKER_IMAGE`) and
  `tests/cli/test_mcp_isolation_target.py` (13: the example, the loader's refusals, the wiring,
  the digest, the dry-run line, a run with no runtime). The argv was run against Docker 29.4.0 on
  2026-10-27 (with a mount, a workdir and lowered limits: accepted, the container removed).

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
- **OD-18** (ADR-0009; decided 2026-10-06 by the owner: C, A first; this unit's half, recorded
  2026-10-12): against a `type: model` target a spec's setup goes out in-band (option A), so each
  adapter says what of it it can carry: `carries_tool_definitions` (OpenAI and Anthropic when the
  endpoint takes tools, translating the scene's tools into the provider's tool definitions; REST,
  WebSocket and MCP carry none) and `carries_system_prompt`, where the memory seed goes (OpenAI
  and Anthropic; a REST template with a system field; a WebSocket template with
  `{{system_prompt}}`). The runner reads both and makes a spec the adapter cannot carry
  `inconclusive: setup_not_delivered` with no send (u08 §2). Option B, a deployment's declared
  seeded scene, changes nothing here (u08, u12).
- **OD-24** (built 2026-10-07, A-39; **decided 2026-10-11 under the owner's delegation (best
  practice), revisable: kept as built**): what a logprob block with one figure no model produces
  reads as. When the figure is a token's own, the whole block is `None`, as if the reply carried
  none, so nothing is scored from it; when it is an alternative's, only that token's alternatives
  are dropped (no alternative is scored). Why: one impossible figure is evidence the block is not a
  model's (a gateway writing probabilities into the field, a forged reply), and a verdict read from
  the rest would be one the reply never had; a tool should not raise a finding from data it has
  caught being wrong, and the cost is an inconclusive membership spec. Not taken: dropping only the
  bad entries, as a null one is dropped, which scores the rest as if it were the reply: four
  confident tokens with one positive figure among them then read "likely memorized". Also decided
  under the same delegation: a positive figure counts as impossible (`log p` is never above 0, and
  a gateway that writes probabilities into the field is caught). Not measured: whether a provider
  sends rounding-level positive figures (`2e-07`); if one does in a token's own figure, its
  membership spec is inconclusive, never a false "memorized", with nothing in the evidence saying
  why (in an alternative it costs only that token's alternatives). And an entry that is not an
  object (a list such as `["a", 0.9]`, a string, a number) or that carries no figure is still
  skipped and the rest is scored, as before A-39: absence is not a contradiction, and voiding the
  block on it would protect nothing, since a target can send confident figures a model could
  produce and is believed (A-39, "Not claimed"). Not taken: void the block on such an entry too
  (the pre-merge audit's reading). Reversing the main rule is one line, the `except
  _UnreadableLogprob` in `map_logprobs`, which would skip the entry instead of returning `None`;
  `tests/cli/test_logprob_figures.py` pins it. Left open, not part of the decision: whether the
  evidence should say a block was unreadable rather than absent, which needs an additive field on
  `ModelResponse` (u00).
- REST auth-injection surface (header vs query vs body-templated token): propose header-only default
  in MVP-1 to shrink the secret-leak surface: needs sign-off.
- **OD-21** (2026-10-07; **decided 2026-10-11 under the owner's delegation (best practice),
  revisable: the attempt fails, the campaign goes on, and a campaign whose first five replies all
  cannot be read stops early; built, §7 A-74 and u08 A-74**): a 200 whose body is not JSON
  (brackets that do not balance included; or not the provider's shape; or JSON with an integer of
  more than 4,300 digits, which Python refuses to read) was `AdapterProductError`, and the runner
  aborted the campaign on it (F5), so one hostile reply of `<html>` stopped a scan, where a reply
  nested too deeply failed only its attempt. Measured with `dottore run` against a local stub:
  exit 3, "aborted on AdapterProductError", 1 request sent. The same rule covered a WebSocket frame
  that is not JSON, is not an object, or is binary (PR #87, exit 3 against the loopback chat
  server on 2026-10-09), and the decision covers both; a text frame that is not UTF-8 was never in
  it, since the library refuses that one before the adapter reads it (`WebSocketUndecodable`,
  inconclusive and not retried, §4). Why: a target's reply is untrusted input, and a scanner whose
  battery a single hostile reply can end lets the target decide what is measured; #65, #68 and
  OD-41 had already moved neighbouring cases to "fail the attempt, not the campaign". What the old
  rule bought, a misconfigured endpoint caught at the first request, is kept by the early stop for
  5 requests. Not taken: keep stopping the campaign; fail the attempt with no early stop (a wrong
  endpoint then sends the whole battery and ends `unreachable`); retry such a reply. A
  non-retryable 4xx is not in question and still stops the campaign.
- **OD-28** (decided 2026-10-07, A-47): what a reply that holds a lone surrogate becomes. The owner
  left the choice to the build on 2026-10-07, and it is U+FFFD where the reply is parsed, the
  attempt evaluated as usual, as built. Why: it is what most of the target's consumers end up with
  once the text is encoded (WebIDL's `USVString`, JavaScript's `toWellFormed` and Go's
  `encoding/json` read a lone surrogate as U+FFFD; Node's `JSON.parse` keeps it until the text is
  encoded), so a verdict is about the reply they get; Unicode's security report advises against
  deleting code points (UTR #36 rev. 15, 2014-09-19, 3.5 "Deletion of Code Points") and, for
  ill-formed input, substituting U+FFFD or stopping (3.6.2), and here deleting would show the
  evaluators text no consumer sees (`<scr`, a half and `ipt>` read as `<script>`, a fail no browser
  would render); and the evidence keeps a mark where something stood. Rejected: deleting the half
  (it would find a canary and mask a credential that half a character splits, at the cost above); a
  visible marker of the code unit (the evaluators would read it as reply text); refusing the reply
  as an environment error, inconclusive and not retried (a target adding six characters to a leaking
  reply would make it "not evaluated", `test_a_lone_surrogate_does_not_hide_a_leak`); replacing it
  only where the evidence is written (a multi-turn spec and the `--judge` request still failed in
  httpx). What it costs, and where it goes: half a character inside a word splits it as a zero-width
  space does today, so a leak split that way is missed by `regex_absence` (inconclusive, exit 0) and
  a canary by `secret_leakage` (`SP-LEAK-001` passes when a judge says secure, where refusing the
  reply would have left it inconclusive), left as its own task for the evaluators; a registered
  credential split that way is masked whole, since PR #57 reads U+FFFD as a splitter (u01 A-32), as
  the owner approved for whichever of the two landed second. Not built: an evidence field
  saying a reply was altered (an additive `ModelResponse` field, u00); U+FFFD is the mark.
- **OD-34** (opened 2026-10-07, PR #87; it numbered these four OD-30 to OD-33, which `main` and PR
  #88 had taken, and they were renumbered on 2026-10-09; **decided 2026-10-11 under the owner's
  delegation (best practice), revisable: the transcript stays in `raw_ids["websocket"]["frames"]`,
  as built**): a WebSocket target's frame transcript lives in `ModelResponse.raw_ids["websocket"]`
  rather than in a dedicated field. Why: `ModelResponse` is u00's frozen shape, which every adapter,
  evaluator, store and reporter codes against, so a field is a program-level change, and `raw_ids`
  is already where a transport puts what it returns beyond text, tool calls, logprobs, finish reason
  and usage, under its own key; it is redacted where the adapter builds it (`redact_ids`) and again
  at rest, it is in each attempt's stored artifact, and `dottore replay` re-derives a verdict from
  it, so the evidence is the same either way. A field for one transport would be designed around one
  transport's frames; when a second streaming transport needs a transcript (an SSE chat, a realtime
  API), one field can be shaped for both in a single u00 revision. The one reader of `raw_ids` as
  tells, the fingerprint's envelope layer, skips a nested value, so a reply's text in the frames
  never names a family (`test_the_transcript_is_not_a_metadata_tell`). Measured on a copy of
  `0bdb6ee` with an optional `transcript: list[JsonDict] | None = None` added: 1 of 5,082 tests
  fails (the JSON report's golden snapshot, `tests/reporting/test_golden_snapshot.py`), and with the
  default serializer every attempt artifact and report written after it carries one more key
  (`"transcript": null` on each response). That cost is small and avoidable (a serializer that drops
  a `None` field, as `ModelResponse` now does for OD-42's `filter_side`, keeps the stored output
  byte-identical), so it is not what decides; the frozen shape and the single transport are.
  Alternative not taken: that field, the WebSocket adapter writing it instead of
  `raw_ids["websocket"]`, with the snapshot regenerated. Revisit when a second transport records a
  transcript. Reversal: add the field in `shared/models.py`, write it in `adapters/websocket.py`
  where `ids["websocket"]` is set, and regenerate the snapshot.
- **OD-35** (opened 2026-10-07, PR #87; **decided 2026-10-11 under the owner's delegation (best
  practice), revisable: refused by design, as built**): a WebSocket target's
  `session.one_query_in_flight: false` is refused by the loader, before anything is sent, and the
  refusal says so ("is refused by design (OD-35)", until then "is not built"). Why: an attempt's
  evidence is the frames of its own turn. On a shared socket the frames of concurrent queries
  interleave, and a frame is tied to its query only by a correlation id the server must echo in
  every frame it sends (each delta, the final frame, an error frame); one frame misread puts one
  attempt's reply text (a canary, a leak) into another attempt's verdict, which no evaluator can
  detect afterwards and `dottore replay` would re-derive faithfully. Nothing is lost by refusing:
  concurrency comes from one connection per conversation, which `--concurrency` already gives (up
  to `MAX_OPEN_CONVERSATIONS`, 256). Alternative not taken: `one_query_in_flight: false` with a
  `{{correlation_id}}` placeholder the adapter fills per query in `message.send`, a
  `response.correlation_path` read from every frame, and a frame with no id or an unknown one
  refused as a product error. Revisit when a deployment caps connections per client and has to be
  scanned faster than one conversation at a time. Reversal: drop the `one_query_in_flight` check
  in `cli/wiring._websocket_spec` and build the alternative in `adapters/websocket.py`.
- **OD-36** (opened 2026-10-07, PR #87; **decided 2026-10-11 under the owner's delegation (best
  practice), revisable: no reconnect mid-conversation, as built**): a WebSocket reconnect is
  attempted only before a query is on the wire, and never more often than the adapter's own retry
  allowance: under `run` (and `-sV`, the identity sweep and a metered judge) every live adapter
  retries nothing itself, so a socket that fails to open is retried by the runner, one debited
  and paced send per dial (since the pre-merge audit of 2026-10-09: `max_attempts: 1` made 8
  dials for 4 debits). A connection closed mid-turn is an environment error the runner retries
  and debits; the adapter never resends a query on its own, so no send escapes the ledger. A
  later turn of a multi-turn attempt whose connection is gone is inconclusive (`WebSocketLost`,
  not retried), never a silent new session, and that holds for a stateless server too
  (`{{messages}}` in the template). Why: `{{messages}}` shows that the client resends the
  history, not that the server ignores its own per-connection state, and the tool cannot check
  which; on a server that keeps state, a re-dialled turn (a new handshake and `session.start`)
  is answered in a fresh conversation, and a multi-turn attack's later turn is scored without the
  context its earlier turns built, a pass of a model that was never asked the question in
  context. Inconclusive says what happened; a silent new session would not, and it is the
  conservative reading where the evidence is at stake. Alternative not taken: an operator
  declaration (`session.stateless: true`, accepted only with `{{messages}}` in `message.send`)
  under which a lost connection is dialled again through the runner (each dial a debited, paced
  send), the handshake and session start sent again, the whole history sent in one frame, and the
  reconnect marked in the frame transcript. Revisit when a live target loses conversations to
  idle timeouts often enough to show in its inconclusive count. Reversal: build the alternative
  in `adapters/websocket.py` (the `WebSocketLost` branch of `send`).
- **OD-37** (opened 2026-10-07, PR #87; **decided 2026-10-11 under the owner's delegation (best
  practice), revisable: a fleet refuses a WebSocket entry; built, u12 §9**): `dottore fleet`
  refuses a `ws://` or `wss://` endpoint (read as `run` reads it, stripped and case-folded,
  whatever `provider` the entry gives) and `provider: websocket` (on any endpoint) in a target
  before it writes anything (exit 3). The refusal names the entry
  (`targets.1.endpoint of 'ws-assistant-staging' is a wss:// URL`) and points to
  `examples/target.websocket.yaml` and `examples/scope.websocket.yaml`. In the `judge:` block the
  same declaration is accepted when `--judge` names a hand-written file that matches the block
  (`_check_judge`): that file is what the run reads, the block authorizes it in the generated
  scope, and no `judge.yaml` is written for it; without `--judge` the block is refused, and the
  refusal says to write the judge's file and pass it with `--judge` (the first build of this
  decision refused it either way, which broke a fleet that worked on `6d5f7ae`, where `fleet`
  exited 0 and `run --dry-run` planned 220 judge requests; pre-merge audit of `be3f2e71`).
  Before: a target entry with a `wss://` path was inferred `rest` and written with no
  `websocket:` block, and `run`, `fleet --run` and the printed `dottore run` refused that target
  file (a `ws://` or `wss://` endpoint is dialled only by `provider: websocket`);
  `provider: websocket` wrote a file with no block, refused the same way; a WebSocket judge
  worked only through a matching `--judge` file, beside a `judge.yaml` written as `rest`.
  Why: a fleet entry is the shorthand for a target whose wire shape is standard and read from its
  endpoint (OpenAI-compatible, Anthropic, a REST URL, an MCP server); a WebSocket target's shape is
  the deployment's own, declared in a block `run` checks field by field before it sends
  (`_websocket_spec`: the placeholder rules, the reserved upgrade headers, the walks of A-44 and
  A-54), and the fleet already leaves the other per-deployment blocks (`seeded_setup`,
  `sampling_defaults`) to a target file written by hand. Refused, not skipped: the unused
  `skipped` list would let `fleet --run` exit on the other targets' findings with one target never
  scanned. Alternative not taken: a `websocket:` block in a fleet entry, the provider read as
  `websocket` from the scheme and the block checked by `_websocket_spec` before anything is
  written (its scope entry pinned to host, port and path, as now). Reversal: `_refuse_websocket`,
  `_websocket_problem`, `_WEBSOCKET_BY_HAND`, `_WEBSOCKET_JUDGE_BY_HAND` and the `judge_doc`
  argument of `_documents` in `cli/fleet.py`, their use in `materialize_fleet`, and
  `tests/cli/test_fleet_websocket.py`.
- **OD-54** (2026-10-24, A-96; **open, owner to decide; built as the smallest reversible version**):
  what a tool from `guard.stop_on_tools` does to the run. Built: the connection is closed and the
  run stops (`AgentToolStop` aborts the campaign, exit 3, naming the tool), and the attempt is not
  scored or stored. Why: the list names tools that write to the tenant, and every later spec could
  provoke one again; a stop the operator reads is safer than a scan that keeps writing. Not taken:
  record the attempt (its partial reply, the tool as a tool call) as evidence and go on to the next
  spec, which would make "the agent ran a writing tool" a finding of its own. Reversing it is the
  `_check_tools` raise in `adapters/websocket.py`. Also built and part of the same decision: a close
  or a silence before the handshake reply counts as an authentication failure (cooldown, the
  credential not refused), where it could be an outage.
- **OD-56** (2026-10-26, A-98; **open, owner to decide; built as the smallest reversible version**):
  five choices of the window, the HTTP guard and profiles. (a) Outside the window the run stops
  (exit 3) and is resumed by hand; not taken: sleep until it opens, which keeps a process waiting
  for days and sends traffic nobody is watching. (b) An overnight window (`22:00`-`06:00`) belongs
  to the day it opens: `fri` covers Friday night into Saturday morning. (c) Every HTTP attempt, a
  retry included, takes a pacing slot, since the agent sees each one; not taken: one slot per
  query. (d) A listed tool in a REST reply stops the run and the reply is discarded, as OD-54 does
  for a WebSocket turn. (e) A bare name that is both a file in the working directory and a profile
  is refused rather than resolved either way. Reversal: `_check_window` in `adapters/agent_guard.py`,
  `RestAdapter._before_attempt` and `_handle_final_response`, and `resolve_profile` in
  `cli/wiring.py`.

- **OD-59** (2026-10-27, A-101, ADR-0015; **decided by the owner on 2026-10-27 ("do it all"), as
  built**): four choices of the MCP pins, all four kept as built. (a) Pins live in the target file and are compared in
  the adapter, so one run decides; not taken: compare two reports in `dottore diff`, or re-list
  within a run. (b) Any difference fails, a pinned entry gone included. (c) The operator copies
  the fingerprints from a reviewed run's JSON report (`jq`); a `dottore mcp pin` command is not
  built. (d) `MCP-RUGPULL-001` maps to LLM06, not LLM03: LLM03 is listed out of reach and the
  remap moves the OWASP coverage figure from 8/10 to 9/10, which one spec does not earn (the
  figure stays 8/10). Reversal: `_pin_lines` and
  `catalogue_fingerprints` in `adapters/mcp.py`, `_mcp_spec` in `cli/wiring.py`, the spec's
  `owasp` and `shared/frameworks.py` `OUT_OF_REACH["LLM03"]`.
- **OD-60** (2026-10-27, A-104, ADR-0016; **open, owner to decide; built as the smallest
  reversible version**): (a) isolation is opt-in per target (built) or the default for every stdio
  server, which needs a runtime and an image wherever one is scanned; (b) the container has no
  network (built), so a server that needs its upstream API runs unisolated, or a declared egress
  is allowed through an allowlist inside the container; (c) the block is a top-level key (built)
  or moves under the `mcp:` block A-101 adds, once that lands; (d) a mount holding the home
  directory is refused (built), or also a list of sensitive directories (`~/.ssh`, `~/.aws`) under
  any source. Reversal: `_isolation_spec` in `cli/wiring.py`, the `isolation` branches of
  `MCPAdapter._discover_stdio`, `adapters/isolation.py`.
