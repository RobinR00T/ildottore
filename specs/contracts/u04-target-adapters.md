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
  A body that is not JSON keeps the product-defect rule of §7 (open decision OD-21). A refused
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
2. `openai.py`: chat/completions over httpx; `seed`+`logprobs`+`top_logprobs`; map to `TokenLogprob`;
   capabilities (tools/json/vision/streaming/seed/logprobs = true, subject to config).
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
- `ModelResponse` carries: `text`, `raw` (provider raw, redacted), `logprobs: list[TokenLogprob]|None`,
  `finish_reason`/`stop_reason`, provider request/response ids, echoed sampling config.
- `Capabilities = {tools, rag, memory, streaming, seed, logprobs, multi_identity, multimodal,
  audio: bool}` (as built, `shared/models.py`: nine flags, `audio` added with the audio carrier,
  and no `max_context_tokens` field), and since 2026-10-09 `sampling: bool | None` (u12 A-68:
  `None` is the default rule, not false). All must validate vs `schemas/`.
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
- **Capabilities:** each adapter reports every bool flag (nine as built); parametrized snapshot per provider.
- **Error classification:** 429/503/timeout cassettes ⇒ retry-then-skip (env); a malformed-schema
  200 ⇒ raise (product defect). No defect masked as flake. A 200 whose brackets balance and nest
  deeper than `MAX_DEPTH` (past the parser's stack included), in the body or in a tool call's
  string arguments, ⇒ `ResponseTooDeep` (env, sent once), for every adapter, the MCP transports
  and a WebSocket frame (`WebSocketFrameTooDeep`, a `ResponseTooDeep`, from 64 levels on the
  parsed frame; `tests/adapters/test_websocket_premerge.py`)
  (a body whose brackets do not balance follows the product-defect rule, OD-21, except over MCP
  stdio, where the line is skipped as stray output; tool-call arguments that do not balance read
  as no arguments)
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
  multibyte character cut short) is still a body that is not JSON and stops the campaign on the base
  adapter and the MCP JSON body, while over an MCP SSE stream it reads as U+FFFD and on an MCP stdio
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
  `tests/adapters/test_provider_filter_block.py` (45 tests; it does not collect on `92c7b11`);
  `tests/adapters/test_status_error.py` now sends a plain bad request, since the Azure body it
  sent at 400 is a block.

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
  that carries no figure is skipped and the rest is scored, as before this change, though the
  whole-block reasoning applies to it too (pre-merge audit). Open: whether the evidence should
  say a block was unreadable rather than absent, which needs an additive field on
  `ModelResponse` (u00).
- REST auth-injection surface (header vs query vs body-templated token): propose header-only default
  in MVP-1 to shrink the secret-leak surface: needs sign-off.
- **OD-21** (open, 2026-10-07): a 200 whose body is not JSON (brackets that do not balance
  included; or not the provider's shape; or JSON with an integer of more than 4,300 digits,
  which Python refuses to read) is
  `AdapterProductError`, and the runner aborts the campaign on it (F5), so one hostile reply of
  `<html>` still stops a scan, where a reply nested too deeply now fails only its attempt.
  Measured with `dottore run` against a local stub: exit 3, "aborted on AdapterProductError", 1
  request sent. Decide whether a malformed success body fails its attempt (inconclusive, as
  `ResponseTooDeep`) or keeps stopping the campaign (a misconfigured endpoint is then caught at
  the first request instead of after the whole battery). A non-retryable 4xx is not in question.
  The same rule covers a WebSocket frame that is not JSON, is not an object, or is binary (as
  built in PR #87: `run` exits 3 with "aborted on AdapterProductError: ... a frame was not valid
  JSON", measured against the loopback chat server on 2026-10-09), so the decision covers both;
  a text frame that is not UTF-8 is not in it, since the library refuses that one before the
  adapter reads it (`WebSocketUndecodable`, inconclusive and not retried, §4).
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
- **OD-34** (open, 2026-10-07, PR #87; it numbered these four OD-30 to OD-33, which `main` and
  PR #88 had taken, and they were renumbered on 2026-10-09): a WebSocket target's frame
  transcript lives in `ModelResponse.raw_ids["websocket"]` rather than in a dedicated field. A
  `transcript` field on the frozen u00 `ModelResponse` would be the honest shape, but it changes
  every stored attempt's dump and the report snapshots; the nested value is skipped by the
  fingerprint's envelope layer. Decide whether to add the field.
- **OD-35** (open, 2026-10-07, PR #87): a WebSocket target's `session.one_query_in_flight: false`
  is refused. Several concurrent queries on one socket need a correlation id in the templates and
  in the reply frames; whether that is wanted, and how a target declares it, is the owner's call.
- **OD-36** (open, 2026-10-07, PR #87): a WebSocket reconnect is attempted only before a query is
  on the wire, and never more often than the adapter's own retry allowance: under `run` (and
  `-sV`, the identity sweep and a metered judge) every live adapter retries nothing itself, so a
  socket that fails to open is retried by the runner, one debited and paced send per dial (since
  the pre-merge audit of 2026-10-09: `max_attempts: 1` made 8 dials for 4 debits). A connection
  closed mid-turn is an environment error the runner retries and debits; the adapter never
  resends a query on its own, so no send escapes the ledger. A later turn of a multi-turn attempt
  whose connection is gone is inconclusive, never a silent new session. Whether a stateless
  server (`{{messages}}` in the template) should be allowed to reconnect mid-conversation is open.
- **OD-37** (open, 2026-10-07, PR #87): `dottore fleet` infers `rest` from a `wss://` endpoint and
  writes no `websocket:` block, and `run` refuses the file it writes (a `ws://` or `wss://`
  endpoint is dialled only by `provider: websocket`), so a WebSocket target is declared by hand
  today; the scope `fleet` writes pins the port (443 for `wss`, 80 for `ws`). Whether a fleet
  entry should carry the block is open.
