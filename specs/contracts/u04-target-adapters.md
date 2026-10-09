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
  main by PR #57, open on 2026-10-09; reproduced end to end by the pre-commit audit of
  `fix/hostile-logprob`, 2026-10-07; `dottore fingerprint`, which writes nothing, exited 0). Every
  reply is now made well formed where it is parsed (`shared.wellformed.well_formed_json`: the base
  adapter's body, so OpenAI, Anthropic and the REST template, and the MCP adapter's JSON body, SSE
  `data:` event and stdio line, the last now decoded with `surrogatepass`, the handler `json.loads`
  decodes bytes with: strict decoding skipped a line with the raw bytes as stray output and the call
  timed out), and so are a tool call's arguments carried as JSON text, which the reply's parse never
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
  secure), and a registered credential split that way is not masked as the credential (each half
  stays readable unless the entropy rule takes it) until the fix for split credentials (PR #57, open
  on 2026-10-09) reads U+FFFD as a splitter, which the owner approved on 2026-10-07 for whichever of
  the two lands second (OD-28); invalid UTF-8 that is not an encoded surrogate (one `FF` byte, a
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
- **OD-21** (open, 2026-10-07): a 200 whose body is not JSON (brackets that do not balance
  included; or not the provider's shape; or JSON with an integer of more than 4,300 digits,
  which Python refuses to read) is
  `AdapterProductError`, and the runner aborts the campaign on it (F5), so one hostile reply of
  `<html>` still stops a scan, where a reply nested too deeply now fails only its attempt.
  Measured with `dottore run` against a local stub: exit 3, "aborted on AdapterProductError", 1
  request sent. Decide whether a malformed success body fails its attempt (inconclusive, as
  `ResponseTooDeep`) or keeps stopping the campaign (a misconfigured endpoint is then caught at
  the first request instead of after the whole battery). A non-retryable 4xx is not in question.
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
  credential split that way is masked once PR #57 (open on 2026-10-09) reads U+FFFD as a splitter,
  which the owner approved for whichever of the two lands second. Not built: an evidence field
  saying a reply was altered (an additive `ModelResponse` field, u00); U+FFFD is the mark.
