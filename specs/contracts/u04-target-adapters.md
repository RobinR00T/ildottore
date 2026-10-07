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
where the reply is parsed (§7 A-47).

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
- **Capabilities:** each adapter reports every bool flag (nine as built); parametrized snapshot per provider.
- **Error classification:** 429/503/timeout cassettes ⇒ retry-then-skip (env); a malformed-schema
  200 ⇒ raise (product defect). No defect masked as flake.
- `ruff check`, `ruff format --check`, `mypy src/ildottore/adapters` clean; `lint-imports` green
  (adapters import only `shared` + u01 interfaces + httpx: never evaluators/core, `docs/01 §2`).
- **A-47 A reply that holds half a character is kept and judged, and nothing downstream sees a
  lone surrogate (added 2026-10-07).** JSON lets a string escape any UTF-16 code unit, so a reply
  can carry a surrogate (U+D800 to U+DFFF) with no partner, escaped or as its raw UTF-8 bytes
  (`ED A0 80`, which `json.loads` decodes with `surrogatepass`), and Python keeps it as a code
  point that no UTF-8 writer accepts. One such reply, in the text, the `id`, the `model` echo, a
  logprob token or alternative, a tool call's name, made `dottore run` exit 3 ("aborted on
  UnicodeEncodeError ... 2 of 2 specs never ran", no evidence written: the evidence store hashes
  the encoded payload) and `run -sV` exit 3 with no report (the probe evidence); a multi-turn spec
  sends the reply on in its next request and the `--judge` request quotes it, and httpx raised the
  same error encoding either (the judge received nothing); sqlite and pydantic's JSON serializer
  refuse it too (pre-commit audit of `fix/hostile-logprob`, 2026-10-07; `dottore fingerprint`,
  which writes nothing, exited 0). Every reply is now made well formed where it is parsed
  (`shared.wellformed.well_formed_json`: the base adapter's body, so OpenAI, Anthropic and the
  REST template, and the MCP adapter's JSON body, SSE `data:` event and stdio line, the last now
  decoded with `surrogatepass` as `json.loads` decodes bytes: strict decoding skipped a line with
  the raw bytes as stray output and the call timed out), and so are a tool call's arguments
  carried as JSON text, which the reply's parse never opens (`shared.toolcalls.call_arguments`,
  read by the evaluators and the in-band tool loop): a lone surrogate reads as U+FFFD, a high half
  followed by a low half is the character the pair encodes, every other character is kept, and
  keys are treated like values; two keys that read the same once replaced keep both values (the
  replaced one takes the next `, #n`; a key the target wrote well formed keeps its name). A reply
  with no surrogate is returned as it is, the same object (copying every reply tripled the peak
  memory of a 4 MiB body of small containers: pre-commit audit). The attempt is evaluated on that
  text, so a leak with half a character beside it still fails (`tests/cli/test_lone_surrogate.py`:
  29 of its 36 cases fail on `0501752`, all on the surrogate, and the other 7, `fingerprint` and a
  well formed pair, pin what already held; `tests/adapters/test_lone_surrogate_replies.py`, 9 of 9
  fail there, the raw stdio line on the timeout; `tests/shared/test_wellformed.py`). Not claimed:
  which code unit stood there (the evidence shows U+FFFD, as for a U+FFFD the target sent: OD-28);
  the same bytes do not read the same on every transport (raw `ED A0 80` is one U+FFFD where a
  body is parsed as bytes and three over an MCP SSE stream, which httpx decodes as text first; a
  CESU-8 pair joins into its character in the first and is six U+FFFD in the second); half a
  character inside a canary or a registered credential splits it as a zero-width space does
  today, so the canary is not found and, until a fix for split credentials reads U+FFFD as a
  splitter, the credential is not masked (OD-28); invalid UTF-8 that is not an encoded surrogate
  (one `FF` byte, a multibyte character cut short) is still a body that is not JSON, a product
  defect that stops the campaign; the walk that looks for a surrogate visits the whole parsed
  reply, so a hostile 4 MiB body of tiny containers costs some 3 to 7 times its parse, and twice
  that when it holds one and is copied (measured under load, bounded by the 4 MiB cap); the
  judge's reasoning, parsed from the judge's text past its adapter, can still hold one, measured as
  harmless because it is neither persisted nor printed (the aggregate verdict writes its own
  reasoning); a spec file whose YAML holds the escape is the operator's input, not a reply: it
  passes `dottore lint` and `run` refuses it with exit 3 before sending, on the same codec error,
  from the battery digest (`shared/digest.py`), without naming the spec.

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
- **OD-28** (open, built reversibly, 2026-10-07, A-47): what a reply that holds a lone surrogate
  becomes. Built: it is read as U+FFFD where it is parsed and the attempt is evaluated as usual.
  The other ways: delete the half instead, which would find a canary and mask a registered
  credential that half a character splits (with U+FFFD the canary spec is inconclusive, as with a
  zero-width space today, and the credential is masked only once a fix for split credentials,
  open PR #57, reads U+FFFD as a splitter), at the cost of evidence that no longer shows anything
  stood there; keep which code unit it was as a visible marker in the text (such as `[U+D800]`),
  which the evaluators would then read as reply text; refuse the reply as an environment error,
  inconclusive and not retried (as open PR #65 proposes for a reply nested too deeply), which
  costs a detection, since a target that adds six characters to a leaking reply makes it "not
  evaluated" (`test_a_lone_surrogate_does_not_hide_a_leak`); or replace it only where the evidence
  is written, which does not hold: a multi-turn spec and the `--judge` request send the reply on,
  and httpx raised encoding it (measured). Also the owner's: whether the evidence should say a
  reply was altered (a count needs an additive `ModelResponse` field, u00).
