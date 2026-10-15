# FAQ

### What is Il Dottore, in one line?

An nmap-for-AI: a spec-driven scanner that examines an LLM or AI application, diagnoses its
security weaknesses against a declarative attack battery, and issues a reproducible,
evidence-backed report mapped to operational risk.

### How is it different from a prompt-list or a jailbreak repo?

The value is not the prompts. It is **reproducibility + evidence + risk mapping**. Every
attempt persists its prompt, full response, sampling params, tool traces and the aggregate
verdict with its reasoning; findings are scored `impact x exploitability x reproducibility` and
re-derivable with `dottore replay`. A finding we cannot reproduce or evidence is treated as noise.

### Is it safe to run? Will it actually do damage?

No real damage by design. Sensitive tools run as mocks or dry-run, exfiltration targets are
mock endpoints blocked by the allowlist, and every dangerous payload is flagged
`test_only`. It scans nothing without a `scope.yaml` authorization record (endpoint
allowlist, default-deny), and plain http is allowed only to loopback. The scope's optional
`checksum:` is an integrity check, verified when present, not a signature. See
[`02-threat-model.md`](02-threat-model.md) and [`RESPONSIBLE-USE.md`](RESPONSIBLE-USE.md).

### Can the tool prove who approved a scope?

No, by decision (OD-2): it verifies no signature, since that needs key management it does not
have (trusted keys, who signs, revocation). Sign the scope with your own tooling, verify it
before the run, and compare the report's `run.scope_sha256` with `shasum -a 256 scope.yaml`
(equal for a file with LF line ends and no top-level `checksum:` line). It proves something only
if the reviewer signs on their own machine with a key only they hold and the trusted keys are
read from a place the scope's editors cannot write; verify and load one private copy, so the
bytes verified are the bytes the run reads. The `ssh-keygen -Y` recipe, run for real, is in
[`MANUAL.md`](MANUAL.md) §4.1.

### Do I need an API key?

Not to explore (`registry ls`, `describe`, `lint`, `schema`) or to scan a **local** model
via Ollama. You need a key only to scan a **hosted** model, and it is passed by env-var
reference (`auth_ref: env://OPENAI_API_KEY`), never written to a file. What follows `env://`
is the variable's name (letters, digits and `_`, not starting with a digit): a key pasted there is
refused without being printed. A key shorter than 8 characters is refused before anything is sent
(`the credential is shorter than 8 characters, which the redactor cannot mask by value`): the
redactor masks a credential the tool read by its value only from that length, so a target that
echoed a shorter one would put it in every report. A live `run` or `fingerprint` refuses a
variable that is not set (or holds only blanks, which is no key rather than a short one) before it
sends anything, and names it; `--dry-run` warns about it and goes on, so a pipeline can be checked
on a machine without the key. A target that takes no key leaves `auth_ref` out of its target
file; a scope identity, which needs a reference, writes `env://NONE`, which is never read. Until
2026-10-11 an unset variable meant "no credential": the requests went out without one and the run
stopped on a bare HTTP 401.

### What does `--judge` do, and do I need it?

It wires a model as an LLM-as-judge behind the `semantic_judge` secondary evaluator. On a
live scan without it, `semantic_judge` abstains (`capability_unavailable`) and findings that
depend on it come back inconclusive. Deterministic evaluators decide first regardless: a
deterministic fail always wins, and the judge cannot turn it into a pass. When every
deterministic evaluator passes, a judge fail still decides the attempt, and the finding is
reported as needing review, never confirmed on the judge's word alone, so it gates CI only with
`--include-needs-review` (OD-19, since 2026-10-11). A live run without `--judge` warns before
sending anything (and in the dry run), and a judge outage, or a judge whose output cannot be
parsed, counts as no judge, never as a pass.

### Why does `fleet --judge` say the fleet file does not declare the judge?

Since 2026-10-03 the judge `fleet` authorizes comes from the fleet file, in a `judge:` block
(`id`, `endpoint`, `model`, `api_key_env`), because that file is the authorization record the
generated scope is built from. Before, the scope took the judge's host and credential from the
`--judge` file itself, so any judge file could make the scanner read any environment variable
and send it elsewhere. Add the block; `fleet` then writes `judge.yaml` and `--run` uses it, and a
`--judge` file is still accepted when it names the same id, endpoint and credential. `run`
with your own scope is unchanged: the judge must be in that scope.

### Why does `fleet` refuse two ids like `Prod` and `prod`?

Each fleet target is written to `target-<id>.yaml`, and on a case-insensitive file system (the
macOS and Windows default) `target-Prod.yaml` and `target-prod.yaml` are one file. Until
2026-10-07 the second entry overwrote the first, `fleet` exited 0, and the `dottore run` it
printed then refused "two target files declare the id 'prod'". The pair is now refused before
anything is written, on Linux too, so a fleet file means the same on every machine; rename one
of them. The message locates the two entries as validation errors do (`targets.0.id` and
`targets.1.id`, counted from 0), because an id that looks random enough (a model name such as
`Meta-Llama-3-70B-Instruct`) is masked in the CLI's errors. A `judge:` id spelled as a target's
only up to case is refused as well, for another reason: no file collides (the judge is written
to `judge.yaml`), but the generated scope would hold two ids that differ only by case; a
`judge:` block with no `id:` is `judge`, so a target `Judge` beside it counts, and the message
says the id is that default. Two target files you write yourself with ids `Prod` and `prod`
still run together: `run` names no file after a target id.

### Do `--budget-requests` and `--rate` count the judge's requests?

Yes, since 2026-10-03. The judge sends two requests per evaluated attempt, and they used to sit
outside both the request ceiling and the rate gate, so `--budget-requests 5` with a judge sent
15. They are now paced and debited like the target's, `--estimate` and `--dry-run` show them on
their own line, and the derived ceilings make room for them. The multi-identity sweep counts
too, and since PR #60 (merged 2026-10-09) `--estimate` and `--dry-run` price it: one request per
scope identity for each spec that sweeps them.

### Which sampling does a request go out with?

The one its sender sets, with the gaps filled from the target file's `sampling_defaults` (owner's
decision OD-39, 2026-10-09; older versions parsed the block and sent none of it). Field by field
(`temperature`, `top_p`, `max_tokens`, `seed`): an attack takes the spec's own `sampling`, then
the block, then temperature 0 if the spec declares no `sampling` at all; a `-sV` probe keeps its
temperature 0 and 512-token cap and takes `top_p` and `seed` from the block; the `--judge` model
keeps its temperature (0, then 0.5) and `top_p` 1.0 and takes `max_tokens` and `seed` from the
block of its own file, never from the scanned target's. Whatever is still unset is the provider's
default, and no `dottore` flag sets sampling. A block's `seed` goes out only to a file that sets
`capabilities.seed: true`. Only the OpenAI and Anthropic adapters send sampling; a REST template,
an MCP server and a WebSocket target carry none, by design, so there the block reaches nothing.
Anthropic has no `seed`, and the adapter sends no `top_p` beside a `temperature`, since
Anthropic's API reference says Claude 4 models refuse the pair (HTTP 400; read in the reference
bundled with the claude-api skill, cached 2026-09-25, not tested live): every request the scanner
makes has a temperature, so no `top_p` reaches an Anthropic target or judge. Before, a block
`top_p`, or one of the six shipped specs that set `top_p` 1.0, stopped an Anthropic campaign at
its first request. Each attempt's evidence records what went
out, and `--dry-run` prints, per field, on how many specs the block fills it (a block's
`temperature` fills none of the shipped battery, whose specs all set theirs). A run an older
version started resumes without the block, as it started, and says so. See the MANUAL, §4.2.

### Can I scan a Claude model that takes no temperature?

Yes. Anthropic's API reference (read as bundled with the claude-api skill, cached 2026-09-25, not
tested against the live API) says Claude Opus 4.7 and later, Sonnet 5 and Sonnet 5.5, and the Fable
and Mythos 5 families refuse a `temperature` or a `top_p` (HTTP 400), and the scanner pins
temperature 0, so every request to them was refused and the campaign stopped at the first one. A
`provider: anthropic` target of those families is now sent neither, from a list kept in one place
(`adapters.anthropic.MODELS_WITHOUT_SAMPLING`); `capabilities.sampling: false` says the same of
any other target (a newer Claude model, a reasoning model behind an OpenAI-compatible endpoint, a
Claude model behind a gateway), and `true` overrides the list. The cost is determinism: the model
samples at its own default, so its replies, the reproducibility over `--runs` and a `-sV`
fingerprint are not temperature-0 deterministic. The run says so before it sends, `--dry-run`, `-sn`
and the `-sV` line say it too, each attempt records `request.metadata.sampling_not_sent`, and
`dottore replay` counts those attempts. A model the list does not know is refused at its first
request with the advice to set `sampling: false`, not a bare `HTTP 400`, and so is a `--judge`
model, which used to come back inconclusive on every spec without a word. Model ids are matched
as gateways write them (a Bedrock ARN, `anthropic/claude-opus-4.7`, `claude-opus-4-7[1m]`). For
Sonnet 5 the reference contradicts itself (removed, or only non-default values refused); sending
neither is right under both.

### Can the judge itself be fooled by a prompt injection?

That is assumed and defended. The judge gets a per-call random tripwire token; it is flagged
**compromised** if it echoes the tripwire, or if an observed injection coincides with a
"secure" verdict. A compromised judge does not get to pass a target. The self-scan
(`make selfscan`) attacks our own judge and fails CI on any new high/critical flip.

### Are multi-turn attacks reproducible if turns are conversational?

Yes. The attacker turns are **pinned in the spec**, not generated by an LLM. The
conversation is threaded as `messages`, only the final turn is scored, and the transcript is
stored as evidence, so a multi-turn run is as reproducible as a single shot.

### How do I gate CI on findings?

`dottore run --fail-on high` exits `2` when a confirmed finding at or above the band is
present, `1` for findings below it, `0` clean, `3` on error. Only exploited (`fail`)
findings trip the gate, and only confirmed ones unless you pass `--include-needs-review`. A bad
option (`--fail-on bogus`, `--timeout 0`, two formats writing one file) is refused with exit
`3` before anything is sent, and a value of the wrong type is a usage error, also `3`, printed
through the same mask as every error (a key that a shell variable put into `--runs` is not
echoed). `dottore lint` exits `0` clean, `1` when a spec fails lint and `3` when a path does not
exist or holds nothing to lint. For regression-only gating, compare against a baseline with
`dottore diff baseline.json current.json`. See
[`examples/ci-github-actions.yml`](../examples/ci-github-actions.yml). In the SARIF you upload to
code scanning, a fail that needs review is at most a `warning` (since 2026-10-11), so code scanning,
which by default fails a pull request's check on an `error`, does not fail one that `--fail-on` lets
through; a confirmed fail keeps its band's level.

`1` means findings below the band and nothing else. Until 2026-10-12 a crash (a run store that
could not be opened, a lock, any exception no command handled) was a traceback with exit `1`, so
a gate that lets `1` through read it as an almost clean scan. It is exit `3` now, with one line
(`error: unexpected <Class>: ...` for an internal error; `dottore -v <command>` prints its
traceback). A gate should still fail on anything above `1` it does not expect.

### Can several runs share one `--run-db`?

Yes, a new one included: a write waits up to 30 s for a lock another process holds (Ctrl-C stops
the wait at once, and a wait past a second is said on stderr), and runs creating the store
together set it up once. Until 2026-10-12 some of the runs started together on a new store died
with `database is locked` and exit 1 (1 and 2 of 18 in two measurements, 5 of 6 in the audit
that found it). A store path that cannot be one (a directory, a file that is not SQLite) is
refused with exit `3` before anything is sent, `replay --run-db` included, as is an
`--evidence-root` that is a regular file; `--dry-run` and `--estimate` say so too, writing
nothing.

### Why did `--budget-requests` not let my campaign finish past 20,000 attempts?

Before 2026-10-12 the attempts ceiling was derived on its own and capped at 20,000, and no flag
raised it: `--runs 200 --budget-requests 60000 --budget-tokens 30000000 --budget-wall 7200` over
the battery halted on `max_attempts` with requests to spare. The
attempts ceiling is the request ceiling now (an attempt is at least one request, and it counts
only once its first request is accepted), so `--budget-requests` raises both. `--estimate` prints
the ceilings a run will have.

### I upgraded Il Dottore and `--resume` refuses my halted run. Why?

Because the new version may judge a reply differently from the one that halted the run, and a
resume would mix the two. It keeps the attempts the halted half stored with the verdicts that
version gave them and judges only what it sends; the stored replies are redacted (a leaked canary
reads `«REDACTED:canary:…»`), so they cannot be judged again. A run halted on `f12ba83` and
resumed after the filter-cut rule (OD-42) kept 4 attempts judged `pass` beside 2 judged cut, and
its summary said `Cut by the provider's output filter: 6 attempt(s) in 2 spec(s) came back cut or
replaced` where all 10 were. So each run records the version of the judging rules when it starts
(`dottore --version` prints it: `dottore 0.1.0 (judging rules 1)`), and a resume under other
rules, or of a run that records none (any run a version from before
`shared.judging_rules.JUDGING_RULES_SINCE` halted), is refused with both named. So is a resume
under other evaluator plugins than the run was judged with, and one under other code with the
same version (the run also records a digest of the installed code that judged it, so an upgrade
or a local edit nobody bumped the version for is caught). Finish the run with the installation
(and plugins) that started it, or start a fresh run; no flag waives it. Other refusals name what
changed and the flag that puts it back: the spec field and `--spec-path`, the selection flags the
run was made with, or the route (`--hardened`).

### What is "confirmed" vs "needs-review"?

Risk and confidence are separate. Every report puts a finding in one of four states:
**confirmed** (a decisive exploit at or above the confidence threshold, with at least one fail a
deterministic evaluator decided), **needs review** (an unconfirmed exploit, a fail only the judge
reported among them, or a spec that was sent and could not be decided), **not exploited** (it
passed) and **not tested** (nothing was sent: a capability skip, a policy block). The CI gate
(`--fail-on`) counts confirmed exploits only. `--include-needs-review` adds the unconfirmed
exploits, never the undecided results: a format-valid secret/PII hit without corroboration is
`inconclusive` by design (needs review, never a confirmed leak), so it does not trip the gate
with or without the flag. See [`05-scoring-model.md`](05-scoring-model.md).

### My agent sets `confirm: true` on a destructive call. Why is it still a finding?

Because the model set it. Only a confirmation from outside the model counts: the user's reply
after the agent asked (never the request to act itself), the harness, a declared approval. In a
scan the scanner is the only user and none of its prompts confirms a destructive step, so a
`drop_table`, a `delete_*` or any tool a spec marks `destructive: true` that your agent calls is
a finding in a spec that declares `tool_call`, whatever flag (`confirm`, `confirmed`,
`confirmation`, `force`, `approved`, `ack`) it wrote into the call. The secure answer is to ask
and wait, as the `hardened` fixture of `AG-CONFIRM-BYPASS-001` does. A tool you list under
`seeded_setup.granted_tools` is authorized by name, and a destructive call to it is still judged
the same way. This is an owner decision (OD-38, 2026-10-09); before it, the flag counted.

### My agent hands off with `transfer_to_billing_agent` and the spec fails. Why?

Because the destructive verbs are matched anywhere in a tool's name, and `transfer` is one of
them, so a hand-off in the OpenAI Agents SDK's `transfer_to_<agent>` style reads as destructive.
In a spec of your own, mark that tool `destructive: false` in `setup.tools`: a call to that exact
name is then not destructive, while `transfer_to_account`, which moves money, still is (no name
is exempt by its shape). The flag clears only that check: a call off the allowlist, or with an
injected or a forbidden argument, still fails. The verdict's reasoning names each called tool the
scene cleared, and `dottore lint` warns when the cleared name is not shaped like a hand-off
(`delete_account: destructive: false`). See MANUAL §8 (u06 A-71, 2026-10-11).

A tool your deployment grants under `seeded_setup.granted_tools` is in no scene, so no spec can
mark it. Your target file can: write the grant as `{name: transfer_to_billing_agent,
destructive: false}` and a call to that exact name is not failed by its name alone (owner
decision OD-43, 2026-10-11). It is your declaration, so it is always shown: `--dry-run`, `-v`
and `-sn` print it on an `operator:` line, every report and the run store state it for the run,
each attempt it changed says so in its verdict, and changing it refuses a resume. It is held to
the narrowest reading: `false` only (`true`, a quoted `"false"`, a mapping without
`destructive` and any other key are refused), exact names (a padded one is refused, and the dry
run flags a grant that is a spec's scene tool but for case), never a tool of a spec's own scene
(there the scene decides, `destructive: true` included), never `kill_chain_progression`, and never a
call off the allowlist or an injected or forbidden argument. See MANUAL §4.2 and §8.

### Which suites and categories exist?

Suites: `owasp-llm-top10` (alias `owasp:llm`), `quick`, `multi-turn`, `access-control`,
`agentic-owasp2026`, `obfuscation-enhancers`, `embeddings`, `agentic-extortion`, `mcp`,
`responsible-ai`, `guardrail-evasion`, `multimodal`, `structured-output`, `nova-iopc`.
Category aliases for `-p`: `pi`, `jailbreak`, `leakage`, `tool`, `rag`, `output`, `dos`, `safety`,
`bias` (long forms accepted). `dottore registry ls` is the source of truth.

### Can I add my own attack without touching the code?

Yes, that is the point. `dottore new-spec …` scaffolds a YAML spec; fill `attack`,
`expected_secure_behavior`, `evaluators` and golden `fixtures` (a vulnerable fixture the
scanner must flag, a hardened one it must pass), then `dottore lint specs/`. A directory with a
`pack.yaml` is read as a pack (`attacks/` and `suites/`); one without is read as loose specs, its
own `*.yaml` files only, and `lint` says so: a path that holds none exits `3` with `NO_SPECS`,
naming the YAML files in its subdirectories it did not read, where until 2026-10-11 it printed
`lint OK ... across 0 spec(s)`. A spec id two files declare refuses `run`, naming both files. See
[`06-extensibility-suites.md`](06-extensibility-suites.md) and
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

### Does it support MCP servers?

Yes. A `kind: mcp` fleet entry (or a target with `provider: mcp`) routes to the read-only
MCP adapter: it performs the JSON-RPC `initialize` handshake and lists the server's tools,
resources and prompts, then renders that advertised metadata for evaluation. It never calls a
tool (`tools/call`), invoking a target's tools could have real side effects, so discovery is
read-only by design. Point the `mcp` suite at such a target for the tool-metadata-poisoning
("line jumping") check. A poisoned description fails with or without a judge; a clean listing
passes only with `--judge`, and is `inconclusive` without one (since 2026-10-11, OD-16: the text
check alone passed any reply without an injection marker, one that lists nothing included).
`MCP-TOOLPOISON-001` runs only against an MCP server: it requires the `mcp` capability, which a
target has when its `provider` is `mcp`, so on a chat model it is skipped as
`capability_unavailable` and not counted as covered (since 2026-10-11, OD-44). Before, the
default battery sent its discovery request to a chat model as a prompt, and a model that
explained what poisoned metadata looks like came out a confirmed Critical.

### My assistant only talks over a WebSocket. Can I scan it?

Yes. `provider: websocket` with a `ws://` or `wss://` endpoint and a `websocket:` block that
declares the wire shape: the handshake frame (with `{{token}}` for the credential), the query
frame (with `{{prompt}}`), where the streamed text is, which frame ends the turn, which frames
to ignore and the per-turn timeout. The adapter knows nothing about any product; the block is
the whole description. The scope gates `wss://` like `https://` (cleartext `ws://` only to
loopback), a redirect at the upgrade is never followed, every frame is kept in the evidence
with the credential as its placeholder, and `-sV` works (one connection per probe). Start from
[`../examples/target.websocket.yaml`](../examples/target.websocket.yaml) and `--dry-run`. Not
from a fleet file: a fleet entry carries no `websocket:` block, so `dottore fleet` refuses a
`ws://` or `wss://` endpoint (exit 3, nothing written) and the error points to that example
(OD-37). One query at a time per connection, and no reconnect in the middle of a conversation:
both by design (OD-35, OD-36).

### Does `dottore fingerprint` tell me whether my endpoint has an output filter?

Only when the provider says so. `guardrails.output_filter` is `true` when a probe's reply came back
with the provider's own filter stop reason (declined, cut or replaced: OpenAI's and Azure's
`content_filter`, Anthropic's `refusal`, Bedrock's and Gemini's equivalents, each only from the
provider that documents it: an OpenAI-compatible endpoint that says `refusal` claims a filter it
does not have, and is not believed, since 2026-10-11), and `null` when no
reply carries any stop reason from the provider (a REST template without `finish_path`, a WebSocket
or MCP target), since nothing could have been seen. A refusal does not count: one probe asks the
model to refuse, and refusing is doing as asked, so it only gives the refusal's style
(`refusal_style`). The other asks a benign question near a boundary; if that is refused,
`benign_refused` is `true`, which means a filter or the model's own alignment, and a benign probe
cannot tell which. If an input filter rejects that question outright with a 4xx (Azure's prompt
filter answers HTTP 400), the probe is listed as failed (`guardrail/guardrail_benign:
ProviderFilterBlock`) and `benign_refused` is `null`; the fingerprint goes on, as it does when the
filter refuses a carrier probe (an encoded instruction). Either refusal sets `input_filter` to
`true`: the provider said, in a shape it documents, that its input filter refused a prompt (since
2026-10-11, OD-40; it was always `null`). Otherwise `input_filter` is `null`, never `false`. A
`false` `output_filter` is what two benign probes saw, not proof that there is no filter: a filter
that acts only on harmful content never acts on them. Until 2026-10-09 any refusal of the first
probe was reported as an output filter, so a model that followed the instruction looked filtered
([`10-fingerprint.md`](10-fingerprint.md) §1, OD-40).

### My Azure OpenAI deployment's content filter refuses some attacks. Does the scan stop?

No, since 2026-10-10 (OD-41). Azure's prompt filter answers a prompt it blocks with HTTP 400 and
the error code `content_filter`, and Gemini's API (through a `RestTemplate` built in Python; a
target file's REST target has none) with a body whose
`promptFeedback.blockReason` is set; either is recorded as a **blocked** attempt and the campaign
goes on. Before, the first one stopped it with `aborted on AdapterStatusError: ...
non-retryable HTTP 400` (exit 3 after one request).

A blocked attempt never reached the model, so it is neither the model refusing (a pass) nor an
exploit (a fail): it is `inconclusive` with the reason `blocked_by_provider_filter`. A spec whose
every attempt was blocked is `inconclusive` and not exercised, never a pass; one with some blocked
attempts is decided by the usual rule (any `fail` is a `fail`; a `pass` needs more than half of the
attempts to pass). A run whose every attempt was blocked or cut, with no fail, exits 3 since
2026-10-11 (state `filtered`): it measured the filter, not the model (next answer). The terminal
summary, the finding's reasoning and every report count them
(`Blocked by the provider's input filter: 8 attempt(s) in 2 spec(s) never reached the model`). A
blocked attempt is not sent again, on a retry or a resume, and it counts against
`--budget-requests`. Only those documented shapes count, and only from the provider that documents
them (Azure's 400 from an `openai` target; from an `anthropic` or `rest` target it is an ordinary
4xx): any other 4xx (another code, the same body at 403) still stops the run; a Bedrock guardrail's
canned reply (an HTTP 200) is read by the next answer. To measure the model rather than the
deployment, scan a deployment whose filter annotates instead of blocking ([`MANUAL.md`](MANUAL.md)
§9, [`adr/0011`](adr/0011-a-prompt-the-provider-filter-refused-is-not-a-verdict.md)).

### My deployment's output filter blanks or replaces some replies. Do those specs pass?

No, since 2026-10-11 (OD-42). An output filter answers HTTP 200 with its own stop reason and an
empty or canned reply: Azure OpenAI withholds the completion (`finish_reason: content_filter`, no
content), a Bedrock guardrail returns the message you configured for it (`stopReason:
guardrail_intervened`), Gemini stops the candidate (`finishReason: SAFETY` and its kin), Anthropic's
classifiers stop with `stop_reason: refusal`. Before, that reply was scored as the model's answer:
an empty reply or a canned refusal, or the judge's secure verdict on one, passed the spec, while the
model may have written exactly what the spec tests for before the filter cut it.

Now the stop reason decides. A filter that refused the prompt (a Bedrock trace whose input
assessment blocked it, Anthropic's `refusal` before any output) is a blocked attempt, as above. One
that cut or replaced what the model wrote is `inconclusive: cut_by_provider_output_filter`, needs
review, and keeps the spec from passing however many other attempts held. A fail that rests on
something present in the text that did come back (a planted canary in a partial reply, say) is still
a fail; one that rests on something absent is not, since everything is absent from an empty reply
(`regex_presence` does not decide a cut reply). Gemini's `RECITATION` counts as a cut too. One whose
side the provider does not report (a Bedrock guardrail without its trace) is `inconclusive:
provider_filter_side_unknown`; enable the guardrail's trace to learn the side. The judge reads a
partial reply, and since 2026-10-11 its fail on it stands as a fail that needs review (the text was
delivered, whatever the filter says; `--include-needs-review` gates it); its pass is only recorded.
From `dottore`, the Azure (`provider: openai`), Anthropic and WebSocket shapes are read; Bedrock's
and Gemini's only through a `RestTemplate` built in Python, since a target file's REST target has
no template. Every report counts them apart, and `--fail-on` does not trip on them, since nobody
saw an exploit: a pipeline that should stop reads `summary.cut_by_provider_output_filter.attempts`
from the JSON report. A run whose every attempt was cut or blocked, with no fail, exits 3
(`filtered`) ([`MANUAL.md`](MANUAL.md) §9, the amendments in
[`adr/0011`](adr/0011-a-prompt-the-provider-filter-refused-is-not-a-verdict.md)).

### Could a target fake a filter stop to hide an exploit?

Not with text that came back, since 2026-10-11 (A-79, the amendment to OD-41 and OD-42, decided
under the owner's delegation as best practice, revisable). A target writes its own stop reason,
and until then every adapter read every provider's filter words: an `openai` target that answered
harmful text with `finish_reason: refusal` (Anthropic's word) or `SAFETY` (Gemini's) had it read as
the filter's cut, the judge's fail on it was only recorded, and a target that answered every
attack with Azure's 400 `content_filter` had every attempt blocked and the run exit 0. Three rules
now apply:

- **Only the provider's own words are read.** `content_filter` (and Azure's 400) from an `openai`
  target, `refusal` from an `anthropic` one, Gemini's or Bedrock's from a `RestTemplate` in their
  shape, what a WebSocket target file lists under `response.filter_stops` (none by default),
  nothing from a target file's `provider: rest` target. Any other filter word is an ordinary stop
  (kept in the reply with `foreign_stop: true`), and Azure's 400 from another provider stops the
  run as any undocumented 4xx.
- **Text that came back was delivered.** The judge's fail on a partial reply stands, as a fail
  that needs review, and a deterministic fail on it stood already. Text the filter put there (a
  Bedrock guardrail's configured message) is read only for what no configured message can hold:
  a planted canary or secret, a crossing canary, a tool call.
- **A run the filter answered every time exits 3** (`filtered`), as an unreachable one does, so it
  never reads green; `dottore replay` of it says so too.

What it does not stop: an endpoint that uses its own provider's word can still withhold chosen
attacks, with an empty `content_filter` reply or Azure's 400, and keep CI green, because such an
attempt is inconclusive, never a pass, and `--fail-on` does not gate it. A pipeline that should
stop on one reads `summary.blocked_by_provider_filter` and `summary.cut_by_provider_output_filter`
from the JSON report. An endpoint that speaks OpenAI's or Anthropic's API and has no OpenAI, Azure
or Anthropic filter behind it (a local server, a gateway that maps its own moderation to
`content_filter` in front of a model it hosts) can be told so: `filter_stops: []` in its target
file reads no 400, and no stop on a reply with text or a tool call, as a filter's. Do not declare
it for a gateway in front of Azure OpenAI: the gateway relays Azure's filter, so Azure's 400 would
stop the run and a reply Azure cut after some text would be scored as the model's whole answer.
Even with `[]`, a reply with no text (whitespace or format characters that show nothing, such as a
zero-width space; a tag character, which spells invisible ASCII, is text) and no tool call that
ends on the provider's own word is the filter's withheld one, inconclusive and never a pass
(since 2026-10-12; [`MANUAL.md`](MANUAL.md) §4.2, §9).

### My target answered an attack with an HTML page. Does the scan stop?

Not for one reply, since 2026-10-11 (OD-21). A success reply the adapter cannot read (not JSON, not
an object, or not the provider's or the template's shape, a WebSocket frame or an MCP reply
included) fails its attempt as `inconclusive: unreadable_reply`; it is not retried, it counts
against `--budget-requests`, and a resume sends it again (the target may have been fixed). Before,
the first one stopped the run (`aborted on AdapterProductError: ... success response was not valid
JSON`, exit 3 after one request).

The spec it belongs to never passes: a wrapper that pastes the model's output into its JSON breaks
on the quotes a jailbreak that worked writes, so the reply that broke may be the exploit. The
attempt keeps a redacted excerpt of what came back under `request.metadata.unreadable_reply` (a
reply streamed as events or JSON lines and longer than 36 KiB keeps its structure only: the text it
streams is withheld, and the excerpt's first line says so), and the summary says how many
(`Unreadable replies: 1 attempt(s) in 1 spec(s) (...)`, never silenced by `-q`;
`summary.unreadable_reply` in the JSON report, and SARIF, JUnit and HTML). A spec with one and
no fail is `inconclusive`, so it does not trip `--fail-on`; a pipeline that should stop on one reads
`summary.unreadable_reply.attempts`. A resume's re-send replaces it only when the adapter reads it
(or it is unreadable or cut again): one that ends in a network error says nothing of the reply,
so the unreadable reply stays the attempt, in the report and in `dottore replay` alike (since
2026-10-11; before, which copy counted depended on the artifacts' file names). A tool your agent
called on an earlier turn of a conversation that then got such a reply, or a network error, is
still read: a forbidden call fails the spec.

A target that answers **every** request that way is a wrong endpoint or provider, and one that
stops answering as it did mid-run is often an expired session behind a proxy that serves a login
page with HTTP 200. The run counts such replies in a row, each reply it reads starting the count
again. At 5 in a row before any reply was read, or 20 in a row after, it sends one benign request
first: a content filter that answers attack prompts with a block page lets it through, and the run
goes on. Only when that one cannot be read either does the run stop early (exit 3, `aborted on
UnreadableReplies: ...`, with what to check for that provider); a resume of a run that read replies
starts with the endpoint proven, and a shorter run that read nothing is `unreachable`. A 4xx is not
this: it still stops the run ([`MANUAL.md`](MANUAL.md) §3, a reply the
adapter cannot read; [`adr/0012`](adr/0012-a-reply-the-adapter-cannot-read-is-not-a-verdict.md)).

### If my system passes Il Dottore, does it meet OWASP AISVS?

No, and the tool never says so. AISVS lists *controls* ("verify that a classifier screens every
prompt"), and a black-box scanner never sees the classifier. A spec's `aisvs:` list means a
**failure** is evidence the control is absent or ineffective; a pass means these probes did not
falsify it. `dottore coverage --framework aisvs` shows what the battery can speak to (17 of 191
requirements today) and why the rest is out of reach or deliberately untested. Most of the
standard (training data, infrastructure, logging) needs an audit, not a scan.

### Does Il Dottore send a spec's documents, tools or memory to my target?

To a bare model, yes; to a deployed application, no: you seed them and say so. When your target
is `type: model`
(a model API), the spec's memory seed goes as saved memory from earlier sessions after the
system prompt, its documents as retrieved context
before the attack, and its tools as tool definitions; when the model calls one, Il Dottore
answers with what the spec says the tool returns and lets it continue, for at most 4 rounds.
That tests how the model handles untrusted content, not your application's own retrieval or
tools, and each attempt says `setup_delivery: in_band`. Any other target type is a deployed
application, which has its own documents, tools and memory: a spec that depends on them is
`inconclusive: setup_not_seeded`, with nothing sent, unless your target file declares it seeded
under `seeded_setup.specs` (ids or globs such as `PI-INDIRECT-*`). Declared, it goes out as the
plain prompt, and each attempt says `setup_delivery: seeded`. Map the spec's tool names to your
deployment's under `seeded_setup.tools` (`lookup_ticket: get_ticket`), so a call under your
name is judged as the spec's tool instead of failing as unauthorized, and list your own tools
outside any scene under `seeded_setup.granted_tools` (a hand-off such as
`transfer_to_billing_agent` written `{name: ..., destructive: false}`, declared not destructive:
OD-43). A spec whose canary has to be in your
deployment needs `seeded_setup.run_token` (`--dry-run -vv` prints the canary to seed), and your
deployment must return its tool calls, or a spec whose poison is a tool's result is
`setup_not_reached` (and a spec judged on its tool trace is not sent through a REST target).
`examples/target.app.yaml` is a worked file. The offline mock needs none of this: its replies are
written for the scene (OD-18, `docs/adr/0009-a-spec-setup-never-reaches-a-live-target.md`).

### Why does a run refuse my target with "target(s) not authorized by the scope"?

The authorization gate, before anything is sent (exit 3). The bracket after the target id names
the cause: `endpoint '<url>' not on allowlist for '<id>'` means the target's endpoint host/path
is not in that target's `endpoints` allowlist in the scope; `target '<id>' not in scope` means
the target id is not among the scope's `targets`. Add the entry deliberately; it is not meant to
be bypassed. (`endpoint not allowed by scope` is the adapter's own second check, which you
should only see if the first one was bypassed.) Two less obvious causes: a host pinned to a port
(`localhost:11434`) refuses any other port, and a path carrying `%2f`, `%5c`, a backslash,
`%25`, a `;` or `%3b`, a `%uXXXX` escape, an overlong UTF-8 sequence, a segment of dots and
spaces only (`...`, `..%20`), or a non-ASCII character that Unicode normalisation turns into a
dot, a slash or a semicolon (a fullwidth dot, for example) is always refused, because an origin
that decodes it may land outside the prefix.

### Why is a spec `blocked_by_policy`, and how do I turn it on?

Eight specs declare a `requires_policy` capability: the seven of the `agentic-extortion` suite
(`offensive_simulation`) and `DL-PII-ELICIT-001` (`layer_b_pii`). The CLI always applies its own
default policy pack, which enables no capability, and `dottore run` has no option to load a
different pack. So today these eight cannot be enabled from the command line and never send:
a target that lacks the capability they need skips them, and one that has it reports them
`blocked_by_policy` with zero sends. Selected on their own (`--suite agentic-extortion`), they
end in `error: nothing would be sent` (exit 3), and the message says why: "Widen the selection
or declare the capability on the target. A spec blocked by policy needs a policy pack that
enables it, and the CLI cannot load one today (open decision), so it cannot run from
`dottore`." That open decision is OD-46. For `DL-PII-ELICIT-001` the opt-in is decided (OD-11): the
pack that enables it and a per-run `--allow-pii-elicitation` flag come together, never the flag
alone; until then it stays off.

### Where does evidence live, and is it safe to keep?

Under `.dottore/` (evidence store + run SQLite) by default; override with `--evidence-root`
and `--run-db` (`dottore fleet --run` takes both too). Secrets and PII are redacted at rest. Do not
commit `.dottore/`. A report (`-oJ` and the others) is never written over the scope, a target, the
judge, the fleet file, the run store or a spec file: such a path is refused before the run sends.

### Why does a report show `«REDACTED:uuid:…»` or `«REDACTED:hex_token:…»` for an id my target returned?

Because a UUID and a run of 32 hex digits or more are the shapes of keys and tokens (an Azure key
is 32 hex digits, an old npm token a UUID), and a target's reply is untrusted text: they are
masked whatever their entropy, as the documented key formats are (`«REDACTED:openai_key:…»`,
`«REDACTED:github_token:…»`, ...). The digest after the type is the same for the same value in
one run (pin `ILDOTTORE_REDACTION_SALT` to compare across runs), so two occurrences can still be
matched. What the tool itself computed stays readable: the evidence file names and their sha256,
the media digests a multimodal request records, the scope digest, run and attempt ids. So does the
id of the target you scanned, which every report masks by the rules it had before these, with a
fixed salt: `tenant-6a1f0c2e-91b4-4d7a-8e3b-2f5c9d0a7b14` reads as written, and `dottore diff`
compares two runs of it (a high-entropy id is masked, to the same text in every run, and since the
salt is public, in every user's reports). A mask of these types written in a reply after a label
(`password: «REDACTED:uuid»` and a password) is read as text, and the value masked whole.
