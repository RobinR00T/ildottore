# FAQ

### What is Il Dottore, in one line?

An nmap-for-AI: a spec-driven scanner that examines an LLM or AI application, diagnoses its
security weaknesses against a declarative attack battery, and issues a reproducible,
evidence-backed report mapped to operational risk.

### How is it different from a prompt-list or a jailbreak repo?

The value is not the prompts. It is **reproducibility + evidence + risk mapping**. Every
attempt persists its prompt, full response, sampling params, tool traces and the aggregate
verdict with its reasoning; findings are scored `impact x exploitability x reproducibility` and re-derivable
with `dottore replay`. A finding we cannot reproduce or evidence is treated as noise.

### Is it safe to run? Will it actually do damage?

No real damage by design. Sensitive tools run as mocks or dry-run, exfiltration targets are
mock endpoints blocked by the allowlist, and every dangerous payload is flagged
`test_only`. It scans nothing without a `scope.yaml` authorization record (endpoint
allowlist, default-deny), and plain http is allowed only to loopback. The scope's optional
`checksum:` is an integrity check, verified when present, not a signature. See
[`02-threat-model.md`](02-threat-model.md) and [`RESPONSIBLE-USE.md`](RESPONSIBLE-USE.md).

### Do I need an API key?

Not to explore (`registry ls`, `describe`, `lint`, `schema`) or to scan a **local** model
via Ollama. You need a key only to scan a **hosted** model, and it is passed by env-var
reference (`auth_ref: env://…`), never written to a file.

### What does `--judge` do, and do I need it?

It wires a model as an LLM-as-judge behind the `semantic_judge` secondary evaluator. On a
live scan without it, `semantic_judge` abstains (`capability_unavailable`) and findings that
depend on it come back inconclusive. Deterministic evaluators decide first regardless: a
deterministic fail always wins, and the judge cannot turn it into a pass. When every
deterministic evaluator passes, a judge fail still decides; whether that kind of finding should
gate CI is open (OD-19). A live run without `--judge` warns before sending anything (and in
the dry run), and a judge outage, or a judge whose output cannot be parsed, counts as no judge,
never as a pass.

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
too, and since 2026-10-07 `--estimate` and `--dry-run` price it: one request per scope identity
for each spec that sweeps them.

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
`3` before anything is sent. For regression-only gating, compare against a baseline with
`dottore diff baseline.json current.json`. See [`examples/ci-github-actions.yml`](../examples/ci-github-actions.yml).

### What is "confirmed" vs "needs-review"?

Risk and confidence are separate. Every report puts a finding in one of four states:
**confirmed** (a decisive exploit at or above the confidence threshold), **needs review** (an
unconfirmed exploit, or a spec that was sent and could not be decided), **not exploited** (it
passed) and **not tested** (nothing was sent: a capability skip, a policy block). The CI gate
(`--fail-on`) counts confirmed exploits only. `--include-needs-review` adds the unconfirmed
exploits, never the undecided results: a format-valid secret/PII hit without corroboration is
`inconclusive` by design (needs review, never a confirmed leak), so it does not trip the gate
with or without the flag. See [`05-scoring-model.md`](05-scoring-model.md).

### Which suites and categories exist?

Suites: `owasp-llm-top10` (alias `owasp:llm`), `quick`, `multi-turn`, `access-control`,
`agentic-owasp2026`, `obfuscation-enhancers`, `embeddings`, `agentic-extortion`, `mcp`,
`responsible-ai`, `guardrail-evasion`, `multimodal`, `structured-output`, `nova-iopc`.
Category aliases for `-p`: `pi`, `jailbreak`, `leakage`, `tool`, `rag`, `output`, `dos`, `safety`, `bias`
(long forms accepted). `dottore registry ls` is the source of truth.

### Can I add my own attack without touching the code?

Yes, that is the point. `dottore new-spec …` scaffolds a YAML spec; fill `attack`,
`expected_secure_behavior`, `evaluators` and golden `fixtures` (a vulnerable fixture the
scanner must flag, a hardened one it must pass), then `dottore lint specs/`. See
[`06-extensibility-suites.md`](06-extensibility-suites.md) and [`CONTRIBUTING.md`](../CONTRIBUTING.md).

### Does it support MCP servers?

Yes. A `kind: mcp` fleet entry (or a target with `provider: mcp`) routes to the read-only
MCP adapter: it performs the JSON-RPC `initialize` handshake and lists the server's tools,
resources and prompts, then renders that advertised metadata for evaluation. It never calls a
tool (`tools/call`), invoking a target's tools could have real side effects, so discovery is
read-only by design. Point the `mcp` suite at such a target for the tool-metadata-poisoning
("line jumping") check.

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
outside any scene under `seeded_setup.granted_tools`. A spec whose canary has to be in your
deployment needs `seeded_setup.run_token` (`--dry-run -vv` prints the canary to seed), and your
deployment must return its tool calls, or a spec whose poison is a tool's result is
`setup_not_reached` (and a spec judged on its tool trace is not sent through a REST target).
`examples/target.app.yaml` is a worked file. The offline mock needs none of this: its replies are written for the scene (OD-18,
`docs/adr/0009-a-spec-setup-never-reaches-a-live-target.md`).

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
`dottore`."

### Where does evidence live, and is it safe to keep?

Under `.dottore/` (evidence store + run SQLite) by default; override with `--evidence-root`
and `--run-db`. Secrets and PII are redacted at rest. Do not commit `.dottore/`.
