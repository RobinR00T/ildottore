# Examples

Worked, copy-pasteable scenarios for `dottore`. They go from "no server, no API key"
to "scan a whole fleet". Every file here is a real, schema-valid input you can point the
scanner at.

Run everything from the repo root with the venv active (see [`INSTALL.md`](../INSTALL.md)).

| File | What it is |
|------|------------|
| [`scope.local.yaml`](scope.local.yaml) | Authorization record for the local-Ollama scenario (default-deny allowlist). |
| [`target.local.yaml`](target.local.yaml) | A local model served by Ollama over the OpenAI-compatible API. |
| [`target.judge.yaml`](target.judge.yaml) | A second local model used as the LLM-as-judge (`--judge`). |
| [`target.openai.yaml`](target.openai.yaml) | A hosted model (key by env-var reference, never inline). |
| [`target.app.yaml`](target.app.yaml) / [`scope.app.yaml`](scope.app.yaml) | A deployed application, with the specs whose scene its operator seeded (`seeded_setup`). |
| [`fleet.yaml`](fleet.yaml) | Declare several targets in one file and scan them all. |
| [`target.mcp.yaml`](target.mcp.yaml) / [`scope.mcp.yaml`](scope.mcp.yaml) | A Model Context Protocol server target (read-only discovery). |
| [`target.websocket.yaml`](target.websocket.yaml) / [`scope.websocket.yaml`](scope.websocket.yaml) | A chat endpoint over a WebSocket, its wire shape declared in the file (`provider: websocket`). |
| [`ci-github-actions.yml`](ci-github-actions.yml) | Gate a pipeline on new high/critical findings. |

Authorization is not optional: a run refuses any target that is not covered by a
`scope.yaml` entry plus an endpoint allowlist (default-deny). See
[`../docs/02-threat-model.md`](../docs/02-threat-model.md).

---

## Scenario A, no server, no key (inspect the battery)

Everything here is fully offline and touches no network:

```bash
dottore registry ls                      # the full spec catalogue
dottore registry ls --category jailbreak # filter by category / owasp / suite / tag
dottore describe PI-DIRECT-001           # one spec's detail card
dottore lint specs/                      # schema + policy + fixtures-prove-detection
dottore schema export                    # the JSON Schemas that validate every spec
dottore coverage                         # what the battery tests, per framework, gaps named
dottore coverage --framework aisvs       # OWASP AISVS by level (falsification, never verification)
```

## Scenario B, validate wiring without sending anything

`--dry-run` resolves the scope, target and battery, validates the whole plan and prints
it, but sends **zero** requests. Use it to check a scope/target pair before a real run: a
target that is not covered by the scope fails here with exit 3 rather than looking fine.

```bash
dottore run --dry-run --quick \
  -t examples/target.local.yaml \
  --scope examples/scope.local.yaml
```

Real output of that exact command:

```
dry-run: plan resolved, sent nothing.
  scope:   examples/scope.local.yaml
  target:  local-llama (chatbot) authorized at http://localhost:11434/v1/chat/completions
  battery: quick, 10 specs selected
    jailbreak: 3
    output_security: 3
    data_leakage: 2
    availability_cost: 1
    prompt_injection: 1
  skipped: 7 spec(s) on local-llama, capability not declared by the target
  blocked: 1 spec(s) on local-llama, refused by the policy pack
  sampling: local-llama's sampling_defaults fills temperature 0.0 on 0 of 10, top_p 1.0 on 9 of 10 specs (a spec's own value wins)
  would send: 125 requests over 10 specs at runs=5
  pacing:  0.5 req/s ceiling (S8)
  budgets: 500000 tokens, 2000 requests, 1800s wall (derived from this plan)
```

Three things in there are worth reading carefully, because the previous version of this
block got all three wrong:

* **the authorized endpoint**, not the phrase "authorized by the scope". A scope that names
  the target with an empty endpoint allowlist is not authorization, and printing the words
  made that case read as green;
* **10 specs, not 18**: the `quick` suite has 18, and this target declares no tools/RAG, so
  seven are skipped and one is refused by the policy pack. The count is what will run;
* **125 requests** is what the run really sends. This line used to print the raw selection
  before both filters, which is how it promised 845.

## Scenario C, scan a local model (needs Ollama)

Stand up two small local models (target + judge) and scan the target. No API key, no
data leaves your machine:

```bash
# one-time
brew install ollama && ollama serve &
ollama pull llama3.2:1b        # target
ollama pull llama3.2:3b        # judge

# reports/ is gitignored, so a fresh clone lacks it; without it the run refuses before
# sending (cannot write the report reports/local.json: reports is not a directory, exit 3)
mkdir -p reports
dottore run --quick \
  -t examples/target.local.yaml \
  --judge examples/target.judge.yaml \
  --scope examples/scope.local.yaml \
  -oA reports/local
```

Without `--judge`, the semantic-judge evaluator abstains (`capability_unavailable`) and
live findings that rely on it come back inconclusive. Deterministic evaluators still fire.

## Scenario D, scan a hosted model (needs an API key)

The key is referenced by env-var, never written to a file:

```bash
export OPENAI_API_KEY=sk-...            # matches auth_ref in target.openai.yaml
mkdir -p reports                        # the report directory must exist, as in Scenario C
dottore run --suite owasp:llm -sV \
  -t examples/target.openai.yaml \
  --scope examples/scope.openai.yaml \
  --fail-on high -oA reports/openai
```

Note the scope: `scope.openai.yaml`, not the local one. A scope authorizes specific targets,
and `openai-gpt-staging` is not in `scope.local.yaml`, so that pairing is refused (exit 3).
This scenario used to be written against the local scope with a parenthetical asking the
reader to add the entry themselves, i.e. the command as printed did not work.

Add `--dry-run` first if you want to see the plan and the cost before spending anything.

## Scenario E, scan a fleet

Declare every target in one file, expand it into a scope plus one target file per model,
and scan them all:

```bash
dottore fleet examples/fleet.yaml --run
# or expand only (review the generated files first):
dottore fleet examples/fleet.yaml --out .dottore/fleet
```

`examples/fleet.yaml` declares its judge in a `judge:` block, so the generated scope
authorizes it and `fleet` writes it to `.dottore/fleet/judge.yaml`. Passing
`--judge examples/target.judge.yaml` as well also works, because that file names the same
id, endpoint and (no) credential; a judge file the fleet does not declare is refused (exit 3)
and nothing is written. Two earlier states of this command: until 2026-09-21 the judge was
missing from the generated scope, so every `semantic_judge` verdict came back inconclusive
and the run exited 0; until 2026-10-03 it was authorized from the `--judge` file itself,
whatever host and environment variable that file named.

The generated scope pins each endpoint to its port (`localhost:11434`), as
`examples/scope.local.yaml` now does by hand.

## Scenario F, scan an MCP server (read-only discovery)

Point the `mcp` suite at a Model Context Protocol server: the adapter does the `initialize`
handshake, lists its tools / resources / prompts, and flags tool-metadata poisoning
("line jumping") in the advertised descriptions. It never calls a tool.

```bash
mkdir -p reports                        # the report directory must exist, as in Scenario C
dottore run --suite mcp \
  -t examples/target.mcp.yaml \
  --scope examples/scope.mcp.yaml \
  -oJ reports/mcp.json
```

Or declare the MCP server in a `fleet.yaml` (`kind: mcp`) and let `dottore fleet` generate its
scope + target for you.

## Scenario G, scan a deployed application you have seeded

A bare model gets a spec's documents, tools and memory in the request (`type: model`). A
deployed application has its own, so the spec's scene is yours to seed into it: the ticket
whose text carries the injection, the knowledge-base page, the saved memory. `target.app.yaml`
declares which specs you seeded (`seeded_setup.specs`), how your deployment names the spec's
tools (`seeded_setup.tools`) and which of its own tools it may call outside any scene
(`seeded_setup.granted_tools`). A spec that needs a scene you did not declare sends nothing:

```bash
dottore run --dry-run -vv --spec 'PI-INDIRECT-*' --spec 'AG-TOOL-*' \
  -t examples/target.app.yaml \
  --scope examples/scope.app.yaml
```

Real output of that exact command (the `--judge` warning on stderr left out):

```
dry-run: plan resolved, sent nothing.
  scope:   examples/scope.app.yaml
  target:  support-agent-staging (agent) authorized at https://support-agent.example.test/v1/chat/completions
  battery: filtered selection, 2 specs selected
    agent_tool_abuse: 1
    prompt_injection: 1
  not seeded: 1 spec(s) on support-agent-staging, their scene is not in the deployment as seeded_setup declares it, or their tool trace cannot be read through this adapter (-vv says which)
    - PI-INDIRECT-RAG-001: setup_not_seeded: this spec needs documents, tools or memory in the deployment, and the target file does not declare them seeded (seeded_setup.specs)
  sampling: support-agent-staging's sampling_defaults fills temperature 0.0 on 0 of 2 specs (a spec's own value wins)
  would send: 20 requests over 2 specs at runs=5
  pacing:  5.0 req/s ceiling (S8)
  budgets: 500000 tokens, 2000 requests, 1800s wall (derived from this plan)
```

`PI-INDIRECT-RAG-001` needs a poisoned document in the knowledge base and is not declared, so
the run reports it `inconclusive: setup_not_seeded` and sends nothing for it. The two declared
specs go out as their plain prompts and record `setup_delivery: seeded`. The poisoned ticket of
`PI-INDIRECT-TOOL-001` reaches the agent only through `lookup_ticket`, which your agent calls
`get_ticket`: a reply that shows a `get_ticket` call counts as having fetched it, and one that
shows none is `inconclusive: setup_not_reached`, since nothing says the agent ever read the
ticket. In `AG-TOOL-UNAUTH-001` the map is what keeps `kb_search` from failing as an
unauthorized tool; the evidence keeps the deployment's names. A spec whose canary has to be in
your deployment (none of these two) would carry `eng-2026-q4-<spec id>` in its place, and
`-vv` would print it on a `seed:` line. The host is `example.test`, so a run without `--dry-run` has nowhere to go: point
both files at your deployment first. What a seeded spec tests is only as good as what you
seeded, which the tool cannot check.

## Scenario H, scan a chat endpoint that only speaks WebSocket

An assistant whose chat surface is a WebSocket streaming JSON frames has no standard wire shape,
so `target.websocket.yaml` declares it: the handshake frame (`{{token}}` is the credential the
`auth_ref` resolves to), the query frame (`{{prompt}}`), how the streamed reply is read back
(`text_path`, the `final_path`/`final_value` that ends a turn, the `ignore_types` to discard,
`error_path`, `timeout_seconds`), a session-start frame and the reconnect cap. The adapter
knows nothing else. `scope.websocket.yaml` authorizes `wss://` as it would `https://`
(cleartext `ws://` only to loopback), and a redirect at the upgrade is never followed:

```bash
dottore run --dry-run --quick \
  -t examples/target.websocket.yaml \
  --scope examples/scope.websocket.yaml
```

Real output of that exact command (the `--judge` warning on stderr left out):

```
dry-run: plan resolved, sent nothing.
  scope:   examples/scope.websocket.yaml
  target:  ws-assistant-staging (chatbot) authorized at wss://assistant.example.test/ws/chat
  battery: quick, 10 specs selected
    jailbreak: 3
    output_security: 3
    data_leakage: 2
    availability_cost: 1
    prompt_injection: 1
  skipped: 6 spec(s) on ws-assistant-staging, capability not declared by the target
  blocked: 1 spec(s) on ws-assistant-staging, refused by the policy pack
  not seeded: 1 spec(s) on ws-assistant-staging, their scene is not in the deployment as seeded_setup declares it, or their tool trace cannot be read through this adapter (-vv says which)
  would send: 125 requests over 10 specs at runs=5
  pacing:  0.5 req/s ceiling (S8)
  budgets: 500000 tokens, 2000 requests, 1800s wall (derived from this plan)
```

The target declares `rag: true` and no tools, so six specs are skipped for capability and the
one RAG spec of the quick battery is "not seeded" (a deployed application holds a spec's scene
only when its operator declares it, as in Scenario G). Each request is one query turn: the
handshake and session frames ride on the connection it opens. Every frame sent and received
lands in the evidence with the credential recorded as `{{token}}`, and `dottore replay`
re-derives the verdicts from them. The host is `example.test`, so a run without `--dry-run`
has nowhere to go: point both files at your deployment first, and read
[`../docs/MANUAL.md`](../docs/MANUAL.md) §4.2 for what each key means and what the loader
refuses.

## Add your own attack (no core code)

```bash
dottore new-spec --id PI-MYORG-001 --family prompt_injection
# fill attack / expected_secure_behavior / evaluators / golden fixtures, then:
dottore lint specs/
```

See [`../docs/06-extensibility-suites.md`](../docs/06-extensibility-suites.md).
