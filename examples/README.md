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
| [`fleet.yaml`](fleet.yaml) | Declare several targets in one file and scan them all. |
| [`target.mcp.yaml`](target.mcp.yaml) / [`scope.mcp.yaml`](scope.mcp.yaml) | A Model Context Protocol server target (read-only discovery). |
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
```

## Scenario B, validate wiring without sending anything

`--dry-run` resolves the scope, target and battery and validates the whole plan, but
sends **zero** requests. Use it to check a scope/target pair before a real run:

```bash
dottore run --dry-run --quick \
  -t examples/target.local.yaml \
  --scope examples/scope.local.yaml
```

## Scenario C, scan a local model (needs Ollama)

Stand up two small local models (target + judge) and scan the target. No API key, no
data leaves your machine:

```bash
# one-time
brew install ollama && ollama serve &
ollama pull llama3.2:1b        # target
ollama pull llama3.2:3b        # judge

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
dottore run --suite owasp:llm -sV \
  -t examples/target.openai.yaml \
  --scope examples/scope.local.yaml \
  --fail-on high -oA reports/openai
```

(Add a `targets` entry to the scope whose `endpoints` cover the hosted host, matching the
target's id.)

## Scenario E, scan a fleet

Declare every target in one file, expand it into a scope plus one target file per model,
and scan them all:

```bash
dottore fleet examples/fleet.yaml --run --judge examples/target.judge.yaml
# or expand only (review the generated files first):
dottore fleet examples/fleet.yaml --out .dottore/fleet
```

## Scenario F, scan an MCP server (read-only discovery)

Point the `mcp` suite at a Model Context Protocol server: the adapter does the `initialize`
handshake, lists its tools / resources / prompts, and flags tool-metadata poisoning
("line jumping") in the advertised descriptions. It never calls a tool.

```bash
dottore run --suite mcp \
  -t examples/target.mcp.yaml \
  --scope examples/scope.mcp.yaml \
  -oJ reports/mcp.json
```

Or declare the MCP server in a `fleet.yaml` (`kind: mcp`) and let `dottore fleet` generate its
scope + target for you.

## Add your own attack (no core code)

```bash
dottore new-spec --id PI-MYORG-001 --family prompt_injection
# fill attack / expected_secure_behavior / evaluators / golden fixtures, then:
dottore lint specs/
```

See [`../docs/06-extensibility-suites.md`](../docs/06-extensibility-suites.md).
