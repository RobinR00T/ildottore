# Using Il Dottore (`dottore`)

nmap-for-AI: a spec-driven security scanner for LLMs and AI apps. This is the practical
guide. For the long-form reference see [`docs/MANUAL.md`](docs/MANUAL.md); the design
corpus lives in [`docs/`](docs/) and `AGENTS.md`; runnable scenarios live in
[`examples/`](examples/).

> **Authorized testing only.** `dottore` refuses any target not covered by a `scope.yaml`
> authorization record (endpoint allowlist, default-deny), never performs real destructive actions
> or exfiltration (mocked tools + planted canaries), and masks secrets/PII in logs,
> evidence and reports. See [`docs/02-threat-model.md`](docs/02-threat-model.md).

## Install

```bash
git clone <repo> && cd ildottore
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/dottore --help          # or `dott --help`
```

Full options (offline dev, local models, hosted keys): [`INSTALL.md`](INSTALL.md).

## 60-second quickstart

You need two files: a **scope** (your authorization record) and a **target**.

`scope.yaml`, what you are allowed to scan (default-deny):
```yaml
version: "1.0"
targets:
  - id: my-chatbot                  # must match the target's id
    base_url: "https://api.example.com/v1/chat/completions"
    endpoints:                      # default-DENY; nothing off this list is ever contacted
      - host: "api.example.com"
        path_prefixes: ["/v1/chat/completions"]
    identities:
      - name: default
        auth_ref: "env://MY_API_KEY"   # reference only; never the secret itself
# Optional top-level `checksum:` (sha256 of the body): verified when present, so a scope
# edited without updating it is refused. An integrity check, not a signature.
```

`target.yaml`, what you are scanning:
```yaml
id: my-chatbot
type: chatbot                       # model | chatbot | agent | rag | api
provider: openai                    # openai (any OpenAI-compatible API) | anthropic | mcp | rest
endpoint: "https://api.example.com/v1/chat/completions"
model: "gpt-4o"
auth_ref: "env://MY_API_KEY"        # never inline secrets
capabilities: { tools: false, rag: false }
```

Run the quick triage battery and write all report formats:
```bash
dottore run --quick -t target.yaml --scope scope.yaml -oA report
```

Copy-pasteable versions of both files (local Ollama, hosted OpenAI, a whole fleet) are in
[`examples/`](examples/).

## Common invocations

```bash
# Fingerprint only: identify the model/guardrails behind an endpoint, attack nothing.
# A live endpoint is probed for real; add --offline for the deterministic mock (no sends).
dottore fingerprint target.yaml --scope scope.yaml    # target is positional

# Full OWASP LLM Top 10 suite, HTML + SARIF out
dottore run --suite owasp:llm -t target.yaml --scope scope.yaml -oH report.html -oS out.sarif

# Fingerprint first, then an aggressive run; break CI on confirmed high/critical
dottore run -A --fail-on high -oX junit.xml -t target.yaml --scope scope.yaml

# Just injection + leakage families, faster (higher timing template)
dottore run -p pi,leakage -T4 -t target.yaml --scope scope.yaml

# LLM-as-judge on a live scan (semantic_judge secondary evaluator)
dottore run --quick -t target.yaml --judge judge.yaml --scope scope.yaml

# Compare several models on the same suite
dottore run --suite owasp:llm --compare -t gpt.yaml -t claude.yaml -t local.yaml --scope scope.yaml

# Scan a whole fleet declared in one file (its `judge:` block is the judge)
dottore fleet fleet.yaml --run

# Inspect / author specs
dottore registry ls [--category .. --owasp .. --suite .. --tag ..]
dottore coverage [--framework owasp|atlas|iopc|aisvs] [--suite ..] [--json]   # what the battery tests, nothing sent
dottore describe PI-DIRECT-001
dottore lint specs/
dottore new-spec --id PI-XYZ-001 --family prompt_injection
dottore replay <run-id> --evidence-root .dottore/evidence --run-db .dottore/runs.sqlite   # reproduce a past run, checked against the run store

# Regression gate: compare a run against a stored baseline (CI-gateable)
dottore diff baseline.json current.json

# Human-in-the-loop: score a run against operator labels (agreement + precision/recall)
dottore calibrate report.json labels.yaml
```

## Flags that matter (`dottore run`)

| Flag | Meaning |
|------|---------|
| `--scope` | **Required** authorization record. Never bypassable. |
| `-t/--target` (repeatable), positional | target file(s) |
| `--judge` | judge model `target.yaml` (LLM-as-judge for `semantic_judge` on live scans) |
| `--suite` | `owasp:llm` (alias of `owasp-llm-top10`, as is `baseline`); also `quick`, `multi-turn`, `access-control`, `agentic-owasp2026`, `obfuscation-enhancers`, `embeddings`, `agentic-extortion` (alias `agentic`), `mcp`, `responsible-ai`, `guardrail-evasion`, `multimodal`, `structured-output`, `nova-iopc`. `mitre:atlas`, `nist:ai`, `eu:ai-act`, `dora` and `iso:42001` are still accepted as aliases but point at no registered suite and exit 3 |
| `--quick` | the T0 battery: selects `--suite quick` (18 specs) at `-T0`. Conflicts with an explicit `--suite` |
| `--deep` | timing `-T2` over the same battery a run with no selection flag gets: it selects no larger suite (on the example target, the same 34 specs, at 2.0 req/s instead of 5.0). By itself it tailors nothing: mutator ordering needs a fingerprint, so its adaptive part only takes effect with `-sV` (or `-A`), as `run --help` says |
| `-p/--categories` | `pi`, `jailbreak`, `leakage`, `tool`, `rag`, `output`, `dos`, `safety`, `bias` (long forms accepted) |
| `--spec` / `--exclude` | run/skip specific spec ids or globs (e.g. `PI-*`); repeatable |
| `--top-tests N` | keep the N highest-signal specs |
| `-sV` | fingerprint the model first, then order each spec's mutators by the carriers this target still understands (17 extra probes per target, printed in the plan, paced; never sent under `--dry-run`/`--estimate`/`-sn`) |
| `-sn` | discovery only: authorized endpoint + declared capabilities + what the battery would run. **Sends nothing** |
| `-A` | aggressive: implies `-sV` + `--deep` (fingerprint first, then `-T2` unless you pass `-T`) |
| `--runs N` | reproducibility runs (default 5) |
| `-T 0..5` | timing template (default 3; `--quick` implies 0, `--deep`/`-A` imply 2; an explicit `-T` wins); higher is faster/louder |
| `--rate` / `--concurrency` / `--timeout` | max req/s, greater than 0 (one shared ceiling for the whole campaign: retries, `-sV` probes, the identity sweep and the `--judge` model included; not applied to an offline mock run, and the plan says so) · max concurrent specs · per-attempt timeout |
| `--resume RUN_ID` | finish a halted run (exit 3): completed attempts are not re-sent |
| `--dry-run` | resolve + validate, send nothing |
| `--estimate` | print a pre-run cost estimate (requests + tokens); no sends |
| `--compare` | model-comparison matrix across targets (needs two or more `-t`) |
| `--hardened` | replay hardened fixtures (clean-run smoke) on a mock target; refused on a live one |
| `-oJ/-oH/-oS/-oX/-oA` | JSON / HTML / SARIF / JUnit / all four to `<prefix>.json`, `.html`, `.sarif`, `.xml` (`-oA report.v2` keeps its name: `report.v2.json`; `-oA report.json` is not doubled: `report.json`, `report.html`, ...). Two formats pointed at the same file are refused before anything is sent |
| `--fail-on <band>` | CI gate on confirmed findings (`low\|medium\|high\|critical`, default `high`) |
| `--include-needs-review` | also gate unconfirmed exploits (an unconfirmed `fail`); an `inconclusive` result never gates |
| `--spec-path` | spec search path (default `specs/`) |

**Exit codes:** `0` clean · `1` findings below `--fail-on` · `2` findings at/above · `3` error
(a usage error, such as an unknown option, is `3` too).

`3` also covers a run that **did not finish**, and it takes precedence over `2`. If a hard
budget ceiling halts the campaign, the exit code is `3`, the reason is printed, and the report
carries `summary.status.state = "budget_exhausted"` with `coverage.specs.total` (planned) above
`coverage.specs.run` (completed); a target that was authorized but answered nothing (every
attempt failed on transport) is `"unreachable"`. A partial scan is never reported as a clean
one. Read `summary.status.reason` before you treat it as a flake;
[`docs/MANUAL.md`](docs/MANUAL.md) explains why. Only an **exploited** (`fail`) finding trips
the gate; `pass`/`inconclusive` never do.

## Multi-turn attacks

Some specs (Crescendo, Linear, Sequential, Bad-Likert, Tree) attack over several turns.
The attacker turns are **pinned in the spec**, not generated by an LLM, so a multi-turn run
stays as reproducible as a single-shot one: the conversation is threaded as `messages`,
only the final turn is scored, and the full transcript is persisted as evidence. Nothing
special to enable: pick the `multi-turn` suite or the individual `JB-*` specs.

## Fleet: many targets, one file

Declare every LLM / URL / MCP endpoint to validate in one `fleet.yaml`, then expand it into
a scope plus one target file per model:

```bash
dottore fleet fleet.yaml --out .dottore/fleet      # generate scope + targets, review them
dottore fleet fleet.yaml --run                     # or scan every target immediately
```

The judge goes in the fleet file too, as a `judge:` block (`id`, `endpoint`, `model`,
`api_key_env`), because the generated scope is built from that file alone: `fleet` writes it
to `judge.yaml` and `--run` uses it. A `--judge judge.yaml` is accepted only when it names the
same id, endpoint and credential as the block. Every generated scope entry is pinned to its
host and port (`localhost:11434`), so a local model does not authorize the machine's other
ports (an offline `mock://` entry sends nothing and keeps a bare host).

Keys are never written to the file: each entry names an env var (`api_key_env`), resolved
only at send time. `provider` is inferred from the endpoint (`/chat/completions` -> openai,
`/messages` -> anthropic, else `rest`). A `kind: mcp` entry routes to the read-only MCP
adapter, which discovers a Model Context Protocol server's advertised tool/resource/prompt
metadata (it never calls a tool); point the `mcp` suite at it. See
[`specs/fleet.example.yaml`](specs/fleet.example.yaml).

An MCP server reachable over the wire uses `provider: mcp` with an `endpoint`; a local one
uses `transport: stdio` + `command` and is launched as a subprocess only if the scope target's
`commands` list authorizes that exact command line (default-deny). See [`docs/MANUAL.md`](docs/MANUAL.md).

## Reading results

A finding separates **risk** from **confidence**: `RiskScore = Impact x Exploitability x
Reproducibility`, banded critical/high/medium/low/info. Every report gives each finding one of
four states: **confirmed** (a decisive exploit at or above the confidence threshold, what the
gate counts), **needs review** (an unconfirmed exploit, or a spec that was sent and could not
be decided: a format-valid PII/secret hit without corroboration is *inconclusive*, never a
confirmed leak), **not exploited** (passed) and **not tested** (nothing sent). An unconfirmed
exploit prints `FAIL (<band>, needs review)` on its progress line. Every finding carries
evidence (prompt, response, tool traces, the aggregate verdict and its reasoning), and
`dottore replay` re-derives a run from stored evidence. See
[`docs/05-scoring-model.md`](docs/05-scoring-model.md).

## Adding a technique (no core code)

The product's whole point is extensibility. A new attack is usually just YAML:
`dottore new-spec …` → fill `attack`, `expected_secure_behavior`, `evaluators`, and golden
`fixtures` (vulnerable ⇒ scanner must flag; hardened ⇒ must pass) → `dottore lint specs/` →
reference it from a suite. Details in [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/06-extensibility-suites.md`](docs/06-extensibility-suites.md).
