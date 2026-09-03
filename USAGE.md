# Using Il Dottore (`dottore`)

nmap-for-AI: a spec-driven security scanner for LLMs and AI apps. This is the practical
guide. For the long-form reference see [`docs/MANUAL.md`](docs/MANUAL.md); the design
corpus lives in [`docs/`](docs/) and `AGENTS.md`; runnable scenarios live in
[`examples/`](examples/).

> **Authorized testing only.** `dottore` refuses any target not covered by a signed
> `scope.yaml` (endpoint allowlist, default-deny), never performs real destructive actions
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
# Optional top-level `checksum:` (sha256 of the body) makes the scope tamper-evident.
```

`target.yaml`, what you are scanning:
```yaml
id: my-chatbot
type: chatbot                       # model | chatbot | agent | rag | api
provider: openai                    # openai-compatible | anthropic | rest
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
# Fingerprint only: identify the model/guardrails behind an endpoint, attack nothing
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

# Scan a whole fleet declared in one file
dottore fleet fleet.yaml --run --judge judge.yaml

# Inspect / author specs
dottore registry ls [--category .. --owasp .. --suite .. --tag ..]
dottore describe PI-DIRECT-001
dottore lint specs/
dottore new-spec --id PI-XYZ-001 --family prompt_injection
dottore replay <run-id> --evidence-root .dottore/evidence   # reproduce a past run

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
| `--suite` | `owasp:llm` (alias of `owasp-llm-top10`); also `quick`, `multi-turn`, `access-control`, `agentic-owasp2026`, `obfuscation-enhancers`, `embeddings`, `agentic-extortion`, `mcp`, `responsible-ai`, `guardrail-evasion` |
| `--quick` / `--deep` | T0 minimum battery / T2 deep-agentic |
| `-p/--categories` | `pi`, `jailbreak`, `leakage`, `tool`, `rag`, `output`, `dos`, `safety`, `bias` (long forms accepted) |
| `--spec` / `--exclude` | run/skip specific spec ids or globs (e.g. `PI-*`); repeatable |
| `--top-tests N` | keep the N highest-signal specs |
| `-sV` / `-sn` / `-A` | fingerprint-first / discovery-only / aggressive (`-sV` + deep + adaptive) |
| `--runs N` | reproducibility runs (default 5) |
| `-T 0..5` | timing template (default 3); higher is faster/louder |
| `--rate` / `--concurrency` / `--timeout` | max req/s · max concurrent specs · per-attempt timeout |
| `--dry-run` | resolve + validate, send nothing |
| `--estimate` | print a pre-run cost estimate (requests + tokens); no sends |
| `--compare` | model-comparison matrix across targets |
| `--hardened` | replay hardened fixtures (clean-run smoke) |
| `-oJ/-oH/-oS/-oX/-oA` | JSON / HTML / SARIF / JUnit / all four to `<prefix>.*` |
| `--fail-on <band>` | CI gate on confirmed findings (`low\|medium\|high\|critical`, default `high`) |
| `--include-needs-review` | also gate low-confidence findings |
| `--spec-path` | spec search path (default `specs/`) |

**Exit codes:** `0` clean · `1` findings below `--fail-on` · `2` findings at/above · `3` error.
Only an **exploited** (`fail`) finding trips the gate; `pass`/`inconclusive` never do.

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
dottore fleet fleet.yaml --run --judge judge.yaml  # or scan every target immediately
```

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
Reproducibility`, banded critical/high/medium/low/info; confidence gates it as **confirmed**
vs **needs-review** (a format-valid PII/secret hit without corroboration is *needs-review*,
never a confirmed leak). Every finding carries evidence (prompt, response, traces, evaluator
reasoning), and `dottore replay` re-derives a run from stored evidence. See
[`docs/05-scoring-model.md`](docs/05-scoring-model.md).

## Adding a technique (no core code)

The product's whole point is extensibility. A new attack is usually just YAML:
`dottore new-spec …` → fill `attack`, `expected_secure_behavior`, `evaluators`, and golden
`fixtures` (vulnerable ⇒ scanner must flag; hardened ⇒ must pass) → `dottore lint specs/` →
reference it from a suite. Details in [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/06-extensibility-suites.md`](docs/06-extensibility-suites.md).
