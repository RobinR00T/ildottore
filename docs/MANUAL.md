# Il Dottore, Manual

The complete operator reference for `dottore`. For a fast start read
[`../USAGE.md`](../USAGE.md) and [`../examples/`](../examples/) first; this manual is the
long form you come back to. The internals are documented in the numbered design corpus
(`docs/00`..`14`); this file is about **using** the tool.

## Contents

1. [Mental model](#1-mental-model)
2. [Vocabulary](#2-vocabulary)
3. [The safety and authorization model](#3-the-safety-and-authorization-model)
4. [File reference: scope, target, fleet](#4-file-reference)
5. [Command reference](#5-command-reference)
6. [The attack battery](#6-the-attack-battery)
7. [Multi-turn attacks](#7-multi-turn-attacks)
8. [Evaluators and verdicts](#8-evaluators-and-verdicts)
9. [Scoring and findings](#9-scoring-and-findings)
10. [Reports, evidence and reproducibility](#10-reports-evidence-and-reproducibility)
11. [CI integration](#11-ci-integration)
12. [Extending the battery](#12-extending-the-battery)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Mental model

Il Dottore is the diagnostician. It works in three movements:

1. **Examine**, optionally fingerprint the target (`-sV`) to identify the model and its
   guardrails before attacking.
2. **Diagnose**, run a battery of declarative attack specs. Each spec sends one or more
   prompts, captures the full response and any tool calls, and hands the transcript to
   deterministic evaluators (and, optionally, an LLM judge) that return a verdict.
3. **Report**, score each confirmed weakness by operational risk, persist the evidence,
   and emit a machine-readable and human-readable report that can be replayed later.

The whole product optimizes for three things: **reproducibility, evidence, and risk
mapping**. Anything that cannot be reproduced, evidenced, or tied to a business risk is
noise.

## 2. Vocabulary

| Term | Meaning |
|------|---------|
| **Target** | The thing under test: a model, chatbot, agent, RAG app or API. Declared in a `target.yaml`. |
| **Scope** | The authorization record (`scope.yaml`): which targets you may scan and the endpoint allowlist. No run without it. |
| **Spec** | One declarative attack test (YAML): the attack, the expected secure behavior, the evaluators, and golden fixtures. |
| **Suite** | An ordered collection of specs (e.g. `owasp-llm-top10`). |
| **Category** | A family a spec belongs to (prompt_injection, jailbreak, data_leakage, agent_tool_abuse, rag_security, output_security, availability_cost). |
| **Evaluator** | The verdict engine for a spec. Deterministic evaluators decide first; `semantic_judge` is an optional LLM secondary. |
| **Verdict** | Per attempt: `pass` (secure), `fail` (exploited), or `inconclusive`. |
| **Finding** | A scored, evidenced weakness derived from failing attempts. |
| **Band** | The severity band of a finding: info / low / medium / high / critical. |
| **Confidence** | Whether a finding is `confirmed` or `needs-review` (low confidence). Separate from risk. |
| **Canary** | A planted secret/marker used to detect leakage without exposing a real secret. |
| **Mutator** | A payload transform (encoding, obfuscation) applied to an attack to test bypasses. |
| **Fingerprint** | A best-effort identification of the model + guardrails behind an endpoint. |
| **Run** | One execution, identified by a run id, whose evidence can be replayed. |

## 3. The safety and authorization model

Il Dottore is a defensive tool and is built to be safe to point at production:

- **Authorization-gated.** Every egress is checked against the scope's endpoint allowlist
  (default-deny) before any request leaves the process. An out-of-scope host or off-prefix
  path raises an error and sends nothing. Plain `http` is allowed only to loopback
  (`localhost`, `127.0.0.1`, `::1`); everything else must be `https`.
- **Safe-by-design.** Sensitive tools are executed as mocks or in dry-run; exfiltration
  targets are mock endpoints that the allowlist blocks; every dangerous payload is flagged
  `test_only`.
- **Policy-gated capabilities.** Every spec carries a `test_only` flag and a list of
  `requires_policy` capabilities. A run applies a **policy pack**; the CLI's default pack
  allows the categories present but enables **no** capabilities, so a spec that declares
  `requires_policy` (for example PII elicitation, or the agentic-extortion battery) yields a
  `blocked_by_policy` result with **zero** sends. Enabling such a spec is a deliberate
  policy-pack decision, not a default.
- **Redact-at-rest.** Secrets and PII are masked in logs, evidence and reports.

See [`02-threat-model.md`](02-threat-model.md) and [`RESPONSIBLE-USE.md`](RESPONSIBLE-USE.md).

## 4. File reference

### 4.1 `scope.yaml`, the authorization record

Required for every scanning command. An optional top-level `checksum:` (sha256 of the body)
makes the scope tamper-evident; when present it is verified and the run records the hash.

```yaml
version: "1.0"
targets:                         # >=1; a target whose id is absent here is refused
  - id: my-chatbot               # must match the target.yaml's id
    base_url: "https://api.example.com/v1/chat/completions"
    endpoints:                   # default-DENY allowlist; host + allowed path prefixes
      - host: "api.example.com"
        path_prefixes: ["/v1/chat/completions"]
    identities:                  # >=1; auth by reference, never a secret value
      - name: default
        auth_ref: "env://MY_API_KEY"
# checksum: "<sha256 of the body>"   # optional, tamper-evident
```

Each target declares its own `endpoints` allowlist and `identities`. Plain `http` is allowed
only to loopback hosts; everything else must be `https`. Template:
[`../specs/scope.example.yaml`](../specs/scope.example.yaml).

### 4.2 `target.yaml`, what you are scanning

```yaml
id: my-chatbot                   # must match a target id in the scope's `targets`
type: chatbot                    # model | chatbot | agent | rag | api
provider: openai                 # openai (and openai-compatible) | anthropic | rest
endpoint: "https://api.example.com/v1/chat/completions"
model: "gpt-4o"                  # provider model id
auth_ref: "env://MY_API_KEY"     # reference only; the secret is read at send time, never stored
capabilities:
  tools: false
  rag: false
  memory: false
  streaming: true
  seed: true                     # provider supports seed -> determinism is recorded
sampling_defaults: { temperature: 0.0, top_p: 1.0 }
```

`id` and `type` are required; the rest are optional but needed for a live scan. `auth_ref`
supports `env://NAME` (and `vault://…` in production); the secret itself is never written to
a file. Template: [`../specs/targets/example-openai.yaml`](../specs/targets/example-openai.yaml).

An **MCP server** target uses `provider: mcp`. Over the wire it declares the Streamable-HTTP
`endpoint`. As a **local subprocess** it declares `transport: stdio` and a `command`:

```yaml
id: local-mcp
type: api
provider: mcp
transport: stdio
command: ["python", "server.py"]   # spawned only if the scope authorizes this exact command
capabilities: { tools: true }
```

For a stdio target the scope authorizes by command, not endpoint: add the exact command line
to the scope target's `commands` list (default-deny). The MCP adapter is read-only for both
transports (it never calls a tool).

### 4.3 `fleet.yaml`, many targets in one file

```yaml
version: "1"
targets:
  - id: openai-gpt4o
    endpoint: https://api.openai.com/v1/chat/completions
    model: gpt-4o
    api_key_env: OPENAI_API_KEY        # env var name, never the key itself
  - id: local-ollama
    endpoint: http://localhost:11434/v1/chat/completions
    model: llama3.2:1b                 # no key needed
  - id: my-app
    provider: rest                     # override the inferred provider
    endpoint: https://my-app.example.com/chat
  - id: my-mcp
    kind: mcp                          # routed to the read-only MCP adapter (discovery)
    endpoint: http://localhost:3000/mcp
```

`provider` is inferred from the endpoint when omitted: `/chat/completions` -> `openai`,
`/messages` -> `anthropic`, otherwise `rest`. `dottore fleet` expands this into a scope plus
one target file per model. Template: [`../specs/fleet.example.yaml`](../specs/fleet.example.yaml).

## 5. Command reference

`dottore` is the command; `dott` is a shorter alias. `run` is the default subcommand.

### `dottore run`, run a campaign

```
dottore run [OPTIONS] [TARGET_POS]...
```

Targets may be passed positionally or with `-t/--target` (repeatable). `--scope` is
required.

**Selection**

| Flag | Meaning |
|------|---------|
| `--suite TEXT` | suite id or alias (`owasp:llm`, `quick`, `multi-turn`, `access-control`, `agentic-owasp2026`, `obfuscation-enhancers`, `embeddings`, `agentic-extortion`, `mcp`, `responsible-ai`, `guardrail-evasion`) |
| `-p/--categories TEXT` | comma-separated categories (`pi,jailbreak,leakage,tool,rag,output,dos`) |
| `--spec TEXT` | spec id or glob, e.g. `PI-*` (repeatable) |
| `--exclude TEXT` | exclude spec id/glob (repeatable) |
| `--top-tests INT` | keep the N highest-signal specs |
| `--quick` / `--deep` | T0 minimum battery / T2 deep-agentic |

**Discovery and aggression**

| Flag | Meaning |
|------|---------|
| `-sn` | discovery only (no attacks) |
| `-sV` | fingerprint before attacking |
| `-A` | aggressive: `-sV` + deep + adaptive |

**Judge and execution**

| Flag | Meaning |
|------|---------|
| `--judge PATH` | judge model `target.yaml` (LLM-as-judge for `semantic_judge`) |
| `--runs INT` | reproducibility runs (default 5) |
| `-T 0..5` | timing template (default 3); higher is faster/louder |
| `--rate FLOAT` | max requests/sec |
| `--concurrency INT` | max concurrent specs |
| `--timeout FLOAT` | per-attempt timeout (s) |
| `--dry-run` | resolve + validate; send nothing |
| `--estimate` | print a pre-run cost estimate (requests + tokens); no sends |
| `--compare` | model-comparison matrix across targets |
| `--hardened` | replay hardened fixtures (clean-run smoke) |

**Output and gating**

| Flag | Meaning |
|------|---------|
| `-oJ/-oH/-oS/-oX PATH` | write JSON / HTML / SARIF / JUnit |
| `-oA PATH` | write all four to `<prefix>.*` |
| `--fail-on BAND` | CI gate: `low\|medium\|high\|critical` (default `high`) |
| `--include-needs-review` | also gate low-confidence findings |
| `--evidence-root PATH` | evidence store root (default `.dottore/evidence`) |
| `--run-db PATH` | run store SQLite path |
| `--spec-path PATH` | spec search path (default `specs/`) |
| `-q/--quiet`, `-v`, `--no-color` | output verbosity |

**Exit codes:** `0` clean · `1` findings below `--fail-on` · `2` findings at/above · `3`
error. Only an exploited (`fail`) finding trips the gate; `pass`/`inconclusive` never do.

### `dottore fingerprint`, identify the model + guardrails

```
dottore fingerprint TARGET --scope scope.yaml
```

`TARGET` is positional (a `target.yaml`). Attacks nothing; reports the best-effort model and
guardrail fingerprint. See [`10-fingerprint.md`](10-fingerprint.md).

### `dottore fleet`, expand and optionally scan a fleet

```
dottore fleet CONFIG [--out DIR] [--run] [--judge PATH] [--runs N] [-p CATEGORIES]
```

Expands `CONFIG` (a `fleet.yaml`) into an authorization scope plus one target file per model
under `--out` (default `.dottore/fleet`). With `--run`, scans every expanded target
immediately.

### `dottore lint`, validate specs

```
dottore lint [PATHS]... [--json]
```

Schema + policy + fixtures-prove-detection lint. `specs/` resolves as a pack (via
`pack.yaml`) so discovery loads `attacks/` + `suites/` and skips the loose example YAMLs.

### `dottore describe`, one spec's detail card

```
dottore describe SPEC_ID [--spec-path PATH]
```

### `dottore registry ls`, list the catalogue

```
dottore registry ls [--category ..] [--owasp ..] [--tag ..] [--suite ..] [--spec-path ..]
```

Read-only. The source of truth for what specs, suites and categories exist.

### `dottore new-spec`, scaffold a new attack

```
dottore new-spec --id PI-NEW-001 --family prompt_injection [--category ..] [--out DIR] [--stdout]
```

Writes a spec skeleton plus empty fixtures (or prints them with `--stdout`).

### `dottore replay`, reproduce a past run from evidence

```
dottore replay RUN_ID [--evidence-root PATH]
```

Re-reads a run from stored evidence without re-sending anything.

### `dottore diff`, regression gate against a baseline

```
dottore diff BASELINE CURRENT
```

Both are JSON run reports (`-oJ` output). Classifies each spec id as NEW-FAIL (regression),
FIXED, STILL-FAIL or UNCHANGED and exits nonzero when any regression is present, so it is
CI-gateable like `run`.

### `dottore schema export`, the JSON Schemas

```
dottore schema export
```

Prints the generated JSON Schemas that machine-validate every spec.

## 6. The attack battery

53 specs across 11 suites, aligned to OWASP LLM Top 10, MITRE ATLAS and OWASP-Agents-2026.
`dottore registry ls` prints the live list; the columns are `id`, OWASP tag, band, category,
and title. Spec ids are family-prefixed: `PI-` prompt injection, `JB-` jailbreak, `DL-` data
leakage, `AC-` access control, `AG-` agentic abuse, `OUT-` insecure output, `EMB-` embeddings,
`SP-` system-prompt, `DOS-` model DoS, `RECON-` reconnaissance.

Suites (with the count `registry ls --suite <id>` reports):

| Suite | Specs | Focus |
|-------|-------|-------|
| `owasp-llm-top10` (alias `owasp:llm`) | 18 | the OWASP LLM Top 10 baseline |
| `quick` | 18 | fast triage battery (`--quick`) |
| `multi-turn` | 5 | Crescendo / Linear / Sequential / Bad-Likert / Tree |
| `access-control` | 9 | BFLA / BOLA / RBAC / SSRF / debug-interface / argument-smuggling |
| `agentic-owasp2026` | 5 | goal theft / recursive hijack / identity abuse / inter-agent / autonomy drift |
| `obfuscation-enhancers` | 2 | encoding / obfuscation bypass enhancers |
| `embeddings` | 3 | embedding inversion / neighbor leak / cross-tenant retrieval |
| `agentic-extortion` | 7 | JadePuffer-class agentic-ransomware susceptibility (policy-gated) |
| `mcp` | 1 | MCP-server metadata poisoning (point it at a `provider: mcp` target) |
| `responsible-ai` | 2 | optional NIST-mapped pack: harmful-content refusal + demographic bias/fairness |
| `guardrail-evasion` | 2 | moderation-layer evasion, input classifier + output filter |

Select with `--suite`, `-p/--categories`, `--spec`/`--exclude` (globs), or `--top-tests`.

## 7. Multi-turn attacks

Multi-turn specs (Crescendo, Linear, Sequential, Bad-Likert, Tree) escalate over several
turns. The attacker turns are **pinned in the spec**, not generated by an LLM, which is the
whole point: the conversation is threaded to the target as `messages`, only the final turn is
scored, and the entire transcript is persisted as evidence. A multi-turn run is therefore as
reproducible as a single-shot one. There is nothing to enable: choose the `multi-turn` suite
or the individual `JB-*` specs.

## 8. Evaluators and verdicts

Each spec names one or more evaluators. The design is **deterministic-first**:

- **Deterministic evaluators** (refusal detection, regex/absence, secret/canary leakage,
  tool-call inspection, SQL/shell/XSS output checks, authz-crossing, logprob membership,
  and so on) decide the verdict with no model in the loop. They are the primary word.
- **`semantic_judge`** is an optional LLM-as-judge, wired with `--judge`. It is a
  **secondary**: it never overrides a deterministic verdict. Without a judge it abstains
  (`capability_unavailable`) and a finding that depends solely on it comes back inconclusive.

The **`tool_call`** evaluator inspects the tool-call trace and fails on four abuse classes:
an unauthorized tool (outside `patterns` / `setup.tools`), an unconfirmed destructive call, an
injection marker smuggled into an argument value, and **argument smuggling** (a.k.a. schema
poisoning). For the last one the spec lists the out-of-schema/privileged argument keys under
the evaluator's `forbidden_args`; a truthy value under any of them (at any nesting depth), on
an otherwise-authorized tool, fails. Declare it only when you want it: omitting `forbidden_args`
leaves that check inert.

```yaml
evaluators:
  - type: tool_call
    patterns: ["update_account"]          # the authorized tool
    forbidden_args: ["role", "bypass_review"]   # privileged fields the task must not populate
```

**Judge hardening.** The judge is assumed to be attackable. Each judge call carries a
per-call random tripwire token; the judge is flagged **compromised** if it echoes the
tripwire, or if an observed injection coincides with a "secure" verdict. A compromised judge
cannot pass a target. The self-scan (`make selfscan`) attacks our own judge with an
adversarial corpus and fails CI on any new high/critical flip.

**Verdict combination.** When both a deterministic evaluator and the judge weigh in: a
deterministic `fail` beats an inconclusive; a judge `fail` never overrides a deterministic
inconclusive; an unconsulted or abstaining judge is dropped rather than allowed to force an
inconclusive; a compromised judge dominates (the result is not trusted as a pass). See
[`04-evaluator-spec.md`](04-evaluator-spec.md).

## 9. Scoring and findings

Risk and confidence are **separate axes**:

- **Risk** = `Impact x Exploitability x Reproducibility`, banded info / low / medium / high /
  critical. Reproducibility is measured over `--runs` with pinned sampling params, not
  assumed. Confidence is deliberately **not** a multiplier on risk.
- **Confidence** gates a finding as `confirmed` or `needs-review`. A format-valid secret/PII
  hit without corroboration is `needs-review`, never a confirmed leak.

Only exploited (`fail`) findings can trip the CI gate, and by default only `confirmed` ones;
`--include-needs-review` extends the gate to low-confidence findings. See
[`05-scoring-model.md`](05-scoring-model.md).

## 10. Reports, evidence and reproducibility

- **Formats.** `-oJ` JSON, `-oH` HTML, `-oS` SARIF (for code-scanning), `-oX` JUnit (for CI
  test reporting), `-oA <prefix>` writes all four.
- **Evidence store.** Every attempt persists its prompt, full response, sampling params, tool
  traces, evaluator reasoning and diffs under `--evidence-root` (default `.dottore/evidence`),
  content-addressed and redacted at rest. The run store is a SQLite db (`--run-db`).
- **Replay.** `dottore replay <run-id>` re-derives a run from stored evidence with no
  re-sending, which is what makes a finding auditable after the fact.
- **Do not commit `.dottore/`** (evidence + runs are runtime artifacts).

## 11. CI integration

Two patterns, often combined:

1. **Absolute gate.** `dottore run --fail-on high -oS out.sarif` exits `2` on a confirmed
   finding at or above the band. Upload the SARIF to code-scanning.
2. **Regression gate.** Keep a baseline JSON run in the repo and compare:
   `dottore diff baseline.json current.json` exits nonzero only on NEW-FAIL regressions.

A ready-made GitHub Actions workflow is in
[`../examples/ci-github-actions.yml`](../examples/ci-github-actions.yml).

## 12. Extending the battery

A new attack is usually just YAML, no core code:

1. `dottore new-spec --id PI-MYORG-001 --family prompt_injection`
2. Fill `attack`, `expected_secure_behavior`, `evaluators`, and golden `fixtures`: a
   **vulnerable** fixture the scanner must flag, and a **hardened** one it must pass.
3. `dottore lint specs/` (schema + policy + fixtures-prove-detection).
4. Reference the spec from a suite.

Mutators (encoding/obfuscation transforms) let one attack test many bypasses without writing
new prompts. A spec lists them under `mutations`; a mutation may be parameterized as
`name:param` (for example `translate:fr` runs the `translate` mutator in French, so one spec
covers a systematic per-language battery). See [`06-extensibility-suites.md`](06-extensibility-suites.md),
[`03-attack-spec-format.md`](03-attack-spec-format.md) and [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## 13. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `endpoint not allowed by scope` | Target endpoint host/path not in that target's `endpoints`, or id not among the scope's `targets`. Add it deliberately. |
| Live findings all inconclusive | No `--judge`, so `semantic_judge` abstains. Pass a judge target; deterministic evaluators still fire. |
| A policy-gated spec never runs (`blocked_by_policy`) | The active policy pack does not enable the spec's `requires_policy` capability. The default CLI pack enables none; enabling one is a deliberate decision. |
| `connection refused` to `localhost:11434` | Ollama not running (`ollama serve`) or model not pulled. |
| Run validates but sends nothing | `--dry-run` is set. Drop it. |
| MCP scan returns the same catalogue for every spec | The MCP adapter does read-only discovery (it is not chat), so it renders the server's advertised metadata regardless of prompt. Use the `mcp` suite for meaningful checks. |
| Plain-http target refused | Non-loopback http is blocked; use `https`, or point at `localhost`/`127.0.0.1`. |
| `authz_leak` is `capability_unavailable` | A cross-tenant spec needs the target's `multi_identity` capability and a scope with >=2 identities (each with its owned `canary`). The runner then sends as each identity. A real scan also needs each tenant's canary pre-seeded in that tenant's data. |
