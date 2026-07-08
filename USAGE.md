# Using Il Dottore (`dottore`)

nmap-for-AI: a spec-driven security scanner for LLMs and AI apps. This is the practical guide;
the design/spec corpus lives in [`docs/`](docs/) and `AGENTS.md`.

> **Authorized testing only.** `dottore` refuses any target not covered by a signed `scope.yaml`
> (endpoint allowlist, default-deny), never performs real destructive actions or exfiltration
> (mocked tools + planted canaries), and masks secrets/PII in logs, evidence and reports. See
> [`docs/02-threat-model.md`](docs/02-threat-model.md).

## Install

```bash
git clone <repo> && cd ildottore
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/dottore --help          # or `dott --help`
```

## 60-second quickstart

You need two files: a **scope** (your authorization record) and a **target**.

`scope.yaml` — what you're allowed to scan (default-deny):
```yaml
version: "1.0"
targets:
  - id: my-chatbot
    base_url: "https://api.example.com"
    endpoints:
      - host: "api.example.com"
        path_prefixes: ["/v1/chat"]
    identities:
      - name: default
        auth_ref: "env://MY_API_KEY"     # never inline secrets
```

`target.yaml` — what you're scanning:
```yaml
id: my-chatbot
type: chatbot          # model | chatbot | agent | rag | api
capabilities: { tools: false, rag: false }
```

Run the quick triage battery and write reports:
```bash
dottore run --quick -t target.yaml --scope scope.yaml -oA report
```

## Common invocations

```bash
# Fingerprint only — identify the model/guardrails behind an endpoint, attack nothing
dottore fingerprint -t target.yaml --scope scope.yaml

# Full OWASP LLM Top 10 suite, HTML + SARIF out
dottore run --suite owasp:llm -t target.yaml --scope scope.yaml -oH report.html -oS out.sarif

# Fingerprint first, then an adaptive (opt-in) run; break CI on confirmed high/critical
dottore run -sV --adaptive --fail-on high -oX junit.xml -t target.yaml --scope scope.yaml

# Just injection + leakage families, faster
dottore run -p pi,leakage -T4 -t target.yaml --scope scope.yaml

# Compare several models on the same suite
dottore run --suite owasp:llm --compare -t gpt.yaml -t claude.yaml -t mistral.yaml --scope scope.yaml

# Inspect / author specs
dottore registry ls [--category .. --owasp .. --suite ..]
dottore describe PI-DIRECT-001
dottore lint specs/
dottore new-spec --family prompt_injection --id PI-XYZ-001
dottore replay <run-id> --evidence-root ./evidence     # reproduce a past run from evidence
```

## Flags that matter

| Flag | Meaning |
|------|---------|
| `--scope` | **Required** authorization record. Never bypassable. |
| `-t/--target` (repeatable), positional | target file(s) |
| `--suite` | `owasp:llm` (default) · `mitre:atlas` · `nist:ai` · `agentic-extortion` · … |
| `--quick` / `--deep` | T0 minimum battery / T2 deep-agentic |
| `-p/--categories` | `pi,jailbreak,leakage,tool,rag,output,dos` |
| `--spec` / `--exclude` | run/skip specific spec ids or globs |
| `-sV` / `-sn` / `-A` | fingerprint-first / discovery-only / aggressive |
| `--runs N` | reproducibility runs (default 5) |
| `--adaptive` | multi-turn escalation (opt-in) |
| `--dry-run` | resolve + validate, send nothing |
| `-oJ/-oH/-oS/-oX/-oA` | JSON / HTML / SARIF / JUnit / all |
| `--fail-on <band>` | CI gate on confirmed findings (`low|medium|high|critical`) |
| `--spec-path` | spec search path (default `specs/`) |

**Exit codes:** `0` clean · `1` findings below `--fail-on` · `2` findings at/above · `>2` error.

## Reading results

A finding separates **risk** from **confidence**: `RiskScore = Impact × Exploitability ×
Reproducibility`, banded critical/high/medium/low/info; confidence gates it as **confirmed** vs
**needs-review** (a format-valid PII/secret hit without corroboration is *needs-review*, never a
confirmed leak). Every finding carries evidence (prompt, response, traces, evaluator reasoning),
and `dottore replay` re-derives a run from stored evidence. See
[`docs/05-scoring-model.md`](docs/05-scoring-model.md).

## Adding a technique (no core code)

The product's whole point is extensibility. A new attack is usually just YAML:
`dottore new-spec …` → fill `attack`, `expected_secure_behavior`, `evaluators`, and golden
`fixtures` (vulnerable ⇒ scanner must flag; hardened ⇒ must pass) → `dottore lint specs/` →
reference it from a suite. Details in [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/06-extensibility-suites.md`](docs/06-extensibility-suites.md).
