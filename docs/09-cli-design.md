# 09 - CLI design (nmap-for-AI, built for red teamers)

Design goal: a red teamer who knows `nmap` is productive in 5 minutes. Same mental model -
**target as positional arg, scan-type/intensity flags, selectable "scripts", multiple output
formats, sane defaults**. The command is `dottore` (short alias `dott`).

## 1. The nmap ⇄ dottore mental map

| nmap concept | dottore equivalent | Flag |
|---|---|---|
| `nmap <host>` | `dottore <target>` (URL, model id, or target.yaml) | positional |
| Host discovery `-sn` | Reachability + capability discovery | `-sn` / `discover` |
| Service/version detect `-sV` | **Model & guardrail fingerprint** (which model, defenses, RAG/tools present) | `-sV` |
| Port selection `-p 80,443` | Category/probe selection | `-p pi,jailbreak,leakage` |
| `--top-ports 100` | Top-N highest-signal tests | `--top-tests 20` |
| Timing template `-T0..-T5` | Aggressiveness/rate template `-T0..-T5` | `-T4` |
| Aggressive `-A` | Everything: fingerprint + deep suite + adaptive | `-A` |
| **NSE scripts** `--script` | **Attack specs** (specs ARE our NSE) `--script pi-*` | `--spec` / `--script` |
| Script categories | Suites / presets (`owasp:llm`, `mitre:atlas`) | `--suite` |
| Output `-oX -oN -oG` | `-oJ` json `-oH` html `-oS` sarif `-oX` junit | `-o*` |
| `--min-rate` | Request rate cap | `--rate` |
| `-Pn` (skip ping) | Skip capability probe | `-Pn` |
| `-v` / `-vv` | Verbosity | `-v` |

> **The killer analogy for red teamers:** *Attack specs are to `dottore` what NSE scripts are
> to nmap.* Declarative, categorized, community-extensible, versioned. "Write a spec" ==
> "write an NSE script". This is how new techniques land with zero core code (`docs/06`).

## 2. Command surface

```
dottore <target> [options]

TARGET
  <url|model-id|target.yaml>        positional; or -t/--target for multiple

SCAN TYPE
  -sn                               discovery only (reachability + capabilities)
  -sV                               fingerprint model + guardrails before attacking
  -A                                aggressive: -sV + --deep + --adaptive
  --quick                           T0 minimum battery (~15 tests)   [fast triage]
  --deep                            T2 deep/agentic suite

SELECTION
  --suite <name>                    owasp:llm (default) | mitre:atlas | nist:ai | eu:ai-act
                                    | dora | iso:42001 | agentic | baseline
  -p, --categories pi,jailbreak,leakage,tool,rag,output,dos
  --spec <id|glob>                  run specific spec(s), e.g. --spec 'PI-*'
  --exclude <id|glob>
  --top-tests N                     N highest-signal specs

EXECUTION
  -T <0-5>                          timing/aggressiveness template (default T3)
  --rate <rps>                      max requests/sec       --concurrency <n>
  --runs N                          reproducibility runs (default 5)
  --adaptive [--max-attempts N]     multi-turn escalation up to a budget
  --seed <int>                      pin determinism
  --timeout <s>                     per-attempt timeout
  --budget-tokens N --budget-usd N  hard cost caps (also stops self-DoS)

SAFETY / SCOPE
  --scope scope.yaml                REQUIRED authorization record (default-deny)
  --allow-endpoint <host/prefix>    extend allowlist (audited)
  --dry-run                         resolve + validate, send nothing
  --unsafe-render                   render raw dangerous payloads in report (off by default)

OUTPUT
  -oJ file.json  -oH file.html  -oS file.sarif  -oX junit.xml  -oA <prefix> (all)
  --fail-on <low|medium|high|critical>     CI gate (confirmed findings)
  --include-needs-review                   also gate on low-confidence findings
  --compare                                model-comparison matrix (multi-target)
  -v, -vv, -q, --no-color

REGISTRY / AUTHORING
  dottore registry ls [--category ..] [--suite ..]
  dottore describe <spec-id>
  dottore lint specs/                       schema + policy + fixtures-prove-detection
  dottore new-spec --family <f> --id <ID>   scaffold a spec + empty fixtures
  dottore replay <run-id>                   re-run from stored evidence (reproducibility)
```

## 3. Example invocations (the red-teamer's cheat sheet)

```bash
# Fast triage of a raw model endpoint (nmap-default vibe)
dottore https://api.openai.com/v1/chat/completions --model gpt-4o --quick --scope scope.yaml

# Fingerprint first, then full OWASP suite, HTML + SARIF out
dottore -sV --suite owasp:llm -oH report.html -oS out.sarif -t target.yaml --scope scope.yaml

# Aggressive agentic assessment with adaptive multi-turn, budget-capped
dottore -A --adaptive --max-attempts 50 --budget-usd 5 -t customer-agent.yaml --scope scope.yaml

# Just the injection + leakage families, fast, break CI on high
dottore -p pi,leakage -T4 --fail-on high -oX junit.xml -t agent.yaml --scope scope.yaml

# Compare three models on the same suite (benchmark mode)
dottore --suite owasp:llm --compare -t gpt.yaml -t claude.yaml -t mistral.yaml --scope scope.yaml

# EU AI Act / DORA regulatory preset
dottore --suite eu:ai-act -oA acme-aiact -t chatbot.yaml --scope scope.yaml
```

## 4. Output ergonomics

- Live progress like nmap: `Scanning target [ 34/60 specs ] PI-DIRECT-001 ... FAIL (high)`.
- Terminal summary table by category + severity band + reproducibility.
- Exit codes: `0` clean, `1` findings below `--fail-on`, `2` findings at/above `--fail-on`,
  `>2` operational error. CI-friendly and scriptable.
- Everything is also machine-output (`-oJ`) so it pipes into other tooling - nmap philosophy.

## 5. Non-goals for the CLI

- No interactive TUI in v1 (scriptability first; TUI optional later).
- The CLI never bypasses the scope/allowlist gate, even with `-A`. Safety is not a flag you
  can turn off except the explicit, audited `--allow-endpoint` / `--unsafe-render`.
