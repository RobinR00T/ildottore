# 09: CLI design (nmap-for-AI, built for red teamers)

Design goal: a red teamer who knows `nmap` is productive in 5 minutes. Same mental model:
**target file as positional arg, scan-type/intensity flags, selectable specs, multiple output
formats, sane defaults**. The command is `dottore` (short alias `dott`, both installed by
`pyproject.toml`).

This document mixes the design with what is built. Every row and flag below says which it is;
the authority for the built surface is `dottore <command> --help`. Items that are design only
are collected in §5, "Not implemented".

## 1. The nmap ⇄ dottore mental map

| nmap concept | dottore equivalent | Flag | Status |
|---|---|---|---|
| `nmap <host>` | `dottore run <target.yaml>` | positional target file(s), or `-t` | built. The positional is a **file**: a URL or model id is read as a path and fails. `run` must be typed: there is no default subcommand (`dottore target.yaml` is "No such command") |
| Host discovery `-sn` | Authorized endpoint + declared capabilities + what the battery would run. Sends nothing | `-sn` | built. A `discover` subcommand is not |
| Service/version detect `-sV` | **Model & guardrail fingerprint** (which model, defenses, carrier comprehension) | `-sV`, or `dottore fingerprint <target.yaml>` | built (17 probes per target, printed in the plan; a probe whose reply is refused fails alone, said on stderr, and the run goes on; one that gets no answer stops it: OD-23) |
| Port selection `-p 80,443` | Category selection | `-p pi,jailbreak,leakage` | built |
| `--top-ports 100` | Top-N highest-signal tests | `--top-tests 20` | built |
| Timing template `-T0..-T5` | Aggressiveness/rate template `-T0..-T5` | `-T4` | built |
| Aggressive `-A` | Fingerprint + timing T2 + adaptive mutator ordering, over the selection the other flags make (the full battery when there is no `--suite`) | `-A` | built (`-A` = `-sV` + `--deep`) |
| **NSE scripts** `--script` | **Attack specs** (specs ARE our NSE) | `--spec 'PI-*'` | built as `--spec`. A `--script` alias is not |
| Script categories | Suites | `--suite` | built for the 14 registered suites. Of the regulatory presets only `owasp:llm` resolves (§2) |
| Output `-oX -oN -oG` | `-oJ` json `-oH` html `-oS` sarif `-oX` junit, `-oA` all four | `-o*` | built |
| `--min-rate` | Request rate cap | `--rate` | built (a ceiling, must be greater than 0) |
| `-Pn` (skip ping) | Skip capability probe | `-Pn` | not built ("No such option") |
| `-v` / `-vv` | Verbosity | `-v`, `-vv` | built (a counter) |

> **The killer analogy for red teamers:** *Attack specs are to `dottore` what NSE scripts are
> to nmap.* Declarative, categorized, community-extensible, versioned. "Write a spec" ==
> "write an NSE script". This is how new techniques land with zero core code (`docs/06`).

## 2. Command surface (built; a grouped summary, `dottore run --help` is the authority)

The block below groups the options by purpose and is written by hand; it is not the help text.

```
dottore run [<target.yaml> ...] [-t <target.yaml>] --scope <scope.yaml> [options]

TARGET
  <target.yaml> ...                 positional target file(s); or -t/--target, repeatable
  --judge <target.yaml>             LLM-as-judge for semantic_judge (must be in the scope)

SCAN TYPE
  -sn                               discovery only: authorized endpoint + declared
                                    capabilities + what the battery would run. Sends nothing
  -sV                               fingerprint model + guardrails before attacking, and
                                    order each spec's mutators by what the target decoded
  -A                                aggressive: -sV + --deep
  --quick                           T0 battery: --suite quick (18 specs) at -T0
  --deep                            timing template T2; it does not change the selection.
                                    Adaptive ordering only with -sV (note below the block)

SELECTION
  --suite <id|alias>                any of the 14 registered suite ids, or an alias:
                                    owasp:llm | baseline (both = owasp-llm-top10),
                                    agentic (= agentic-extortion), quick.
                                    No --suite = the full battery (every spec the target
                                    can run), not owasp:llm
  -p, --categories                  pi, jailbreak (jb), leakage, tool (agent), rag, output,
                                    dos, safety, bias (fairness), or the canonical names
  --spec <id|glob>                  run specific spec(s), e.g. --spec 'PI-*'. Repeatable
  --exclude <id|glob>               repeatable
  --top-tests N                     N highest-signal specs

EXECUTION
  -T <0-5>                          timing/aggressiveness template (default T3; an explicit
                                    -T wins over the one --quick/--deep imply)
  --rate <rps>                      max requests/sec       --concurrency <n>
  --runs N                          reproducibility runs (default 5, for every spec)
  --timeout <s>                     per-attempt timeout
  --budget-tokens / --budget-requests / --budget-wall
                                    hard ceilings; each overrides the one derived from the plan
  --resume <run-id>                 finish a halted run; answered attempts are not re-sent
  --resume-unverified               resume a run whose integrity record is missing

SAFETY / SCOPE
  --scope scope.yaml                REQUIRED authorization record (default-deny)
  --dry-run                         resolve + validate, send nothing
  --estimate                        pre-run cost estimate (requests + tokens), send nothing
  --hardened                        replay the hardened fixtures (clean-run smoke)

OUTPUT
  -oJ file.json  -oH file.html  -oS file.sarif  -oX junit.xml
  -oA <prefix>                             all four: <prefix>.json .html .sarif .xml (a
                                           prefix ending in one of those has it dropped first)
  --fail-on <info|low|medium|high|critical> CI gate (confirmed findings; default high)
  --include-needs-review                   also gate on unconfirmed fails (never on an
                                           inconclusive or a pass)
  --compare                                model-comparison matrix (two or more targets)
  -v, -vv, -q, --no-color
  --evidence-root <dir>  --run-db <path>  --spec-path <dir>

OTHER COMMANDS
  dottore fingerprint <target.yaml> --scope <scope.yaml> [--offline]
  dottore fleet <fleet.yaml> --out <dir> [--run] [--judge ..] [--runs N] [-p ..]
  dottore coverage [--framework all|owasp|atlas|iopc|aisvs] [--suite ..] [--gaps] [--json]
  dottore registry ls [--category ..] [--owasp ..] [--tag ..] [--suite ..]
  dottore describe <spec-id>
  dottore lint specs/ [--json]              schema + policy + fixtures-prove-detection
  dottore new-spec --family <f> --id <ID>   scaffold a spec + empty fixtures
  dottore render-media <spec-id> --out <dir>
  dottore replay <run-id>                   re-read a run from stored evidence; sends nothing
  dottore diff <baseline.json> <current.json>
  dottore calibrate <report.json> <labels.yaml>
  dottore schema export [--name ..]
```

**`--deep` and adaptive planning.** With no `--suite`, a plain `run` already selects the full
battery, so `--deep` alone changes the timing template (T2 instead of T3) and turns on adaptive
mode. Adaptive mode reorders a spec's mutators by the fingerprint's carrier-comprehension
result, and only `-sV` produces a fingerprint, so `--deep` without `-sV` keeps every spec's
declared order. The mode is still recorded: the in-memory plan is marked adaptive (each
selection's reason reads "adaptive-tailored", which no output prints), and the run's integrity
record stores the planning mode, so a `--resume` that changes it is refused. `-A` is the form
that does both. Measured with `--dry-run` on `examples/target.local.yaml` (a chat model with no
tools, RAG or memory): no flag, `--deep` and `-A` each select the same 34 specs and 550
requests; the pacing line reads 5.0 req/s with no flag and 2.0 with `--deep` or `-A`, and `-A`
adds `+17 probe(s) per target`.

**`runs` comes from the command line.** A spec's own `runs:` and a suite's `default_runs:` are
not read by the runner: every mutation variant of every spec is sent `--runs` times (default
5). See `docs/03`.

**Options are validated before the campaign.** `run` refuses, with exit 3 and before the scope
is loaded or anything is sent: a `--rate` that is not greater than 0; an unknown `--fail-on`
band; `--timeout` not greater than 0; `--concurrency`, `--top-tests` or `--runs` below 1; a
report path whose directory does not exist; and two report formats that would write the same
file (paths compared after resolving, Unicode-normalized and case-folded, because a
case-insensitive volume treats `R.json` and `r.json` as one file). These used to be accepted,
and some failed only after the whole campaign had run.

**Resume sends again what ended in an environment error (F11, built 2026-10-04).** `--resume
<run-id>` skips every attempt the halted run ANSWERED and sends again, under the same attempt
id, each one that ended in an environment error (a timeout, a 5xx after retries, a conversation
aborted on one), except an error that would repeat identically (a reply over the size cap, an
undecodable body: recorded with `[not retryable]`). The failed try stays in the evidence tree
and is cited as evidence; the finding scores one attempt per id, the answered one, as `replay`
counts. A resume halted by a ceiling while re-sending keeps the finding a spec already had when
that finding held every planned attempt. The resume message says how many attempts are kept and
how many will be sent again, and `--estimate --resume` subtracts the requests already done (one
per turn of each). What made this safe: the run store journals every attempt artifact as it is
written (schema v4, `pending` before the write and `written` after), so a resume interrupted
mid-spec leaves no artifact the manifest does not know, and the next resume is not refused as
tampered (it was, which is why the first attempt was withdrawn). A resume adopts into the
journal the artifacts already on disk once they pass the check, so a run started by an older
version keeps resuming.

## 3. Example invocations (the red-teamer's cheat sheet)

Each line below parses and resolves under `--dry-run` with real target and scope files (the
first one exactly as written; the others with the file names replaced).

```bash
# Fast triage of a hosted model (the endpoint, provider and credential ref live in the
# target file; there is no positional-URL form and no --model flag)
dottore run --quick -t examples/target.openai.yaml --scope examples/scope.openai.yaml

# Fingerprint first, then the OWASP LLM suite, HTML + SARIF out
dottore run -sV --suite owasp:llm -oH report.html -oS out.sarif -t target.yaml --scope scope.yaml

# Aggressive agentic assessment: fingerprint first, full battery, adaptive ordering
dottore run -A -t customer-agent.yaml --scope scope.yaml

# Just the injection + leakage families, fast, break CI on high
dottore run -p pi,leakage -T4 --fail-on high -oX junit.xml -t agent.yaml --scope scope.yaml

# Compare two or more models on the same suite (benchmark mode)
dottore run --suite owasp:llm --compare -t gpt.yaml -t claude.yaml -t mistral.yaml --scope scope.yaml
```

A regulatory preset (`--suite eu:ai-act`, `dora`, `nist:ai`, `mitre:atlas`, `iso:42001`) is
not built: the alias table in `cli/flags.py` maps each to a suite id no file in `specs/suites/`
has, so the run exits 3 with "suite ... is not registered". For a framework view of what the
battery tests, use `dottore coverage --framework atlas` (OWASP, ATLAS, IoPC and AISVS axes).

## 4. Output ergonomics

- Live progress like nmap: `Scanning target [ 34/60 specs ] PI-DIRECT-001 ... FAIL (high)`.
  An unconfirmed fail reads `FAIL (high, needs review)`, because it does not trip `--fail-on`
  unless `--include-needs-review` is given.
- Terminal summary table by category + severity band + reproducibility.
- Exit codes (`cli/exit_codes.py`): `0` clean, `1` findings below `--fail-on`, `2` findings
  at/above `--fail-on`, `3` operational error, which includes a run that did not finish and a
  command-line usage error (an unknown option exits 3, not 2). CI-friendly and scriptable.
- Everything is also machine-output (`-oJ`) so it pipes into other tooling: nmap philosophy.

## 5. Non-goals for the CLI

- No interactive TUI in v1 (scriptability first; TUI optional later).
- The CLI never bypasses the scope/allowlist gate, even with `-A`. Safety is not a flag you
  can turn off: no flag extends the allowlist or renders raw payloads (both are listed below
  as not built).

### Not implemented (this document is the design, not a changelog)

Each of these was in the design and is **not** on the CLI today. Every flag in the list was
tried on `run --quick --dry-run` and answered "No such option" (exit 3):

- `--seed <int>` (determinism is pinned per spec in its `sampling`, not by a run flag).
- `--allow-endpoint <host/prefix>` (extend the allowlist, audited). The scope file is the only
  way to authorize an endpoint.
- `--unsafe-render` (render raw dangerous payloads in the report). `config.SafetyFlags` and the
  HTML reporter carry an `unsafe_render` switch, off by default, and no flag sets it (OD-12).
- `-Pn` (skip the capability probe) and `--script` (an alias for `--spec`).
- `--adaptive`, `--max-attempts`, `--budget-usd`. Adaptive ordering is reached through `-sV`
  or `-A` (see §2). The budget flags that do exist are `--budget-tokens`, `--budget-requests`
  and `--budget-wall`; without them each ceiling is derived from the resolved plan.
- `--allow-pii-elicitation` and any flag that loads a policy pack. The gated specs
  (`requires_policy`) therefore cannot be enabled from `dottore` today; whether to add a
  policy-pack flag is an open decision.
- A positional URL or model id (`dottore run https://...`): the positional is read as a file.
- `run` as the default subcommand.
- The `discover` subcommand (`-sn` is a flag on `run`).
- The regulatory suite presets `mitre:atlas`, `nist:ai`, `eu:ai-act`, `dora`, `iso:42001`
  (in the alias table, with no suite behind them) and `gdpr` (not even in the table).

Listing them in §1 or §2 without this note is how a design doc turns into a false claim about
the product.
