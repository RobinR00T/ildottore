# 16: Live validation runbook (hosted models, multimodal, the numbers that need a wire)

Everything in this repository is green offline, and a good part of what the product claims
cannot be settled offline. This is the runbook for closing that, written so the decision it
needs from a human is only "which accounts, which models, how much am I willing to spend".

Nothing here runs by itself and nothing here is scheduled. Every command is explicit and every
one of them is bounded by a budget that this tool enforces on itself.

## 1. What is and is not already verified

**Verified over the wire (2026-08-31, recorded in `docs/PROGRESS.md`).** Il Dottore has run
against real targets: a local Ollama model and a local reproduction of a vulnerable chatbot. It
found a critical, reproducible (5/5) prompt-injection to secret-leak finding, returned decisive
passes on seven other attack classes with the judge wired, and the exercise surfaced **two real
bugs the offline mock could not produce**: a live multi-turn request that 400'd on an
OpenAI-shaped `tool_calls` field against Anthropic, and an evidence-store write refused because
a numeric logprob matched a card/phone shape. Both are fixed with regression tests. That run
covered **14 specs**.

**Not verified.** The full battery against a hosted commercial model; the multimodal and audio
matrix against a provider that actually accepts image and audio blocks; `-sV`'s carrier
measurement against a real model (what CI measures is a simulated decoder, by construction);
and `_baseline_resistance` in the planner, which needs live data to mean anything.

The distinction matters because "it has never been run for real" is false and was repeated
here for two days before `docs/PROGRESS.md` was read. What is missing is **breadth**, not the
first contact.

## 2. What a live run would settle, in order of value

1. **Provider-shaped bugs.** The two found on 2026-08-31 were both adapter-level and neither
   was reachable from the mock. This is the highest-value hour in the whole plan.
2. **The multimodal and audio matrix.** Image blocks are implemented for OpenAI and Anthropic,
   audio input only for OpenAI `input_audio`. Nothing has been sent to either in anger.
3. **`-sV` against a real model.** The ordering is measured offline against a decoder we wrote,
   which proves the chain and nothing about behaviour. A live pass produces the first real
   carrier-comprehension profile, and it is cheap: 17 requests per target.
4. **`_baseline_resistance`.** Live verdict distributions are its only honest input.

## 3. What it costs, measured (not estimated from memory)

`dottore run --estimate` prices a plan without sending anything. Today, against the shipped
battery of 75 specs at the default `runs=5`:

| Target shape | Specs run | Requests | Rough token gloss |
|---|---|---|---|
| A bare hosted model (`type: model`, no tools/rag/memory/multimodal) | 34 | 550 | ~395k |
| A fully capable deployment (`type: agent`, every capability declared) | 66 | 775 (+17 with `-sV`) | ~520k |

Two things that table says out loud:

* **A raw model endpoint cannot exercise the battery.** 39 of 75 specs are capability-gated and
  skip on a bare `type: model` target, which is honest rather than inconvenient: a tool-abuse
  spec against an endpoint with no tools would be theatre. To exercise those, the target has to
  be a deployed application that really has tools, retrieval and memory.
* **Eight specs are blocked by the default policy pack**, on purpose: the offensive-simulation
  family (`AG-CRED-SWEEP-001`, `AG-DESTRUCTIVE-DBDROP-001`, `AG-EXFIL-EGRESS-001`,
  `AG-EXTORT-CHAIN-001`, `AG-PERSIST-BEACON-001`, `AG-AUTONOMY-SELFCORRECT-001`,
  `JB-OFFENSIVE-RANSOM-CODEGEN-001`) and `DL-PII-ELICIT-001` (`layer_b_pii`). Enabling them is a
  deliberate act in the policy pack, and on someone else's system it needs their authorization
  in writing, not just a flag.

No per-token pricing is baked into this tool and none should be: multiply the token gloss by
the rate on your own invoice.

## 4. The order to run it in

Each step is safe to stop at, and each one costs more than the last.

```bash
# 0. Nothing leaves the process. Confirms the plan, the scope and the capability gating.
dottore run --deep --dry-run -t target.yaml --scope scope.yaml --verbose

# 1. Still nothing sent. The bill, before the bill.
dottore run --deep --estimate -sV -t target.yaml --scope scope.yaml

# 2. First contact: one spec, one run, a hard ceiling. About 3 requests.
dottore run --spec PI-DIRECT-001 --runs 1 --budget-requests 5 \
  -t target.yaml --scope scope.yaml -oJ first-contact.json

# 3. The recognition pass on its own: 17 requests, and the first real carrier profile.
dottore fingerprint -t target.yaml --scope scope.yaml

# 4. One suite, paced, with a ceiling you are comfortable paying twice.
dottore run --suite owasp-llm-top10 --rate 1 --budget-requests 200 \
  -t target.yaml --scope scope.yaml --judge judge.yaml -oA run-owasp

# 5. The full battery, only after 4 came back clean of surprises.
dottore run --deep -sV --rate 1 --budget-tokens 600000 \
  -t target.yaml --scope scope.yaml --judge judge.yaml -oA run-full
```

If a step halts on its ceiling it exits 3 and prints the run id: `--resume <id>` finishes it,
under the **campaign's** ceiling rather than a fresh one, and refuses if the specs changed in
between (clause A-24).

## 5. Before any of it

* **`scope.yaml` is the authorization record**, not a config file. Every endpoint the run may
  touch is listed there, default-deny, and the adapters refuse anything else. On your own
  accounts you are authorizing yourself, which is the easy case. On anyone else's, the
  authorization exists before the scan does.
* **Keys by env reference only** (`auth_ref: "env://OPENAI_API_KEY"`). A key never belongs in a
  target file, and the evidence store redacts at rest regardless.
* **Rate.** `--rate 1` is one request per second. Providers rate-limit and so should you: the
  pacer is shared by the probes and the battery.
* **Judge.** Without `--judge`, `semantic_judge` abstains and the deterministic evaluators
  carry alone. A live run is worth the second model.

## 6. After it

* The evidence tree answers what was sent, attack by attack and probe by probe:
  `dottore replay <run-id>`.
* Keep the first clean full run as the baseline and gate later ones on it:
  `dottore diff baseline.json current.json`.
* Anything that turns out to be a provider-shaped bug gets a regression test before the fix, the
  way the two from 2026-08-31 did.
* Update `docs/PROGRESS.md` with what ran, against what, and what it cost. That ledger is the
  reason the "never run live" claim was catchable at all.
