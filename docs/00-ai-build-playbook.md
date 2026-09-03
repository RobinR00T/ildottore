# 00 - Build playbook (Zynap specs-driven method, applied to Il Dottore)

How we build Il Dottore, following Zynap's *Specs-Driven Development with AI*. **Read `AGENTS.md`
+ this + the relevant `docs/` + your unit contract before writing code.** Specs are the source
of truth; the AI does the typing. This is a **net-new** build (no live reference to migrate
against), so the **spec is the oracle**.

## 0. Golden rules

1. **Specs before code.** Don't start typing - start from the contract. Missing decision →
   write an ADR (`docs/adr/`), implement the smallest reversible version, flag it in the PR.
2. **Contract = spec = harness.** A unit's acceptance criteria are what "done" is measured by.
3. **Humans own decisions.** Log every fork in the unit's §9 and the index ledger; never let
   the AI silently decide what isn't its call.
4. **Due diligence, especially security.** AI output is never security-first - always review.
5. **Every module ships tests** satisfying `docs/07`. No PR without them.
6. **Boundaries are law** (`docs/01 §2`), enforced by import-linter.
7. **Each PR updates** docs touched + `CHANGELOG.md` + `docs/PROGRESS.md` + the spec/schema if
   the contract changed.

## 1. The six stages (each hands an artifact to the next)

| Stage | For Il Dottore (net-new) | Artifact |
|-------|--------------------------|----------|
| **1 Understand** | Architecture + threat model already mapped, pinned at a frozen commit | `docs/01`, `docs/02` + frozen tree |
| **2 Specify** | Slice the build into **units**; one **contract** each (§1-§9); master index + DAG + ledger | `specs/contracts/` |
| **3 Execute** | **PITV loop** per contract, dependency-gated, PARK on budget | working units + tests |
| **4 Validate** | Spec-as-oracle: acceptance criteria + golden fixtures + design review + human sign-off | green gates + reports |
| **5 Sweep** | Close deferred items + KEEP/FIX backlog (itemized) | gap-closed build |
| **6 Finish** | Senior tests hard, lists defects, bulk-prompts fixes (70% rule) | production-ready |

Build-up = 1→3, Convergence = 4→6. The orchestrator (Claude Code) drives 1-4; humans own the
decisions throughout and drive stage 6.

## 2. Specify - unit slicing & the contract anatomy

The build is sliced into units in `specs/contracts/00-INDEX.md` (dependency DAG +
single-executor ledger + open-decisions rollup). Every unit contract follows the same 9 sections
(adapted for net-new):

- **§1 Scope & ownership** - files it owns, files it must NOT touch.
- **§2 Intended behavior** - what the unit must do (net-new analogue of "current behavior").
- **§3 Dependencies & interface contracts** - upstream units + the `shared` protocols/models
  that must stay stable (the interface registry).
- **§4 Known constraints - KEEP / DECIDE** - fixed choices vs things to resolve.
- **§5 Implementation plan** - ordered steps, each its own commit behind green tests.
- **§6 Data/wire shapes** - schemas, model fields, formats it produces/consumes.
- **§7 Acceptance criteria** - machine-checkable: oracles, exact commands, coverage/detection
  gates (golden fixtures for attack specs).
- **§8 Out of scope / forbidden** - hard fences and must-not-touch list.
- **§9 Open decisions** - every fork needing human sign-off; rolls up to the index.

**One rule that saves the most pain:** a refactor and a feature never share a commit.

## 3. Execute - the PITV harness

One workflow template drives every unit. Distilled:

```js
// HARD RULES (see AGENTS.md §2): write only in src/ildottore + tests; never commit/push;
// never print secrets; reports→reports/; env failure ⇒ retry/skip, product defect ⇒ FAIL.
async function pitvLoop(unit) {
  let plan = await agent(planPrompt(unit));          // 1 PLAN - reads contract + AGENTS.md + docs
  let iter = 0, feedback = '';
  while (iter < MAX_ITERS) {                          // budget 3-4, else PARK
    iter++;
    const impl = await agent(implPrompt(unit, feedback));   // 2 IMPLEMENT
    if (!impl.pass) { feedback = impl.failures; continue }
    const test = await agent(testPrompt(unit, iter));       // 3 TEST (adversarial)
    if (!test.pass) { feedback = test.failures; continue }
    const val  = await agent(valPrompt(unit, iter));        // 4 VALIDATE vs acceptance criteria
    if (val.verdict === 'pass') return DONE;                // unlocks dependents
    feedback = val.defects;
    if (val.planDefect) plan = await replan(unit, feedback);
  }
  return PARK(unit, defectDossier);                   // human review - never merge degraded work
}
```

- **Iterate then park:** hard ceiling (3-4). Model quality degrades if it grinds; PARK with a
  defect dossier beats merging junk.
- **Adversarial by design:** Test and Validate hunt for reasons to FAIL; a pass is earned with
  evidence (the golden-fixture gate, `docs/07`).

## 4. Orchestration - dynamic, gated, unattended

The index DAG schedules units: **independent chains run in parallel**, a unit **starts only when
its deps are DONE**, units touching the **same files serialize** back-to-back. We serialize
files **and decisions**: the `shared` interface registry (models + protocols, `docs/01 §3`)
stops file-disjoint units from making conflicting choices, and a **final merge gate** validates
the combined result (Cognition's fragmentation critique, handled). Single-executor ledger: one
owner per unit, no double-edits.

## 5-6. Converge - validate, sweep, finish

- **Validate (spec-as-oracle):** acceptance criteria green + golden fixtures pass (scanner flags
  the vulnerable fixture, passes the hardened one) + design review + human sign-off. `docs/07`.
- **Sweep:** attack the deferred ~items + KEEP/DECIDE backlog - a concrete itemized list, each
  tied to a criterion.
- **Finish:** senior (Daniel / conductor) tests hard, compiles the defect list, bulk-prompts the
  fixes against the standing context. Test → list → fix → re-test.

## 7. Unit map & build order (MVP‑1 = T0 battery)

See `specs/contracts/00-INDEX.md` for the authoritative DAG. Waves:

- **W0** `u00-shared-models`
- **W1** `u01-config-scope-policy` · `u02-spec-registry-linter` · `u05-prompt-mutator` · `u07-scoring`
- **W2** `u03-mock-target-golden-harness` · `u04-target-adapters` · `u10-evidence-run-store`
- **W3** `u06-evaluators` · `u09-fingerprint-engine`
- **W4** `u08-execution-engine` · `u11-reporting` · `u13-attack-specs-battery`
- **W5** `u12-cli` · `u14-self-validation-ci`

**MVP‑1 exit:** T0 battery (incl. data-leak family, `docs/11`), OpenAI + REST adapters, logprobs
capture, multi-identity scope, regex/refusal/secret/pii/secret-shape/tool + hardened judge,
JSON + HTML report, full self-validation green. MVP‑2/3 per `docs/12-gaps-backlog.md`.

## 8. Recommended stack

| Layer | Choice | Note |
|---|---|---|
| Runtime | Python 3.11+ | dev env 3.14 |
| Specs & validation | YAML + **Pydantic v2** + **JSON Schema** | schema = machine contract |
| CLI | Typer | entry `dottore` |
| API | FastAPI | from MVP‑2 |
| Concurrency | **asyncio** first | Celery/RQ only when API+queue needed |
| DB / evidence | SQLite → Postgres · FS → S3-compatible | behind interfaces |
| LLM access | **own thin adapters** (ADR‑0002) + logprobs capture | byte-exact control |
| Reports | JSON + Jinja2 HTML + **SARIF** + JUnit | |

## 9. Definition of Done (per unit / PR)

- [ ] Matches contract; deviations captured as ADRs; §9 open decisions logged.
- [ ] Unit + property + golden tests pass; coverage ≥ 85% core; import-boundary green.
- [ ] Attack specs ship golden fixtures incl. hallucinated-but-valid negatives (`docs/11 §4`).
- [ ] Self-scan (SARIF) has no new high/critical in our own code.
- [ ] Docs + `CHANGELOG.md` + `docs/PROGRESS.md` updated.

## 10. Provenance & references

Method: Zynap *Specs-Driven Development with AI* (2026). Patterns named by Anthropic (PITV =
evaluator-optimizer; orchestration = orchestrator-workers - a *workflow*, not autonomous
agents). Guardrails/EDD per Anthropic & Vercel; built to survive Cognition / Karpathy / Willison.
Full sources: `docs/REFERENCES.md`.
