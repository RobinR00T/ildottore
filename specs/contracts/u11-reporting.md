# u11-reporting.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/05`
+ `docs/07 §11` + `shared/` before implementing. Bar = `unit-06-evaluators.md`.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/reporting/`: `base.py` (Reporter protocol impl + registry),
  `json_reporter.py`, `html_reporter.py`, `sarif_reporter.py`, `junit_reporter.py`,
  `summary.py` (severity/framework rollup + model-comparison matrix), `masking.py`
  (redactor call-site wiring), `templates/report.html.j2` (+ partials).
- **MUST NOT touch:** `shared/`, `scoring/` (u07), `store/` (u10), `core/`, `evaluators/`,
  `adapters/`, any spec YAML. Consumes their outputs; owns none of their files.

## §2 Intended behavior
Serialize a finished `TestRun` + its `list[Finding]` into report artifacts. One `Reporter`
per format (`json`, `html`, `sarif`, `junit`), each `render(run, findings) -> bytes`, pure and
deterministic (no I/O, no clock, no network: timestamps come from the run). JSON is the
lossless canonical form; HTML is a human view (Jinja2, autoescape ON); SARIF 2.1.0 is the
CI/security-tool interchange (must validate against the SARIF schema); JUnit XML is the
pipeline pass/fail view. Every report carries the run summary from `docs/05 §4`: counts by
status, severity banding (`docs/05 §3`), framework rollup (OWASP LLM / ATLAS / NIST), and the
model-comparison matrix (`docs/05 §5`) when the run spans >1 target. Confirmed vs needs-review
findings are surfaced separately (`docs/05 §2`). **All secrets/PII are masked via the central
redactor before serialization**: no reporter ever emits raw sensitive strings.
**As built (2026-10-04):** every format prints one of four states per finding, from
`summary.finding_state(finding)`: `confirmed`; `needs_review` (an unconfirmed fail, or a finding
that was sent and came back inconclusive); `not_exploited` (a pass); `not_tested` (nothing
sent). The HTML report has three finding sections: "Confirmed findings (n)", "Needs review:
unconfirmed exploits and undecided results (n)" and "Not exploited or not tested (n)". The JSON
`confirmed_count` and `needs_review_count` count the first two states only, and SARIF carries
the state in each result's `properties.state`.

## §3 Dependencies & interface contracts
- Implements `shared.protocols.Reporter` (`format: str`, `render(run, findings) -> bytes`).
- Consumes `shared.models.{TestRun, Finding, RiskScore, Verdict, Attempt, Evidence}`: read-only
  stable interface registry (`docs/01 §3`, `00-INDEX` §"Shared interface registry").
- Banding + confirmed/needs-review state are **read from** `RiskScore`/`Finding` as produced by
  u07; this unit does not compute or re-derive scores or bands. (As built `Finding.confirmed` is
  set by the runner, u08, and the four-way display state is derived here by `finding_state` from
  `confirmed`, `status` and whether any attempt was sent; nothing re-decides confirmation.)
- Redaction goes through the central redactor from u01 (`docs/11 §5`), injected as an interface
  (`Redactor` protocol): not re-implemented here.
- Evidence bytes/refs are read via u10's `EvidenceRef`/store interface; reports embed refs +
  masked excerpts, never re-open raw artifacts directly.

## §4 Known constraints: KEEP / DECIDE
- KEEP: `render` is pure/deterministic: same `(run, findings)` ⇒ byte-identical output
  (stable key order, sorted collections, no `datetime.now()`, `ensure_ascii` fixed).
- KEEP: HTML autoescape ON; `--unsafe-render` (raw HTML in reasoning/evidence) is **OFF by
  default** and must be an explicit opt-in flag surfaced to the operator, never a template
  default. (As built: the switch is the `HtmlReporter(unsafe_render=False)` constructor argument
  and the template's banner branch; no CLI flag reaches it, so it is always off from `dottore`.
  It governs only whether finding reasoning is emitted unescaped. No reporter reads a spec's
  `test_only` mark, and the JSON report carries each attempt's request, prompt included. That
  text goes through the redactor, which masks secret, PII and high-entropy shapes and nothing
  else, so the attack text of a `test_only` spec is readable in the JSON report. The HTML report
  shows no prompts.)
- KEEP: SARIF output is 2.1.0, `level` mapped from band per `docs/05 §3`
  (critical/high→`error`, medium→`warning`, low/info→`note`), a fail whose state is
  `needs_review` at most `warning` (A-73); ruleId = spec id; rules carry OWASP/ATLAS/NIST tags.
- KEEP: masking is mandatory and applied centrally before any format writer runs (single choke
  point in `masking.py`), so a new format can't bypass it.
- DECIDE: whether HTML embeds evidence excerpts inline or links to store refs only (propose:
  masked excerpt inline + ref); Doc it in §9 if it becomes a fork.

## §5 Implementation plan (each step its own commit, green before next)
1. `base.py`: Reporter protocol impl, format registry, shared masking pre-pass hook.
2. `summary.py`: status/band counts, framework rollup, model-comparison matrix (`docs/05 §4-§5`).
3. `json_reporter.py`: canonical lossless JSON (stable ordering) + JSON Schema for the report.
4. `sarif_reporter.py`: SARIF 2.1.0 doc (runs/results/rules, band→level, framework tags).
5. `junit_reporter.py`: testsuite/testcase mapping (fail=exploited, skipped=inconclusive).
6. `html_reporter.py` + `templates/`: Jinja2, autoescape, `--unsafe-render` gate.

## §6 Data/wire shapes
- JSON: `{schema_version, run: TestRun, findings: [Finding], summary: RunSummary}` where
  `RunSummary = {by_status, by_band, by_framework{owasp,atlas,nist}, model_comparison?,
  repro_distribution, confidence_distribution, confirmed_count, needs_review_count}` (as built
  also `coverage`, `status` and, since OD-41, `blocked_by_provider_filter: {attempts, specs}`;
  since OD-42, `cut_by_provider_output_filter` and `provider_filter_side_unknown`, the same shape;
  since OD-21, `unreadable_reply`, the same shape too, u08 A-74).
- SARIF: `sarif-2.1.0` root; one `run` per tool invocation; `results[]` with `ruleId`, `level`,
  `message`, `properties{band, risk_score, reproducibility, confidence, state}`.
- JUnit: `<testsuites>`→`<testsuite name=framework>`→`<testcase name=spec_id>` with `<failure>`
  for exploited, `<skipped>` for inconclusive/blocked-by-policy.
- Masking: every string field passing through `masking.py` is redacted (typed/hashed per
  `docs/11 §5`); no raw secret/PII reaches any writer. Fields the tool computed are restored
  after masking only in their exact shape: evidence references, spec and attempt ids, and
  (since 2026-10-05) `run.scope_sha256`, which the SARIF run `properties` and a JUnit
  framework-suite property also carry (audit D-17).

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/reporting -q` green; coverage ≥ 90% for `src/ildottore/reporting`.
- **SARIF validity** (`docs/07 §11`): every generated SARIF validates against the SARIF 2.1.0
  JSON Schema (`jsonschema`/`sarif-om`); 0 violations on the golden run.
- **JSON schema snapshot:** report JSON validates against its schema; golden-fixture snapshot
  in `tests/reporting/fixtures/reports/` is byte-stable across two renders (determinism gate).
- **JUnit validity:** output parses as well-formed JUnit XML (schema/`junitparser` check).
- **HTML renders:** template renders without error; autoescape verified; a payload with `<script>`
  in reasoning is escaped when `--unsafe-render` is off.
- **Masking gate:** a fixture with a planted secret/PII/canary yields **0 raw occurrences** in
  every format's bytes (grep-assert on JSON/HTML/SARIF/JUnit).
- **Summary correctness:** band/status/framework counts match a hand-labeled golden run;
  model-comparison matrix populated only when >1 target and shape-checked.
- `ruff check`, `ruff format --check`, `mypy src/ildottore/reporting` clean; `lint-imports` green.

**A-12 A denominator is never measured on the survivors (added 2026-09-22).**
`coverage.specs.total` is what the plan selected; `specs.run` is what completed. They were the
same number by construction, so a campaign halted after 45 of 72 specs published `total: 45,
run: 45`, i.e. 100% of itself, and computed every framework percentage over the subset that
survived. A test asserts `run <= total` and that a complete run has them equal.

**A-13 A value that is not counted is reported.** A framework value outside its pinned universe
never reaches a numerator **and** appears in `coverage.off_universe`; a spec that produced a
finding without a reply that could be scored (nothing sent, or every send ended in an environment
error or, since OD-41, was refused by the provider's input filter, or since OD-42 was stopped by
its filter on a side it did not report) appears in `coverage.not_exercised` and is credited
nothing. A reply the provider's output filter cut did reach the model, which wrote it: exercised.
A run does not lint, so silently dropping either is how a numerator shrinks with nobody told.

**A-14 Every figure carries its edition, and percentages floor.** OWASP renumbered in 2026 and
ATLAS renames tactics between releases, so a bare "not covered: LLM03" reads as the opposite
claim to a reader holding the other edition. `100%` requires `exercised >= total`: rounding
published 199/200 as complete. As built the machine formats carry the editions too: the JSON
report puts an `edition` on each coverage axis (`owasp`, `atlas`, `iopc`), SARIF has
`runs[0].properties.framework_editions` and JUnit an `edition.*` property block on each
testsuite, the last two for OWASP LLM, MITRE ATLAS, Nova IoPC and OWASP AISVS
(`shared.frameworks.framework_editions`).

**A-15 The machine formats carry the run state.** SARIF sets `invocations[0].executionSuccessful`
and JUnit emits an `<error>` when a campaign did not finish. Those two are what CI reads, and
they rendered a truncated scan as a fully green suite while the JSON and HTML said otherwise.

**A-26 A gap says which kind of gap it is (added 2026-09-22, widened the same night after
audit).** The coverage report printed one undifferentiated list of uncovered codes, so "8 of 10"
read as two items of pending work. Gaps now print in **three** groups: not covered *yet* (the
roadmap), *out of reach* for a black-box runtime scanner (physics: no request settles it), and
*not tested by design* (a decision this product made and could revisit). The third bucket exists
because the first version put both in one: "the turns of a multi-turn attack are pinned in the
spec" is a design choice, and printing it under "out of reach" tells a reader the category is
impossible when what is true is that we chose not to. An audit called it dressing a decision as
a law of nature, and it was right.

All three stay in the **denominator**: removing them would raise every percentage by redefining
the universe as the part the tool can already do, which is A-12 from the other side. A reason is
mandatory. A test can assert a reason is present; it cannot assert it is true, so the membership
of each bucket is **pinned per axis** in the test file: moving a code between buckets then shows
up as a test change next to the argument for it. That guard was added after an audit moved a
plainly testable gap into "out of reach" with a fabricated reason and the suite stayed green.
One code was withdrawn from the classification entirely on the same grounds: `Command and
Control` was called unobservable in a target's replies while this repository ships fixtures in
which an agent writes a cron entry calling a C2-shaped address. Checked by
`tests/cli/test_coverage_cmd.py`.

**A-69 (u08's clause; this unit's half, added 2026-10-10, OD-41) The attempts the provider's
input filter refused are counted apart in every format.** Such an attempt is `inconclusive:
blocked_by_provider_filter` (ADR-0011): neither the model's refusal nor an exploit, so a report
that folded it into "inconclusive" could not tell a model that held from one that was never asked.
The summary (`RunSummary.provider_filter`, read from the stored attempts by
`shared.provider_filter`, never re-scored) is `blocked_by_provider_filter: {attempts, specs}` in
the JSON report, always emitted and optional in report-1.0 (the schema gains it additively, and
`schema_version` stays `1.0` as it did for `edition` and `status`: a new report fails an older copy
of the schema, an older report validates against the new one; pre-merge audit of `3d739f3`, L5);
SARIF
adds `blocked_by_provider_filter` to `runs[0].properties` and to a result's `properties`, and
`; <k> of <n> attempt(s) blocked by the provider's input filter before the model saw them` to its
message, when there are any; JUnit adds ` blocked_by_provider_filter=<k>` to a passing case's
detail, and a failure or a skip quotes the finding's reasoning, which says it; the HTML summary
prints a line under the counts. A spec whose every attempt was blocked is in `not_exercised`, SARIF
kind `open`, state `needs_review`. With none blocked, only the JSON report changes (the key, with 0
and `[]`), so the golden JSON snapshot gains it and the SARIF, JUnit and HTML ones do not move.
Checked by `tests/cli/test_provider_filter_campaign.py` (every format of one run, the JSON against
the schema).

**A-73 (u06's clause; this unit's half, added 2026-10-11 after the audit of the scoring, LOW 4) A
fail that needs review is no `error` in SARIF.** A fail only the judge reported is never confirmed
(OD-19), and neither is one not reproduced on every attempt of a variant: `--fail-on` gates neither
without `--include-needs-review`. SARIF gave such a fail its band's level, so a judge-only critical
fail was an `error`, which GitHub code scanning fails a pull request's check on by default
("Triaging code scanning alerts in pull requests": a result "with a severity of `error`,
`critical`, or `high`" fails the check, read 2026-10-12), while `dottore` exited 0 for it. A `fail` result whose `properties.state` is `needs_review` is now at most
`warning` (`error` becomes `warning`; `warning` and `note` stay), its band unchanged in
`properties.band`; a confirmed fail keeps its band's level, and every other kind keeps `none`.
The golden SARIF snapshot does not move (its fail is confirmed). Checked by
`tests/reporting/test_sarif_reporter.py` (6 cases; the critical and high ones fail on `de122e26`).
**Amended 2026-10-12 after the pre-merge audit of `d07a1088` (LOW 3):** the cap holds only
without `--include-needs-review`. With it such a fail trips `--fail-on`, and capped at `warning`
it let code scanning pass the check `dottore` exited 2 on. The flag reaches the writer as
`include_needs_review` (`BaseReporter`, `get_reporter`, `cli.wiring.build_reporter`, from
`RunOptions` in `cli.run._write_reports`); with it a needs-review fail keeps its band's level and
the SARIF run's `properties` carry `"include_needs_review": true` (absent without it, so the
golden snapshot does not move). The other formats take the flag and do not read it. Checked by
`tests/reporting/test_sarif_reporter.py` (5 more cases, the 4 with the flag failing on
`d07a1088`) and `tests/cli/test_flags.py` (2 cases through `_write_reports` beside
`exit_code_for`, the one with the flag failing on `d07a1088`).

**A-74 (u08's clause; this unit's half, added 2026-10-11, OD-21; pre-merge audit of `598f0858`,
HIGH 1) The replies the adapter could not read are counted apart in every format.** Such an attempt
is never the model's refusal, and the reply that broke may be the one an attack changed (a wrapper
whose JSON a quote in the model's output broke), so a report that folded it into "inconclusive", or
let a majority outvote it, would hide the one attempt a reader must review. The summary
(`RunSummary.unreadable`, read from the stored attempts by `shared.unreadable`) is
`unreadable_reply: {attempts, specs}` in the JSON report, always emitted and optional in report-1.0
(additively, as A-69's and A-70's keys); SARIF adds it to `runs[0].properties` and to a result's
`properties`, and `; <k> of <n> attempt(s) whose reply could not be read as the provider's, which
may be the one an attack changed: review them` to its message; a JUnit skip's or failure's
`message` carries ` unreadable_reply=<k>`; the HTML summary prints `Unreadable replies: ...` under
the counts. With none, only the JSON report changes (the key, with 0 and `[]`): the golden JSON
snapshot gains it. Checked by `tests/cli/test_malformed_reply_campaign.py` (the JSON, SARIF, JUnit
and HTML reports of one run with an unreadable reply).

**A-70 (u08's clause; this unit's half, added 2026-10-11, OD-42) The replies the provider's filter
cut, or stopped on a side it did not report, are counted apart in every format.** Such an attempt
is never the model's refusal, and the model may have written what the filter hid, so a report that
folded it into "inconclusive" would hide the one thing a reader must review. The summary
(`RunSummary.output_filter` and `filter_side_unknown`, read from the stored attempts by
`shared.provider_filter`) is `cut_by_provider_output_filter: {attempts, specs}` and
`provider_filter_side_unknown: {attempts, specs}` in the JSON report, always emitted and optional in
report-1.0 (additively, `schema_version` staying `1.0`, as A-69's key did: a report from this
version fails an earlier copy of the schema, and an earlier build cannot load this version's runs,
whose verdicts carry reasons its enum rejects; L6 of the pre-merge audit of `a55e953`); SARIF adds
both to
`runs[0].properties` and to a result's `properties`, and `; <k> of <n> attempt(s) cut or replaced
by the provider's output filter, which may have hidden an exploit: review them` (and `; <k> of <n>
attempt(s) stopped by the provider's filter on a side it did not report: review them`) to its
message, when there are any; in JUnit a spec with one never passes, so its skip's or failure's
`message` carries ` cut_by_provider_output_filter=<k>` and ` provider_filter_side_unknown=<k>`
(`inconclusive: BR-001 provider_filter_side_unknown=2`), and its text quotes the finding's
reasoning, which says how many (L4: they had been put in a passing case's detail, where they could
never appear); the HTML summary prints a line under the counts for each. A
spec with such an attempt and no fail is `inconclusive`, SARIF kind `open`, state `needs_review`;
one whose only stops are on an unreported side is in `not_exercised`. With none, only the JSON
report changes (the two keys, with 0 and `[]`), so the golden JSON snapshot gains them and the
SARIF, JUnit and HTML ones do not move. Checked by
`tests/cli/test_provider_output_filter_campaign.py` (every format of one run, the JSON against the
schema) and `tests/reporting/test_provider_filter_cut_counts.py` (the side-unknown SARIF counts and
the JUnit messages).

**A-72 (u06's clause; this unit's half, added 2026-10-11, OD-43) Every format states the operator's
declaration for the run, as an operator declaration, and the attempts it changed.** A pass the
target file's declaration made is the operator's word that a tool destroys nothing, not the target's
resistance, so no format may let it read as any other pass. The summary
(`RunSummary.operator_declarations`, built from the run's targets and from the stored verdicts'
record, never re-scored and never read from the text: `Verdict.operator_cleared`, since a judge's
words or a tool's name can echo the note, pre-merge audit of `ed381359`, L1) is
`operator_declarations: {not_destructive_tools: {<target id>: [tools]}, attempts, specs}` in the
JSON report, always emitted and optional in report-1.0 (the schema gains it additively and
`schema_version` stays `1.0`, as for A-69's and A-70's keys: a new report fails an older copy of the
schema, an older report validates against the new one), beside
`run.targets[].seeded_setup.not_destructive` (left out when empty) and each changed attempt's
`verdict.operator_cleared`; the finding's line, which a failure or a skip quotes, names the tools
(L6); SARIF adds `operator_declarations` to `runs[0].properties` when a target declares one, and to
a result that has such attempts an `operator_declaration_attempts` count and `; <k> of <n>
attempt(s) with a call the target file declares not destructive (operator declaration, OD-43)` in
its message; JUnit adds an `operator_declaration.not_destructive.<target id>` property to every
suite and ` operator_declaration_attempts=<k>` to a passing case's detail (a failure or a skip
quotes the finding's reasoning, which counts them); the HTML names the tools under the target and
prints a line under the summary's counts. With none declared only the JSON report changes (the key,
with `{}`, 0 and `[]`): the target's dump has no `not_destructive`, no verdict an
`operator_cleared`, and the HTML target line is byte for byte the one before OD-43 (whitespace
control, L4), so the golden JSON snapshot gains the key and the SARIF, JUnit and HTML ones do not
move. Checked by `tests/cli/test_operator_declaration_campaign.py` (every format of one run, the
JSON against the schema, and the same run without the declaration).

## §8 Out of scope / forbidden
- MUST NOT compute risk scores, bands, or confirmed/needs-review state (that is u07): only read.
- MUST NOT read/persist to the run or evidence store beyond the injected read interface (u10).
- MUST NOT emit raw secrets/PII: redactor is the only path; no `--unsafe-render` default-on.
- MUST NOT perform I/O, network, or wall-clock reads inside `render` (keeps it deterministic).
- MUST NOT own CLI wiring/`--fail-on` exit-code logic (that is u12): reporters produce bytes only.
- Not its call: HTML evidence inline-vs-ref policy (§9); scoring formula (u07); at-rest evidence
  encryption (OD-4, u10).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- HTML evidence rendering: masked-excerpt inline + store ref, vs ref-only (propose inline+ref).
- Whether `--unsafe-render` is exposed at all in MVP‑1 or deferred to MVP‑2 (propose: present but
  hard-gated + warning banner). Flag to conductor before enabling. (Ledger OD-12 records
  "present"; as built it is not exposed on the CLI.)
