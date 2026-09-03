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

## §3 Dependencies & interface contracts
- Implements `shared.protocols.Reporter` (`format: str`, `render(run, findings) -> bytes`).
- Consumes `shared.models.{TestRun, Finding, RiskScore, Verdict, Attempt, Evidence}`: read-only
  stable interface registry (`docs/01 §3`, `00-INDEX` §"Shared interface registry").
- Banding + confirmed/needs-review state are **read from** `RiskScore`/`Finding` as produced by
  u07; this unit does not compute or re-derive scores or bands.
- Redaction goes through the central redactor from u01 (`docs/11 §5`), injected as an interface
  (`Redactor` protocol): not re-implemented here.
- Evidence bytes/refs are read via u10's `EvidenceRef`/store interface; reports embed refs +
  masked excerpts, never re-open raw artifacts directly.

## §4 Known constraints: KEEP / DECIDE
- KEEP: `render` is pure/deterministic: same `(run, findings)` ⇒ byte-identical output
  (stable key order, sorted collections, no `datetime.now()`, `ensure_ascii` fixed).
- KEEP: HTML autoescape ON; `--unsafe-render` (raw HTML in reasoning/evidence) is **OFF by
  default** and must be an explicit opt-in flag surfaced to the operator, never a template
  default.
- KEEP: SARIF output is 2.1.0, `level` mapped from band per `docs/05 §3`
  (critical/high→`error`, medium→`warning`, low/info→`note`); ruleId = spec id; rules carry
  OWASP/ATLAS/NIST tags.
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
  repro_distribution, confidence_distribution, confirmed_count, needs_review_count}`.
- SARIF: `sarif-2.1.0` root; one `run` per tool invocation; `results[]` with `ruleId`, `level`,
  `message`, `properties{band, risk_score, reproducibility, confidence, state}`.
- JUnit: `<testsuites>`→`<testsuite name=framework>`→`<testcase name=spec_id>` with `<failure>`
  for exploited, `<skipped>` for inconclusive/blocked-by-policy.
- Masking: every string field passing through `masking.py` is redacted (typed/hashed per
  `docs/11 §5`); no raw secret/PII reaches any writer.

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/reporting -q` green; coverage ≥ 90% for `src/ildottore/reporting`.
- **SARIF validity** (`docs/07 §11`): every generated SARIF validates against the SARIF 2.1.0
  JSON Schema (`jsonschema`/`sarif-om`); 0 violations on the golden run.
- **JSON schema snapshot:** report JSON validates against its schema; golden-fixture snapshot
  in `tests/fixtures/reports/` is byte-stable across two renders (determinism gate).
- **JUnit validity:** output parses as well-formed JUnit XML (schema/`junitparser` check).
- **HTML renders:** template renders without error; autoescape verified; a payload with `<script>`
  in reasoning is escaped when `--unsafe-render` is off.
- **Masking gate:** a fixture with a planted secret/PII/canary yields **0 raw occurrences** in
  every format's bytes (grep-assert on JSON/HTML/SARIF/JUnit).
- **Summary correctness:** band/status/framework counts match a hand-labeled golden run;
  model-comparison matrix populated only when >1 target and shape-checked.
- `ruff check`, `ruff format --check`, `mypy src/ildottore/reporting` clean; `lint-imports` green.

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
  hard-gated + warning banner). Flag to conductor before enabling.
