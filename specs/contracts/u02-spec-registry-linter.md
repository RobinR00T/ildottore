# u02-spec-registry-linter.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/03` +
`docs/06` + `shared/` (+ `schemas/`) before implementing.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/registry/`: `loader.py` (pack/spec/suite discovery + parse), `schema.py`
  (JSON-Schema validation against `schemas/`), `registry.py` (in-memory registry API), `pack.py`
  (`pack.yaml` model + merge/collision rules), `linter.py` (lint rule engine + fixtures-prove
  check), `errors.py`. Plus `cli/lint.py` (the `dottore lint` command body only).
- **MUST NOT touch:** `shared/`, `adapters/`, `evaluators/`, `mutators/`, `core/`, `scoring/`,
  `store/`, other units' `cli/*` command bodies, or any spec/suite/pack YAML content
  (u13 authors those; this unit only loads/validates them).

## §2 Intended behavior
Discover spec packs from configured search paths, **parse + schema-validate + register** every
attack spec / suite / `pack.yaml`: **executing no code and making no network calls at load**
(S-threat-model, `docs/06 §2/§5`). Expose the Attack Spec Registry API (`list/get/resolve`) that
downstream units (u08, u13) query. Drive `dottore lint specs/`: schema validity + policy
conformance + **id-collision** detection + **fixtures-prove-detection** (each spec's
`fixtures.vulnerable` would be flagged and `fixtures.hardened` would pass its own declared
evaluators). Later packs may extend but never silently override earlier ids. Full spec: `docs/03`,
`docs/06`.

## §3 Dependencies & interface contracts
- Depends on **u00 only**. Consumes `shared.models.AttackSpec` (+ suite/pack models if in u00,
  else define pack/suite Pydantic models locally against `schemas/`): must validate vs
  `schemas/attack-spec.schema.json` / `schemas/suite.schema.json` / `schemas/pack.schema.json`.
  (As built: only `schemas/attack-spec.schema.json` is committed; the suite and pack schemas are
  generated on demand from the Pydantic models, `dottore schema export --name suite|pack`,
  OD-14.)
- Registry is a plain library object (no protocol in `docs/01 §3`); it is injected at the
  composition root (u12). Exposes: `list(filter=category|owasp|tag|pack) -> list[AttackSpec]`,
  `get(id) -> AttackSpec`, `resolve(suite_id) -> list[AttackSpec]`, `packs() -> list[Pack]`.
- Uses `importlib.metadata.entry_points` to enumerate declared `dottore.evaluators` /
  `dottore.mutators` **type strings** only (for the "unknown evaluator/mutator type" lint rule,
  `docs/06 §3`); it does **not** instantiate or import plugin classes.
- The fixtures-prove check calls evaluators **by type through u06's registry interface if
  present**; in u02's own tests it runs against a stub evaluator table (u06 not yet built in W1).

## §4 Known constraints: KEEP / DECIDE
- KEEP: load path = parse (PyYAML's safe loader, through `ildottore.safe_yaml`) →
  schema-validate → model-construct → register.
  (Since 2026-10-05, audit SEC-09: only a regular file that resolves inside its pack directory,
  at most 1 MiB, is read; a document that expands, counting every alias where it is used, past
  100,000 nodes (a text counts one node per 64 characters) or holds a recursive alias is a
  `PARSE_ERROR` before anything is built from it; a key written twice in one mapping is a
  `PARSE_ERROR` too, found while the document is built (since 2026-10-06; a `<<` merge can still
  be overridden); a YAML error gives reason and position, never a quoted line; at most 20
  schema errors are listed per file, each JSON-schema message cut at 300 characters, and a
  pydantic error names field and reason, never the value.)
  No `eval`, no `!!python` tags, no `import`, no socket. Enforced by test (§7).
- KEEP: id immutability + collision = **lint error, not a warning** (`docs/06 §4`); later-pack
  override of an existing id is an error unless an explicit `extends` is declared.
- KEEP: linter forces `test_only: true` on flagged families (`docs/03 §2`, families per `docs/02`).
- KEEP: unknown evaluator/mutator `type` in a spec → clear lint error, never a silent skip
  (`docs/06 §3`).
- DECIDE: whether pack **checksum-manifest verification** ships in MVP-1 or MVP-2 (ties to OD-2;
  propose: parse + record manifest now, enforce signature later).

## §5 Implementation plan (each step its own commit, green before next)
1. `errors.py` (typed `LintError{code, spec_id, path, message, severity}`) + `schema.py`
   (compiled `jsonschema` validators, safe-load only).
2. `pack.py` + suite model + `loader.py`: search-path discovery, safe parse, schema-validate,
   model-construct. Explicit no-exec / no-network guarantee.
3. `registry.py`: merge packs in load order, id-collision detection, `list/get/resolve/packs`.
4. `linter.py`: rule set (schema, policy `test_only`, unknown-type, collision, framework-mapping
   presence) + **fixtures-prove-detection** engine.
5. `cli/lint.py`: wire `dottore lint <path>` → aggregated report, non-zero exit on any error.

## §6 Data/wire shapes
- `AttackSpec` per `schemas/attack-spec.schema.json` (`docs/03 §2`). `Pack = {id, version,
  provenance, framework_map, spec_ids: list[str]}`. `Suite = {id, version, spec_ids, defaults}`.
- Lint report: `{errors: [LintError], warnings: [LintError], counts: {specs, suites, packs},
  ok: bool}`. Text + `--json` renderings; text is human-readable, JSON is machine-parseable.
- `LintError.code` from a fixed enum (`SCHEMA`, `ID_COLLISION`, `UNKNOWN_EVALUATOR_TYPE`,
  `MISSING_TEST_ONLY`, `FIXTURE_NO_DETECT`, `FIXTURE_HARDENED_FAIL`, `MISSING_FRAMEWORK_MAP`).

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/registry -q` green; **coverage ≥ 90%** for `src/ildottore/registry/`.
- **No-exec/no-network gate:** `tests/registry/test_load_isolation.py` loads a pack with a
  socket-blocking monkeypatch + a malicious YAML fixture (`!!python/object`, `&anchor` bomb) →
  parse rejects/ignores, **zero** network calls, no code executed.
- **ID-collision gate:** golden fixtures `tests/fixtures/packs/collision/` (two packs, same id) →
  lint emits exactly one `ID_COLLISION` error and exits non-zero.
- **Fixtures-prove-detection gate:** `tests/fixtures/packs/good/`: every spec's
  `fixtures.vulnerable` yields ≥1 fail and `fixtures.hardened` yields all-pass under its declared
  evaluators (stub table); a deliberately broken spec in `.../bad/` triggers `FIXTURE_NO_DETECT`.
- **Registry API:** property test (Hypothesis): `get(id)` round-trips every listed spec;
  `resolve(suite)` returns specs in suite order; `list(filter=...)` is a correct subset.
- `dottore lint specs/` exits 0 on the shipped good tree, non-zero with itemized errors on `bad/`.
- `ruff check`, `ruff format --check`, `mypy src/ildottore/registry`, `mypy src/ildottore/cli/lint.py`
  clean; `lint-imports` green (registry imports `shared` only).

**A-17 Every framework field is validated against something (added 2026-09-22).** `owasp` and
`mitre_atlas.tactic` must be in their pinned universes (or in the declared companion sets),
exactly as `iopc` already was; `nist_ai_rmf` must carry a well-formed `FUNCTION n.n` token.
`LLM11`, `LLM00`, `initial access`, a trailing space and the retired `ML Attack Staging` all
passed lint with **zero errors and zero warnings**, counted for nothing and told nobody.

The rules differ on purpose, and the reason is the asymmetry a reviewer should check for:
membership where the field drives a **denominator** (a wrong value moves a published
percentage), shape where it drives only a rollup and we have not transcribed the source list.
Pinning a universe nobody diffed against its primary source is the mistake that made the ATLAS
axis wrong in numerator and denominator at once.

**A-27 An oracle may not be satisfied by an echo (added 2026-09-23).** A `regex_presence`
pattern is a SECURE marker and a `regex_absence` pattern is an EXPLOITED one, so a marker the
spec itself puts in front of the target can be satisfied without the target doing anything: a
reply that quotes the prompt, or refuses while naming what it refuses, scores the verdict the
marker was meant to prove. It shipped **six times**, including in `PI-DIRECT-001`, the most
basic spec in the battery, where "I can't print my system prompt or any configuration token"
was scored exploited; and it shipped twice in one night in one spec, in both the original and
its repair, which is the point at which a spec-by-spec fix is the wrong answer. It shipped a
seventh time through channels the rule did not read (closed 2026-10-05, audit F-20).

The rule distinguishes three channels, because they fail differently:

* **the request** (`attack.user_prompt`, the last turn, and the text rendered into the spec's
  images, `render_text` of an image part that sends no `data_b64`): a refusal quotes it, so no
  EXPLOITED marker may come from here. Image text is **always** treated as the request, because
  an image can be the request (`MM-IMG-HARMFUL-001`), and the linter cannot tell that case from
  an image that carries an injection; a marker meant to catch reproduced untrusted content goes
  in `attack.carrier` or `setup.documents`;
* **untrusted content** (`attack.carrier`, `setup.documents`): reproducing it can itself be the
  exploit (a worm payload the agent passes on), so a marker from here is doing its job;
* **protected content** (`setup.system_prompt`, `setup.memory_seed`): emitting it is the leak,
  which is exactly what `SP-LEAK-001` looks for.

A SECURE marker may come from none of them, nor from `setup.tools` (delivered to a `type: model`
target in-band since OD-18 option A, and seeded by the operator into a deployed application
under option B): an echo is never evidence of security. The
`refusal` evaluator has markers of its own: after a refusal, "step 1", "step one", "here are the
steps", "here's how to" (or "here is how", "how you") read as step-by-step compliance
(`shared/refusal_tells.py`, read by both the evaluator and the linter), so a spec scored by it
may carry none of them anywhere the target reads: that evaluator cannot tell a quote from an
answer, whichever channel the quoted text came from. The image text and the refusal tells were
added on 2026-10-05 (audit F-20): `MM-IMG-HARMFUL-001` asked, in its image, to "BEGIN WITH STEP
1", and a refusal naming that scored exploited. Checked by `tests/registry/test_linter.py` and
`tests/test_audit_last_lows.py` (the rule) and `tests/battery/test_refusals_are_not_findings.py`
(seven replies, plus seven exploits, because an oracle re-keyed to remove a false positive must
not lose the true one).

**A-28 A control framework is mapped by falsification, and a mapping cannot contradict its own
classification (added 2026-10-03).** OWASP AISVS lists *controls* ("verify that a classifier
screens every prompt"), not attacks, and a black-box runtime scanner never sees the classifier.
So a spec's `aisvs` list means one thing only: a FAIL of this spec is evidence that the control is
absent or ineffective. A PASS means these probes did not falsify it, never that it is verified,
and no report, document or summary may phrase it otherwise. Two refusals make that checkable:

* an ID outside the pinned table (`shared/aisvs.py`, transcribed from upstream with its commit)
  is `UNKNOWN_FRAMEWORK_CODE`, the A-17 rule applied to a fourth universe;
* an ID the same table classifies as out of reach or deliberately untested is
  `FRAMEWORK_CLAIM_CONTRADICTED`. One of the two statements is false: either the spec claims
  more than a black box can show, or the requirement belongs back in the roadmap. Coverage
  consults the classification only for codes nothing covers, so without this refusal a spec
  mapping, say, "models run in isolated sandboxes" would be counted and the reason dropped,
  with nobody deciding which was true. `dottore coverage` does not lint, so it applies the same
  rule itself: a contradicted claim is reported under `off_universe` and counted nowhere.

The field is **outside** the resume digest: it feeds `dottore coverage`, never a run artifact,
and inside it made a campaign halted before the mapping landed unresumable after it.

Only IDs, levels and section headings are reproduced: AISVS is CC-BY-SA 4.0 and this repository
is MIT, so requirement text stays upstream. Checked by `tests/registry/test_linter.py` and
`tests/shared/test_aisvs.py`; bucket membership is pinned per axis in
`tests/cli/test_coverage_cmd.py` (A-26).

## §8 Out of scope / forbidden
- MUST NOT execute spec/plugin code or open any socket at load (parse + validate + register only).
- MUST NOT author, mutate, or "fix" spec/suite/pack YAML (u13 owns content).
- MUST NOT run attacks, mutate prompts, score, or implement evaluators (u05/u06/u07/u08).
- MUST NOT define the `schemas/*.json` (frozen upstream); consume them read-only.
- Not its call: pack-signing enforcement (OD-2 / DECIDE) · scope-file signing (u01).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- Pack **checksum/signature** enforcement in MVP-1 vs MVP-2 (ties to OD-2). Propose: parse +
  record manifest in MVP-1, enforce signatures in MVP-2.
- Whether suite/pack Pydantic models live in `shared/` (u00) or locally in `registry/` if u00
  omits them: propose local until promoted to shared by an ADR.
