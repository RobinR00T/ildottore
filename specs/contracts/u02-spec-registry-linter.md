# u02-spec-registry-linter.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/03` +
`docs/06` + `shared/` (+ `schemas/`) before implementing.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/registry/` - `loader.py` (pack/spec/suite discovery + parse), `schema.py`
  (JSON-Schema validation against `schemas/`), `registry.py` (in-memory registry API), `pack.py`
  (`pack.yaml` model + merge/collision rules), `linter.py` (lint rule engine + fixtures-prove
  check), `errors.py`. Plus `cli/lint.py` (the `dottore lint` command body only).
- **MUST NOT touch:** `shared/`, `adapters/`, `evaluators/`, `mutators/`, `core/`, `scoring/`,
  `store/`, other units' `cli/*` command bodies, or any spec/suite/pack YAML content
  (u13 authors those; this unit only loads/validates them).

## §2 Intended behavior
Discover spec packs from configured search paths, **parse + schema-validate + register** every
attack spec / suite / `pack.yaml` - **executing no code and making no network calls at load**
(S-threat-model, `docs/06 §2/§5`). Expose the Attack Spec Registry API (`list/get/resolve`) that
downstream units (u08, u13) query. Drive `dottore lint specs/`: schema validity + policy
conformance + **id-collision** detection + **fixtures-prove-detection** (each spec's
`fixtures.vulnerable` would be flagged and `fixtures.hardened` would pass its own declared
evaluators). Later packs may extend but never silently override earlier ids. Full spec: `docs/03`,
`docs/06`.

## §3 Dependencies & interface contracts
- Depends on **u00 only**. Consumes `shared.models.AttackSpec` (+ suite/pack models if in u00,
  else define pack/suite Pydantic models locally against `schemas/`) - must validate vs
  `schemas/attack-spec.schema.json` / `schemas/suite.schema.json` / `schemas/pack.schema.json`.
- Registry is a plain library object (no protocol in `docs/01 §3`); it is injected at the
  composition root (u12). Exposes: `list(filter=category|owasp|tag|pack) -> list[AttackSpec]`,
  `get(id) -> AttackSpec`, `resolve(suite_id) -> list[AttackSpec]`, `packs() -> list[Pack]`.
- Uses `importlib.metadata.entry_points` to enumerate declared `dottore.evaluators` /
  `dottore.mutators` **type strings** only (for the "unknown evaluator/mutator type" lint rule,
  `docs/06 §3`); it does **not** instantiate or import plugin classes.
- The fixtures-prove check calls evaluators **by type through u06's registry interface if
  present**; in u02's own tests it runs against a stub evaluator table (u06 not yet built in W1).

## §4 Known constraints - KEEP / DECIDE
- KEEP: load path = parse (`yaml.safe_load`) → schema-validate → model-construct → register.
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
- **Fixtures-prove-detection gate:** `tests/fixtures/packs/good/` - every spec's
  `fixtures.vulnerable` yields ≥1 fail and `fixtures.hardened` yields all-pass under its declared
  evaluators (stub table); a deliberately broken spec in `.../bad/` triggers `FIXTURE_NO_DETECT`.
- **Registry API:** property test (Hypothesis) - `get(id)` round-trips every listed spec;
  `resolve(suite)` returns specs in suite order; `list(filter=...)` is a correct subset.
- `dottore lint specs/` exits 0 on the shipped good tree, non-zero with itemized errors on `bad/`.
- `ruff check`, `ruff format --check`, `mypy src/ildottore/registry`, `mypy src/ildottore/cli/lint.py`
  clean; `lint-imports` green (registry imports `shared` only).

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
  omits them - propose local until promoted to shared by an ADR.
