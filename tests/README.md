# tests/ - validation harness map

This directory is the executable form of `docs/07-validation-plan.md`. Every one of the **18
taxonomy layers** (`docs/07 §1`) has a home here, and the **ordered CI gates** (`docs/07 §5`,
mirrored in `.github/workflows/ci.yml`) run these layers fail-closed. Scaffolding, shared
fixtures and gates are owned by `u14-self-validation-ci`; the per-layer **test bodies** are
owned by each unit's contract (evaluators own their P/R tests, the mutator owns property tests,
etc. - see `specs/contracts/00-INDEX.md`).

## Shared scaffolding (u14-owned)

| File | Purpose |
|------|---------|
| `conftest.py` | Root fixtures: `repo_root`, `fixtures_dir`, `specs_dir`, `load_fixture_json`, `frozen_clock`, `mock_target_factory`, and the **autouse `no_live_socket` guard** (fails closed on any non-loopback connect - CI KEEP: no live provider calls). |
| `test_import_contract.py` | Layer 14 smoke: runs `lint-imports` against `.importlinter`, asserts all contracts KEPT and that the config is not double-defined in `pyproject.toml`. |
| `test_harness_scaffolding.py` | Self-tests for the shared fixtures + the no-live-socket guard. |
| `fixtures/` | Shared corpora consumed across layers (see below). |

Per-unit `conftest.py` files under each sub-directory own their domain fixtures; the root
`conftest.py` deliberately does **not** redefine them.

## Taxonomy → directory map (`docs/07 §1`)

| # | Layer | Type | Lives in |
|---|-------|------|----------|
| 1 | Models / specs | Schema validation | `shared/test_schema_parity.py`, `shared/test_shared_models.py`, `registry/test_schema.py` |
| 2 | Spec linter | Static checks | `registry/test_linter.py`, `registry/test_cli_lint.py` |
| 3 | Units | Unit tests (coverage ≥ 85% core) | every `test_*.py` across all sub-dirs |
| 4 | Mutator | Property-based (Hypothesis) | `mutators/test_determinism.py`, `mutators/test_reversibility.py`, `mutators/test_golden.py` |
| 5 | Adapters | Contract tests + recorded cassettes | `adapters/test_{openai,anthropic,rest,base}.py` + `adapters/cassettes/`; **no live keys** (`no_live_socket` guard) |
| 6 | Golden targets | Detection-accuracy (hard gate) | `golden/test_golden.py`, `golden/test_mock.py`, `battery/test_battery.py` + `fixtures/{vulnerable,hardened}` (inline fixtures in specs) |
| 7 | Evaluators | Labeled precision / recall | `evaluators/test_precision_recall.py`, `evaluators/test_data_leak.py` + `fixtures/labeled/` |
| 8 | Judge | Robustness / injection | `evaluators/test_adversarial_judge.py`, `evaluators/test_semantic_judge.py` + `fixtures/adversarial-judge/` |
| 9 | Determinism | Replay | `evaluators/test_deterministic.py`, `core/test_determinism.py`, `core/test_reproduce.py` |
| 10 | Scoring | Property tests | `scoring/test_properties.py`, `scoring/test_banding.py`, `scoring/test_confidence.py` |
| 11 | Reporting | Snapshot + schema (SARIF/JUnit/HTML/JSON, masking) | `reporting/test_{sarif,junit,html,json}_reporter.py`, `reporting/test_masking*.py`, `reporting/test_golden_snapshot.py` |
| 12 | CLI / API | E2E | `cli/test_e2e.py`, `cli/test_commands.py`, `cli/test_exit_codes.py` |
| 13 | Availability specs | Budget / guardrail (fake clock) | `core/test_budgets.py`, `core/test_runner_budget.py` (uses `frozen_clock`) |
| 14 | Boundaries | Import-linter contract | `test_import_contract.py` + `.importlinter` |
| 15 | Safety | Negative tests | `cli/test_scope_gate.py`, `core/test_policy_gate.py`, `policy/test_{allowlist,scope,packs}.py` |
| 16 | Meta / regression | Golden-run snapshot | `reporting/test_golden_snapshot.py` + nightly regression (`.github/workflows/audit.yml` / `tests/golden-run/`) |
| 17 | Self-scan | Dogfooding | CI job `self-scan` (`ci.yml`) - `dottore` run against our own judge, gate on new high/critical |
| 18 | Metamorphic | Metamorphic tests | `evaluators/test_deterministic.py` (semantics-preserving invariance) + nightly metamorphic run |

## Fixture corpora (`docs/07 §4`)

| Path | Layer | Contents |
|------|-------|----------|
| `fixtures/vulnerable/`, `fixtures/hardened/` | 6 | Golden targets mirroring attack families (vulnerable → `fail`, hardened → `pass`). Inline-in-spec fixtures are resolved first (OD-7). |
| `fixtures/labeled/` | 7 | Evaluator precision/recall corpus (positives, negatives, hard cases). |
| `fixtures/adversarial-judge/` | 8 | Target outputs that try to prompt-inject the judge (must not flip a verdict). |
| `adapters/cassettes/` | 5 | Recorded provider interactions, secrets scrubbed. **No real API keys, ever.** |
| `fixtures/{specs,packs,plans,scoring,mutators,fingerprint}/` | 1-4 | Registry / pack / plan / scoring / mutator / fingerprint inputs. |

## Running locally (mirrors CI gates)

```sh
dottore lint specs/                    # gate 1  (layers 1-2)
lint-imports                           # gate 2  (layer 14)
pytest -q                              # gates 3-10, 13, 15, 18
pytest --cov=src/ildottore --cov-report=term-missing --cov-fail-under=85   # gate 12
ruff check . && ruff format --check . && mypy src                          # static
```

The **golden-fixture accuracy** (layer 6) and **self-scan** (layer 17) are hard merge blockers:
a spec whose fixtures don't produce the expected verdicts, or a new high/critical finding in
our own LLM-using code, fails CI. Thresholds are `docs/07 §3` and must never be relaxed to go
green - a red gate is **escalated to its owning unit**, not patched here (contract §8).
