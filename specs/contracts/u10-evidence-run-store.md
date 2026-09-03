# u10-evidence-run-store.md

Stage-2 build contract. 9-section anatomy per `docs/00 §2`. Read `AGENTS.md` + `docs/01 §3`
(EvidenceStore/RunStore) + `docs/11 §5` (redaction/legal) + `shared/` before implementing.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/store/` - `evidence_fs.py` (filesystem EvidenceStore), `run_sqlite.py`
  (SQLite RunStore), `schema.sql` (DDL), `migrations.py` (versioned schema), `paths.py`
  (run-dir layout + id derivation), `replay.py` (reproducible-replay reader), `__init__.py`.
- **MUST NOT touch:** `shared/`, `adapters/`, `evaluators/`, `core/`, `scoring/`, `reporting/`,
  `policy/`, `redactor.py` (import it, never edit), any spec YAML.

## §2 Intended behavior
Persist a campaign durably for reproducible replay and downstream reporting. Two stores behind
the u00 protocols:
- **EvidenceStore (fs):** `put(run_id, attempt) -> EvidenceRef` writes each `Attempt` (prompt,
  response, traces, sampling config, provider request/response ids, token logprobs) as an
  immutable artifact under a per-run directory. Content-addressed by SHA-256 so identical
  attempts dedupe and refs are verifiable.
- **RunStore (sqlite):** `save_run(run)` / `save_finding(f)` upsert `TestRun` + `Finding` rows;
  idempotent on `(run_id)` / `(run_id, finding_id)`. Queryable for reporting.
- **Redaction at rest is mandatory (`docs/11 §5` DL2):** every payload passes through the u01
  redactor before write - no raw secrets/PII/canary values touch disk or DB. Detector hits are
  stored typed + masked/hashed only.
- **Replay:** `replay.py` reconstructs a run's attempts + findings from stored evidence so a
  reader can recompute `repro = successful_attacks / N` (`docs/01 §5`); refs are hash-verified.

## §3 Dependencies & interface contracts
- Implements `shared.protocols.{EvidenceStore, RunStore}` exactly (`docs/01 §3`).
- Consumes `shared.models.{TestRun, Attempt, Finding, Evidence, EvidenceRef}` - treat as the
  stable registry; any field change is a program-level OD, not a unit choice.
- Depends on **u00** (models/protocols) and **u01** for the central redactor (`redactor.py`) and
  config (store root path); imports the redactor **interface**, never re-implements masking.
- Pure persistence: MUST NOT import `core`, `evaluators`, `adapters`, `reporting`.

## §4 Known constraints - KEEP / DECIDE
- KEEP: evidence artifacts are **immutable + content-addressed** (SHA-256); a rewrite with the
  same content is a no-op, differing content is a new ref (never overwrites).
- KEEP: SQLite opened with `PRAGMA journal_mode=WAL`, `foreign_keys=ON`; all writes in a
  transaction; schema version tracked in a `schema_version` table (forward-only migrations).
- KEEP: redaction is **fail-closed** - if the redactor errors or a raw-secret pattern survives,
  refuse the write and raise, never persist unredacted.
- KEEP: paths-with-spaces safe; store root from config, never hardcoded; no writes outside root.
- DECIDE (**OD-4**): evidence at-rest **encryption** in MVP‑1 vs MVP‑2 - propose plaintext-on-
  disk + redaction for MVP‑1, pluggable cipher seam for MVP‑2 (human sign-off).

## §5 Implementation plan (each step its own commit, green before next)
1. `paths.py` - deterministic run-dir layout (`<root>/<run_id>/attempts/<sha256>.json`) + id
   helpers; `schema.sql` + `migrations.py` (v1 tables, WAL/FK pragmas, `schema_version`).
2. `evidence_fs.py` - `put()` with redact→hash→atomic-write (temp + `os.replace`) + `EvidenceRef`
   (run_id, sha256, path, byte size); idempotent dedupe.
3. `run_sqlite.py` - `save_run` / `save_finding` upserts, connection mgmt, typed row mappers.
4. `replay.py` - read-back API: list attempts for a run, verify hashes, reconstruct for repro.
5. Property + golden tests, redaction leak-test, migration round-trip.

## §6 Data/wire shapes
- **Disk:** `<root>/<run_id>/run.json` (redacted `TestRun`), `attempts/<sha256>.json` (redacted
  `Attempt`); artifacts UTF-8 JSON, one attempt per file, filename == content hash.
- **`EvidenceRef` = {run_id, sha256, path, size_bytes}** (per u00 model).
- **SQLite tables:** `runs(run_id PK, suite_id, target_id, started_at, finished_at, n_runs,
  status, meta_json)`; `findings(run_id FK, finding_id, spec_id, status, severity, repro,
  confidence, evidence_refs_json, PRIMARY KEY(run_id, finding_id))`; `schema_version(version)`.
- Detector-hit fields carry **masked/hashed** values only (`docs/11 §5` DL2); no raw logprob
  secrets, no canary plaintext.

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/store -q` green; coverage ≥ 90% for `src/ildottore/store/`.
- **Redaction leak-test (DL2, gating):** `tests/store/test_redaction_at_rest.py` seeds attempts
  containing planted canaries + secret-shaped strings + synthetic PII, runs full write path, then
  greps every on-disk artifact and every DB cell - **0 raw hits** (assert masked/hashed only).
- **Content-addressing:** identical `Attempt` written twice ⇒ one file, one ref; mutated content
  ⇒ new hash; `replay.py` hash-verify passes and detects a tampered artifact (raises).
- **Idempotency:** `save_run`/`save_finding` called twice ⇒ single row, no duplicate-key error.
- **Migration round-trip:** fresh DB → migrate → `schema_version == latest`; re-run is a no-op.
- **Replay determinism:** stored run replays to the same finding set + recomputed `repro`.
- `ruff check`, `ruff format --check .`, `mypy src/ildottore/store` clean; `lint-imports` green
  (store imports only `shared` + `redactor`).

## §8 Out of scope / forbidden
- MUST NOT compute scores/severity (u07), evaluate responses (u06), or render reports (u11) -
  store only what it is given.
- MUST NOT implement its own masking; redaction is u01's redactor, imported.
- MUST NOT persist any raw secret/PII/canary/logprob value (`docs/11 §5` DL2) - fail-closed.
- MUST NOT write outside the configured store root; no network, no S3 in MVP‑1.
- Not its call: at-rest encryption decision (**OD-4**) · scope signing (OD-2).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-4** evidence at-rest encryption in MVP‑1 or MVP‑2 (propose: plaintext + redaction now,
  pluggable cipher seam later).
- Retention/pruning policy for evidence dirs - propose deferred to MVP‑2 (out of scope here).
- SQLite-only for MVP‑1 vs Postgres seam now - propose interface-only seam, SQLite concrete only.
