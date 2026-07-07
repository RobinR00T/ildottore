-- Il Dottore RunStore schema (u10) — SQLite concrete, Postgres seam later.
-- Forward-only. The current version lives in `migrations.py` (SCHEMA_VERSION);
-- `schema_version` records the applied version. All DDL is idempotent so a
-- re-run on an already-migrated DB is a no-op (contract §7 migration round-trip).

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT    NOT NULL PRIMARY KEY,
    suite_id    TEXT,
    target_id   TEXT,
    started_at  TEXT,
    finished_at TEXT,
    n_runs      INTEGER,
    status      TEXT,
    meta_json   TEXT    NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    run_id            TEXT    NOT NULL,
    finding_id        TEXT    NOT NULL,
    spec_id           TEXT,
    status            TEXT,
    severity          TEXT,
    repro             REAL,
    confidence        REAL,
    evidence_refs_json TEXT   NOT NULL DEFAULT '[]',
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id) REFERENCES runs (run_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings (run_id);
