"""SQLite :class:`~ildottore.shared.protocols.RunStore` (u10).

Concrete SQLite behind the u00 ``RunStore`` protocol (Postgres seam later —
contract §9). ``save_run`` / ``save_finding`` are **idempotent upserts** keyed on
``(run_id)`` and ``(run_id, finding_id)`` respectively: calling twice yields a
single row and never a duplicate-key error (contract §7).

Every value written to the DB passes through the u01 redactor first — no raw
secret/PII/canary/logprob reaches a cell (``docs/11 §5`` DL2). All writes run in a
transaction; the connection enforces WAL + foreign keys (``migrations.connect``).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import TracebackType
from typing import Any

from ildottore.redactor import Redactor
from ildottore.shared.models import Finding, TestRun
from ildottore.store import migrations


def finding_id_of(finding: Finding) -> str:
    """Derive a stable per-run finding id (``<spec_id>::<target_id>``).

    ``Finding`` has no explicit id; one spec against one target is unique within a
    run, so the pair is the natural key (contract §6 ``PRIMARY KEY(run_id, id)``).
    """

    return f"{finding.spec_id}::{finding.target_id}"


class SqliteRunStore:
    """RunStore over a single SQLite file; opened/migrated on construction."""

    def __init__(self, db_path: Path, *, redactor: Redactor | None = None) -> None:
        self._db_path = Path(db_path)
        self._redactor = redactor if redactor is not None else Redactor()
        self._conn = migrations.connect(self._db_path)
        migrations.migrate(self._conn)

    # --- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SqliteRunStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # --- writes --------------------------------------------------------------

    def save_run(self, run: TestRun) -> None:
        """Idempotent upsert of one run row (keyed on ``run_id``)."""

        target_id = run.targets[0].id if run.targets else None
        status = _dominant_status(run)
        meta = self._redact_json(
            {
                "summary": run.summary.model_dump(mode="json"),
                "target_ids": [t.id for t in run.targets],
            }
        )
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO runs
                    (run_id, suite_id, target_id, started_at, finished_at,
                     n_runs, status, meta_json)
                VALUES (:run_id, :suite_id, :target_id, :started_at, :finished_at,
                        :n_runs, :status, :meta_json)
                ON CONFLICT(run_id) DO UPDATE SET
                    suite_id    = excluded.suite_id,
                    target_id   = excluded.target_id,
                    started_at  = excluded.started_at,
                    finished_at = excluded.finished_at,
                    n_runs      = excluded.n_runs,
                    status      = excluded.status,
                    meta_json   = excluded.meta_json
                """,
                {
                    "run_id": run.run_id,
                    "suite_id": self._redact_str(run.suite_ref),
                    "target_id": self._redact_str(target_id),
                    "started_at": run.started_at,
                    "finished_at": run.finished_at,
                    "n_runs": len(run.targets) or None,
                    "status": status,
                    "meta_json": meta,
                },
            )
            for finding in run.findings:
                self._upsert_finding(run.run_id, finding)

    def save_finding(self, f: Finding) -> None:
        """Idempotent upsert of one finding row (keyed on ``(run_id, id)``).

        ``Finding`` carries no ``run_id`` (u00 model, contract §3), so a standalone
        save scopes the finding under its ``target_id`` as the run key and ensures
        a placeholder run row so ``foreign_keys=ON`` never rejects it. The common
        path is :meth:`save_run`, which persists each finding under the real
        ``run.run_id``.
        """

        run_id = _finding_run_id(f)
        self._ensure_run_row(run_id)
        with self._conn:
            self._upsert_finding(run_id, f)

    def _upsert_finding(self, run_id: str, f: Finding) -> None:
        """Upsert one finding under ``run_id`` (caller owns the transaction)."""

        refs = self._redact_json([ref.model_dump(mode="json") for ref in f.evidence])
        # The finding_id is a persisted key derived from spec_id/target_id, so it
        # is redacted like any other stored value (DL2). Redaction is
        # deterministic for a given salt, so the redacted id still matches on
        # conflict → idempotency holds.
        finding_id = self._redact_str(finding_id_of(f))
        self._conn.execute(
            """
            INSERT INTO findings
                (run_id, finding_id, spec_id, status, severity, repro,
                 confidence, evidence_refs_json)
            VALUES (:run_id, :finding_id, :spec_id, :status, :severity,
                    :repro, :confidence, :evidence_refs_json)
            ON CONFLICT(run_id, finding_id) DO UPDATE SET
                spec_id            = excluded.spec_id,
                status             = excluded.status,
                severity           = excluded.severity,
                repro              = excluded.repro,
                confidence         = excluded.confidence,
                evidence_refs_json = excluded.evidence_refs_json
            """,
            {
                "run_id": run_id,
                "finding_id": finding_id,
                "spec_id": self._redact_str(f.spec_id),
                "status": f.status.value,
                "severity": f.risk.band.value,
                "repro": f.risk.reproducibility,
                "confidence": f.risk.confidence,
                "evidence_refs_json": refs,
            },
        )

    def _ensure_run_row(self, run_id: str) -> None:
        """Insert a minimal run row if absent (satisfies the FK, upserted later)."""

        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO runs (run_id) VALUES (?)",
                (run_id,),
            )

    # --- queries (reporting / replay support) --------------------------------

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row) if row is not None else None

    def list_findings(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY finding_id",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def schema_version(self) -> int:
        return migrations.current_version(self._conn)

    # --- redaction helpers ---------------------------------------------------

    def _redact_str(self, value: str | None) -> str | None:
        if value is None:
            return None
        return self._redactor.redact_text(value)

    def _redact_json(self, obj: object) -> str:
        redacted = self._redactor.redact(obj)
        return json.dumps(redacted, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _dominant_status(run: TestRun) -> str | None:
    """Coarse run status: ``fail`` if any finding failed, else ``pass``/None."""

    if not run.findings:
        return None
    statuses = {f.status.value for f in run.findings}
    if "fail" in statuses:
        return "fail"
    if "inconclusive" in statuses:
        return "inconclusive"
    return "pass"


def _finding_run_id(f: Finding) -> str:
    """A finding's owning run. Findings carry no run_id; use the target scope.

    In MVP-1 a ``Finding`` is persisted through the run it belongs to, so the
    caller passes the run via ``save_run`` first; when ``save_finding`` is called
    standalone the ``target_id`` doubles as the run scope key. This keeps the FK
    satisfiable without inventing a field on the shared model (contract §3).
    """

    return f.target_id
