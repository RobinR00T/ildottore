"""SQLite :class:`~ildottore.shared.protocols.RunStore` (u10).

Concrete SQLite behind the u00 ``RunStore`` protocol (Postgres seam later -
contract §9). ``save_run`` / ``save_finding`` are **idempotent upserts** keyed on
``(run_id)`` and ``(run_id, finding_id)`` respectively: calling twice yields a
single row and never a duplicate-key error (contract §7).

Every value written to the DB passes through the u01 redactor first - no raw
secret/PII/canary/logprob reaches a cell (``docs/11 §5`` DL2). All writes run in a
transaction; the connection enforces WAL + foreign keys (``migrations.connect``).
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from types import TracebackType
from typing import Any

from ildottore.redactor import Redactor, redact_evidence_ref, redact_identity
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
                    # Fixed-salt mask: `--resume` recomputes it to verify the target.
                    "target_id": None if target_id is None else redact_identity(target_id),
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

        # Evidence references are the tool's own pointers (run id, attempt id, path, sha256),
        # stored as written: they are the manifest `replay` and `--resume` check the evidence
        # tree against. Masked, a digest read as `high_entropy` and nothing could tell a
        # tampered artifact renamed to its new hash from the original (audit 2026-10-03, F12).
        refs = _dumps_list(
            [redact_evidence_ref(self._redactor, ref.model_dump(mode="json")) for ref in f.evidence]
        )
        # The finding_id is a persisted key derived from spec_id/target_id, so it is masked
        # like any other stored identifier (DL2), with the FIXED identity salt: the general
        # redactor's salt is random per process, and a resume in a new process must hit the
        # same row on conflict or it would duplicate every finding.
        finding_id = redact_identity(finding_id_of(f))
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

    def save_run_context(
        self,
        run_id: str,
        *,
        spec_digests: dict[str, str] | None = None,
        spend: dict[str, float] | None = None,
        context: dict[str, Any] | None = None,
        target_id: str | None = None,
    ) -> None:
        """Record which battery a run executed and what it spent (``--resume`` support).

        ``target_id`` is recorded here too, with the same fixed identity mask ``save_run``
        uses, and only if the row has none yet. This record is written BEFORE the campaign
        sends, so a campaign killed mid-flight left a row whose target was NULL, and the
        unwaivable target check then refused to resume exactly the run this record exists to
        make resumable (audit 2026-10-03, F4).

        Both columns are written **unredacted**, deliberately. They hold SHA-256 digests of
        our own spec files and four integers of consumption: no secret, no PII, no canary,
        no logprob, so DL2 does not reach them. It matters because the redactor's
        high-entropy rule masks a bare SHA-256 (it cannot tell a digest from a key), and a
        masked digest would still compare equal to itself while being useless to a human
        reading the row to find out which spec changed.

        A partial call keeps the other column: the digests are known before the campaign
        runs, the spend only after it.
        """

        self._ensure_run_row(run_id)
        if target_id is not None:
            with self._conn:
                self._conn.execute(
                    "UPDATE runs SET target_id = ? WHERE run_id = ? AND target_id IS NULL",
                    (redact_identity(target_id), run_id),
                )
        # Two fixed statements rather than one assembled from column names: dynamic SQL in
        # the store of a security scanner is a shape worth not having, even where every
        # fragment is an internal constant.
        with self._conn:
            if spec_digests is not None:
                self._conn.execute(
                    "UPDATE runs SET spec_digests_json = ? WHERE run_id = ?",
                    (_dumps(spec_digests), run_id),
                )
            if spend is not None:
                # Monotonic PER AXIS. Two resumes of one run id race read-modify-write (there
                # is no lease), and a last-writer-wins UPDATE let the loser erase the winner's
                # spend: the store then reported LESS than the campaign had spent, the one
                # direction a spend record must never move. An all-or-nothing guard on the
                # request axis fixed that and introduced its own version of it, discarding a
                # higher token or wall figure along with the refused request count. It cannot
                # prevent a concurrent overspend, and the contract clause says so rather than
                # claiming more.
                current = self.get_run_spend(run_id) or {}
                merged = {
                    axis: max(float(spend.get(axis, 0)), float(current.get(axis, 0)))
                    for axis in {*spend, *current}
                }
                self._conn.execute(
                    "UPDATE runs SET spend_json = ? WHERE run_id = ?",
                    (_dumps(merged), run_id),
                )

        if context is not None:
            self._write_context(run_id, context)

    def _write_context(self, run_id: str, context: dict[str, Any]) -> None:
        """Replace the context, keeping the scope list `add_run_scope` owns (one transaction)."""

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if _SCOPES_KEY not in context:
                stored = self._context_in_transaction(run_id) or {}
                if _SCOPES_KEY in stored:
                    context = {**context, _SCOPES_KEY: stored[_SCOPES_KEY]}
            self._conn.execute(
                "UPDATE runs SET context_json = ? WHERE run_id = ?", (_dumps(context), run_id)
            )
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise

    def add_run_scope(
        self, run_id: str, scope_sha256: str, *, resumed: bool = False
    ) -> tuple[list[str], list[str]]:
        """Record that ``scope_sha256`` authorized traffic of ``run_id``; return (before, after).

        The context keeps ``scope_sha256s``, the scope of each invocation in order, appended
        whenever it differs from the last one (so a return to an earlier scope shows too). A
        ``resumed`` run whose context has no list was recorded before scopes were kept: its list
        starts with ``"unrecorded"``, so the first scope is not silently taken for the whole
        run's. One immediate transaction: two resumes of one run id cannot each drop the other's
        entry (audit D-17).
        """

        self._ensure_run_row(run_id)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            context = self._context_in_transaction(run_id) or {}
            recorded = context.get(_SCOPES_KEY)
            if isinstance(recorded, list):
                before = [s for s in recorded if isinstance(s, str)]
            else:
                before = [_UNRECORDED_SCOPE] if resumed and context else []
            after = before if before and before[-1] == scope_sha256 else [*before, scope_sha256]
            if after != recorded:
                self._conn.execute(
                    "UPDATE runs SET context_json = ? WHERE run_id = ?",
                    (_dumps({**context, _SCOPES_KEY: after}), run_id),
                )
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise
        return before, after

    def _context_in_transaction(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT context_json AS value FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return _loads_dict(row["value"] if row is not None else None, column="context_json")

    # --- queries (reporting / replay support) --------------------------------

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row) if row is not None else None

    def get_run_spec_digests(self, run_id: str) -> dict[str, str] | None:
        """The battery digests recorded for ``run_id``, or ``None`` if never recorded.

        ``None`` is not "they match": it is a run written before this column existed, or one
        whose campaign never got that far. The caller has to say which, rather than treat an
        absent record as a clean bill.
        """

        row = self._conn.execute(
            "SELECT spec_digests_json AS value FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return _loads_dict(row["value"] if row is not None else None, column="spec_digests_json")

    def get_run_spend(self, run_id: str) -> dict[str, float] | None:
        """What ``run_id`` has consumed so far across every invocation, or ``None``."""

        row = self._conn.execute(
            "SELECT spend_json AS value FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        spend = _loads_dict(row["value"] if row is not None else None, column="spend_json")
        # Every figure is an amount before anyone converts it: `int()` of an infinity or of a
        # list was a traceback and exit 1, an integer past a float was one when the resume wrote
        # its spend back, and a negative or NaN figure was taken as what the campaign had spent
        # (2026-10-07). No value is quoted, as for the other corrupt columns.
        if spend is not None and not all(_is_amount(value) for value in spend.values()):
            raise CorruptRunContext(
                "spend_json holds a value that is not a finite, non-negative number. An integrity "
                "record that cannot be read is not the same as one that was never written: "
                "refusing rather than continuing."
            )
        return spend

    def get_run_context(self, run_id: str) -> dict[str, Any] | None:
        """The target digest and run parameters recorded for ``run_id``, or ``None``."""

        row = self._conn.execute(
            "SELECT context_json AS value FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        context = _loads_dict(row["value"] if row is not None else None, column="context_json")
        # `--runs` is read back with `int()`: a list or an infinity was a traceback and exit 1, a
        # string was quoted in the error, and `true` or `1.9` resumed at one run (pre-commit
        # audit of the spend check, 2026-10-07). It is written with the target digest, so a
        # context that has the digest and no count, or a null one, lost it: the resume took this
        # invocation's default instead and wrote it over the record (delta audit).
        fields = context or {}
        runs = fields.get("runs")
        # A count that is there is checked whatever else is in the row, so no reader of it ever
        # converts a bad one; a missing one only beside a digest. Without a digest the target
        # refusal, which no flag waives, fires first and says what is wrong (audits of #61).
        expected = runs is not None or fields.get("target_digest") is not None
        if expected and (isinstance(runs, bool) or not isinstance(runs, int) or runs < 1):
            raise CorruptRunContext(
                "context_json holds no runs value, or one that is not a positive whole number. "
                "An integrity record that cannot be read is not the same as one that was never "
                "written: refusing rather than continuing."
            )
        return context

    # --- artifact journal (schema v4) ------------------------------------------

    def record_artifact(self, run_id: str, spec_id: str, sha256: str) -> None:
        """Journal an attempt artifact BEFORE it is written (state ``pending``).

        Idempotent: an artifact already journaled keeps its row and state.
        """

        with self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO artifacts (run_id, spec_id, sha256, state) "
                "VALUES (?, ?, ?, 'pending')",
                (run_id, spec_id, sha256),
            )

    def confirm_artifact(self, run_id: str, sha256: str) -> None:
        """Mark a journaled artifact as on disk (state ``written``)."""

        with self._conn:
            self._conn.execute(
                "UPDATE artifacts SET state = 'written' WHERE run_id = ? AND sha256 = ?",
                (run_id, sha256),
            )

    def pending_artifacts(self, run_id: str) -> set[str]:
        """Digests journaled but never confirmed: a write the process may not have finished.

        A digest a saved finding cites is never pending, whatever its row says: the finding was
        scored from that artifact, so it was on disk, and a deletion of it must be refused. A
        crash between the write and the confirm left such a row, and deleting the file then
        passed the check (pre-commit audit of F11).
        """

        rows = self._conn.execute(
            "SELECT sha256 FROM artifacts WHERE run_id = ? AND state = 'pending'", (run_id,)
        ).fetchall()
        return {str(row["sha256"]) for row in rows} - self._cited_digests(run_id)

    def recorded_battery(self, run_id: str) -> set[str] | None:
        """The spec ids the run recorded before it sent anything, or ``None`` if unrecorded."""

        digests = self.get_run_spec_digests(run_id)
        return set(digests) if digests else None

    def adopt_artifacts(self, run_id: str, artifacts: list[tuple[str, str]]) -> None:
        """Journal ``(spec_id, sha256)`` pairs as written, in ONE transaction.

        A resume adopts the artifacts already on disk once they pass the check. One row at a
        time, an interruption left a spec half adopted, and its other artifacts were refused
        from then on (second audit of F11).
        """

        with self._conn:
            self._conn.executemany(
                "INSERT INTO artifacts (run_id, spec_id, sha256, state) "
                "VALUES (?, ?, ?, 'written') "
                "ON CONFLICT(run_id, sha256) DO UPDATE SET state = 'written'",
                [(run_id, spec_id, sha) for spec_id, sha in artifacts],
            )

    def _cited_digests(self, run_id: str) -> set[str]:
        cited: set[str] = set()
        for row in self._conn.execute(
            "SELECT evidence_refs_json FROM findings WHERE run_id = ?", (run_id,)
        ).fetchall():
            try:
                refs = _loads(row["evidence_refs_json"] or "[]")
            except ValueError:
                continue
            for ref in refs if isinstance(refs, list) else []:
                sha = ref.get("sha256") if isinstance(ref, dict) else None
                if isinstance(sha, str):
                    cited.add(sha)
        return cited

    def recorded_evidence(self, run_id: str) -> dict[str, set[str]]:
        """``spec_id -> {sha256}`` of every evidence artifact the run's findings cite or the
        artifact journal recorded.

        The manifest ``replay`` and ``--resume`` check the evidence tree against. A spec is in
        it only when EVERY reference of its findings is a plain 64-hex digest, and then with
        the exact set, possibly empty (a finding that cites no evidence: nothing may appear
        for it). A run stored before 2026-10-03 has some of its digests masked; skipping them
        one reference at a time left a partial set, and the untouched artifacts of that spec
        were then refused as tampered (review of PR #32). Such a spec is left out: "cannot
        verify", never "nothing is allowed".
        """

        manifest: dict[str, set[str]] = {}
        unverifiable: set[str] = set()
        rows = self._conn.execute(
            "SELECT spec_id, evidence_refs_json FROM findings WHERE run_id = ?", (run_id,)
        ).fetchall()
        for row in rows:
            spec_id = str(row["spec_id"])
            try:
                refs = _loads(row["evidence_refs_json"] or "[]")
            except ValueError:
                unverifiable.add(spec_id)
                continue
            digests = manifest.setdefault(spec_id, set())
            for ref in refs if isinstance(refs, list) else []:
                sha = ref.get("sha256") if isinstance(ref, dict) else None
                if isinstance(sha, str) and _SHA256.fullmatch(sha):
                    digests.add(sha)
                else:
                    unverifiable.add(spec_id)
        # The journal (schema v4) adds every artifact recorded as it was written, so a spec whose
        # finding was never saved (an interrupted campaign or resume) is checked too, instead of
        # being let through, and an artifact a resume added is known before its finding exists.
        journaled: set[str] = set()
        for row in self._conn.execute(
            "SELECT spec_id, sha256 FROM artifacts WHERE run_id = ?", (run_id,)
        ).fetchall():
            sha = str(row["sha256"])
            if _SHA256.fullmatch(sha):
                spec_id = str(row["spec_id"])
                manifest.setdefault(spec_id, set()).add(sha)
                journaled.add(spec_id)
        # A spec whose findings cite masked digests is checkable again once its artifacts are
        # journaled (a resume adopts them): the journal holds the real digests.
        return {
            spec: shas
            for spec, shas in manifest.items()
            if spec not in unverifiable or spec in journaled
        }

    def knows_run(self, run_id: str) -> bool:
        """True if this store holds a run row or any finding for ``run_id``."""

        row = self._conn.execute(
            "SELECT 1 FROM runs WHERE run_id = ? UNION SELECT 1 FROM findings WHERE run_id = ? "
            "LIMIT 1",
            (run_id, run_id),
        ).fetchone()
        return row is not None

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


_SHA256 = re.compile(r"[0-9a-f]{64}")


def _dumps_list(obj: list[dict[str, Any]]) -> str:
    """Canonical JSON for a list column."""

    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


#: Context key holding every scope digest that authorized traffic of a run, in order.
_SCOPES_KEY = "scope_sha256s"
#: First entry for a run recorded before scope digests were kept.
_UNRECORDED_SCOPE = "unrecorded"


def _dumps(obj: dict[str, Any]) -> str:
    """Canonical JSON for a stored context column (stable bytes, stable diffs)."""

    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class CorruptRunContext(ValueError):
    """A stored integrity column exists but cannot be read.

    Distinct from absent on purpose. An unreadable integrity record is a STRONGER signal than a
    missing one, and folding the two together reported a tampered database as "this run predates
    the check, continuing", which names the wrong cause and waves the run through.
    """


#: The deepest a stored column may nest. This tool writes them at most 3 levels deep.
_MAX_COLUMN_DEPTH = 100


def _loads(raw: str) -> Any:
    """``json.loads`` for a stored column, where a value nested too deeply is bad JSON too.

    Past the parser's stack it raises ``RecursionError``, which is not a ``ValueError``, so every
    reader of these columns let it through and ``replay`` or ``run --resume`` on a tampered store
    exited 1, the code for findings below ``--fail-on`` (2026-10-07). Under that stack a value can
    still be too deep to write back: 110,000 levels parse on 3.14 and ``json.dumps`` overflows
    past about 104,500, so a resume that rewrote the context exited 1 too (pre-merge audit of
    #61). A column is refused past :data:`_MAX_COLUMN_DEPTH` levels, measured without recursion.
    """

    try:
        value = json.loads(raw)
    except RecursionError as exc:
        raise ValueError("nested too deeply to read") from exc
    level = [(value, 1)]
    while level:
        item, depth = level.pop()
        if depth > _MAX_COLUMN_DEPTH:
            raise ValueError("nested too deeply to read")
        if isinstance(item, dict):
            level.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            level.extend((child, depth + 1) for child in item)
    return value


def _is_amount(value: object) -> bool:
    """A spend figure: a finite, non-negative number a float can hold (a JSON bool is not one)."""

    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except OverflowError:  # an integer past the largest float
        return False


def _loads_dict(raw: str | None, *, column: str) -> dict[str, Any] | None:
    """Parse a stored JSON object column. ``None`` means absent; malformed **raises**."""

    if raw is None:
        return None
    try:
        parsed = _loads(raw)
    except ValueError as exc:
        raise CorruptRunContext(
            f"{column} is not readable JSON. An integrity record that cannot be read is not "
            "the same as one that was never written: refusing rather than continuing."
        ) from exc
    if not isinstance(parsed, dict):
        raise CorruptRunContext(f"{column} holds {type(parsed).__name__}, not an object.")
    return parsed


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
