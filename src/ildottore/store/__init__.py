"""Evidence + run persistence (u10).

Two concrete stores behind the u00 protocols (``shared.protocols``):

* :class:`~ildottore.store.evidence_fs.FsEvidenceStore` - content-addressed,
  immutable, redact-at-rest filesystem ``EvidenceStore``.
* :class:`~ildottore.store.run_sqlite.SqliteRunStore` - idempotent SQLite
  ``RunStore`` (Postgres seam later - contract §9).

Redaction (u01) is applied before every write; raw secrets/PII/canaries never
touch disk or DB (``docs/11 §5`` DL2, fail-closed). :mod:`ildottore.store.replay`
reconstructs a run's attempts for reproducibility recomputation.
"""

from __future__ import annotations

from ildottore.store.evidence_fs import FsEvidenceStore, RedactionLeakError
from ildottore.store.migrations import SCHEMA_VERSION, connect, current_version, migrate
from ildottore.store.paths import UnsafePathError, content_hash
from ildottore.store.replay import ReplayResult, TamperError, replay_run, verify_ref
from ildottore.store.run_sqlite import SqliteRunStore, finding_id_of

__all__ = [
    "SCHEMA_VERSION",
    "FsEvidenceStore",
    "RedactionLeakError",
    "ReplayResult",
    "SqliteRunStore",
    "TamperError",
    "UnsafePathError",
    "connect",
    "content_hash",
    "current_version",
    "finding_id_of",
    "migrate",
    "replay_run",
    "verify_ref",
]
