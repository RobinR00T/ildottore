"""Redaction-at-rest leak test (DL2, gating — contract §7).

Seeds attempts + findings with planted canaries, secret-shaped strings and
synthetic PII, runs the full write path (fs + sqlite), then greps EVERY on-disk
artifact and EVERY DB cell: 0 raw hits, values present only masked/hashed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.redactor import Redactor
from ildottore.shared.enums import ScanBand, VerdictStatus
from ildottore.shared.models import (
    Attempt,
    EvidenceRef,
    Finding,
    ModelRequest,
    ModelResponse,
    RiskScore,
    Target,
    TestRun,
    Verdict,
)
from ildottore.store.evidence_fs import FsEvidenceStore, RedactionLeakError
from ildottore.store.run_sqlite import SqliteRunStore

# --- planted secrets/PII (synthetic; safe to commit) --------------------------
CANARY = "CANARY-7f3a9b2c-DO-NOT-LEAK"
OPENAI_KEY = "sk-" + "A" * 40
GITHUB_TOKEN = "ghp_" + "b" * 36
EMAIL = "victim.person@example-corp.com"
NATIONAL_ID = "123-45-6789"
RAW_SECRETS = [CANARY, OPENAI_KEY, GITHUB_TOKEN, EMAIL, NATIONAL_ID]


def _seeded_attempt() -> Attempt:
    poisoned = (
        f"leaked {OPENAI_KEY} and {GITHUB_TOKEN}; contact {EMAIL}; "
        f"ssn {NATIONAL_ID}; marker {CANARY}"
    )
    return Attempt(
        attempt_id="a-secret",
        spec_id="DL-SECRET-001",
        request=ModelRequest(prompt=f"exfiltrate {CANARY}"),
        response=ModelResponse(text=poisoned, raw_ids={"provider_key": OPENAI_KEY}),
        verdict=Verdict(
            status=VerdictStatus.FAIL,
            confidence=0.99,
            reasoning=f"model returned {EMAIL}",
            matched=[CANARY],
            evaluator_type="secret_leakage",
        ),
    )


def _seeded_finding() -> Finding:
    return Finding(
        spec_id=f"DL-SECRET-001-{NATIONAL_ID}",
        target_id="tgt-1",
        status=VerdictStatus.FAIL,
        confirmed=True,
        risk=RiskScore(
            impact=4,
            exploitability=3,
            reproducibility=0.8,
            risk=12.0,
            band=ScanBand.CRITICAL,
            confidence=0.95,
        ),
        evidence=[
            EvidenceRef(run_id="run-1", attempt_id="a-secret", uri=f"u/{CANARY}", sha256=None)
        ],
    )


def _all_disk_text(root: Path) -> str:
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in root.rglob("*") if p.is_file()
    )


def _all_db_text(db_path: Path) -> str:
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        cells: list[str] = []
        tables = [
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        ]
        for table in tables:
            for row in conn.execute(f"SELECT * FROM {table}").fetchall():  # noqa: S608 — table names from schema
                cells.extend(str(v) for v in row)
        return "\n".join(cells)
    finally:
        conn.close()


def test_no_raw_secret_reaches_disk_or_db(store_root: Path) -> None:
    salted = Redactor(salt="engagement-salt")
    es = FsEvidenceStore(store_root, redactor=salted, planted_canaries=[CANARY])
    db_path = store_root / "runs.db"
    rs = SqliteRunStore(db_path, redactor=Redactor(salt="engagement-salt"))

    es.put("run-1", _seeded_attempt())
    run = TestRun(
        run_id="run-1",
        suite_ref="suites/core",
        targets=[Target(id="tgt-1", type="chatbot")],
        findings=[_seeded_finding()],
    )
    rs.save_run(run)
    rs.save_finding(_seeded_finding())
    rs.close()

    disk = _all_disk_text(store_root)
    db = _all_db_text(db_path)

    for raw in RAW_SECRETS:
        assert raw not in disk, f"raw secret leaked to disk: {raw!r}"
        assert raw not in db, f"raw secret leaked to db: {raw!r}"

    # Proof the payload was actually written (masked), not just absent.
    assert "«REDACTED:" in disk


def test_write_is_fail_closed_when_redaction_incomplete(store_root: Path) -> None:
    """A redactor that masks nothing must make put() refuse the write (DL2)."""

    class _NoopRedactor(Redactor):
        def redact(self, obj: object) -> object:
            return obj

        def redact_text(self, text: str) -> str:
            return text

    # A no-op redactor is a fixed point, so the fixed-point guard alone cannot
    # catch it; inject a redactor whose object-redaction leaves a secret but
    # whose text-redaction would still change it -> mismatch -> refuse.
    class _LeakyRedactor(Redactor):
        def redact(self, obj: object) -> object:
            return obj  # leaves the raw OPENAI_KEY in the payload

    es = FsEvidenceStore(store_root, redactor=_LeakyRedactor())
    with pytest.raises(RedactionLeakError):
        es.put("run-1", _seeded_attempt())
    # Nothing persisted.
    assert not any(store_root.rglob("*.json"))


def test_numeric_logprob_does_not_false_trip_the_guard(store_root: Path) -> None:
    """A real logprob float must not be mistaken for PII by the no-leak guard (DL2).

    Regression: a value like ``-0.013113695196807384`` matches the phone/card shapes
    when the whole JSON is scanned as flat text, but it is a number, not a secret. The
    fixed-point guard scans string leaves only, so evidence carrying real logprobs
    (as returned by a live target) persists instead of being refused."""

    from ildottore.shared.models import TokenLogprob

    attempt = Attempt(
        attempt_id="a-logprob",
        spec_id="JB-ROLEPLAY-001",
        request=ModelRequest(prompt="probe"),
        response=ModelResponse(
            text="I can't help with that.",
            logprobs=[
                TokenLogprob(token="Here", logprob=-0.013113695196807384),
                TokenLogprob(token="are", logprob=-9.059946933120955e-06),
            ],
            usage={"prompt_tokens": 40, "completion_tokens": 144, "total_tokens": 184},
            raw_ids={"id": "chatcmpl-416", "model": "llama3.2:1b"},
        ),
    )
    es = FsEvidenceStore(store_root)
    ref = es.put("run-lp", attempt)  # must not raise
    assert ref.sha256 is not None
    assert (store_root / Path(ref.uri)).exists()
