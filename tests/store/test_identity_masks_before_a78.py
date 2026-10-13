"""A run halted before u01 A-78 still resumes against its own target, and keeps one row a finding.

The key formats, the hex run and the UUID changed the identity mask the run store keeps for an id
that holds one: on ``main`` ``prod-<uuid>`` was stored as written and ``<uuid>`` with a phone mask
in its digit-only groups; now both store ``«REDACTED:uuid:...»``. A resume recomputed the current
mask, so such a run was refused as "made against target ..., not ...", and a resume keyed its
findings anew beside the rows of the first half. The values below are what ``main`` (``de122e26``)
wrote, computed with its ``redact_identity``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.cli.resume import _assert_same_target, _declaration_changed
from ildottore.redactor import identity_masks, redact_identity
from ildottore.shared.enums import TargetType, VerdictStatus
from ildottore.shared.models import Finding, SeededSetup, Target, TestRun
from ildottore.store.run_sqlite import SqliteRunStore, finding_id_of

from ..reporting.conftest import make_finding

UUID = "b3dd0f36-6819-4748-a1de-4b44fa4b4790"
#: (id, the mask main stored for it).
BEFORE = [
    (UUID, "b3dd0f36-«REDACTED:phone»-a1de-4b44fa4b4790"),
    ("prod-3f2a1b4c-5d6e-4f80-9a1b-2c3d4e5f6071", "prod-3f2a1b4c-5d6e-4f80-9a1b-2c3d4e5f6071"),
    ("tenant-" + "deadbeef" * 4, "tenant-" + "deadbeef" * 4),
    ("x_eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl", "x_eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"),
    (f"PI-DEMO-001::{UUID}", "PI-DEMO-001::b3dd0f36-«REDACTED:phone»-a1de-4b44fa4b4790"),
    (f"tool_{UUID}", "tool_b3dd0f36-«REDACTED:phone»-a1de-4b44fa4b4790"),
]


@pytest.mark.parametrize(("value", "stored"), BEFORE)
def test_the_mask_of_before_a78_is_the_one_main_wrote(value: str, stored: str) -> None:
    masks = identity_masks(value)
    assert masks[0] == redact_identity(value) != stored
    assert masks[-1] == stored


@pytest.mark.parametrize("value", ["mock-target", "tenant-0123456789abcdef0123456789abcdef"])
def test_an_id_whose_mask_did_not_change_has_one(value: str) -> None:
    assert identity_masks(value) == (redact_identity(value),)


def _store_as_main_did(db: Path, run_id: str, target_id: str) -> None:
    with SqliteRunStore(db) as store:
        store.save_run_context(run_id, target_id="placeholder")
        store._conn.execute(
            "UPDATE runs SET target_id = ? WHERE run_id = ?",
            (dict(BEFORE)[target_id], run_id),
        )
        store._conn.commit()


@pytest.mark.parametrize("target_id", [UUID, "prod-3f2a1b4c-5d6e-4f80-9a1b-2c3d4e5f6071"])
def test_a_run_stored_before_a78_resumes_against_its_own_target(
    tmp_path: Path, target_id: str
) -> None:
    db = tmp_path / "runs.sqlite"
    _store_as_main_did(db, "run-1", target_id)
    _assert_same_target(db, "run-1", Target(id=target_id, type=TargetType.MODEL))
    with pytest.raises(ValueError, match="was made against target"):
        _assert_same_target(db, "run-1", Target(id="another-target", type=TargetType.MODEL))


def test_a_resume_across_the_change_keeps_one_row_a_finding(tmp_path: Path) -> None:
    finding = make_finding(target_id=UUID, status=VerdictStatus.FAIL)
    assert isinstance(finding, Finding)
    db = tmp_path / "runs.sqlite"
    with SqliteRunStore(db) as store:
        run = TestRun(
            run_id="run-1",
            suite_ref="quick",
            started_at="2026-10-11T00:00:00Z",
            targets=[Target(id=UUID, type=TargetType.MODEL)],
            findings=[finding],
        )
        store.save_run(run)
        # The first half's row, under the key main gave it.
        old = dict(BEFORE)[finding_id_of(finding)]
        store._conn.execute("UPDATE findings SET finding_id = ? WHERE run_id = ?", (old, "run-1"))
        store._conn.commit()
        store.save_run(run)  # the resume writes the merged finding again
        rows = store.list_findings("run-1")
    assert [row["finding_id"] for row in rows] == [redact_identity(finding_id_of(finding))]


def test_a_declaration_recorded_before_a78_is_not_a_change() -> None:
    name = f"tool_{UUID}"
    target = Target(
        id="live",
        type=TargetType.AGENT,
        seeded_setup=SeededSetup(specs=["*"], granted_tools=[name], not_destructive=[name]),
    )
    stored = {"not_destructive_tools": [dict(BEFORE)[name]]}
    assert _declaration_changed(stored, target) is None
    assert _declaration_changed({"not_destructive_tools": ["other"]}, target) is not None
    # A file that now declares nothing differs from a run that declared a name, in either form.
    bare = Target(id="t1", type=TargetType.AGENT)
    assert _declaration_changed(stored, bare) is not None


def test_the_run_row_lists_its_targets_with_the_identity_mask(tmp_path: Path) -> None:
    # R2-L6: `meta_json.target_ids` took the store's per-process salt, so a UUID-named target
    # had another mask in every run; it now reads as the `target_id` column does.
    import json
    import sqlite3
    from contextlib import closing

    from ildottore.redactor import Redactor

    run = TestRun(run_id="run-1", targets=[Target(id=f"tenant-{UUID}", type=TargetType.AGENT)])
    rows = []
    for salt in ("one", "two"):
        db = tmp_path / f"{salt}.sqlite"
        with SqliteRunStore(db, redactor=Redactor(salt=salt)) as store:
            store.save_run(run)
        with closing(sqlite3.connect(db)) as conn:
            rows.append(conn.execute("SELECT target_id, meta_json FROM runs").fetchone())
    assert rows[0] == rows[1]
    target_id, meta = rows[0]
    assert json.loads(meta)["target_ids"] == [target_id] == [redact_identity(f"tenant-{UUID}")]
