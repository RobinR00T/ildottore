"""The labels ledger: ``calibrate --record`` writes it, ``run --fp-ledger`` reads it (u08 A-105).

One JSON object per line, appended, never rewritten::

    {"run_id": "run-2942acf40f3b", "spec_id": "PI-DIRECT-001", "scanner": "fail",
     "operator": "pass", "recorded_at": "2026-10-27T19:40:00Z"}

The ledger is read whole and refused whole: a line that is not such an object stops the run
before anything is sent, since a breaker that skips what it cannot read holds less than the
operator labelled (a gate fails closed). It is read through the operator-file cap, 1 MiB, about
8,000 labels; a record that would take it past the cap is refused at ``calibrate --record``,
not discovered by the next run. Which specs it holds is :mod:`ildottore.shared.review_holds`.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from ildottore.cli.calibrate import CalibrationReport
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.files import MAX_FILE_BYTES, read_text_capped
from ildottore.shared.models import SPEC_ID_PATTERN, Finding
from ildottore.shared.review_holds import WINDOW, LabelRecord, ReviewHold, review_holds

__all__ = ["load_review_holds", "read_ledger", "record_labels"]

_SPEC_ID: Final = re.compile(SPEC_ID_PATTERN)
#: A run id as this tool mints it (``run-<hex>``), and any id of the same alphabet a report holds.
_RUN_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_KEYS: Final = frozenset({"run_id", "spec_id", "scanner", "operator", "recorded_at"})


def _record(path: Path, number: int, line: str) -> LabelRecord:
    where = f"labels ledger {path}, line {number}"
    try:
        raw: Any = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{where} is not JSON ({exc.msg}); the ledger is refused whole") from exc
    if not isinstance(raw, dict) or set(raw) != _KEYS:
        raise ValueError(
            f"{where} is not a label record (keys {', '.join(sorted(_KEYS))}); "
            "the ledger is refused whole"
        )
    run_id, spec_id = raw["run_id"], raw["spec_id"]
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError(f"{where}: run_id is not a run id; the ledger is refused whole")
    if not isinstance(spec_id, str) or not _SPEC_ID.fullmatch(spec_id):
        raise ValueError(f"{where}: spec_id is not a spec id; the ledger is refused whole")
    verdicts: list[VerdictStatus] = []
    for key in ("scanner", "operator"):
        value = raw[key]
        if not isinstance(value, str) or value not in {v.value for v in VerdictStatus}:
            raise ValueError(
                f"{where}: {key} is not one of {', '.join(v.value for v in VerdictStatus)}; "
                "the ledger is refused whole"
            )
        verdicts.append(VerdictStatus(value))
    return LabelRecord(run_id=run_id, spec_id=spec_id, scanner=verdicts[0], operator=verdicts[1])


def read_ledger(path: Path) -> list[LabelRecord]:
    """Every record of the ledger at ``path``, in file order; blank lines are skipped."""

    text = read_text_capped(path)
    return [
        _record(path, number, line)
        for number, line in enumerate(text.split("\n"), start=1)
        if line.strip()
    ]


def load_review_holds(path: Path) -> dict[str, ReviewHold]:
    """The specs the ledger at ``path`` holds for review."""

    return review_holds(read_ledger(path))


def record_labels(
    ledger: Path, run_id: object, findings: dict[str, Finding], result: CalibrationReport
) -> int:
    """Append one record per scored spec of a calibration to ``ledger``; return how many.

    ``run_id`` is the report's own (``run.run_id``): a report without one cannot be recorded,
    since a label the ledger cannot tie to a run would count again each time it was recorded.
    The ledger is created readable by its owner only (0600) and never through a symbolic link.
    """

    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError(
            "--record needs a report that names its run (run.run_id), as -oJ writes it; "
            "a bare list of findings cannot be recorded"
        )
    scored = sorted(set(findings) - set(result.only_in_report))
    disagree = {spec_id: want for spec_id, _got, want in result.disagreements}
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = "".join(
        json.dumps(
            {
                "run_id": run_id,
                "spec_id": spec_id,
                "scanner": findings[spec_id].status.value,
                # An agreement is labelled what the scanner said.
                "operator": disagree.get(spec_id, findings[spec_id].status).value,
                "recorded_at": stamp,
            },
            sort_keys=True,
        )
        + "\n"
        for spec_id in scored
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(ledger, flags, 0o600)
    try:
        size = os.fstat(fd).st_size
        if size + len(lines) > MAX_FILE_BYTES:
            raise ValueError(
                f"recording {len(scored)} label(s) would take the labels ledger {ledger} past "
                f"the {MAX_FILE_BYTES:,} bytes a run reads; start a new ledger (only the last "
                f"{WINDOW} labelled fails of a spec count)"
            )
        # Whole lines, appended: two recordings at once interleave by line, never mid-line.
        view = memoryview(lines)
        while view:
            view = view[os.write(fd, view) :]
    finally:
        os.close(fd)
    return len(scored)
