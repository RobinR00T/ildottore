"""The false-positive breaker: which specs the labels ledger holds for review (u08 A-105).

``dottore calibrate --record`` appends the operator's labels to a ledger, one JSON object per
line, each naming a run, a spec, what the scanner said and what the operator said. A spec whose
recent labelled fails were too often false alarms is held: ``run --fp-ledger`` reads the ledger
before anything is sent, and a fail of a held spec is reported and scored as before but never
confirmed, so it needs review and does not trip ``--fail-on`` (unless ``--include-needs-review``).

The rule, per spec: the last :data:`WINDOW` labelled records whose scanner verdict was ``fail``;
with at least :data:`MINIMUM` of them, the spec is held when more than :data:`RATE_PERCENT` per
cent were labelled anything but ``fail``. Fewer records hold nothing: one false alarm in one
labelled run is not a rate. A run and spec labelled twice counts once, at its latest label, so
an operator who corrects a label does not count the same decision twice.

Pure: records in, holds out. Reading and writing the file is the CLI's (``cli.calibrate``).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from ildottore.shared.enums import VerdictStatus

__all__ = [
    "MINIMUM",
    "RATE_PERCENT",
    "WINDOW",
    "LabelRecord",
    "ReviewHold",
    "review_holds",
]

#: The labelled fails of a spec the rate is read over: the most recent ones (OD-61).
WINDOW: Final = 50
#: The fewest labelled fails a rate is read from (OD-61).
MINIMUM: Final = 5
#: A spec is held when MORE than this share of its labelled fails were false alarms (OD-61).
RATE_PERCENT: Final = 30


@dataclass(frozen=True)
class LabelRecord:
    """One line of the ledger: the scanner's verdict on a spec in a run, and the operator's."""

    run_id: str
    spec_id: str
    scanner: VerdictStatus
    operator: VerdictStatus


@dataclass(frozen=True)
class ReviewHold:
    """Why a spec is held: how many of the labelled fails read were false alarms."""

    false_alarms: int
    labelled: int

    def describe(self) -> str:
        return (
            f"{self.false_alarms} of its last {self.labelled} labelled fails were false positives"
        )


def review_holds(records: Iterable[LabelRecord]) -> dict[str, ReviewHold]:
    """The specs to hold, each with its counts, from the ledger's records in file order."""

    latest: dict[tuple[str, str], LabelRecord] = {}
    for record in records:
        key = (record.run_id, record.spec_id)
        # A label recorded again moves to where it was recorded: it is the newest decision.
        latest.pop(key, None)
        latest[key] = record
    fails: dict[str, list[LabelRecord]] = {}
    for record in latest.values():
        if record.scanner is VerdictStatus.FAIL:
            fails.setdefault(record.spec_id, []).append(record)
    holds: dict[str, ReviewHold] = {}
    for spec_id, labelled in fails.items():
        recent = labelled[-WINDOW:]
        false_alarms = sum(1 for r in recent if r.operator is not VerdictStatus.FAIL)
        # In whole numbers: 30% of 10 is 3, and 3 of 10 is not more than it.
        if len(recent) >= MINIMUM and false_alarms * 100 > RATE_PERCENT * len(recent):
            holds[spec_id] = ReviewHold(false_alarms=false_alarms, labelled=len(recent))
    return dict(sorted(holds.items()))
