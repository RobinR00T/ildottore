"""Measure the ``refusal`` evaluator on the adjudicated corpus (u06 A-124, docs/07 §3).

The labelled precision/recall gate (``test_precision_recall.py``) scores the evaluator on 20
canonical phrasings, where it is perfect. This module scores it on replies written the way
deployed models answer (``tests/fixtures/labeled/refusal_adjudicated.json``) and reports what a
precision/recall pair hides for a three-way verdict:

* **false pass**: a compliance read as a refusal, the error that calls an exploited target
  secure. It must stay at zero.
* **false fail**: a refusal read as a compliance, a false alarm.
* **abstention**: ``inconclusive``, which a run reports as not exercised for that attempt; the
  share of refusals and of compliances the evaluator decides is its coverage.
* **ECE** (expected calibration error) over the decided cases: the gap, bin by bin, between the
  confidence the evaluator states and how often it is right (docs/04 §1 states 0.7-0.95).

Run ``python -m tests.evaluators.refusal_measure`` for the table by category; the test module
``test_refusal_measure.py`` holds the gates. Pure functions over the corpus: no I/O beyond
reading the fixture, no model, no network.
"""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ildottore.evaluators.refusal import RefusalEvaluator
from ildottore.shared.enums import EvaluatorType, VerdictStatus
from ildottore.shared.models import EvaluatorConfig
from tests.evaluators.conftest import make_ctx

__all__ = [
    "CORPUS",
    "Outcome",
    "RefusalMeasurement",
    "expected_calibration_error",
    "measure",
    "render",
]

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "labeled" / "refusal_adjudicated.json"

#: Ten equal-width confidence bins over [0, 1], the usual reading of ECE.
_BINS = 10


@dataclass(frozen=True)
class Outcome:
    """One case: its label, the evaluator's verdict and the confidence it stated."""

    case_id: str
    category: str
    expect: VerdictStatus
    got: VerdictStatus
    confidence: float

    @property
    def decided(self) -> bool:
        return self.got is not VerdictStatus.INCONCLUSIVE

    @property
    def correct(self) -> bool:
        return self.got is self.expect


@dataclass(frozen=True)
class RefusalMeasurement:
    """Counts over the corpus; refusals are labelled ``pass``, compliances ``fail``."""

    outcomes: list[Outcome] = field(default_factory=list)

    def _count(self, expect: VerdictStatus, got: VerdictStatus) -> int:
        return sum(1 for o in self.outcomes if o.expect is expect and o.got is got)

    @property
    def refusals(self) -> int:
        return sum(1 for o in self.outcomes if o.expect is VerdictStatus.PASS)

    @property
    def compliances(self) -> int:
        return sum(1 for o in self.outcomes if o.expect is VerdictStatus.FAIL)

    @property
    def refusals_detected(self) -> int:
        return self._count(VerdictStatus.PASS, VerdictStatus.PASS)

    @property
    def compliances_detected(self) -> int:
        return self._count(VerdictStatus.FAIL, VerdictStatus.FAIL)

    @property
    def false_pass(self) -> int:
        """Compliances scored ``pass``: an exploited target called secure."""

        return self._count(VerdictStatus.FAIL, VerdictStatus.PASS)

    @property
    def false_fail(self) -> int:
        """Refusals scored ``fail``: a false alarm."""

        return self._count(VerdictStatus.PASS, VerdictStatus.FAIL)

    @property
    def abstained(self) -> int:
        return sum(1 for o in self.outcomes if not o.decided)

    @property
    def ece(self) -> float | None:
        """ECE over the decided cases, ``None`` when none was decided."""

        decided = [o for o in self.outcomes if o.decided]
        return expected_calibration_error([(o.confidence, o.correct) for o in decided])


def expected_calibration_error(pairs: list[tuple[float, bool]]) -> float | None:
    """Weighted mean gap between stated confidence and observed accuracy, per bin.

    ``pairs`` are ``(confidence, correct)``. A confidence of exactly 1.0 falls in the last bin.
    ``None`` for no pairs: an empty measurement is not perfectly calibrated.
    """

    if not pairs:
        return None
    bins: dict[int, list[tuple[float, bool]]] = defaultdict(list)
    for confidence, correct in pairs:
        bins[min(int(confidence * _BINS), _BINS - 1)].append((confidence, correct))
    total = len(pairs)
    gap = 0.0
    for members in bins.values():
        mean_conf = sum(c for c, _ in members) / len(members)
        accuracy = sum(1 for _, ok in members if ok) / len(members)
        gap += len(members) / total * abs(accuracy - mean_conf)
    return gap


def _load(path: Path) -> list[dict[str, str]]:
    corpus = json.loads(path.read_text(encoding="utf-8"))
    cases: list[dict[str, str]] = corpus["cases"]
    return cases


async def measure(path: Path = CORPUS) -> RefusalMeasurement:
    """Run the evaluator over every case of the corpus."""

    evaluator = RefusalEvaluator()
    config = EvaluatorConfig(type=EvaluatorType.REFUSAL)
    outcomes: list[Outcome] = []
    for case in _load(path):
        verdict = await evaluator.evaluate(make_ctx(response_text=case["response"], config=config))
        outcomes.append(
            Outcome(
                case_id=case["id"],
                category=case["category"],
                expect=VerdictStatus(case["expect"]),
                got=verdict.status,
                confidence=verdict.confidence,
            )
        )
    return RefusalMeasurement(outcomes=outcomes)


def render(m: RefusalMeasurement) -> str:
    """The measurement as text: totals, then one line per category."""

    ece = "n/a" if m.ece is None else f"{m.ece:.3f}"
    lines = [
        f"refusal evaluator on {len(m.outcomes)} adjudicated replies "
        f"({m.refusals} refusals, {m.compliances} compliances)",
        f"  refusals detected     {m.refusals_detected}/{m.refusals}",
        f"  compliances detected  {m.compliances_detected}/{m.compliances}",
        f"  false pass            {m.false_pass}  (compliance read as a refusal)",
        f"  false fail            {m.false_fail}  (refusal read as a compliance)",
        f"  abstained             {m.abstained}/{len(m.outcomes)}  (inconclusive)",
        f"  ECE (decided cases)   {ece}",
        "  by category (pass / fail / inconclusive of n):",
    ]
    by_cat: dict[str, list[Outcome]] = defaultdict(list)
    for o in m.outcomes:
        by_cat[o.category].append(o)
    for category, items in by_cat.items():
        counts = {s: sum(1 for o in items if o.got is s) for s in VerdictStatus}
        lines.append(
            f"    {category:<28} expect {items[0].expect.value:<5} "
            f"{counts[VerdictStatus.PASS]} / {counts[VerdictStatus.FAIL]} / "
            f"{counts[VerdictStatus.INCONCLUSIVE]} of {len(items)}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(render(asyncio.run(measure())))
