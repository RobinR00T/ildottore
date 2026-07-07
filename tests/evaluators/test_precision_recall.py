"""Labeled precision/recall gate for the evaluators (docs/07 §3-§4, contract §7).

Each evaluator ships a labeled corpus under ``tests/fixtures/labeled/``. This test runs the
evaluator over every case, maps the resulting verdict to a binary "positive detection", and
asserts precision >= 0.90 and recall >= 0.85 against the labels. Corpora deliberately include
**hallucinated-but-valid negatives** (checksum-valid PII / credential-shaped lookalikes) to gate
the false-positive rate specifically (docs/11 §4).

Label → binary mapping (per corpus ``positive_class``):
* ``refusal``: positive = the model refused (verdict ``pass``). A ``pass`` is a positive
  detection of a refusal; ``fail`` is a negative (compliance).
* data-leak (``pii_detector``/``secret_shape``): positive = a PII/secret was *detected*
  (verdict ``fail`` for corroborated, or ``inconclusive``/needs-review for uncorroborated).
  ``pass`` (clean) is a negative — so a hallucinated-but-valid lookalike labelled ``pass`` that
  the evaluator flags counts as a false positive.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.evaluators.pii_detector import PIIDetectorEvaluator
from ildottore.evaluators.refusal import RefusalEvaluator
from ildottore.evaluators.secret_shape import SecretShapeEvaluator
from ildottore.shared.enums import EvaluatorType, VerdictStatus
from ildottore.shared.models import EvaluatorConfig, Verdict
from ildottore.shared.protocols import Evaluator
from tests.evaluators.conftest import make_ctx

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "labeled"

_PRECISION_GATE = 0.90
_RECALL_GATE = 0.85


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


def _predict_positive(verdict: Verdict, positive_class: str) -> bool:
    """Map a verdict to a binary positive detection for the corpus's positive class."""
    if positive_class == "leak":
        # A detection is anything that is not a clean 'pass'.
        return verdict.status is not VerdictStatus.PASS
    # 'refusal' positive class: a refusal is a 'pass' verdict.
    return verdict.status is VerdictStatus.PASS


def _label_positive(expect: str, positive_class: str) -> bool:
    """Map a case label to the binary positive class."""
    if positive_class == "leak":
        return expect in {"fail", "needs_review", "inconclusive"}
    return expect == "pass"


async def _run_corpus(
    evaluator: Evaluator, corpus: dict, evaluator_type: EvaluatorType
) -> tuple[float, float]:
    """Run every case; return (precision, recall) over the corpus positive class."""
    positive_class = corpus["positive_class"]
    tp = fp = fn = 0
    for case in corpus["cases"]:
        cfg = EvaluatorConfig(type=evaluator_type)
        ctx = make_ctx(
            response_text=case["response"],
            tool_calls=case.get("tool_calls"),
            config=cfg,
            canaries=case.get("canaries"),
        )
        verdict = await evaluator.evaluate(ctx)
        predicted = _predict_positive(verdict, positive_class)
        actual = _label_positive(case["expect"], positive_class)
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    return precision, recall


@pytest.mark.parametrize(
    ("corpus_file", "evaluator", "evaluator_type"),
    [
        ("refusal.json", RefusalEvaluator(), EvaluatorType.REFUSAL),
        ("pii_detector.json", PIIDetectorEvaluator(), EvaluatorType.PII_DETECTOR),
        ("secret_shape.json", SecretShapeEvaluator(), EvaluatorType.SECRET_SHAPE),
    ],
)
async def test_precision_recall_gate(
    corpus_file: str, evaluator: Evaluator, evaluator_type: EvaluatorType
) -> None:
    corpus = _load(corpus_file)
    precision, recall = await _run_corpus(evaluator, corpus, evaluator_type)
    assert precision >= _PRECISION_GATE, (
        f"{corpus_file}: precision {precision:.3f} < {_PRECISION_GATE}"
    )
    assert recall >= _RECALL_GATE, f"{corpus_file}: recall {recall:.3f} < {_RECALL_GATE}"
