"""Canonical lossless JSON reporter (contract u11 §5 step 3, §6).

JSON is the **lossless canonical form**: the whole (masked) ``TestRun``, every ``Finding``
and the aggregated :class:`~ildottore.reporting.summary.RunSummary`, under a stable
``schema_version``. Output is byte-identical across two renders of the same ``(run, findings)``
- keys are sorted, ``ensure_ascii`` is fixed, and the trailing newline is deterministic
(contract §4 KEEP). The document validates against ``schemas/report-1.0.schema.json`` (§7).
"""

from __future__ import annotations

import json
from typing import Any

from ildottore.reporting.base import BaseReporter, register_reporter
from ildottore.reporting.masking import MaskingContext
from ildottore.reporting.summary import Coverage, ModelComparison, RunSummary
from ildottore.shared.enums import ReportFormat

__all__ = ["JsonReporter", "summary_to_wire"]

SCHEMA_VERSION = "1.0"


def _comparison_to_wire(comparison: ModelComparison) -> dict[str, Any]:
    return {
        "spec_ids": list(comparison.spec_ids),
        "target_ids": list(comparison.target_ids),
        "cells": [
            {
                "spec_id": cell.spec_id,
                "target_id": cell.target_id,
                "band": cell.band,
                "reproducibility": cell.reproducibility,
                "confidence": cell.confidence,
            }
            for cell in comparison.cells
        ],
        "category_rollups": comparison.category_rollups,
    }


def _coverage_to_wire(coverage: Coverage) -> dict[str, Any]:
    return {
        "owasp": {
            "categories": list(coverage.owasp_categories),
            "exercised": coverage.owasp_exercised,
            "total": coverage.owasp_total,
            "pct": coverage.owasp_pct,
        },
        "atlas": {
            "tactics": list(coverage.atlas_tactics),
            "exercised": coverage.atlas_exercised,
            "total": coverage.atlas_total,
            "pct": coverage.atlas_pct,
        },
        "specs": {
            "total": coverage.specs_total,
            "run": coverage.specs_run,
            "pass": coverage.specs_pass,
            "fail": coverage.specs_fail,
            "inconclusive": coverage.specs_inconclusive,
        },
    }


def summary_to_wire(summary: RunSummary) -> dict[str, Any]:
    """Serialize a :class:`RunSummary` to the JSON wire shape (contract §6)."""

    wire: dict[str, Any] = {
        "total": summary.total,
        "by_status": summary.by_status,
        "by_band": summary.by_band,
        "by_framework": {
            "owasp": summary.by_framework.owasp,
            "atlas": summary.by_framework.atlas,
            "nist": summary.by_framework.nist,
        },
        "repro_distribution": summary.repro_distribution,
        "confidence_distribution": summary.confidence_distribution,
        "confirmed_count": summary.confirmed_count,
        "needs_review_count": summary.needs_review_count,
        "coverage": _coverage_to_wire(summary.coverage),
    }
    if summary.model_comparison is not None:
        wire["model_comparison"] = _comparison_to_wire(summary.model_comparison)
    return wire


class JsonReporter(BaseReporter):
    """Serializes the masked run/findings + summary to canonical JSON bytes."""

    format = ReportFormat.JSON.value

    def _render(self, ctx: MaskingContext, summary: RunSummary) -> bytes:
        document = {
            "schema_version": SCHEMA_VERSION,
            "run": ctx.run.model_dump(mode="json"),
            "findings": [f.model_dump(mode="json") for f in ctx.findings],
            "summary": summary_to_wire(summary),
        }
        text = json.dumps(
            document,
            sort_keys=True,
            ensure_ascii=True,
            indent=2,
            separators=(",", ": "),
        )
        return (text + "\n").encode("utf-8")


register_reporter(ReportFormat.JSON, JsonReporter)
