"""ATT&CK Navigator layer reporter (``dottore run -oN``).

A fifth output beside JSON, HTML, SARIF and JUnit, and the one a security team opens in a tool
it already has: the :mod:`ildottore.reporting.navigator` run layer, coloured by this run's
verdicts. It goes through the same base as every reporter (masked once, summarised once), and
reads from the masked run and findings only; the layer's text is spec ids, spec names,
technique ids, run id and target ids, never a reply.

It is **not** part of ``-oA``: a Navigator layer is a companion to a report, not a report (it
holds no finding, no evidence and no verdict detail), and the four-file contract of ``-oA``
is what CI pipelines and the e2e test pin.
"""

from __future__ import annotations

import json

from ildottore.redactor import log_safe_json
from ildottore.reporting.base import BaseReporter, register_reporter
from ildottore.reporting.masking import MaskingContext
from ildottore.reporting.navigator import fold_states, run_layer
from ildottore.reporting.summary import RunSummary, finding_exercised
from ildottore.shared.enums import ReportFormat

__all__ = ["NavigatorReporter"]


class NavigatorReporter(BaseReporter):
    """Serializes the run layer to deterministic JSON bytes."""

    format = ReportFormat.NAVIGATOR.value

    def _render(self, ctx: MaskingContext, summary: RunSummary) -> bytes:
        # Per finding, as the coverage figure is built: a spec blocked on one target and
        # scored on another is exercised; several findings per spec (one per target) fold to
        # the worst state, so the colour does not depend on the order the findings arrived in.
        state_of = fold_states(
            (f.spec_id, f.status.value)
            for f in ctx.findings
            if f.spec_id in self._specs and finding_exercised(f)
        )
        layer = run_layer(
            self._specs.values(),
            state_of,
            run_id=ctx.run.run_id,
            started_at=ctx.run.started_at or "<unknown>",
            targets=(t.id for t in ctx.run.targets),
        )
        text = json.dumps(layer, indent=2, ensure_ascii=True, sort_keys=True)
        return (log_safe_json(text) + "\n").encode("utf-8")


register_reporter(ReportFormat.NAVIGATOR, NavigatorReporter)
