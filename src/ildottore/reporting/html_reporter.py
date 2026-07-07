"""HTML reporter (contract u11 §5 step 6, §4 KEEP, §7; OD-12).

Renders the human view with Jinja2, **autoescape ON** (``select_autoescape`` for ``.html``/
``.j2``), so a payload containing ``<script>`` in a finding's reasoning is escaped, not
executed. ``--unsafe-render`` (raw HTML passed through in reasoning/evidence) is **OFF by
default** and is a hard-gated explicit opt-in: enabling it flips a template flag *and* renders
a prominent warning banner (OD-12 — "present, hard-gated + banner"). It is never a template
default and never silently on.

Evidence is surfaced as **masked excerpt inline + store ref** (OD-12 resolution): the excerpt
is taken from the already-masked context (the redactor ran in the base pre-pass, so no raw
secret reaches the template) and the ``EvidenceRef`` uri/sha is shown alongside. Rendering is
pure/deterministic — no clock, no I/O beyond loading the packaged template (contract §2, §8).
"""

from __future__ import annotations

from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from ildottore.reporting.base import BaseReporter, register_reporter
from ildottore.reporting.json_reporter import summary_to_wire
from ildottore.reporting.masking import MaskingContext, Redactor
from ildottore.reporting.summary import RunSummary
from ildottore.shared.enums import ReportFormat, VerdictStatus
from ildottore.shared.models import AttackSpec, Finding

__all__ = ["EVIDENCE_EXCERPT_LEN", "UNSAFE_RENDER_BANNER", "HtmlReporter"]

EVIDENCE_EXCERPT_LEN = 240
UNSAFE_RENDER_BANNER = (
    "UNSAFE RENDER ENABLED — raw model output is emitted without HTML escaping. "
    "Open this report only in a trusted, sandboxed viewer."
)


def _environment() -> Environment:
    """Jinja2 environment with autoescape forced on for HTML templates."""

    return Environment(
        loader=PackageLoader("ildottore.reporting", "templates"),
        autoescape=select_autoescape(
            enabled_extensions=("html", "j2", "html.j2"),
            default_for_string=True,
            default=True,
        ),
        trim_blocks=True,
        lstrip_blocks=True,
        auto_reload=False,
    )


def _excerpt(text: str | None) -> str | None:
    """Truncate an already-masked reasoning/excerpt string for inline display."""

    if text is None:
        return None
    if len(text) <= EVIDENCE_EXCERPT_LEN:
        return text
    return text[:EVIDENCE_EXCERPT_LEN].rstrip() + "…"


class HtmlReporter(BaseReporter):
    """Serializes the masked run/findings + summary to a standalone HTML page."""

    format = ReportFormat.HTML.value

    def __init__(
        self,
        *,
        specs: dict[str, AttackSpec] | None = None,
        redactor: Redactor | None = None,
        unsafe_render: bool = False,
    ) -> None:
        super().__init__(specs=specs, redactor=redactor)
        self._unsafe_render = unsafe_render

    def _finding_view(self, finding: Finding) -> dict[str, Any]:
        spec = self._specs.get(finding.spec_id)
        evidence = [
            {"uri": ref.uri, "sha256": ref.sha256, "attempt_id": ref.attempt_id}
            for ref in finding.evidence
        ]
        return {
            "spec_id": finding.spec_id,
            "target_id": finding.target_id,
            "status": finding.status.value,
            "is_fail": finding.status is VerdictStatus.FAIL,
            "band": finding.risk.band.value,
            "risk": finding.risk.risk,
            "impact": finding.risk.impact,
            "exploitability": finding.risk.exploitability,
            "reproducibility": finding.risk.reproducibility,
            "confidence": finding.risk.confidence,
            "confirmed": finding.confirmed,
            "state": "confirmed" if finding.confirmed else "needs_review",
            "reasoning": _excerpt(finding.reasoning),
            "name": spec.name if spec is not None else None,
            "owasp": spec.owasp if spec is not None else "unknown",
            "atlas": spec.mitre_atlas.tactic if spec is not None else "unknown",
            "nist": spec.nist_ai_rmf if spec is not None else "unknown",
            "evidence": evidence,
        }

    def _render(self, ctx: MaskingContext, summary: RunSummary) -> bytes:
        env = _environment()
        template = env.get_template("report.html.j2")
        findings_view = [self._finding_view(f) for f in ctx.findings]
        # Confirmed vs needs-review surfaced separately (docs/05 §2).
        confirmed = [f for f in findings_view if f["confirmed"]]
        needs_review = [f for f in findings_view if not f["confirmed"]]
        html = template.render(
            run_id=ctx.run.run_id,
            suite_ref=ctx.run.suite_ref,
            started_at=ctx.run.started_at,
            finished_at=ctx.run.finished_at,
            targets=[{"id": t.id, "type": t.type.value, "name": t.name} for t in ctx.run.targets],
            summary=summary_to_wire(summary),
            has_comparison=summary.model_comparison is not None,
            comparison=summary.model_comparison,
            confirmed=confirmed,
            needs_review=needs_review,
            unsafe_render=self._unsafe_render,
            unsafe_banner=UNSAFE_RENDER_BANNER,
        )
        return html.encode("utf-8")


register_reporter(ReportFormat.HTML, HtmlReporter)
