"""SARIF 2.1.0 reporter (contract u11 §5 step 4, §6, §7; ``docs/05 §3``).

Emits a SARIF 2.1.0 log — the CI / security-tool interchange format. One ``run`` per report;
one ``reportingDescriptor`` (rule) per distinct spec, tagged with its OWASP LLM / MITRE ATLAS
/ NIST framework ids; one ``result`` per finding. ``ruleId`` is the spec id; ``level`` is
mapped from the risk **band** (critical/high → ``error``, medium → ``warning``,
low/info → ``note``). Result ``properties`` carry ``{band, risk_score, reproducibility,
confidence, state}`` so downstream tools keep the two-axis model (``docs/05``).

Every generated document validates against the vendored SARIF 2.1.0 JSON Schema
(``schemas/sarif-2.1.0.schema.json``) — the contract's SARIF-validity gate (§7). Output is
deterministic: rules and results follow the (sorted) finding order and ``json.dumps`` uses a
fixed separator/ASCII policy (contract §4 KEEP).
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any

import jsonschema

from ildottore.reporting.base import BaseReporter, register_reporter
from ildottore.reporting.masking import MaskingContext
from ildottore.reporting.summary import RunSummary
from ildottore.shared.enums import ReportFormat, ScanBand
from ildottore.shared.models import AttackSpec, Finding

__all__ = ["SARIF_SCHEMA_VERSION", "SarifReporter", "band_to_level", "load_sarif_schema"]

SARIF_SCHEMA_VERSION = "2.1.0"
_TOOL_NAME = "Il Dottore"
_TOOL_URI = "https://github.com/RobinR00T/ildottore"

# docs/05 §3: critical/high → error, medium → warning, low/info → note.
_BAND_LEVEL: dict[ScanBand, str] = {
    ScanBand.CRITICAL: "error",
    ScanBand.HIGH: "error",
    ScanBand.MEDIUM: "warning",
    ScanBand.LOW: "note",
    ScanBand.INFO: "note",
}


def band_to_level(band: ScanBand) -> str:
    """Map a severity band to a SARIF ``level`` (``docs/05 §3``)."""

    return _BAND_LEVEL[band]


@lru_cache(maxsize=1)
def load_sarif_schema() -> dict[str, Any]:
    """Load the vendored SARIF 2.1.0 JSON Schema (memoized)."""

    text = (
        resources.files("ildottore.reporting.schemas")
        .joinpath("sarif-2.1.0.schema.json")
        .read_text(encoding="utf-8")
    )
    schema: dict[str, Any] = json.loads(text)
    return schema


def _rule(spec_id: str, spec: AttackSpec | None) -> dict[str, Any]:
    """Build a ``reportingDescriptor`` for ``spec_id`` with framework tags."""

    tags: list[str] = []
    rule: dict[str, Any] = {"id": spec_id}
    if spec is not None:
        rule["name"] = spec.name
        rule["shortDescription"] = {"text": spec.description}
        tags = [
            f"owasp:{spec.owasp}",
            f"atlas:{spec.mitre_atlas.tactic}",
            f"nist:{spec.nist_ai_rmf}",
            f"category:{spec.category.value}",
        ]
        if spec.mitre_atlas.technique is not None:
            tags.append(f"atlas-technique:{spec.mitre_atlas.technique}")
    else:
        tags = ["owasp:unknown", "atlas:unknown", "nist:unknown"]
    rule["properties"] = {"tags": tags}
    return rule


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    """Build a SARIF ``result`` for one finding."""

    risk = finding.risk
    level = band_to_level(risk.band)
    state = "confirmed" if finding.confirmed else "needs_review"
    message = (
        f"{finding.spec_id} against {finding.target_id}: {finding.status.value} "
        f"(band={risk.band.value}, risk={risk.risk:g}, state={state})"
    )
    result: dict[str, Any] = {
        "ruleId": finding.spec_id,
        "ruleIndex": rule_index,
        "level": level,
        "kind": "fail" if finding.status.value == "fail" else "pass",
        "message": {"text": message},
        "locations": [
            {
                "logicalLocations": [
                    {"name": finding.target_id, "kind": "resource"},
                ],
            }
        ],
        "properties": {
            "band": risk.band.value,
            "risk_score": risk.risk,
            "impact": risk.impact,
            "exploitability": risk.exploitability,
            "reproducibility": risk.reproducibility,
            "confidence": risk.confidence,
            "state": state,
            "status": finding.status.value,
            "target_id": finding.target_id,
        },
    }
    return result


class SarifReporter(BaseReporter):
    """Serializes the masked findings to a schema-valid SARIF 2.1.0 log."""

    format = ReportFormat.SARIF.value

    def build_document(self, ctx: MaskingContext) -> dict[str, Any]:
        """Build (and validate) the SARIF document dict for ``ctx``."""

        rule_ids: list[str] = []
        rules: list[dict[str, Any]] = []
        rule_index: dict[str, int] = {}
        for finding in ctx.findings:
            if finding.spec_id not in rule_index:
                rule_index[finding.spec_id] = len(rules)
                rule_ids.append(finding.spec_id)
                rules.append(_rule(finding.spec_id, self._specs.get(finding.spec_id)))

        results = [_result(f, rule_index[f.spec_id]) for f in ctx.findings]

        document: dict[str, Any] = {
            "$schema": "https://ildottore.dev/schemas/sarif-2.1.0.schema.json",
            "version": SARIF_SCHEMA_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "informationUri": _TOOL_URI,
                            "organization": "Dani Solis",
                            "rules": rules,
                        }
                    },
                    "columnKind": "utf16CodeUnits",
                    "results": results,
                    "properties": {"run_id": ctx.run.run_id},
                }
            ],
        }
        jsonschema.validate(document, load_sarif_schema())
        return document

    def _render(self, ctx: MaskingContext, summary: RunSummary) -> bytes:
        document = self.build_document(ctx)
        text = json.dumps(
            document,
            sort_keys=True,
            ensure_ascii=True,
            indent=2,
            separators=(",", ": "),
        )
        return (text + "\n").encode("utf-8")


register_reporter(ReportFormat.SARIF, SarifReporter)
