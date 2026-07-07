"""``dottore describe <spec-id>`` — show one spec's detail (contract §5.5).

A thin delegator over the u02 registry: look a spec up by id and render its
human-readable card (id, name, category, OWASP/ATLAS/NIST mapping, severity, requires,
evaluators, mutations). No parsing/validation logic here.
"""

from __future__ import annotations

from pathlib import Path

from ildottore.cli import wiring
from ildottore.registry import SpecNotFoundError
from ildottore.shared.models import AttackSpec

__all__ = ["DescribeError", "describe_spec", "render_describe"]


class DescribeError(KeyError):
    """Raised when the requested spec id is not registered."""


def describe_spec(spec_paths: list[Path], spec_id: str) -> AttackSpec:
    """Return the spec with ``spec_id`` (raises :class:`DescribeError` if absent)."""

    registry = wiring.build_registry(spec_paths)
    try:
        return registry.get(spec_id)
    except SpecNotFoundError as exc:
        raise DescribeError(spec_id) from exc


def render_describe(spec: AttackSpec) -> str:
    """Render a human-readable card for one spec (no raw dangerous payloads)."""

    lines = [
        f"id:          {spec.id}",
        f"name:        {spec.name}",
        f"category:    {spec.category.value}",
        f"owasp:       {spec.owasp}",
        f"mitre_atlas: {spec.mitre_atlas.tactic}"
        + (f" / {spec.mitre_atlas.technique}" if spec.mitre_atlas.technique else ""),
        f"nist_ai_rmf: {spec.nist_ai_rmf}",
        f"severity:    {spec.severity.value}",
        f"target_type: {spec.target_type.value}",
        f"requires:    {', '.join(r.value for r in spec.requires) or '(none)'}",
        f"mutations:   {', '.join(spec.mutations or []) or '(identity)'}",
        f"evaluators:  {', '.join(e.type.value for e in spec.evaluators)}",
        f"description: {spec.description.strip()}",
    ]
    return "\n".join(lines)
