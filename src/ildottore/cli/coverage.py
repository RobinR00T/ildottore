"""``dottore coverage`` - what the battery TESTS, answered without running anything.

The run report already says "this run exercised X of Y". This command answers the question
that comes *before* a run, and before a purchase: **what does this battery actually cover?**
It reads the spec registry and nothing else: no target, no credential, no request leaves the
process, so it is safe to run and to paste into a document.

Two design choices worth stating:

* **The gaps are printed, not just the percentages.** A coverage number with no list of what
  is missing invites the reader to assume the remainder is small or unimportant. Naming the
  uncovered codes is the honest form, and it is also the useful one: it is the roadmap.
* **Off-universe values never count.** A Responsible-AI ``RAI0x`` code is not an OWASP LLM
  category and an IoPC code outside the pinned taxonomy is a lint error, so neither reaches a
  numerator. Percentages therefore cannot exceed 100%.
"""

from __future__ import annotations

import json
from pathlib import Path

from ildottore.cli import wiring
from ildottore.reporting.summary import AxisCoverage, BatteryCoverage, build_battery_coverage
from ildottore.shared.models import AttackSpec

__all__ = ["battery_coverage", "render_coverage", "render_coverage_json"]

#: Axis keys accepted by ``--framework`` (``all`` keeps every axis).
FRAMEWORK_KEYS: tuple[str, ...] = ("all", "owasp", "atlas", "iopc")


def _selected(coverage: BatteryCoverage, framework: str) -> tuple[AxisCoverage, ...]:
    if framework == "all":
        return coverage.axes
    if framework == "iopc":
        return tuple(a for a in coverage.axes if a.key.startswith("iopc"))
    return tuple(a for a in coverage.axes if a.key == framework)


def battery_coverage(spec_paths: list[Path], *, suite: str | None = None) -> BatteryCoverage:
    """Load the registry (optionally narrowed to a suite) and compute static coverage.

    An unregistered ``--suite`` **raises**. It used to resolve to the empty spec set and
    report a confident 0% across every axis, which reads as "this battery covers nothing"
    rather than as "you typed a suite that does not exist": a wrong answer where a refusal
    belongs, and the same false-green shape as a run against an unscoped target.
    """

    registry = wiring.build_registry(spec_paths)
    specs: list[AttackSpec]
    if suite is not None:
        from ildottore.cli.flags import resolve_suite_id

        suite_id = resolve_suite_id(suite)
        if not registry.has_suite(suite_id):
            known = ", ".join(sorted(s.id for s in registry.suites())) or "<none>"
            raise ValueError(
                f"suite {suite!r} (resolved to {suite_id!r}) is not registered. "
                f"Registered suites: {known}"
            )
        specs = list(registry.resolve(suite_id))
    else:
        specs = list(registry.list())
    return build_battery_coverage(specs)


def render_coverage(
    coverage: BatteryCoverage, *, framework: str = "all", show_gaps: bool = True
) -> str:
    """Human-readable report: a percentage per axis, then what is NOT covered."""

    axes = _selected(coverage, framework)
    scope = f"{coverage.specs} spec{'s' if coverage.specs != 1 else ''}"
    lines = [f"Battery coverage ({scope}, no scan performed)", ""]
    width = max((len(a.label) for a in axes), default=0)
    for axis in axes:
        lines.append(
            f"  {axis.label:<{width}}  {axis.exercised:>3}/{axis.total:<3} {axis.pct * 100:>3.0f}%"
        )
    if not show_gaps:
        return "\n".join(lines)

    for axis in axes:
        if not axis.missing:
            continue
        lines.extend(["", f"  Not covered, {axis.label}:"])
        for code, title in axis.missing:
            lines.append(f"    {code}  {title}" if title != code else f"    {code}")
    return "\n".join(lines)


def render_coverage_json(
    coverage: BatteryCoverage, *, framework: str = "all", show_gaps: bool = True
) -> str:
    """Machine-readable form, for a dashboard or a report generator.

    ``show_gaps=False`` (``--no-gaps``) drops the ``missing`` list here too. It used to be
    honoured only by the human renderer, so the two output modes of one command disagreed
    about what the operator had asked for.
    """

    axes = _selected(coverage, framework)
    payload = {
        "specs": coverage.specs,
        "axes": [
            {
                "key": a.key,
                "label": a.label,
                "exercised": a.exercised,
                "total": a.total,
                "pct": a.pct,
                "covered": [{"code": c, "title": t} for c, t in a.covered],
                **(
                    {"missing": [{"code": c, "title": t} for c, t in a.missing]}
                    if show_gaps
                    else {}
                ),
            }
            for a in axes
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
