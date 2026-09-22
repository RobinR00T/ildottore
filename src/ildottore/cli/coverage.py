"""``dottore coverage`` - what the battery TESTS, answered without running anything.

The run report already says "this run exercised X of Y". This command answers the question
that comes *before* a run, and before a purchase: **what does this battery actually cover?**
It reads the spec registry and nothing else: no target, no credential, no request leaves the
process, so it is safe to run and to paste into a document.

Two design choices worth stating:

* **The gaps are printed, not just the percentages, and in three groups.** A coverage number
  with no list of what is missing invites the reader to assume the remainder is small. Naming
  the uncovered codes is the honest form; naming them in one list was not, because it read as
  one queue of pending work. What is *not covered yet* is the roadmap, what is *out of reach*
  is physics (no request settles it), and what is *not tested by design* is a decision this
  product made and could revisit. All three stay in the denominator (clause A-26).
* **Off-universe values never count**, and this command says how many it dropped. A
  Responsible-AI ``RAI0x`` code is not an OWASP LLM category and an IoPC code outside the
  pinned taxonomy is a lint error, so neither reaches a numerator. Percentages therefore
  cannot exceed 100%. Nothing here runs the linter, though (a third-party pack can be
  measured without ever being linted), so a dropped value is reported as a warning rather
  than left to shrink the numerator in silence.
* **Percentages are floored** (:func:`~ildottore.reporting.summary.pct_display`). This module
  formatted its own with ``%.0f`` until 2026-09-21, which meant it printed 96% for the same
  22/23 the run summary and the HTML report printed as 95%: one figure, published two
  different ways, by the command written to be the interrogable one.
"""

from __future__ import annotations

import json
from pathlib import Path

from ildottore.cli import wiring
from ildottore.reporting.summary import (
    AxisCoverage,
    BatteryCoverage,
    build_battery_coverage,
    pct_display,
)
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
            f"  {axis.label:<{width}}  {axis.exercised:>3}/{axis.total:<3} "
            f"{pct_display(axis.exercised, axis.total):>4}"
        )
    lines.extend(_off_universe_lines(coverage))
    if not show_gaps:
        return "\n".join(lines)

    for axis in axes:
        if axis.missing:
            lines.extend(["", f"  Not covered yet, {axis.label}:"])
            for code, title in axis.missing:
                lines.append(f"    {code}  {title}" if title != code else f"    {code}")
        for header, entries in (
            (f"  Out of reach for a black-box runtime scanner, {axis.label}:", axis.out_of_reach),
            (f"  Deliberately not tested, and why, {axis.label}:", axis.by_design),
        ):
            if not entries:
                continue
            lines.extend(["", header])
            for code, title, reason in entries:
                head = f"    {code}  {title}" if title != code else f"    {code}"
                lines.append(head)
                lines.append(f"      {reason}")
    if any(a.out_of_reach or a.by_design for a in axes):
        lines.extend(
            [
                "",
                "  Both lists stay in the denominator: removing them would raise every",
                "  percentage by redefining the universe as the part this tool can already do.",
            ]
        )
    return "\n".join(lines)


def _off_universe_lines(coverage: BatteryCoverage) -> list[str]:
    """A warning for every framework value that was dropped for being off-universe.

    Nothing in this path runs the linter (``build_registry`` only loads), so a third-party
    pack can be measured without ever being linted. Dropping a value silently is how a
    numerator shrinks without anyone being told, which is the whole failure this command was
    written against, so the drop is reported here even though the refusal lives in lint.
    """

    if not coverage.off_universe:
        return []
    lines = [
        "",
        f"  WARNING: {len(coverage.off_universe)} framework value(s) outside their pinned "
        "universe are NOT counted (run `dottore lint` to refuse them):",
    ]
    lines.extend(
        f"    {spec_id}  {field} = {value!r}" for spec_id, field, value in coverage.off_universe
    )
    return lines


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
        "off_universe": [
            {"spec_id": spec_id, "field": field, "value": value}
            for spec_id, field, value in coverage.off_universe
        ],
        "axes": [
            {
                "key": a.key,
                "label": a.label,
                "exercised": a.exercised,
                "total": a.total,
                "pct": a.pct,
                "covered": [{"code": c, "title": t} for c, t in a.covered],
                **(
                    {
                        "missing": [{"code": c, "title": t} for c, t in a.missing],
                        # Named, not merged into `missing`: a consumer that adds the two
                        # lists gets the old number back, one that reads them apart can say
                        # what is roadmap and what is not this tool's job.
                        "out_of_reach": [
                            {"code": c, "title": t, "reason": r} for c, t, r in a.out_of_reach
                        ],
                        "not_tested_by_design": [
                            {"code": c, "title": t, "reason": r} for c, t, r in a.by_design
                        ],
                    }
                    if show_gaps
                    else {}
                ),
            }
            for a in axes
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
