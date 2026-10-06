"""``dottore registry ls`` - list registered specs with optional filters (contract §5.5).

A thin delegator over the u02 :class:`~ildottore.registry.Registry`: load the spec
tree, apply ``--category``/``--owasp``/``--tag``/``--suite`` filters and format a
compact table. No spec parsing/validation logic lives here - that is u02.
"""

from __future__ import annotations

from pathlib import Path

from ildottore.cli import wiring
from ildottore.shared.models import AttackSpec

__all__ = ["list_specs", "list_specs_and_unloaded", "render_spec_rows", "unloaded_warning"]


def list_specs(
    spec_paths: list[Path],
    *,
    category: str | None = None,
    owasp: str | None = None,
    tag: str | None = None,
    suite: str | None = None,
) -> list[AttackSpec]:
    """Return the registered specs matching every provided filter.

    ``--suite`` narrows to a suite's spec set first, then the other filters apply
    (AND semantics, matching the registry's ``list``). An unknown suite yields an
    empty list rather than raising - ``registry ls`` is a read-only inspection.
    """

    return list_specs_and_unloaded(
        spec_paths, category=category, owasp=owasp, tag=tag, suite=suite
    )[0]


def list_specs_and_unloaded(
    spec_paths: list[Path],
    *,
    category: str | None = None,
    owasp: str | None = None,
    tag: str | None = None,
    suite: str | None = None,
) -> tuple[list[AttackSpec], int]:
    """:func:`list_specs`, plus how many load errors the spec paths gave.

    A file that does not load is in no listing, so ``registry ls`` printed `(no specs match)`
    for a spec that, say, repeats a key, and exited 0 (pre-merge audit of PR #45).
    """

    registry, errors = wiring.load_registry(spec_paths)
    # Errors, not files: a path is relative to its own root, so two roots collide, and a
    # missing path is not a file (delta audit of the #45 follow-ups).
    unloaded = len(errors)
    if suite is not None:
        from ildottore.cli.flags import resolve_suite_id

        suite_id = resolve_suite_id(suite)
        if not registry.has_suite(suite_id):
            return [], unloaded
        base = registry.resolve(suite_id)
        result = []
        for spec in base:
            if category is not None and spec.category.value != category:
                continue
            if owasp is not None and spec.owasp != owasp:
                continue
            if tag is not None and tag not in (spec.tags or []):
                continue
            result.append(spec)
        return result, unloaded
    return registry.list(category=category, owasp=owasp, tag=tag), unloaded


def unloaded_warning(count: int) -> str:
    """The note for load errors, whose specs, suites or packs are missing from the answer."""

    return (
        f"warning: the spec paths gave {count} load error(s); the specs, suites or packs they "
        "hit are left out (`dottore lint` lists them)"
    )


def render_spec_rows(specs: list[AttackSpec]) -> list[str]:
    """Format specs into aligned ``id  owasp  severity  category  name`` rows."""

    if not specs:
        return ["(no specs match)"]
    rows = [f"{s.id}\t{s.owasp}\t{s.severity.value}\t{s.category.value}\t{s.name}" for s in specs]
    return rows
