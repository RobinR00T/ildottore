"""``dottore registry ls`` - list registered specs with optional filters (contract §5.5).

A thin delegator over the u02 :class:`~ildottore.registry.Registry`: load the spec
tree, apply ``--category``/``--owasp``/``--tag``/``--suite`` filters and format a
compact table. No spec parsing/validation logic lives here - that is u02.
"""

from __future__ import annotations

from pathlib import Path

from ildottore.cli import wiring
from ildottore.redactor import visible_controls
from ildottore.registry import LintError
from ildottore.shared.models import AttackSpec

__all__ = ["list_specs", "list_specs_and_unloaded", "render_spec_rows", "unloaded_warnings"]


def list_specs(
    spec_paths: list[Path],
    *,
    category: str | None = None,
    owasp: str | None = None,
    tag: str | None = None,
    suite: str | None = None,
    default_spec_path: bool = False,
) -> list[AttackSpec]:
    """Return the registered specs matching every provided filter.

    ``--suite`` narrows to a suite's spec set first, then the other filters apply
    (AND semantics, matching the registry's ``list``). An unknown suite raises
    ``ValueError``, as ``run`` and ``coverage`` refuse it: an empty listing read as "this suite
    holds no spec" and exited 0 (u12 A-82, CLI audit L7).
    """

    return list_specs_and_unloaded(
        spec_paths,
        category=category,
        owasp=owasp,
        tag=tag,
        suite=suite,
        default_spec_path=default_spec_path,
    )[0]


def list_specs_and_unloaded(
    spec_paths: list[Path],
    *,
    category: str | None = None,
    owasp: str | None = None,
    tag: str | None = None,
    suite: str | None = None,
    default_spec_path: bool = False,
) -> tuple[list[AttackSpec], list[LintError]]:
    """:func:`list_specs`, plus the load errors the spec paths gave.

    A file that does not load is in no listing, so ``registry ls`` printed `(no specs match)`
    for a spec that, say, repeats a key, and exited 0 (pre-merge audit of PR #45).
    """

    registry, unloaded = wiring.load_registry(spec_paths)
    wiring.refuse_spec_paths_that_hold_nothing(unloaded, to="list", default=default_spec_path)
    if suite is not None:
        from ildottore.cli.flags import resolve_suite_id, unknown_suite

        suite_id = resolve_suite_id(suite)
        if not registry.has_suite(suite_id):
            raise ValueError(unknown_suite(suite, suite_id, [s.id for s in registry.suites()]))
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


def unloaded_warnings(errors: list[LintError]) -> list[str]:
    """The notes for load errors, whose specs, suites or packs are missing from the answer.

    Errors are counted, not files: a path is relative to its own root, so two roots collide
    (delta audit of the #45 follow-ups). A spec path that does not exist is named apart: it
    hit nothing, and running from a folder with no ``specs/`` read as a broken spec file
    (pre-merge audit of the #45 follow-ups).
    """

    prefix = "path not found: "
    # A path that does not exist or holds nothing is refused before this is reached (A-82);
    # `describe` still lists the notes of a spec it did not find.
    missing = [e.message.removeprefix(prefix) for e in errors if e.message.startswith(prefix)]
    failed = len(errors) - len(missing)
    notes = []
    if missing:
        notes.append(f"warning: spec path(s) not found: {visible_controls(', '.join(missing))}")
    if failed:
        notes.append(
            f"warning: the spec paths gave {failed} load error(s); the specs, suites or packs "
            "they hit are left out (`dottore lint` lists them)"
        )
    return notes


def render_spec_rows(specs: list[AttackSpec]) -> list[str]:
    """Format specs into aligned ``id  owasp  severity  category  name`` rows."""

    if not specs:
        return ["(no specs match)"]
    # The name is the pack author's, written out; the tabs between columns stay tabs.
    rows = [
        f"{s.id}\t{s.owasp}\t{s.severity.value}\t{s.category.value}\t{visible_controls(s.name)}"
        for s in specs
    ]
    return rows
