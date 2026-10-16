"""Where the package's own data files are: inside the package, found one way (u12 A-84).

The built-in battery (``battery/``: ``pack.yaml``, ``attacks/`` with their media assets,
``suites/``) and the hand-authored attack-spec schema (``registry/schemas/``) live under
``src/ildottore``, so a wheel carries them like every other file of the package and a source
checkout, an editable install and an installed wheel all find them at the same place relative to
the package, through ``importlib.resources``. Until A-84 they sat at the repository root
(``specs/``, ``schemas/``) and were found three directories above the package (``parents[3]``),
which is the repository root only in a checkout: an installed wheel could load neither (exit 3).
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Final

__all__ = ["ATTACK_SPEC_SCHEMA", "BATTERY", "MOVED", "moved_note", "moved_to", "package_path"]


def package_path(*parts: str) -> Path:
    """The path of ``parts`` under the installed ``ildottore`` package directory.

    The package is a regular package on the filesystem in every supported install, so the
    traversable ``importlib.resources`` returns is a ``Path``. Anything else (a zip import, which
    the judging digest refuses anyway) is turned into the path it names, which does not exist on
    disk, so the caller reports the file missing instead of reading half a package.
    """

    root = resources.files("ildottore")
    base = root if isinstance(root, Path) else Path(str(root))
    return base.joinpath(*parts)


#: The built-in battery: a spec pack (``pack.yaml``, ``attacks/``, ``suites/``) inside the package.
BATTERY: Final = package_path("battery")

#: The hand-authored JSON Schema every attack spec is validated against (ADR-0006).
ATTACK_SPEC_SCHEMA: Final = package_path("registry", "schemas", "attack-spec.schema.json")


#: The paths of the repository's layout before u12 A-84, relative to a checkout's root, and where
#: each is now, so a refusal of an old one can name the new one: the built-in battery moved into
#: the package and the three example files to ``examples/``. ``specs/`` itself keeps the unit
#: contracts, so it is matched only as the directory a spec path names.
MOVED: Final[tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]] = (
    (("specs", "attacks"), ("src", "ildottore", "battery", "attacks")),
    (("specs", "suites"), ("src", "ildottore", "battery", "suites")),
    (("specs", "pack.yaml"), ("src", "ildottore", "battery", "pack.yaml")),
    (("specs", "targets", "example-openai.yaml"), ("examples", "target.example-openai.yaml")),
    (("specs", "scope.example.yaml"), ("examples", "scope.example.yaml")),
    (("specs", "fleet.example.yaml"), ("examples", "fleet.example.yaml")),
    (
        ("schemas", "attack-spec.schema.json"),
        ("src", "ildottore", "registry", "schemas", "attack-spec.schema.json"),
    ),
    (("specs",), ("src", "ildottore", "battery")),
)


def moved_to(path: str | Path) -> Path | None:
    """Where ``path`` is now, when it names a path of the layout before A-84 that moved.

    Only when the new path exists beside it, in the same checkout: a ``specs/attacks`` of a tree
    that is not an Il Dottore checkout is not said to have moved. The last match in the path
    wins (``a/specs/b/specs/attacks`` is read at its second ``specs``).
    """

    parts = Path(path).parts
    for old, new in MOVED:
        width = len(old)
        for start in range(len(parts) - width, -1, -1):
            if parts[start : start + width] != old:
                continue
            if old == ("specs",) and start + width != len(parts):
                continue
            candidate = Path(*parts[:start], *new, *parts[start + width :])
            try:
                if candidate.exists():
                    return candidate
            except (OSError, ValueError):  # a name too long to look up, or a NUL in it
                return None
            break
    return None


def moved_note(path: str | Path) -> str:
    """``"; it is now <new> (CHANGELOG, Unreleased)"`` for a path :func:`moved_to` places, else
    ``""``; for ``specs/`` itself, which is still there, the battery it held is named."""

    new = moved_to(path)
    if new is None:
        return ""
    what = "the built-in battery it held is" if Path(path).name == "specs" else "it is"
    return f"; {what} now {new} (CHANGELOG, Unreleased)"
