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


#: The paths of the repository's layout before u12 A-84, relative to a checkout's root, where
#: each is now and what moved it, so a refusal of an old one can name the new one: the built-in
#: battery moved into the package and the three example files to ``examples/``. ``specs/`` itself
#: keeps the unit contracts, so it is matched only as the directory a spec path names.
_BATTERY_MOVED: Final = "the built-in battery moved into the package"
_EXAMPLE_MOVED: Final = "the example files moved from specs/ to examples/"
MOVED: Final[tuple[tuple[tuple[str, ...], tuple[str, ...], str], ...]] = (
    (("specs", "attacks"), ("src", "ildottore", "battery", "attacks"), _BATTERY_MOVED),
    (("specs", "suites"), ("src", "ildottore", "battery", "suites"), _BATTERY_MOVED),
    (("specs", "pack.yaml"), ("src", "ildottore", "battery", "pack.yaml"), _BATTERY_MOVED),
    (
        ("specs", "targets", "example-openai.yaml"),
        ("examples", "target.example-openai.yaml"),
        _EXAMPLE_MOVED,
    ),
    (("specs", "scope.example.yaml"), ("examples", "scope.example.yaml"), _EXAMPLE_MOVED),
    (("specs", "fleet.example.yaml"), ("examples", "fleet.example.yaml"), _EXAMPLE_MOVED),
    (
        ("schemas", "attack-spec.schema.json"),
        ("src", "ildottore", "registry", "schemas", "attack-spec.schema.json"),
        "the attack-spec schema moved into the package",
    ),
    (("specs",), ("src", "ildottore", "battery"), _BATTERY_MOVED),
)


def _moved(path: str | Path) -> tuple[Path, str] | None:
    """Where ``path`` is now and what moved it, when it names a path of the layout before A-84.

    Only when the new path exists beside it, in the same checkout: a ``specs/attacks`` of a tree
    that is not an Il Dottore checkout is not said to have moved. The last match in the path
    wins (``a/specs/b/specs/attacks`` is read at its second ``specs``).
    """

    parts = Path(path).parts
    for old, new, why in MOVED:
        width = len(old)
        for start in range(len(parts) - width, -1, -1):
            if parts[start : start + width] != old:
                continue
            if old == ("specs",) and start + width != len(parts):
                continue
            candidate = Path(*parts[:start], *new, *parts[start + width :])
            try:
                if candidate.exists():
                    return candidate, why
            except (OSError, ValueError):  # a name too long to look up, or a NUL in it
                return None
            break
    return None


def moved_to(path: str | Path) -> Path | None:
    """Where ``path`` is now, when it names a path of the layout before A-84 that moved."""

    found = _moved(path)
    return None if found is None else found[0]


def moved_note(path: str | Path) -> str:
    """``"; it is now <new> (<what moved it>)"`` for a path :func:`moved_to` places, else ``""``;
    for ``specs/`` itself, which is still there, the battery it held is named instead."""

    found = _moved(path)
    if found is None:
        return ""
    new, why = found
    if Path(path).name == "specs":
        return f"; the built-in battery it held moved into the package: it is now {new}"
    return f"; it is now {new} ({why})"
