"""Print a pip constraints file that holds every direct dependency at its declared floor.

The ``floors`` job of ``.github/workflows/ci.yml`` installs Il Dottore with it
(``pip install -c floors.txt -e ".[dev]"``) and runs the test suite, so a lower bound in
``pyproject.toml`` that no longer works fails CI instead of an operator's install (u12 A-84). The
direct dependencies (``[project] dependencies`` and the ``dev`` extra) are pinned to the version
after their ``>=``; what they pull in resolves as usual, to the newest release each allows (pip
has no lowest-resolution mode, and the floors of those are theirs to declare, not ours).

A runtime dependency must declare a floor: one without, or a specifier this script does not
read (an upper bound, ``~=``, ``==``, an environment marker), stops it, exit 1, so a new kind of
requirement is looked at instead of silently left unconstrained. A ``dev`` dependency without a
floor (the type stubs) is left to resolve, and said so in a comment line.

usage: python scripts/dependency_floors.py [pyproject.toml] > floors.txt
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

#: ``name`` or ``name>=floor``, nothing else: a name, an optional extra, an optional lower bound.
_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\[[A-Za-z0-9._,-]+\])?"
    r"(?:>=(?P<floor>[0-9][0-9A-Za-z.]*))?$"
)


class FloorError(ValueError):
    """A requirement this script cannot pin to a floor."""


def floors(pyproject: str) -> list[str]:
    """The constraints lines for ``pyproject``'s text: ``name==floor``, or a ``#`` comment."""

    project = tomllib.loads(pyproject)["project"]
    groups = [("runtime", project.get("dependencies", []))]
    groups.append(("dev", project.get("optional-dependencies", {}).get("dev", [])))
    lines: list[str] = []
    for group, requirements in groups:
        for requirement in requirements:
            text = requirement.replace(" ", "")
            match = _REQUIREMENT.fullmatch(text)
            if match is None:
                raise FloorError(f"{group} dependency {requirement!r}: not `name` or `name>=X`")
            floor = match.group("floor")
            if floor is None:
                if group == "runtime":
                    raise FloorError(f"runtime dependency {requirement!r} declares no floor")
                lines.append(f"# {match.group('name')}: no floor declared, left to resolve")
                continue
            lines.append(f"{match.group('name')}=={floor}")
    return lines


def main(argv: list[str]) -> int:
    default = Path(__file__).resolve().parents[1] / "pyproject.toml"
    path = Path(argv[1]) if len(argv) > 1 else default
    try:
        lines = floors(path.read_text(encoding="utf-8"))
    except FloorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
