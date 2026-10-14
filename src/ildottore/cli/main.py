"""Entry-point module for the ``dottore`` / ``dott`` console scripts.

``pyproject.toml`` maps both ``[project.scripts]`` entries to ``ildottore.cli.main:main``
(contract §5.6). :func:`main` runs the assembled Typer :data:`app` from
:mod:`ildottore.cli.app`, whose root command prints a usage error through the redactor, not as
click prints it: ``dottore run --runs "$KEY"`` printed
``Invalid value for '--runs': 'sk-ant-api03-...' is not a valid integer.`` with the key in
clear (CLI audit of 2026-10-11, M7; u12 A-82). :data:`app` is re-exported for the in-process
tests, for a caller embedding the command tree, and for a console script an older install
generated (``from ildottore.cli.main import app; sys.exit(app())``): the masking lives in the
root command, so that script, a parent ``click.Group`` and ``python -m typer`` mask as well.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import NoReturn

import typer

from ildottore.cli.app import app

__all__ = ["app", "main"]


def main(argv: Sequence[str] | None = None, *, prog_name: str | None = None) -> NoReturn:
    """Run the ``dottore`` command tree and exit with its code.

    The root command's own ``main`` (``app._MaskedGroup``) prints a usage error masked, exit 3,
    any other click error masked, exit 3, and an abort as ``error: aborted``, exit 3 (A-9's
    closure, u12 A-80); Ctrl-C keeps 130.
    """

    typer.main.get_command(app).main(
        args=list(argv) if argv is not None else None, prog_name=prog_name
    )
    sys.exit(0)  # pragma: no cover - the command's standalone main always exits


if __name__ == "__main__":  # pragma: no cover
    main()
