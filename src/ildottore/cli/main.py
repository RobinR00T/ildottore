"""Entry-point module for the ``dottore`` / ``dott`` console scripts.

``pyproject.toml`` maps both ``[project.scripts]`` entries to
``ildottore.cli.main:app`` (contract §5.6). This module re-exports the assembled
Typer :data:`app` from :mod:`ildottore.cli.app` so the packaging entry point and the
in-process import path are one and the same object.
"""

from __future__ import annotations

from ildottore.cli.app import app

__all__ = ["app", "main"]


def main() -> None:
    """Invoke the Typer app (used by ``python -m ildottore.cli.main``)."""

    app()


if __name__ == "__main__":  # pragma: no cover
    main()
