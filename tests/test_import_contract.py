"""Smoke test for the package-boundary contract (validation-plan layer 14).

Asserts that ``lint-imports`` runs against the standalone ``.importlinter`` file and keeps
every contract. This is the in-suite mirror of the CI import-boundary gate: if the layering
in ``docs/01 §2`` is ever violated, this fails locally before it reaches CI.

Owned by ``u14-self-validation-ci``.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _lint_imports_cmd() -> list[str]:
    """Prefer the installed console script; fall back to ``python -m importlinter``."""

    script = Path(sys.executable).parent / "lint-imports"
    if script.exists():
        return [str(script)]
    if shutil.which("lint-imports"):
        return ["lint-imports"]
    return [sys.executable, "-m", "importlinter"]


def test_importlinter_config_present() -> None:
    """The standalone ``.importlinter`` exists and there is no duplicate pyproject block."""

    assert (_REPO_ROOT / ".importlinter").is_file()
    pyproject = (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section_lines = [
        line for line in pyproject.splitlines() if line.strip().startswith("[tool.importlinter")
    ]
    assert not section_lines, (
        "importlinter config is double-defined: it must live only in .importlinter"
    )


def test_import_contract_holds() -> None:
    """``lint-imports`` exits 0 — all layering contracts KEPT."""

    result = subprocess.run(  # noqa: S603 — fixed argv, no shell, repo-local binary
        _lint_imports_cmd(),
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 0, f"import-linter reported a broken contract:\n{combined}"
    assert "broken" not in combined.lower() or "0 broken" in combined.lower()
