"""Attack Spec Registry + linter (u02).

Loads, schema-validates and registers attack specs / suites / packs **without executing
any code or making any network call** (contract §2/§4, ``docs/06 §2/§5``), and drives
``dottore lint``. Downstream units (u08, u13) query :class:`Registry`.
"""

from __future__ import annotations

from .errors import LintCode, LintCounts, LintError, LintReport, Severity
from .fixtures_engine import DEFAULT_STUB_TABLE, EvalInput, StubEvaluator, evaluate_fixture
from .linter import lint, lint_packs
from .loader import LoadResult, load_path, load_paths
from .pack import FLAGGED_FAMILIES, LoadedPack
from .registry import Registry, SpecNotFoundError, SuiteNotFoundError
from .schema import SafeLoadError, safe_load_yaml, validate_attack_spec_schema

__all__ = [
    "DEFAULT_STUB_TABLE",
    "FLAGGED_FAMILIES",
    "EvalInput",
    "LintCode",
    "LintCounts",
    "LintError",
    "LintReport",
    "LoadResult",
    "LoadedPack",
    "Registry",
    "SafeLoadError",
    "Severity",
    "SpecNotFoundError",
    "StubEvaluator",
    "SuiteNotFoundError",
    "evaluate_fixture",
    "lint",
    "lint_packs",
    "load_path",
    "load_paths",
    "safe_load_yaml",
    "validate_attack_spec_schema",
]
