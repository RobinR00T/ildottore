"""Safe YAML load + JSON-Schema validation (contract §5.1, §4 KEEP).

The load path is strictly **parse → schema-validate → model-construct**. Parsing uses
``yaml.safe_load`` only: ``!!python/...`` tags and arbitrary object construction are
rejected by the safe loader, and no ``eval``/``import``/socket is ever touched here.

``schemas/attack-spec.schema.json`` is the hand-authored oracle for attack specs; the
``suite`` and ``pack`` schemas are Pydantic-first (ADR-0006 / OD-14) and generated from the
u00 models, so those are validated by constructing the model, not against a JSON file.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

# Repo layout: <root>/schemas/attack-spec.schema.json ; this file lives at
# <root>/src/ildottore/registry/schema.py → three parents up to the package src root,
# then two more to the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_ATTACK_SPEC_SCHEMA = _REPO_ROOT / "schemas" / "attack-spec.schema.json"


class SafeLoadError(Exception):
    """Raised when a document cannot be safely parsed (bad YAML / unsafe tag)."""


def safe_load_yaml(text: str) -> Any:
    """Parse a YAML document with the safe loader only.

    ``yaml.safe_load`` refuses ``!!python/object`` and other code-constructing tags,
    raising ``yaml.YAMLError``. We re-raise as :class:`SafeLoadError` so callers get one
    exception type. No code is executed and no import is triggered.
    """
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:  # includes ConstructorError for unsafe tags
        raise SafeLoadError(str(exc)) from exc


def load_yaml_file(path: Path) -> Any:
    """Read + safe-parse a YAML file from disk (no network, no code exec)."""
    return safe_load_yaml(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _attack_spec_validator() -> Draft202012Validator:
    """Compile the hand-authored attack-spec validator once."""
    schema = json.loads(_ATTACK_SPEC_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_attack_spec_schema(data: object) -> list[str]:
    """Validate a parsed spec dict against the JSON Schema.

    Returns a list of human-readable error messages (empty ⇒ schema-valid). Sorting by
    JSON path keeps the output deterministic for golden comparisons.
    """
    validator = _attack_spec_validator()
    errors: list[ValidationError] = sorted(
        validator.iter_errors(data), key=lambda e: list(e.absolute_path)
    )
    return [_format_error(e) for e in errors]


def _format_error(err: ValidationError) -> str:
    """Render a ``jsonschema`` error as a stable ``<path>: <message>`` string."""
    location = "/".join(str(p) for p in err.absolute_path) or "<root>"
    return f"{location}: {err.message}"
