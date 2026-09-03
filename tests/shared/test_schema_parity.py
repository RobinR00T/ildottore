"""Schema-parity gate (contract §7).

Asserts the Pydantic ``AttackSpec`` family stays 1:1 with the hand-authored
``schemas/attack-spec.schema.json`` (the source of truth), and drives the
``tests/fixtures/specs/{valid,invalid}/*.yaml`` corpus:

* every ``valid/*.yaml`` parses into ``AttackSpec`` **and** its
  ``model_dump(mode="json")`` re-validates against the JSON Schema (round-trip);
* every ``invalid/*.yaml`` raises ``pydantic.ValidationError``;
* model field names == schema property names (no drift);
* model enum values == schema ``enum`` values (no drift), including the distinct
  ``requires`` vocabulary (``RequiresCapability``);
* ``additionalProperties: false`` ⇔ ``extra="forbid"``.

This is the exact gate that catches model↔schema drift (e.g. the ``requires``
enum that once omitted ``system_prompt``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml
from pydantic import BaseModel, ValidationError

from ildottore.shared import (
    Category,
    EvaluatorLogic,
    EvaluatorType,
    RequiresCapability,
    Severity,
    TargetType,
)
from ildottore.shared.enums import Capability
from ildottore.shared.models import (
    Attack,
    AttackSpec,
    Budget,
    Capabilities,
    EvaluatorConfig,
    FixtureCase,
    Fixtures,
    MitreAtlas,
    Sampling,
    Scoring,
    Setup,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "attack-spec.schema.json"
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "specs"
VALID_DIR = FIXTURES / "valid"
INVALID_DIR = FIXTURES / "invalid"


def _load_schema() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(SCHEMA_PATH.read_text())
    return loaded


SCHEMA = _load_schema()
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)

VALID_SPECS = sorted(VALID_DIR.glob("*.yaml"))
INVALID_SPECS = sorted(INVALID_DIR.glob("*.yaml"))


def test_fixture_corpus_present() -> None:
    """The corpus the gate drives must actually exist (guards against silent no-op)."""
    assert VALID_SPECS, "no valid fixtures found"
    assert INVALID_SPECS, "no invalid fixtures found"


# --- corpus: valid parses + round-trips; invalid rejects ---------------------------


@pytest.mark.parametrize("path", VALID_SPECS, ids=lambda p: p.name)
def test_valid_fixture_parses_and_round_trips(path: Path) -> None:
    data = yaml.safe_load(path.read_text())
    # 1) schema-valid input parses into the model
    spec = AttackSpec.model_validate(data)
    # 2) round-trip: the model's JSON dump re-validates against the JSON Schema, verbatim
    dumped = spec.model_dump(mode="json")
    VALIDATOR.validate(dumped)
    # 3) byte-stable on re-dump
    assert AttackSpec.model_validate(dumped).model_dump(mode="json") == dumped


@pytest.mark.parametrize("path", INVALID_SPECS, ids=lambda p: p.name)
def test_invalid_fixture_is_rejected(path: Path) -> None:
    data = yaml.safe_load(path.read_text())
    with pytest.raises(ValidationError):
        AttackSpec.model_validate(data)
    # corroborate: the JSON Schema also rejects it (oracle agreement)
    assert list(VALIDATOR.iter_errors(data)), f"{path.name} unexpectedly passes JSON Schema"


# --- field-name parity: model fields == schema property names ----------------------

# (schema-node, model) pairs to compare 1:1.
_NODE_MODEL_PAIRS: dict[str, tuple[dict[str, Any], type[BaseModel]]] = {
    "root": (SCHEMA, AttackSpec),
    "setup": (SCHEMA["properties"]["setup"], Setup),
    "attack": (SCHEMA["properties"]["attack"], Attack),
    "evaluators.items": (SCHEMA["properties"]["evaluators"]["items"], EvaluatorConfig),
    "scoring": (SCHEMA["properties"]["scoring"], Scoring),
    "sampling": (SCHEMA["properties"]["sampling"], Sampling),
    "budget": (SCHEMA["properties"]["budget"], Budget),
    "fixtures": (SCHEMA["properties"]["fixtures"], Fixtures),
    "fixtures.vulnerable": (
        SCHEMA["properties"]["fixtures"]["properties"]["vulnerable"],
        FixtureCase,
    ),
    "fixtures.hardened": (
        SCHEMA["properties"]["fixtures"]["properties"]["hardened"],
        FixtureCase,
    ),
    "mitre_atlas": (SCHEMA["properties"]["mitre_atlas"], MitreAtlas),
}


@pytest.mark.parametrize("name", sorted(_NODE_MODEL_PAIRS))
def test_field_names_match_schema(name: str) -> None:
    node, model = _NODE_MODEL_PAIRS[name]
    schema_props = set(node.get("properties", {}).keys())
    model_fields = set(model.model_fields.keys())
    assert schema_props == model_fields, (
        f"{name}: drift - schema-only={schema_props - model_fields} "
        f"model-only={model_fields - schema_props}"
    )


# --- enum parity: model enum values == schema enum values --------------------------

# (schema enum location, StrEnum) - every enumerated field.
_ENUM_PAIRS: dict[str, tuple[list[str], type[Any]]] = {
    "category": (SCHEMA["properties"]["category"]["enum"], Category),
    "severity": (SCHEMA["properties"]["severity"]["enum"], Severity),
    "target_type": (SCHEMA["properties"]["target_type"]["enum"], TargetType),
    "requires": (SCHEMA["properties"]["requires"]["items"]["enum"], RequiresCapability),
    "evaluators.type": (
        SCHEMA["properties"]["evaluators"]["items"]["properties"]["type"]["enum"],
        EvaluatorType,
    ),
    "evaluator_logic": (SCHEMA["properties"]["evaluator_logic"]["enum"], EvaluatorLogic),
}


@pytest.mark.parametrize("name", sorted(_ENUM_PAIRS))
def test_enum_values_match_schema(name: str) -> None:
    schema_values, enum_cls = _ENUM_PAIRS[name]
    assert set(schema_values) == {e.value for e in enum_cls}, f"{name}: enum drift"


def test_capability_enum_matches_capabilities_model() -> None:
    """The ``Capability`` enum stays 1:1 with the ``Capabilities`` model fields (no drift).

    The ``requires`` half is guarded above; this guards the target-capability half, so adding a
    capability (e.g. ``audio``) to one without the other is a test failure (multimodal audit).
    """
    assert {c.value for c in Capability} == set(Capabilities.model_fields.keys())


def test_requires_to_cap_map_is_complete_and_targets_real_fields() -> None:
    """Every ``RequiresCapability`` (except the setup-only ``system_prompt``) maps to a real
    ``Capabilities`` field, so the planner can gate it."""
    from ildottore.core.planner import _REQUIRES_TO_CAP

    expected = {r for r in RequiresCapability if r is not RequiresCapability.SYSTEM_PROMPT}
    assert set(_REQUIRES_TO_CAP) == expected
    assert all(field in Capabilities.model_fields for field in _REQUIRES_TO_CAP.values())


def test_fixture_expect_verdict_enums_match_schema() -> None:
    """``fixtures.vulnerable/hardened.expect_verdict`` literals are fixed by the schema."""
    fx = SCHEMA["properties"]["fixtures"]["properties"]
    assert fx["vulnerable"]["properties"]["expect_verdict"]["enum"] == ["fail"]
    assert fx["hardened"]["properties"]["expect_verdict"]["enum"] == ["pass"]


# --- additionalProperties: false ⇔ extra="forbid" ----------------------------------


@pytest.mark.parametrize("name", sorted(_NODE_MODEL_PAIRS))
def test_additional_properties_matches_extra_forbid(name: str) -> None:
    node, model = _NODE_MODEL_PAIRS[name]
    extra = model.model_config.get("extra")
    # Every model in the family forbids unknown fields (contract §4 KEEP).
    assert extra == "forbid", f"{name}: model must set extra='forbid'"
    # Biconditional: where the schema explicitly sets additionalProperties:false,
    # the model's extra='forbid' mirrors it. (Nodes that leave it unset are permissive
    # in the schema; our models are stricter, which is allowed and safe.)
    if node.get("additionalProperties") is False:
        assert extra == "forbid", f"{name}: additionalProperties:false ⇔ extra='forbid'"


def test_model_dump_json_excludes_none() -> None:
    """The schema-mirror ``model_dump_json`` default also drops unset optionals."""
    data = yaml.safe_load((VALID_DIR / "JB-MULTITURN-001.yaml").read_text())
    spec = AttackSpec.model_validate(data)
    payload = json.loads(spec.model_dump_json())
    # ``budget`` is unset on this fixture - must be absent, not ``null``.
    assert "budget" not in payload
    # and the JSON string round-trips through the schema
    VALIDATOR.validate(payload)


def test_fixtures_polarity_guards() -> None:
    """``fixtures.vulnerable`` must expect ``fail``; ``hardened`` must expect ``pass``."""
    base = yaml.safe_load((VALID_DIR / "PI-INDIRECT-RAG-001.yaml").read_text())

    swapped_vuln = json.loads(json.dumps(base))
    swapped_vuln["fixtures"]["vulnerable"]["expect_verdict"] = "pass"
    with pytest.raises(ValidationError):
        AttackSpec.model_validate(swapped_vuln)

    swapped_hard = json.loads(json.dumps(base))
    swapped_hard["fixtures"]["hardened"]["expect_verdict"] = "fail"
    with pytest.raises(ValidationError):
        AttackSpec.model_validate(swapped_hard)


def test_required_fields_match_schema_root() -> None:
    """Schema ``required`` list == the model's required (no-default) fields at the root."""
    schema_required = set(SCHEMA["required"])
    model_required = {n for n, f in AttackSpec.model_fields.items() if f.is_required()}
    assert schema_required == model_required, (
        f"required drift - schema-only={schema_required - model_required} "
        f"model-only={model_required - schema_required}"
    )
