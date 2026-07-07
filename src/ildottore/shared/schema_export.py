"""Pydantic-first JSON Schema export (ADR-0006, OD-14).

Only ``schemas/attack-spec.schema.json`` is hand-authored. The ``suite``, ``pack`` and
``test-plan`` schemas are generated from the Pydantic models here — the model is the
single source of truth. Owned by u00; surfaced later via ``dottore schema export``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ildottore.shared.models import AttackSpec, TestPlan, _Frozen


class SuiteEntry(_Frozen):
    """A referenced spec id plus optional per-entry overrides in a suite."""

    spec_id: str
    enabled: bool = True
    runs: int | None = None


class Suite(_Frozen):
    """A suite: an ordered, versioned reference list of spec ids (``docs/03 §5``)."""

    id: str
    suite_version: str
    name: str
    specs: list[SuiteEntry] = Field(default_factory=list)
    default_runs: int | None = None
    description: str | None = None
    tags: list[str] | None = None


class Pack(BaseModel):
    """A distributable policy/spec pack manifest (parse+record now; enforce MVP-2)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    pack_version: str
    name: str
    specs: list[str] = Field(default_factory=list)
    suites: list[str] = Field(default_factory=list)
    signature: str | None = None
    checksum: str | None = None


# Models whose JSON Schema we generate (name → model). ``AttackSpec`` is included so a
# caller can cross-check against the hand-authored file, but it is not the authority.
_EXPORTED: dict[str, type[BaseModel]] = {
    "suite": Suite,
    "pack": Pack,
    "test-plan": TestPlan,
    "attack-spec": AttackSpec,
}


def export_schemas() -> dict[str, dict[str, object]]:
    """Return ``{schema_name: json_schema_dict}`` for the Pydantic-first schemas."""

    return {name: model.model_json_schema() for name, model in _EXPORTED.items()}
