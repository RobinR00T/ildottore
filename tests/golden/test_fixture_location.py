"""OD-7, decided 2026-10-11 (under the owner's delegation, revisable): fixtures live inline only.

A spec is self-proving as one file: its ``fixtures`` block is inside its digest
(``shared/digest.py``), so the lint proof and the resume binding cover the proof with the spec.
The contracts once said "schema supports both" (inline and a sidecar file); it was never true.
These tests pin what is built, so a sidecar seam cannot appear without the decision changing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from ildottore.shared.digest import spec_digest
from ildottore.shared.models import AttackSpec, Fixtures

_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA = json.loads((_ROOT / "schemas" / "attack-spec.schema.json").read_text(encoding="utf-8"))

_CASES = {
    "vulnerable": {"response": "the canary is X", "expect_verdict": "fail"},
    "hardened": {"response": "I cannot share that.", "expect_verdict": "pass"},
}


def test_the_schema_takes_two_inline_cases_and_no_path() -> None:
    fixtures = _SCHEMA["properties"]["fixtures"]
    assert set(fixtures["properties"]) == {"vulnerable", "hardened"}
    assert fixtures["additionalProperties"] is False


@pytest.mark.parametrize("key", ["path", "file", "sidecar", "ref"])
def test_a_fixture_path_is_refused_by_the_model(key: str) -> None:
    Fixtures.model_validate(_CASES)  # the two inline cases alone are valid
    with pytest.raises(ValidationError):
        Fixtures.model_validate({**_CASES, key: "tests/fixtures/specs/X/fixtures.yaml"})


def test_the_fixtures_are_inside_the_spec_digest() -> None:
    """Change only a fixture and the spec's digest changes: the proof travels with the spec."""

    base = yaml.safe_load((_ROOT / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text("utf-8"))
    edited = json.loads(json.dumps(base))
    edited["fixtures"]["hardened"]["response"] = "a different refusal"
    assert spec_digest(AttackSpec.model_validate(base)) != spec_digest(
        AttackSpec.model_validate(edited)
    )
