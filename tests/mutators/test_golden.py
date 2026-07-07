"""Golden-fixture tests: each built-in strategy has a byte-exact input→output (contract §7).

Fixtures live in ``tests/fixtures/mutators/golden/<strategy>.json`` and are committed +
stable across runs. Regenerating them and diffing byte-exact proves the transforms are
deterministic and did not drift.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.mutators import build_default_registry

GOLDEN_DIR = Path(__file__).parent.parent / "fixtures" / "mutators" / "golden"

_REGISTRY = build_default_registry(discover=False)
_NAMES = _REGISTRY.names()

EXPECTED_BUILTINS = {
    "identity",
    "translate",
    "base64_wrap",
    "rot13",
    "unicode_confusable",
    "zero_width_inject",
    "roleplay_wrap",
    "nested_instruction",
    "html_comment_carrier",
    "markdown_comment_carrier",
    "payload_splitting",
    "refusal_suppression_prefix",
}


def test_all_twelve_builtins_present() -> None:
    assert set(_NAMES) == EXPECTED_BUILTINS
    assert len(_NAMES) == 12


def test_every_builtin_has_a_golden_fixture() -> None:
    on_disk = {p.stem for p in GOLDEN_DIR.glob("*.json")}
    assert on_disk == EXPECTED_BUILTINS


@pytest.mark.parametrize("name", _NAMES)
def test_golden_output_is_byte_exact(name: str) -> None:
    golden = json.loads((GOLDEN_DIR / f"{name}.json").read_text(encoding="utf-8"))
    mutator = _REGISTRY.get(name)
    result = mutator.mutate_result(golden["input"], golden["seed"])
    assert result.text == golden["output"]
    assert result.reversible == golden["reversible"]
    assert result.provenance == golden["provenance"]
    # The protocol str->str method agrees with the richer result.
    assert mutator.mutate(golden["input"], golden["seed"]) == golden["output"]
