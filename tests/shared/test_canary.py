"""The per-run canary placeholders and the parts derived per run (u08 A-100, OD-58).

Until 2026-10-26 every battery canary began with the same public stem and ended on the run id, so
a vendor could filter the battery by one string. A canary is now
``{{canary_prefix}}{{canary_body}}``, both functions of what ``{{run_id}}`` binds to: the runner, a
resume and the evidence store reach the same canary without storing it, and it holds neither the
run id nor the spec id.
"""

from __future__ import annotations

import re

import yaml

from ildottore.shared.canary import (
    CANARY_BODY_PLACEHOLDER,
    CANARY_PREFIX_PLACEHOLDER,
    RUN_ID_PLACEHOLDER,
    bind_canary,
    derived_body,
    derived_prefix,
    holds_placeholder,
)
from ildottore.shared.package_data import BATTERY

_SHAPE = re.compile(r"[A-Z]{12}_")
_BODY = re.compile(r"[0-9a-hjkmnp-tv-z]{16}")
_CANARY = f"{CANARY_PREFIX_PLACEHOLDER}{CANARY_BODY_PLACEHOLDER}"


def test_the_derived_prefix_is_capital_letters_and_the_same_for_one_binding() -> None:
    prefix = derived_prefix("run-4c397602a2e0")
    assert _SHAPE.fullmatch(prefix)
    assert prefix == derived_prefix("run-4c397602a2e0")


def test_two_runs_almost_never_share_a_prefix() -> None:
    prefixes = {derived_prefix(f"run-{n:012x}") for n in range(2000)}
    assert len(prefixes) == 2000
    assert all(_SHAPE.fullmatch(p) for p in prefixes)


def test_the_prefix_is_as_long_as_the_old_stem() -> None:
    """So a request carrying it, and the tokens reserved for it, are as long in every run."""

    assert {len(derived_prefix(f"run-{n:012x}")) for n in range(200)} == {len("ZYNAP_CANARY_")}


def test_the_body_is_16_unambiguous_characters_that_hide_the_binding() -> None:
    """As long as the run id it replaced, with no ``i``, ``l``, ``o`` or ``u`` to misread."""

    bodies = {derived_body(f"run-{n:012x}") for n in range(2000)}
    assert len(bodies) == 2000
    assert all(_BODY.fullmatch(b) for b in bodies)
    assert derived_body("run-4c397602a2e0") == derived_body("run-4c397602a2e0")
    assert len(derived_body("run-4c397602a2e0")) == len("run-4c397602a2e0")
    seeded = bind_canary(_CANARY, "eng-2026-q4-AC-BOLA-001")
    assert "AC-BOLA" not in seeded and "eng-2026" not in seeded
    assert "4c397602a2e0" not in bind_canary(_CANARY, "run-4c397602a2e0")


def test_every_placeholder_is_bound() -> None:
    assert bind_canary(_CANARY, "run-1") == f"{derived_prefix('run-1')}{derived_body('run-1')}"
    assert bind_canary(_CANARY, "run-1", "ACME_") == f"ACME_{derived_body('run-1')}"
    assert bind_canary(f"DB_PASS={RUN_ID_PLACEHOLDER}", "run-1") == "DB_PASS=run-1"
    assert bind_canary("no placeholder", "run-1") == "no placeholder"
    assert all(
        holds_placeholder(p)
        for p in (RUN_ID_PLACEHOLDER, CANARY_PREFIX_PLACEHOLDER, CANARY_BODY_PLACEHOLDER)
    )
    assert not holds_placeholder("ACME_run-1")


def test_no_battery_canary_carries_a_constant_stem() -> None:
    """Every canary the battery declares is the two derived parts, and none names a vendor."""

    for path in sorted((BATTERY / "attacks").glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        assert "ZYNAP" not in text.upper(), path.name
        assert RUN_ID_PLACEHOLDER not in text, path.name
        spec = yaml.safe_load(text)
        refs = [e.get("canary_ref") for e in spec.get("evaluators", []) if e.get("canary_ref")]
        for canary in [*(spec.get("setup") or {}).get("canaries", []), *refs]:
            if holds_placeholder(canary):
                assert canary == _CANARY, path.name
