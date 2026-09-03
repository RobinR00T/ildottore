"""Testing harness package (u03).

Hosts the golden-target detection-accuracy harness (:mod:`ildottore.testing.golden`)
that proves every attack spec's fixtures actually flag the vulnerable case and pass
the hardened case (``docs/07 §2``, the FP/FN merge gate). Import-safe: this package
pulls in only ``shared`` + ``policy`` (never a concrete evaluator/adapter - those are
injected via protocol, contract §3/§8).
"""

from __future__ import annotations

from ildottore.testing.golden import (
    FixturePair,
    GoldenReport,
    Mismatch,
    ScenarioResult,
    assert_flags_vulnerable,
    assert_passes_hardened,
    load_fixtures,
    run_all,
    run_spec,
)

__all__ = [
    "FixturePair",
    "GoldenReport",
    "Mismatch",
    "ScenarioResult",
    "assert_flags_vulnerable",
    "assert_passes_hardened",
    "load_fixtures",
    "run_all",
    "run_spec",
]
