"""``dottore fingerprint`` (``-sV``) — model + guardrail recognition (contract §5.5).

A thin delegator: enforce the non-bypassable scope gate, build a target adapter and
call the u09 :class:`~ildottore.fingerprint.engine.FingerprintEngine`. It adds no
recognition logic (contract §8) — it wires the engine to an adapter and renders the
returned :class:`~ildottore.shared.models.ModelFingerprint`.

Offline default: fingerprints the deterministic :class:`MockTarget` built from a
target.yaml so ``-sV`` is exercisable in CI without a live endpoint (contract §5).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.cli import wiring
from ildottore.cli.run import ScopeRequiredError
from ildottore.shared.models import ModelFingerprint

__all__ = ["fingerprint_target"]


def fingerprint_target(
    target_path: Path,
    scope_path: Path | None,
    *,
    scenario: MockScenario | None = None,
) -> ModelFingerprint:
    """Fingerprint the target described by ``target_path`` (scope-gated).

    ``scope_path`` is **required** (contract §4 KEEP): ``-sV`` sends benign probes, so
    it obeys the same non-bypassable authorization gate as ``run``. A ``scenario`` may
    be injected for tests; by default a neutral offline scenario is used so the engine
    has something deterministic to probe.
    """

    if scope_path is None:
        raise ScopeRequiredError(
            "fingerprint requires --scope <scope.yaml>: -sV sends probes and the "
            "authorization record cannot be bypassed (docs/09 §5)"
        )
    # Load + integrity-check the scope (raises on tamper); the adapter honours it.
    wiring.build_scope(scope_path)
    target = wiring.load_target(target_path)
    canned = (
        scenario
        if scenario is not None
        else MockScenario(
            response="I am a helpful assistant. I can't share internal configuration.",
            capabilities=target.capabilities,
        )
    )
    adapter = MockTarget(canned, id=target.id)
    engine = wiring.build_fingerprint_engine()
    return asyncio.run(engine.run(adapter))
