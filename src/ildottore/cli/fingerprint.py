"""``dottore fingerprint`` (``-sV``) - model + guardrail recognition (contract §5.5).

A thin delegator: enforce the non-bypassable scope gate, build a target adapter and
call the u09 :class:`~ildottore.fingerprint.engine.FingerprintEngine`. It adds no
recognition logic (contract §8) - it wires the engine to an adapter and renders the
returned :class:`~ildottore.shared.models.ModelFingerprint`.

Offline default: fingerprints the deterministic :class:`MockTarget` built from a
target.yaml so ``-sV`` is exercisable in CI without a live endpoint (contract §5).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from ildottore.adapters.mock import MockScenario
from ildottore.cli import wiring
from ildottore.cli.run import ScopeRequiredError
from ildottore.policy import authorize_target
from ildottore.policy.errors import ScopeError
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
    scope = wiring.build_scope(scope_path)
    target = wiring.load_target(target_path)

    # ...and then actually USE it. This command loaded the scope and threw it away: no
    # target-id check, no endpoint check. Today that leaks nothing only because the probe
    # below was pinned to the offline mock, i.e. the safety came from an implementation
    # detail rather than from the gate. Now that a live target is probed for real (so that
    # ``-sV`` fingerprints the thing it is about to attack), the gate has to be here, and it
    # is the same predicate the engine uses (scope membership AND endpoint reachability).
    endpoint = wiring.scope_endpoint_of(scope, target)
    decision = authorize_target(scope, target.id, endpoint)
    if not decision.allowed:
        authorized = ", ".join(sorted(t.id for t in scope.targets)) or "<none>"
        raise ScopeError(
            f"target {target.id!r} is not authorized by the scope: "
            f"{decision.reason}. The scope authorizes: {authorized}."
        )

    real_target = None if (scenario is not None or wiring.target_uses_mock(target_path)) else target
    if real_target is not None:
        wiring.check_target_credential(scope, real_target)
    adapter = wiring.build_probe_adapter(scope, target, real_target=real_target, scenario=scenario)
    engine = wiring.build_fingerprint_engine()
    return asyncio.run(engine.run(adapter))
