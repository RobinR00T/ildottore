"""Shared fixtures for the T0 attack-spec battery acceptance suite (u13).

The battery unit owns *data* - the ~18 T0 attack specs (``docs/08 §3``), the two
suites and the golden fixtures. This conftest wires the **real** engine pieces the
unit depends on (u02 registry linter, u03 golden harness + :class:`MockTarget`, u06
evaluators) so the acceptance test can prove, end-to-end and offline, that every spec:

* lints clean (schema-valid, fixtures-prove, framework-mapped, test_only-flagged), and
* drives its declared *primary* evaluator to ``fail`` on the ``vulnerable`` fixture and
  ``pass`` on the ``hardened`` fixture through the u03 harness (the FP/FN gate).

No network, no clock, no RNG: the registry loader executes no code and opens no socket,
the :class:`MockTarget` is a pure replayer, and every evaluator used here is
deterministic (or capability-gated to ``inconclusive``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.evaluators import build_default_registry
from ildottore.registry import Registry, load_paths
from ildottore.shared.models import AttackSpec, EvalContext, Verdict

# Repo layout: tests/battery/conftest.py -> repo root is parents[2].
REPO_ROOT = Path(__file__).resolve().parents[2]
ATTACKS_DIR = REPO_ROOT / "specs" / "attacks"
SUITES_DIR = REPO_ROOT / "specs" / "suites"

# The T0 "Quick" battery ids in docs/08 §3 order (row 15 DOS uppercased to satisfy the
# schema id pattern ^[A-Z]+(-[A-Z0-9]+)+$). These are the 18 the suites must reference.
T0_BATTERY_IDS: tuple[str, ...] = (
    "PI-DIRECT-001",
    "PI-INDIRECT-RAG-001",
    "PI-INDIRECT-TOOL-001",
    "JB-ROLEPLAY-001",
    "JB-REFUSAL-SUPPRESS-001",
    "JB-ENCODING-001",
    "SP-LEAK-001",
    "DL-SECRET-CANARY-001",
    "DL-XSESSION-001",
    "OUT-CODEINJ-001",
    "OUT-XSS-001",
    "OUT-SQLI-001",
    "AG-TOOL-UNAUTH-001",
    "AG-CONFIRM-BYPASS-001",
    "DOS-TOKEN-AMP-001",
    "DL-MEMORIZE-DIVERGENCE-001",
    "DL-XTENANT-001",
    "DL-PII-ELICIT-001",
)

# The extra KEEP specs shipped alongside the T0 battery (docs/13 agentic-extortion).
KEEP_EXTRA_IDS: tuple[str, ...] = (
    "AG-EXTORT-CHAIN-001",
    "JB-OFFENSIVE-RANSOM-CODEGEN-001",
)


class PrimaryEvaluatorDispatcher:
    """A single :class:`~ildottore.shared.protocols.Evaluator` for the u03 harness.

    The golden harness (:func:`ildottore.testing.golden.run_spec`) drives one injected
    evaluator against ``spec.evaluators[0]`` (the *primary* arbiter). Different specs
    declare different primary types, so this dispatcher looks up the real u06 evaluator
    for ``ctx.config.type`` and delegates - turning the harness's single-evaluator seam
    into "run each spec's declared primary evaluator". No new engine logic: it is a thin
    router over the real :class:`~ildottore.evaluators.registry.EvaluatorRegistry`.
    """

    type = "battery-primary-dispatch"

    def __init__(self) -> None:
        # No judge injected: semantic_judge is never a *primary* evaluator in the battery
        # (it is always a secondary arbiter), so the deterministic built-ins suffice.
        self._registry = build_default_registry(discover=False)

    async def evaluate(self, ctx: EvalContext) -> Verdict:
        evaluator = self._registry.get(ctx.config.type.value)
        return await evaluator.evaluate(ctx)


@pytest.fixture(scope="session")
def load_result() -> object:
    """Load the shipped ``specs/attacks`` tree once (no code exec, no network)."""

    return load_paths([ATTACKS_DIR])


@pytest.fixture(scope="session")
def registry(load_result: object) -> Registry:
    """The merged registry over the shipped attack specs."""

    return Registry.from_packs(load_result.packs)  # type: ignore[attr-defined]


@pytest.fixture(scope="session")
def specs_by_id(registry: Registry) -> dict[str, AttackSpec]:
    """All shipped attack specs keyed by id."""

    return {spec.id: spec for spec in registry.list()}


@pytest.fixture
def dispatcher() -> PrimaryEvaluatorDispatcher:
    """The real-evaluator dispatcher used to drive the golden harness."""

    return PrimaryEvaluatorDispatcher()
