"""Composition root (contract §1/§5.2) — the **only** place concretes meet interfaces.

``wiring`` builds every concrete implementation (adapters, evaluators, mutators,
scorer, stores, reporters, spec registry, fingerprint engine) from resolved config
and assembles the u08 :class:`~ildottore.core.runner.CampaignRunner`. It adds **no**
business logic: it constructs and injects, nothing else (contract §2/§8).

Import-linter forbids any package importing ``cli`` and forbids ``core``/``adapters``/
… importing ``cli`` (``docs/01 §2``), so the concrete↔interface meeting point is
contained here. Every collaborator is passed through a ``shared.protocols`` seam.

The default adapter factory builds a deterministic offline :class:`MockTarget` from
each spec's declared fixtures, so an E2E ``dottore run`` against a target.yaml is
fully replayable in CI (contract §5 acceptance). A real over-the-wire adapter (u04)
is swapped in here without touching ``core``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.config import SafetyFlags
from ildottore.core.runner import CampaignRunner, PolicyGate
from ildottore.evaluators import build_default_registry as build_evaluator_registry
from ildottore.fingerprint import FingerprintEngine
from ildottore.mutators import build_default_registry as build_mutator_registry
from ildottore.policy import (
    EndpointAllowlist,
    PolicyEngine,
    PolicyPack,
    Scope,
    load_scope,
)
from ildottore.registry import Registry, load_paths
from ildottore.reporting import get_reporter
from ildottore.scoring import DefaultRiskScorer
from ildottore.shared.enums import Category, TargetType
from ildottore.shared.models import AttackSpec, Capabilities, Target
from ildottore.shared.protocols import Reporter, TargetAdapter
from ildottore.store import FsEvidenceStore, SqliteRunStore

__all__ = [
    "BuiltRunner",
    "build_evidence_store",
    "build_fingerprint_engine",
    "build_permissive_pack",
    "build_policy_engine",
    "build_registry",
    "build_reporter",
    "build_run_store",
    "build_runner",
    "build_scope",
    "deterministic_clock",
    "load_target",
    "mock_adapter_factory",
    "scope_endpoint_for",
]


@dataclass
class BuiltRunner:
    """The assembled engine + the collaborators the commands still need directly."""

    runner: CampaignRunner
    scope: Scope
    policy: PolicyEngine
    evidence_root: Path


# --- registry ---------------------------------------------------------------------


def build_registry(spec_paths: list[Path]) -> Registry:
    """Load + merge every spec/pack under ``spec_paths`` into a :class:`Registry`.

    No code execution, no network — the loader (u02) only walks the filesystem and
    ``yaml.safe_load``s. Load errors are surfaced by ``dottore lint``; here we build
    the queryable registry from whatever parsed.
    """

    result = load_paths(spec_paths)
    return Registry.from_packs(result.packs)


# --- policy / scope ----------------------------------------------------------------


def build_permissive_pack(specs: list[AttackSpec], *, name: str = "cli-default") -> PolicyPack:
    """A pack enabling every category present in ``specs`` (default engagement pack).

    ``run`` needs a :class:`PolicyPack` to authorize categories; when the operator
    does not supply one we enable exactly the categories the selected specs use.
    Layer-B / PII-elicitation stay **off** (their extra gates are unchanged), so this
    is permissive for ordinary categories only — never a safety bypass (contract §8).
    """

    categories = sorted({spec.category for spec in specs}, key=lambda c: c.value)
    # availability_cost is budget-capped elsewhere; still enable it so DoS specs run
    # under the engine's hard budgets (they cannot self-DoS).
    return PolicyPack(name=name, allow_categories=categories or list(Category))


def build_policy_engine(
    scope: Scope,
    pack: PolicyPack,
    *,
    safety: SafetyFlags | None = None,
) -> PolicyEngine:
    """Assemble the default-deny :class:`PolicyEngine` gate (u01)."""

    return PolicyEngine(scope, pack, safety)


# --- stores ------------------------------------------------------------------------


def build_evidence_store(
    root: Path,
    *,
    planted_canaries: list[str] | None = None,
) -> FsEvidenceStore:
    """Content-addressed, redact-at-rest evidence store rooted at ``root`` (u10)."""

    return FsEvidenceStore(root, planted_canaries=planted_canaries)


def build_run_store(db_path: Path) -> SqliteRunStore:
    """Idempotent SQLite run store at ``db_path`` (u10)."""

    return SqliteRunStore(db_path)


# --- reporters ---------------------------------------------------------------------


def build_reporter(fmt: str, *, specs: dict[str, AttackSpec] | None = None) -> Reporter:
    """Instantiate the u11 reporter for ``fmt`` (json|html|sarif|junit)."""

    return get_reporter(fmt, specs=specs)


# --- fingerprint -------------------------------------------------------------------


def build_fingerprint_engine() -> FingerprintEngine:
    """The default six-layer fingerprint engine (u09)."""

    return FingerprintEngine()


# --- adapters ----------------------------------------------------------------------


def mock_adapter_factory(target: Target, spec: AttackSpec) -> TargetAdapter:
    """Build a deterministic offline :class:`MockTarget` from ``spec``'s fixtures.

    The scenario replays the spec's *vulnerable* fixture so an offline E2E exercises
    the full detect→score→report loop against real declared responses (contract §5
    acceptance). The target's declared capabilities are carried onto the scenario so
    capability-gated specs behave honestly (never a fabricated pass). A real adapter
    (u04) replaces this factory in a live engagement — ``core`` is unchanged.
    """

    scenario = MockScenario.from_fixture(
        spec.fixtures.vulnerable,
        capabilities=target.capabilities,
    )
    return MockTarget(scenario, id=target.id)


def deterministic_clock() -> Callable[[], float]:
    """A monotonic, integer-valued clock for offline determinism (contract §7).

    The MockTarget performs no I/O, so a wall clock would inject non-reproducible
    (and, worse, arbitrarily-shaped) latency floats into stored evidence. This clock
    steps by exactly ``1.0`` per read, so each attempt records a clean, round
    ``latency_ms`` — byte-stable across replays and never colliding with the
    redactor's numeric patterns. A live engagement (real adapter) would pass the wall
    clock instead; the seam is here in the composition root.
    """

    counter = {"t": 0.0}

    def _now() -> float:
        counter["t"] += 1.0
        return counter["t"]

    return _now


def scope_endpoint_for(scope: Scope) -> Callable[[Target, AttackSpec], str]:
    """Build the ``endpoint_for`` the runner uses to authorize each send.

    The policy gate authorizes a concrete request **URL** against the scope's
    allowlist (host + path prefix). We map a target to the ``base_url`` the scope
    declares for it, so an in-scope target passes the allowlist and an out-of-scope
    target (or one whose base_url is off-allowlist) is blocked — the gate stays the
    single authority (contract §4 KEEP). A target absent from scope falls back to its
    id, which never parses to an allowlisted host ⇒ default-deny.
    """

    base_by_id = {t.id: t.base_url for t in scope.targets}

    def _endpoint(target: Target, _spec: AttackSpec) -> str:
        return base_by_id.get(target.id, target.id)

    return _endpoint


def hardened_adapter_factory(target: Target, spec: AttackSpec) -> TargetAdapter:
    """Like :func:`mock_adapter_factory` but replays the *hardened* fixture (secure).

    Useful for a clean-run smoke (exit code 0) and for tests that assert a hardened
    target produces no gated findings.
    """

    scenario = MockScenario.from_fixture(
        spec.fixtures.hardened,
        capabilities=target.capabilities,
    )
    return MockTarget(scenario, id=target.id)


# --- target.yaml -------------------------------------------------------------------


def load_target(path: Path) -> Target:
    """Load a ``target.yaml`` into a :class:`~ildottore.shared.models.Target`.

    The file declares ``id``/``type`` and an optional ``capabilities`` map; secrets
    are **never** read here (``auth_ref`` is a reference resolved elsewhere, S6).
    Unknown top-level keys (provider/endpoint/model/auth_ref/sampling_defaults …) are
    ignored — this loader only extracts what the runtime :class:`Target` model needs.
    """

    import yaml

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"target file {path} must be a mapping at top level")
    target_id = raw.get("id")
    if not isinstance(target_id, str) or not target_id:
        raise ValueError(f"target file {path} is missing a string 'id'")
    type_raw = raw.get("type", TargetType.MODEL.value)
    try:
        target_type = TargetType(type_raw)
    except ValueError as exc:
        raise ValueError(
            f"target file {path} has invalid type {type_raw!r}; "
            f"expected one of {', '.join(t.value for t in TargetType)}"
        ) from exc
    caps_raw = raw.get("capabilities") or {}
    if not isinstance(caps_raw, dict):
        raise ValueError(f"target file {path} 'capabilities' must be a mapping")
    known = set(Capabilities.model_fields)
    caps = Capabilities.model_validate({k: v for k, v in caps_raw.items() if k in known})
    name = raw.get("name") if isinstance(raw.get("name"), str) else None
    return Target(id=target_id, type=target_type, capabilities=caps, name=name)


# --- the runner --------------------------------------------------------------------


def build_runner(
    *,
    scope: Scope,
    specs: list[AttackSpec],
    evidence_root: Path,
    run_db: Path,
    pack: PolicyPack | None = None,
    safety: SafetyFlags | None = None,
    concurrency: int = 4,
    timeout_s: float | None = None,
    n: int = 5,
    hardened: bool = False,
) -> BuiltRunner:
    """Assemble the whole middle tier into a :class:`CampaignRunner` (contract §5.2).

    Every concrete is built here and injected through a ``shared.protocols`` seam;
    ``core`` sees only interfaces. ``hardened=True`` swaps in the hardened-fixture
    adapter factory (a clean target) — handy for a green smoke run.
    """

    resolved_pack = pack if pack is not None else build_permissive_pack(specs)
    policy = build_policy_engine(scope, resolved_pack, safety=safety)
    mutators = build_mutator_registry()
    evaluators = build_evaluator_registry()
    scorer = DefaultRiskScorer()
    evidence = build_evidence_store(evidence_root)
    runs = build_run_store(run_db)
    factory = hardened_adapter_factory if hardened else mock_adapter_factory

    # PolicyEngine structurally satisfies the runner's PolicyGate protocol (its
    # ``check`` returns a CheckResult with ``.allowed``/``.reason``); the cast makes
    # that explicit for the type checker (the runner's own docstring asserts this).
    policy_gate: PolicyGate = cast(PolicyGate, policy)
    runner = CampaignRunner(
        policy=policy_gate,
        mutators=mutators,
        evaluators=evaluators,
        scorer=scorer,
        evidence_store=evidence,
        run_store=runs,
        adapter_factory=factory,
        endpoint_for=scope_endpoint_for(scope),
        now=deterministic_clock(),
        n=n,
        concurrency=concurrency,
        timeout_s=timeout_s,
    )
    return BuiltRunner(
        runner=runner,
        scope=scope,
        policy=policy,
        evidence_root=evidence_root,
    )


def build_scope(path: Path) -> Scope:
    """Load + integrity-check a ``scope.yaml`` (u01, S3/S4). Never bypassable."""

    return load_scope(path)


# Re-export for the scope-gate command (kept explicit so the gate lives in one place).
_ALLOWLIST = EndpointAllowlist
