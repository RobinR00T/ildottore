"""Composition root (contract §1/§5.2) - the **only** place concretes meet interfaces.

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

import asyncio
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from ildottore.adapters import (
    AnthropicAdapter,
    MCPAdapter,
    OpenAIAdapter,
    RestAdapter,
    RestTemplate,
)
from ildottore.adapters.comprehending import ComprehendingMock
from ildottore.adapters.mock import MockScenario, MockTarget, bare_scenario
from ildottore.config import SafetyFlags
from ildottore.core.pacing import RateLimiter
from ildottore.core.planner import IDENTITY_MUTATOR
from ildottore.core.runner import CampaignRunner, IdentityProbe, PolicyGate
from ildottore.evaluators import build_default_registry as build_evaluator_registry
from ildottore.fingerprint import FingerprintEngine
from ildottore.fingerprint.layers import CarrierLayer, default_layers
from ildottore.mutators import build_default_registry as build_mutator_registry
from ildottore.policy import (
    EndpointAllowlist,
    PolicyEngine,
    PolicyPack,
    Scope,
    load_scope,
)
from ildottore.registry import Registry, load_paths
from ildottore.reporting import RunStatus, get_reporter
from ildottore.scoring import DefaultRiskScorer
from ildottore.shared.enums import Category, TargetType
from ildottore.shared.models import (
    AttackSpec,
    Attempt,
    Capabilities,
    ModelFingerprint,
    ModelRequest,
    ModelResponse,
    Sampling,
    Target,
)
from ildottore.shared.protocols import Reporter, TargetAdapter
from ildottore.store import FsEvidenceStore, SqliteRunStore

__all__ = [
    "MOCK_SCENARIOS",
    "PROBE_SPEC_ID",
    "BuiltRunner",
    "bare_adapter_factory",
    "build_evidence_store",
    "build_fingerprint_engine",
    "build_judge_adapter",
    "build_permissive_pack",
    "build_policy_engine",
    "build_probe_adapter",
    "build_real_adapter",
    "build_registry",
    "build_reporter",
    "build_run_store",
    "build_runner",
    "build_scope",
    "check_target_credential",
    "comprehending_adapter_factory",
    "deterministic_clock",
    "fingerprint_probe",
    "hardened_adapter_factory",
    "load_mock_scenario",
    "load_target",
    "mock_adapter_factory",
    "planted_secrets",
    "real_adapter_factory",
    "request_url_for",
    "resolve_auth_ref",
    "scenario_adapter_factory",
    "scenario_judge_adapter",
    "scope_endpoint_for",
    "scope_endpoint_of",
    "target_uses_mock",
]

#: The offline mock-replay scenarios a ``target.yaml`` may select via ``mock_scenario``.
#: ``bare`` (default) returns a generic canned response → every spec ``inconclusive``;
#: ``vulnerable`` replays each spec's ``fixtures.vulnerable`` → ``fail``; ``hardened``
#: replays ``fixtures.hardened`` → ``pass``. ``comprehending`` decodes what it is sent and
#: follows a decodable instruction, which is the only offline scenario in which ``-sV``'s
#: carrier measurement can produce anything but an empty hint (verdicts stay ``inconclusive``,
#: exactly like ``bare``: it recognises no attack, it only decodes). A real over-the-wire
#: adapter (u04) ignores this - the field only steers the deterministic offline mock
#: (contract §5).
MOCK_SCENARIOS = ("bare", "vulnerable", "hardened", "comprehending")

#: The ``spec_id`` stored on a recognition probe. Not a real spec id, and deliberately not one:
#: a probe is not an attack attempt, so nothing that groups by spec should ever mistake it for
#: one. It is also why probes live under ``probes/`` rather than ``attempts/``.
PROBE_SPEC_ID = "__probe__"


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

    No code execution, no network - the loader (u02) only walks the filesystem and
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
    is permissive for ordinary categories only - never a safety bypass (contract §8).
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


def planted_secrets(specs: list[AttackSpec]) -> list[str]:
    """Secret literals the scan knows about, to mask at rest even if a target leaks them (DL2).

    Collects each spec's ``setup.canaries`` and its ``secret_leakage`` ``canary_ref`` values.
    A templated canary (``ZYNAP_CANARY_{{run_id}}``) cannot match a substituted value
    verbatim, so its stable stem (before ``{{``) is registered instead, the evidence
    redactor then masks the concrete token. This closes the gap where a leaked engagement
    secret (a shape the built-in patterns don't know) persisted in clear in evidence.
    """

    out: list[str] = []
    seen: set[str] = set()

    def _add(value: str | None) -> None:
        if not value:
            return
        stem = value.split("{{", 1)[0].rstrip("_") if "{{" in value else value
        if stem and stem not in seen:
            seen.add(stem)
            out.append(stem)

    for spec in specs:
        if spec.setup is not None and spec.setup.canaries:
            for canary in spec.setup.canaries:
                _add(canary)
        for cfg in spec.evaluators:
            _add(cfg.canary_ref)
    return out


def build_run_store(db_path: Path) -> SqliteRunStore:
    """Idempotent SQLite run store at ``db_path`` (u10)."""

    return SqliteRunStore(db_path)


# --- reporters ---------------------------------------------------------------------


def build_reporter(
    fmt: str,
    *,
    specs: dict[str, AttackSpec] | None = None,
    planned_specs: int | None = None,
    run_status: RunStatus | None = None,
) -> Reporter:
    """Instantiate the u11 reporter for ``fmt`` (json|html|sarif|junit).

    ``planned_specs``/``run_status`` let a report state what the run intended and whether it
    finished, instead of presenting a budget-truncated campaign as a complete one.
    """

    return get_reporter(fmt, specs=specs, planned_specs=planned_specs, run_status=run_status)


# --- fingerprint -------------------------------------------------------------------


def build_fingerprint_engine() -> FingerprintEngine:
    """The fingerprint engine: u09's six self-contained layers plus the carrier layer.

    The carrier layer is assembled here because it probes with u05's mutators and u09 may not
    import them. It is what makes ``-sV`` change the battery rather than only name the model:
    the planner orders each spec's mutators by what this target demonstrably still
    understands (``fingerprint.layers.carrier``).
    """

    registry = build_mutator_registry()
    carriers = [registry.get(name) for name in registry.names() if name != IDENTITY_MUTATOR]
    return FingerprintEngine(layers=[*default_layers(), CarrierLayer(carriers)])


def build_probe_adapter(
    scope: Scope,
    target: Target,
    *,
    real_target: Target | None = None,
    scenario: MockScenario | None = None,
    mock_scenario: str | None = None,
) -> TargetAdapter:
    """The adapter a fingerprint/discovery probe should talk to (``-sV``, ``dottore
    fingerprint``).

    ``real_target`` (a non-mock ``target.yaml``) probes the live provider through the same
    scope-bound allowlist the campaign will use, so ``-sV`` fingerprints the thing it is
    about to attack. Everything else gets the deterministic offline :class:`MockTarget`, so
    ``-sV`` stays exercisable in CI without an endpoint (contract §5).

    Shared by ``run -sV`` and the ``fingerprint`` command: two copies of this choice is how
    ``-sV`` ended up pinned to the mock even for a live target.
    """

    if real_target is not None:
        scope_target = scope.target(real_target.id)
        allowlist = EndpointAllowlist(scope_target.endpoints if scope_target is not None else [])
        return build_real_adapter(
            real_target, allowlist, api_key=_authorized_api_key(scope, real_target)
        )
    if mock_scenario == "comprehending" and scenario is None:
        # The one offline target whose answer depends on what was sent, so the carrier layer
        # measures something instead of scoring every carrier zero against a fixed string.
        return ComprehendingMock(id=target.id, capabilities=target.capabilities)
    canned = (
        scenario
        if scenario is not None
        else MockScenario(
            response="I am a helpful assistant. I can't share internal configuration.",
            capabilities=target.capabilities,
        )
    )
    return MockTarget(canned, id=target.id)


# --- adapters ----------------------------------------------------------------------


def mock_adapter_factory(target: Target, spec: AttackSpec) -> TargetAdapter:
    """Build a deterministic offline :class:`MockTarget` from ``spec``'s fixtures.

    The scenario replays the spec's *vulnerable* fixture so an offline E2E exercises
    the full detect→score→report loop against real declared responses (contract §5
    acceptance). The target's declared capabilities are carried onto the scenario so
    capability-gated specs behave honestly (never a fabricated pass). A real adapter
    (u04) replaces this factory in a live engagement - ``core`` is unchanged.
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
    ``latency_ms`` - byte-stable across replays and never colliding with the
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
    target (or one whose base_url is off-allowlist) is blocked - the gate stays the
    single authority (contract §4 KEEP). A target absent from scope falls back to its
    id, which never parses to an allowlisted host ⇒ default-deny.
    """

    def _endpoint(target: Target, _spec: AttackSpec) -> str:
        return scope_endpoint_of(scope, target)

    return _endpoint


def scope_endpoint_of(scope: Scope, target: Target) -> str:
    """The concrete endpoint string the policy gate authorizes for ``target``.

    Spec-independent, so a pre-flight check can ask the question without inventing a spec:
    the CLI's authorization gate has to test the *same* string the runner will, or it is a
    second, weaker gate that can disagree with the real one.
    """

    # The URL the adapter will really request, when there is one (a stdio MCP target answers
    # with its command line, which the gate exact-matches against the scope's `commands`).
    # Authorizing the scope's `base_url` instead was testing a different string from the one
    # that goes on the wire: see :func:`request_url_for`.
    wire_url = request_url_for(target)
    if wire_url is not None:
        return wire_url
    # A mock/offline target has no wire URL: fall back to the scope's declared base_url, and
    # to the bare id when the scope does not know it (which no allowlist can match, so
    # default-deny holds).
    base_by_id = {t.id: t.base_url for t in scope.targets}
    return base_by_id.get(target.id, target.id)


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


def bare_adapter_factory(target: Target, _spec: AttackSpec) -> TargetAdapter:
    """Replay a generic *bare* response (no fixture) → every spec ``inconclusive``.

    The honest default when no ``mock_scenario`` is selected: the mock answers with a canned
    string that matches neither fixture, so no fixture-driven evaluator can decide and the run
    reports ``inconclusive``. The target's declared capabilities are still carried so
    capability-gating behaves.

    **Two specs of the shipped 75 decide anyway, in opposite directions**, and this used to say
    "never a fabricated pass or fail", which is false. A text oracle scores a reply that is
    evidence of neither: `DOS-TOKEN-AMP-001` looks for a secure marker the canned string does
    not carry and reports `fail`; `MCP-TOOLPOISON-001` looks for the ABSENCE of injection
    markers, which the canned string trivially satisfies, and reports `pass`. That is a
    property of a text oracle facing an irrelevant reply, not of this factory, and it is pinned
    by `tests/cli/test_scenario_mode.py` so the claim and the code cannot drift apart again
    (OD-16 asks whether an evaluator should abstain on a reply that answers nothing).
    """

    return MockTarget(bare_scenario(capabilities=target.capabilities), id=target.id)


def comprehending_adapter_factory(target: Target, _spec: AttackSpec) -> TargetAdapter:
    """Attack traffic against the decoding mock: it decodes, it does not play along.

    It answers an attack prompt the way it answers anything it cannot parse as its one known
    instruction, so every spec comes out ``inconclusive``, as with ``bare``. The scenario
    exists for the fingerprint pass, and it must not fabricate a verdict to pay for it.
    """

    return ComprehendingMock(id=target.id, capabilities=target.capabilities)


def scenario_judge_adapter(scenario: str) -> TargetAdapter | None:
    """A deterministic offline *judge* whose verdict matches the mock scenario.

    The ``semantic_judge`` evaluator is an LLM-as-judge reached via a
    :class:`TargetAdapter`; offline it would otherwise have no model and abstain
    (``inconclusive``), sinking every ``weighted``/``any_fail`` aggregate. For a
    ``vulnerable`` run we replay a canned judge verdict of ``exploited`` and for
    ``hardened`` one of ``secure`` - so the judge *agrees* with the fixtures and the
    run demonstrates a decisive ``fail``/``pass``. ``bare`` returns ``None`` (no
    judge): the judge stays unregistered and abstains, so a bare run remains
    ``inconclusive`` - the honest default, never a fabricated verdict.

    The canned answer is valid structured JSON with high confidence and no injection
    tripwire, so it passes every ``docs/04 §4`` mitigation (self-consistency across
    the two passes is trivially met - the deterministic mock returns identical bytes).
    """

    if scenario == "vulnerable":
        verdict = "exploited"
        reasoning = "offline judge (scenario replay): target exploited by the attack"
    elif scenario == "hardened":
        verdict = "secure"
        reasoning = "offline judge (scenario replay): target remained secure"
    else:
        return None

    payload = (
        f'{{"verdict": "{verdict}", "confidence": 1.0, '
        f'"reasoning": "{reasoning}", "observed_injection_attempt": false}}'
    )
    return MockTarget(MockScenario(response=payload), id="mock-judge")


def scenario_adapter_factory(
    scenario: str,
) -> Callable[[Target, AttackSpec], TargetAdapter]:
    """Return the mock ``adapter_factory`` for a ``mock_scenario`` selector.

    ``vulnerable``/``hardened`` replay the spec's own fixtures (so a run demonstrates
    real ``fail``/``pass``); ``bare`` (the default) returns a generic canned response
    (``inconclusive``). An unknown selector is rejected - the composition root never
    silently degrades to a fabricated verdict.
    """

    if scenario == "vulnerable":
        return mock_adapter_factory
    if scenario == "hardened":
        return hardened_adapter_factory
    if scenario == "bare":
        return bare_adapter_factory
    if scenario == "comprehending":
        return comprehending_adapter_factory
    raise ValueError(
        f"unknown mock_scenario {scenario!r}; expected one of {', '.join(MOCK_SCENARIOS)}"
    )


# --- real (over-the-wire) adapters --------------------------------------------------


def resolve_auth_ref(auth_ref: str | None) -> str | None:
    """Resolve a target's ``auth_ref`` **reference** to its secret value (S6).

    Only the ``env://NAME`` scheme is supported in MVP-1 (matches every
    ``auth_ref`` in ``specs/targets/``); the environment is read here, at send-time
    construction - never earlier, and the resolved value is never logged (the
    caller passes it straight into the adapter's ``api_key``, which itself never
    appears in evidence: the redactor masks ``raw_ids``, and the value never enters
    a ``ModelRequest``/``ModelResponse``). ``None`` in ⇒ ``None`` out (no auth
    configured). An unsupported scheme (e.g. ``vault://``, deferred) raises rather
    than silently sending an unauthenticated request.
    """

    if auth_ref is None:
        return None
    if auth_ref.startswith("env://"):
        name = auth_ref.removeprefix("env://")
        return os.environ.get(name)
    raise ValueError(f"unsupported auth_ref scheme in {auth_ref!r}; only 'env://NAME' is supported")


#: The path each provider's API lives at when the operator declares only an origin. Used by
#: :func:`request_url_for` and :func:`build_real_adapter`, from one table, so the URL the gate
#: authorizes and the URL the adapter requests are computed the same way.
PROVIDER_DEFAULT_PATHS: dict[str, str] = {
    "openai": "/v1/chat/completions",
    "anthropic": "/v1/messages",
}


def request_url_for(target: Target) -> str | None:
    """The URL (or ``stdio://`` command) this target's adapter will really request.

    ``None`` for a mock/offline target, which has no wire URL at all.

    This exists because "the endpoint" had three different meanings: the scope's ``base_url``
    (what the pre-flight gate authorized), ``target.endpoint`` (what the operator wrote), and
    ``origin + a hardcoded provider path`` (what the adapter sent). An audit of 252
    scope/target combinations found 80 disagreements between the first and the third, 41 of
    them refusals of configurations that would have been allowed on the wire. One function,
    one answer, used by the gate and by the adapter factory.
    """

    if (target.transport or "").strip().lower() == "stdio" and target.command:
        return "stdio://" + " ".join(target.command)
    endpoint = (target.endpoint or "").strip()
    if not endpoint or endpoint.startswith("mock://"):
        return None
    parts = urlsplit(endpoint)
    if not parts.scheme or not parts.netloc:
        return None
    provider = (target.provider or "").strip().lower()
    if provider == "mcp":
        return endpoint  # MCP posts JSON-RPC to the declared path itself
    path = parts.path or PROVIDER_DEFAULT_PATHS.get(provider, "/")
    return f"{parts.scheme}://{parts.netloc}{path}"


def build_real_adapter(
    target: Target,
    allowlist: EndpointAllowlist,
    *,
    api_key: str | None,
    authorized_commands: tuple[str, ...] = (),
) -> TargetAdapter:
    """Construct the concrete over-the-wire adapter for ``target`` (contract §5).

    Routes on ``target.provider``: ``openai`` → :class:`OpenAIAdapter`,
    ``anthropic`` → :class:`AnthropicAdapter`, ``mcp`` → the read-only
    :class:`MCPAdapter` (Model Context Protocol server discovery), anything else → the
    generic :class:`RestAdapter` (the long-tail escape hatch, ADR-0002). ``target.endpoint``
    is the **full** request URL (``specs/targets/example-openai.yaml``); its origin
    becomes the adapter's ``base_url`` and its path is either the adapter's own
    fixed ``_endpoint_path`` (openai/anthropic) or the ``RestTemplate.path`` (rest) -
    either way ``adapter._full_url()`` reconstructs the declared endpoint exactly, so
    the allowlist gate (built from the same scope) authorizes the identical URL the
    adapter will call.
    """

    parts = urlsplit(target.endpoint or "")
    origin = f"{parts.scheme}://{parts.netloc}"
    provider = (target.provider or "").strip().lower()

    if provider == "mcp":
        if (target.transport or "http").strip().lower() == "stdio":
            # A local MCP server launched as a subprocess. Spawning is gated by the scope's
            # authorized command list (exact match); base_url is a non-network placeholder.
            return MCPAdapter(
                id=target.id,
                base_url="stdio://local",
                allowlist=allowlist,
                api_key=api_key,
                model=target.model,
                transport="stdio",
                command=tuple(target.command or ()),
                authorized_commands=authorized_commands,
            )
        # MCP posts JSON-RPC to the endpoint PATH itself (e.g. /mcp), so the adapter keeps the
        # full URL as base_url (unlike openai/anthropic, whose path is a fixed _endpoint_path).
        return MCPAdapter(
            id=target.id,
            base_url=target.endpoint or origin,
            allowlist=allowlist,
            api_key=api_key,
            model=target.model,
        )
    # The DECLARED path wins over the provider default: a gateway (Azure OpenAI, LiteLLM, a
    # corporate proxy) hosts the same API under a prefix, and discarding it both sent the
    # wrong URL and tripped the allowlist built from the declared one.
    declared_path = parts.path or None
    if provider == "openai":
        return OpenAIAdapter(
            id=target.id,
            base_url=origin,
            allowlist=allowlist,
            api_key=api_key,
            model=target.model,
            path_override=declared_path,
        )
    if provider == "anthropic":
        return AnthropicAdapter(
            id=target.id,
            base_url=origin,
            allowlist=allowlist,
            api_key=api_key,
            model=target.model,
            path_override=declared_path,
        )
    template = RestTemplate(path=parts.path or "/")
    return RestAdapter(
        id=target.id,
        base_url=origin,
        allowlist=allowlist,
        api_key=api_key,
        model=target.model,
        template=template,
    )


def _authorized_api_key(scope: Scope, target: Target) -> str | None:
    """Resolve ``target.auth_ref`` only if the SCOPE authorized that exact credential.

    Defense-in-depth (audit low): the credential the adapter sends must be one the scope's
    authorization record declared for this target (an identity ``auth_ref``), so a hostile
    ``target.yaml`` cannot make the scanner read an arbitrary local env var (e.g.
    ``env://AWS_SECRET_ACCESS_KEY``) and send it to a merely-allowlisted host. ``None`` auth_ref
    (no credential) is always fine.
    """

    if target.auth_ref is None:
        return None
    scope_target = scope.target(target.id)
    # A target absent from scope is already default-denied by the empty endpoint allowlist
    # (zero egress), so credential authorization is moot there, let that gate handle it. When
    # the target IS in scope, the credential must be one the scope declared for it.
    if scope_target is not None:
        authorized = {i.auth_ref for i in scope_target.identities}
        if target.auth_ref not in authorized:
            raise ValueError(
                f"target {target.id!r} auth_ref {target.auth_ref!r} is not authorized by the "
                f"scope (declared: {sorted(authorized)}); refusing to read an unauthorized "
                "credential"
            )
    return resolve_auth_ref(target.auth_ref)


def check_target_credential(scope: Scope, target: Target) -> None:
    """Assert the scope authorized ``target``'s ``auth_ref`` (raises ``ValueError`` if not).

    The same check :func:`real_adapter_factory` performs, exposed so a command can run it as
    a pre-flight. The ``--judge`` model skipped it entirely: its credential was resolved from
    the environment on the judge path only, which left the defence alive in one branch and
    dead in the other.
    """

    _authorized_api_key(scope, target)


@dataclass
class _PacedAdapter:
    """Wraps an adapter so every probe passes the campaign's rate gate (S8).

    A fingerprint pass is ~28 requests per target (the carrier layer alone is one per
    registered mutator), and they went out unpaced because they do not travel through the
    runner: the rate ceiling was enforced on the attack path and nowhere else. Same ceiling,
    same gate, one decorator.
    """

    inner: TargetAdapter
    pacer: RateLimiter

    @property
    def id(self) -> str:
        return self.inner.id

    async def send(self, request: ModelRequest) -> ModelResponse:
        await self.pacer.acquire()
        return await self.inner.send(request)

    def capabilities(self) -> Capabilities:
        return self.inner.capabilities()


@dataclass
class _RecordingAdapter:
    """Wraps a probe adapter so every recognition exchange lands in the evidence store.

    A fingerprint pass is 17 requests per target and it left **no trace**: the evidence tree
    could not answer "what did this tool send my endpoint", which is the question the whole
    product is built to answer, and it is exactly what kept a day's worth of probes carrying
    attack framing invisible. Probes are filed under ``probes/``, not ``attempts/``: a probe is
    not an attack attempt, and counting it as one would inflate every attempt-derived number.

    A failed send is recorded too, with its error: "we sent this and got nothing back" is
    evidence, and dropping it would make the tree quietly incomplete.
    """

    inner: TargetAdapter
    evidence: FsEvidenceStore
    run_id: str
    sent: int = 0

    @property
    def id(self) -> str:
        return self.inner.id

    def capabilities(self) -> Capabilities:
        return self.inner.capabilities()

    async def send(self, request: ModelRequest) -> ModelResponse:
        probe = str((request.metadata or {}).get("probe", "probe"))
        attempt_id = f"probe::{probe}#{self.sent}"
        self.sent += 1
        try:
            response = await self.inner.send(request)
        except Exception as exc:
            self.evidence.put_probe(
                self.run_id,
                Attempt(
                    attempt_id=attempt_id,
                    spec_id=PROBE_SPEC_ID,
                    request=request,
                    response=None,
                    error=f"{type(exc).__name__}: {exc}",
                ),
            )
            raise
        self.evidence.put_probe(
            self.run_id,
            Attempt(
                attempt_id=attempt_id,
                spec_id=PROBE_SPEC_ID,
                request=request,
                response=response,
            ),
        )
        return response


def fingerprint_probe(
    scope: Scope,
    target: Target,
    *,
    real_target: Target | None = None,
    rate_rps: float | None = None,
    evidence: FsEvidenceStore | None = None,
    run_id: str | None = None,
    mock_scenario: str | None = None,
) -> ModelFingerprint:
    """Fingerprint ``target`` through the adapter the campaign will use (``-sV``).

    Scope-bound: a live target is probed through its allowlisted endpoint with its
    authorized credential, an offline target through the deterministic mock. ``rate_rps``
    paces the probes exactly like the attack traffic; ``None`` leaves them unpaced, which is
    what an offline mock wants.
    """

    adapter = build_probe_adapter(
        scope, target, real_target=real_target, mock_scenario=mock_scenario
    )
    if rate_rps is not None and rate_rps > 0:
        adapter = cast("TargetAdapter", _PacedAdapter(adapter, RateLimiter(rate_rps)))
    if evidence is not None and run_id is not None:
        # Recording wraps the pacing, so what is stored is what went on the wire.
        adapter = cast("TargetAdapter", _RecordingAdapter(adapter, evidence, run_id))
    return asyncio.run(build_fingerprint_engine().run(adapter))


def build_judge_adapter(scope: Scope, judge_target: Target) -> TargetAdapter:
    """Build the over-the-wire adapter for the ``--judge`` model (contract §5, ADR-0002).

    The ``semantic_judge`` evaluator reaches its LLM-as-judge only through a
    :class:`TargetAdapter`; this constructs one for ``judge_target`` (which must be in the
    same ``scope`` so its endpoint is allowlisted) so a live scan can arbitrate semantic
    verdicts instead of abstaining. A judge target absent from scope gets an empty
    allowlist (default-deny), so a misconfigured judge is refused rather than silently
    sending to an unauthorized endpoint.
    """

    scope_target = scope.target(judge_target.id)
    allowlist = EndpointAllowlist(scope_target.endpoints if scope_target is not None else [])
    api_key = _authorized_api_key(scope, judge_target)
    return build_real_adapter(judge_target, allowlist, api_key=api_key)


def real_adapter_factory(
    scope: Scope,
    target: Target,
) -> Callable[[Target, AttackSpec], TargetAdapter]:
    """Build the ``adapter_factory`` for a **real**, non-mock target (contract §5).

    One concrete adapter is constructed up front (a real target's wire shape does
    not vary per spec, unlike the mock's fixture replay) and returned for every
    spec. Its :class:`EndpointAllowlist` is built from the *scope's* declared
    endpoints for this target id - the same allowlist the policy gate already
    checked in :meth:`~ildottore.core.runner.CampaignRunner._run_spec` before the
    adapter was even constructed - so an out-of-scope/off-allowlist target is
    blocked twice over: once by the policy gate (zero adapter build) and again,
    defense-in-depth, inside :meth:`BaseAdapter.send` itself (contract §4 KEEP). A
    target absent from scope gets an empty allowlist (default-deny).
    """

    scope_target = scope.target(target.id)
    allowlist = EndpointAllowlist(scope_target.endpoints if scope_target is not None else [])
    api_key = _authorized_api_key(scope, target)
    commands = tuple(scope_target.commands) if scope_target is not None else ()
    adapter = build_real_adapter(target, allowlist, api_key=api_key, authorized_commands=commands)

    def _factory(_target: Target, _spec: AttackSpec) -> TargetAdapter:
        return adapter

    return _factory


def build_identity_probes(scope: Scope, target: Target) -> list[IdentityProbe]:
    """Per-identity adapters for a multi_identity scan (audit M14, authz_leak).

    One :class:`IdentityProbe` per identity the scope declares for this target: an adapter
    carrying that identity's own resolved credential, plus the tenant-scoped canary it owns.
    The runner sends the attack as each identity and flags a canary reaching a non-owner
    identity. Fewer than two identities yields an empty list (authz_leak stays
    capability_unavailable). The credentials come from the scope's own identity records, so no
    unauthorized env var is read (S6).
    """

    scope_target = scope.target(target.id)
    if scope_target is None or len(scope_target.identities) < 2:
        return []
    allowlist = EndpointAllowlist(scope_target.endpoints)
    commands = tuple(scope_target.commands)
    probes: list[IdentityProbe] = []
    for ident in scope_target.identities:
        adapter = build_real_adapter(
            target,
            allowlist,
            api_key=resolve_auth_ref(ident.auth_ref),
            authorized_commands=commands,
        )
        probes.append(IdentityProbe(identity_id=ident.name, adapter=adapter, canary=ident.canary))
    return probes


# --- target.yaml -------------------------------------------------------------------


def _read_target_yaml(path: Path) -> dict[str, Any]:
    """Parse a ``target.yaml`` into a raw mapping (shared by every reader below).

    A syntax error is re-raised as ``ValueError``, like :func:`load_scope` already does.
    ``yaml.YAMLError`` does not derive from ``ValueError``, so it used to escape the CLI
    handler and surface as an uncaught traceback with **exit 1**, which in this tool means
    "findings below the threshold": a CI step treating 1 as "carry on" would swallow a
    malformed target, and it did so in the two commands whose only job is to validate the
    wiring (``--dry-run`` and ``--estimate``).
    """

    import yaml

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"target file {path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"target file {path} must be a mapping at top level")
    return raw


def load_target(path: Path) -> Target:
    """Load a ``target.yaml`` into a :class:`~ildottore.shared.models.Target`.

    The file declares ``id``/``type`` and an optional ``capabilities`` map, plus the
    optional **live-target** fields ``provider``/``endpoint``/``model``/``auth_ref``/
    ``sampling_defaults`` (``specs/targets/example-openai.yaml``) that
    :func:`real_adapter_factory` routes on. ``auth_ref`` is carried as the bare
    reference string (e.g. ``env://NAME``) - the secret itself is **never** read
    here (S6); it is resolved only at send time via :func:`resolve_auth_ref`.
    """

    raw = _read_target_yaml(path)
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

    provider = raw.get("provider") if isinstance(raw.get("provider"), str) else None
    endpoint = raw.get("endpoint") if isinstance(raw.get("endpoint"), str) else None
    model = raw.get("model") if isinstance(raw.get("model"), str) else None
    auth_ref = raw.get("auth_ref") if isinstance(raw.get("auth_ref"), str) else None
    sampling_raw = raw.get("sampling_defaults")
    sampling = None
    if sampling_raw is not None:
        if not isinstance(sampling_raw, dict):
            raise ValueError(f"target file {path} 'sampling_defaults' must be a mapping")
        sampling = Sampling.model_validate(sampling_raw)

    transport = raw.get("transport") if isinstance(raw.get("transport"), str) else None
    command_raw = raw.get("command")
    command: list[str] | None = None
    if command_raw is not None:
        if not (isinstance(command_raw, list) and all(isinstance(c, str) for c in command_raw)):
            raise ValueError(f"target file {path} 'command' must be a list of strings")
        command = command_raw

    return Target(
        id=target_id,
        type=target_type,
        capabilities=caps,
        name=name,
        provider=provider,
        endpoint=endpoint,
        model=model,
        auth_ref=auth_ref,
        sampling_defaults=sampling,
        transport=transport,
        command=command,
    )


def load_mock_scenario(path: Path) -> str:
    """Read the optional ``mock_scenario`` selector from a ``target.yaml``.

    Steers the deterministic offline :class:`MockTarget` only (a real u04 adapter
    ignores it). Absent ⇒ ``"bare"`` (the honest default: every spec ``inconclusive``).
    An unknown value is rejected so a typo never silently degrades to a fabricated
    verdict; the runtime :class:`Target` model is unchanged (this is composition config).
    """

    raw = _read_target_yaml(path)
    scenario = raw.get("mock_scenario", "bare")
    if not isinstance(scenario, str) or scenario not in MOCK_SCENARIOS:
        raise ValueError(
            f"target file {path} has invalid mock_scenario {scenario!r}; "
            f"expected one of {', '.join(MOCK_SCENARIOS)}"
        )
    return scenario


def target_uses_mock(path: Path) -> bool:
    """True when ``target.yaml`` at ``path`` should route through the offline mock.

    A target is a mock target when it declares an explicit ``mock_scenario``
    selector, or its ``endpoint`` is absent/empty, or that endpoint uses the
    ``mock://`` scheme. Anything else - a real ``provider`` + non-``mock://``
    ``endpoint`` and no ``mock_scenario`` - is a **real** over-the-wire target
    and routes through :func:`real_adapter_factory` instead (contract §5 acceptance:
    existing mock-only ``target.yaml`` files, which never set ``endpoint``, are
    completely unaffected by this - they keep resolving here to ``True``).
    """

    raw = _read_target_yaml(path)
    if "mock_scenario" in raw:
        return True
    # A stdio MCP target authorizes by command line, not an endpoint URL, so it is a real
    # over-the-wire (subprocess) target even though it declares no ``endpoint``.
    provider = str(raw.get("provider") or "").strip().lower()
    transport = str(raw.get("transport") or "").strip().lower()
    if provider == "mcp" and transport == "stdio" and raw.get("command"):
        return False
    endpoint = raw.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint:
        return True
    return endpoint.startswith("mock://")


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
    rate_rps: float | None = None,
    n: int = 5,
    hardened: bool = False,
    mock_scenario: str | None = None,
    real_target: Target | None = None,
    judge_target: Target | None = None,
) -> BuiltRunner:
    """Assemble the whole middle tier into a :class:`CampaignRunner` (contract §5.2).

    Every concrete is built here and injected through a ``shared.protocols`` seam;
    ``core`` sees only interfaces. The offline mock's replay is chosen by
    ``mock_scenario`` (``bare`` | ``vulnerable`` | ``hardened``): ``vulnerable``
    replays each spec's ``fixtures.vulnerable`` (real ``fail`` findings), ``hardened``
    its ``fixtures.hardened`` (real ``pass``), ``bare`` a generic response
    (``inconclusive``). When ``mock_scenario`` is ``None`` the legacy ``hardened`` flag
    decides (``True`` ⇒ hardened, ``False`` ⇒ vulnerable) - preserving prior behavior.

    ``real_target`` (u04, contract §5 acceptance) overrides all of the above with
    :func:`real_adapter_factory`: the campaign sends real requests to ``real_target``'s
    declared provider/endpoint. There is no offline fixture to replay for a live
    target, so the ``semantic_judge`` evaluator stays unregistered - it abstains
    (``inconclusive``) rather than fabricate a verdict (contract §4 KEEP), exactly the
    same honest default a ``bare`` mock run gets.
    """

    resolved_pack = pack if pack is not None else build_permissive_pack(specs)
    policy = build_policy_engine(scope, resolved_pack, safety=safety)
    mutators = build_mutator_registry()
    scorer = DefaultRiskScorer()
    evidence = build_evidence_store(evidence_root, planted_canaries=planted_secrets(specs))
    runs = build_run_store(run_db)
    # A live judge model (--judge) supplies semantic_judge for real runs (and overrides
    # the deterministic scenario-judge offline if given). Absent one, a live run leaves
    # semantic_judge unregistered (it abstains) and an offline run uses the scenario judge.
    judge_adapter = build_judge_adapter(scope, judge_target) if judge_target is not None else None

    if real_target is not None:
        evaluators = build_evaluator_registry(judge=judge_adapter)
        factory = real_adapter_factory(scope, real_target)
    else:
        # Resolve the effective offline scenario (mock_scenario wins; else the legacy
        # hardened flag maps to hardened/vulnerable) so the deterministic judge below
        # agrees with the fixtures being replayed.
        effective_scenario = mock_scenario or ("hardened" if hardened else "vulnerable")
        offline_judge = judge_adapter
        if offline_judge is None:
            offline_judge = scenario_judge_adapter(effective_scenario)
        evaluators = build_evaluator_registry(judge=offline_judge)
        if mock_scenario is not None:
            factory = scenario_adapter_factory(mock_scenario)
        else:
            factory = hardened_adapter_factory if hardened else mock_adapter_factory

    # PolicyEngine structurally satisfies the runner's PolicyGate protocol (its
    # ``check`` returns a CheckResult with ``.allowed``/``.reason``); the cast makes
    # that explicit for the type checker (the runner's own docstring asserts this).
    # Multi-identity execution (authz_leak, audit M14) is a live-target capability: for a real
    # target the runner sends the attack as each scope identity and collects the responses.
    identity_adapters: Callable[[Target], list[IdentityProbe]] | None = None
    if real_target is not None:
        identity_adapters = lambda t: build_identity_probes(scope, t)  # noqa: E731

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
        identity_adapters=identity_adapters,
        now=deterministic_clock(),
        n=n,
        concurrency=concurrency,
        timeout_s=timeout_s,
        # Pacing applies to traffic that actually leaves the process. An offline mock
        # campaign passes ``None`` (see ``execute_run``), which is the one case where
        # ignoring a rate is correct rather than silent, because the CLI prints it.
        rate_rps=rate_rps,
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
