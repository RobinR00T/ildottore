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

import os
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import SplitResult, unquote, urlsplit

from pydantic import ConfigDict, StrictStr, ValidationError, create_model

from ildottore.adapters import (
    AdapterStatusError,
    AnthropicAdapter,
    MCPAdapter,
    OpenAIAdapter,
    ProviderFilterBlock,
    RestAdapter,
    RestTemplate,
    RetryConfig,
    WebSocketAdapter,
)
from ildottore.adapters.anthropic import sent_sampling as anthropic_sent_sampling
from ildottore.adapters.anthropic import takes_no_sampling
from ildottore.adapters.base import CredentialTooShort, refuse_short_credential
from ildottore.adapters.comprehending import ComprehendingMock
from ildottore.adapters.mock import MockScenario, MockTarget, bare_scenario
from ildottore.adapters.openai import sent_sampling as openai_sent_sampling
from ildottore.adapters.websocket import (
    CONNECTION_PLACEHOLDERS,
    MESSAGES,
    PROMPT,
    RESERVED,
    RESERVED_HEADERS,
    TOKEN,
    placeholders,
)
from ildottore.cli import interrupts
from ildottore.config import SafetyFlags
from ildottore.core.budgets import BudgetExhausted, BudgetLedger, Spend
from ildottore.core.execute import default_is_env_error, is_provider_filter_block
from ildottore.core.metering import MeteredAdapter, SendMeter
from ildottore.core.pacing import RateLimiter
from ildottore.core.planner import IDENTITY_MUTATOR
from ildottore.core.runner import (
    SAMPLING_NOT_SENT,
    CampaignRunner,
    IdentityProbe,
    PolicyGate,
    fill_sampling,
    store_withholding,
    sweeps_identities,
    unsent_fields,
)
from ildottore.evaluators import build_default_registry as build_evaluator_registry
from ildottore.fingerprint import FingerprintEngine
from ildottore.fingerprint.layers import CarrierLayer, default_layers
from ildottore.mutators import build_default_registry as build_mutator_registry
from ildottore.policy import (
    EndpointAllowlist,
    Identity,
    PolicyEngine,
    PolicyPack,
    Scope,
    load_scope,
    load_scope_with_digest,
)
from ildottore.policy.scope import MAX_ID_CHARS
from ildottore.redactor import register_known_secret
from ildottore.registry import (
    PATH_CODES,
    PATH_NOT_FOUND_TEXT,
    LintCode,
    LintError,
    Registry,
    load_paths,
    non_json_values,
    non_string_keys,
)
from ildottore.registry import (
    Severity as LintSeverity,
)
from ildottore.reporting import RunStatus, get_reporter
from ildottore.scoring import DefaultRiskScorer
from ildottore.shared.config_errors import (
    cut,
    listed,
    quoted,
    shown_endpoint,
    validation_problems,
    yaml_problem,
)
from ildottore.shared.credential_refs import (
    ENV_NAME_RULE,
    NO_CREDENTIAL,
    env_name_of,
    is_env_name,
    unset_variable,
)
from ildottore.shared.digits import described, too_long
from ildottore.shared.enums import Category, TargetType
from ildottore.shared.files import read_text_capped
from ildottore.shared.filter_stops import (
    documented_stops,
    own_filter_stops_of,
    target_filter_stops,
)
from ildottore.shared.models import (
    AttackSpec,
    Attempt,
    Capabilities,
    ModelFingerprint,
    ModelRequest,
    ModelResponse,
    Sampling,
    SeededSetup,
    Target,
    WebSocketSpec,
)
from ildottore.shared.package_data import BATTERY
from ildottore.shared.protocols import Reporter, TargetAdapter
from ildottore.store import FsEvidenceStore, SqliteRunStore

__all__ = [
    "MOCK_SCENARIOS",
    "PROBE_SPEC_ID",
    "TARGET_PROVIDERS",
    "TARGET_TRANSPORTS",
    "BuiltRunner",
    "ProbeCeilingHit",
    "ProbePass",
    "TargetFile",
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
    "build_scope_with_digest",
    "check_target_credential",
    "comprehending_adapter_factory",
    "deterministic_clock",
    "fingerprint_probe",
    "hardened_adapter_factory",
    "load_mock_scenario",
    "load_target",
    "mock_adapter_factory",
    "planted_secrets",
    "read_target_file",
    "real_adapter_factory",
    "refuse_spec_paths_that_hold_nothing",
    "request_url_for",
    "resolve_auth_ref",
    "sampling_fallback",
    "sampling_written",
    "scenario_adapter_factory",
    "scenario_judge_adapter",
    "scope_endpoint_for",
    "scope_endpoint_of",
    "sent_sampling_for",
    "shown_auth_ref",
    "spec_id_collisions",
    "takes_sampling",
    "target_uses_mock",
    "unset_credentials",
    "utc_timestamp",
    "with_sent_sampling",
    "with_takes_sampling",
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
    run_store: SqliteRunStore | None = None

    def close(self) -> None:
        """Close the run store the runner (and its evidence journal) wrote through.

        It was left to the garbage collector, one unclosed SQLite connection per target.
        """

        if self.run_store is not None:
            self.run_store.close()


# --- registry ---------------------------------------------------------------------


def build_registry(spec_paths: list[Path]) -> Registry:
    """Load + merge every spec/pack under ``spec_paths`` into a :class:`Registry`.

    No code execution, no network - the loader (u02) only walks the filesystem and
    ``yaml.safe_load``s. Load errors are surfaced by ``dottore lint``; here we build
    the queryable registry from whatever parsed.
    """

    return load_registry(spec_paths)[0]


#: The built-in battery, inside the package (``ildottore/battery``), where a source checkout, an
#: editable install and an installed wheel all have it (u12 A-84). It was ``<repo>/specs``, found
#: three directories above this file, which a wheel does not have.
PACKAGED_SPEC_PATH = BATTERY


def is_own_checkout() -> bool:
    """Whether the working directory is the root of the source checkout this package runs from.

    Its ``specs/`` holds the unit contracts, not attack specs, since the battery moved into the
    package (u12 A-84), so with no spec path the commands read the built-in battery there. The
    one exception to reading ``specs/`` whenever it is here, and a deterministic one, on the
    checkout's shape: the battery is ``<root>/src/ildottore/battery``, the working directory
    resolves to ``<root>``, and ``<root>/pyproject.toml`` names the project ``ildottore``. The
    working directory three above the battery alone was fooled by ``pip install --target
    <dir>/deps``: from ``<dir>`` the operator's ``specs/`` went unread and the built-in 75 ran
    under an "own checkout" note (round 2 of the pre-merge audit of A-84, HIGH 1).
    """

    import tomllib

    try:
        battery = PACKAGED_SPEC_PATH.resolve()
        package, src = battery.parent, battery.parent.parent
        if battery.name != "battery" or package.name != "ildottore" or src.name != "src":
            return False
        root = src.parent
        if Path.cwd().resolve() != root:
            return False
        pyproject = root / "pyproject.toml"
        # A regular file only: opening a FIFO waits for a writer, and a command would hang there
        # (round 3 of the pre-merge audit of A-84, LOW).
        if not pyproject.is_file():
            return False
        project = tomllib.loads(read_text_capped(pyproject)).get("project")
    except (OSError, RuntimeError, tomllib.TOMLDecodeError):
        # The working directory was removed, a link loop, no pyproject.toml or one that is not
        # TOML: not the checkout.
        return False
    return isinstance(project, dict) and project.get("name") == "ildottore"


def default_spec_paths() -> list[Path]:
    """Where every command reads specs when it is given no spec path (u12 A-80, A-84).

    ``specs/`` in the working directory when it is a directory (a project that keeps its own pack
    or specs there, as before), else the built-in battery inside the installed package, else
    ``specs/`` (whose absence the commands report). A ``specs/`` here that holds nothing to read
    is read all the same and refused, exit 3, as before: it is never replaced by the battery, so
    a pack that lost its files, or one ``specs/`` reaches only through a link, fails a pipeline
    instead of passing it on another battery (pre-merge audit of A-84, HIGH 2). The root of this
    package's own checkout (:func:`is_own_checkout`) reads the battery. ``fleet --run`` had no
    ``--spec-path`` and read ``specs/`` only, so it worked from the repository root only.
    """

    local = Path("specs")
    if local.is_dir() and not is_own_checkout():
        return [local]
    if PACKAGED_SPEC_PATH.is_dir():
        return [PACKAGED_SPEC_PATH]
    return [local]


def load_registry(spec_paths: list[Path]) -> tuple[Registry, list[LintError]]:
    """:func:`build_registry`, plus the load-time findings it would otherwise drop.

    For callers that publish a count (``dottore coverage``): a file that failed to load is in
    no numerator, so it has to be reported rather than quietly subtracted.
    """

    registry, errors, _ = load_registry_reading(spec_paths)
    return registry, errors


def load_registry_reading(
    spec_paths: list[Path],
) -> tuple[Registry, list[LintError], list[Path]]:
    """:func:`load_registry`, plus every file the load read (u12 A-80).

    Each ``pack.yaml``, spec and suite file and each media asset a spec inlined: what a run's
    report may not overwrite. A file under a spec path the loader does not read (a report an
    earlier run wrote there) is not one of them.
    """

    result = load_paths(spec_paths)
    # A warning (``FILES_NOT_READ``) is lint's to print: it refuses nothing here.
    errors = [e for e in result.errors if e.severity is LintSeverity.ERROR]
    return Registry.from_packs(result.packs), errors, list(result.files)


def spec_id_collisions(registry: Registry) -> dict[str, list[str]]:
    """Each spec id more than one loaded file declares, with those files in load order.

    ``lint`` reports such a collision (``ID_COLLISION``); a run took the first file and dropped
    the rest without a word, a ``--spec-path`` pack that redeclared a shipped id included (u12
    A-82, CLI audit L2). A file the loader did not record (a pack built in code) reads
    ``<pack id>``.
    """

    files: dict[str, list[str]] = {}
    for pack in registry.packs():
        for index, spec in enumerate(pack.specs):
            files.setdefault(spec.id, []).append(pack.spec_file(index) or f"<pack {pack.id}>")
    # One file read twice (a spec path given twice, or `specs` and `specs/attacks`) declares
    # nothing twice: the same bytes, whichever is taken.
    return {
        spec_id: found
        for spec_id, found in files.items()
        if len({_real(name) for name in found}) > 1
    }


def _real(name: str) -> str:
    """``name`` resolved, to tell one file read twice from two files; as given if it cannot be."""

    try:
        return str(Path(name).resolve())
    except (OSError, RuntimeError, ValueError):
        return name


#: For each command's verb, how it is given a spec path and how it is named, for the refusal of
#: a default spec path that is not there (u12 A-80's wording).
_DEFAULT_SPEC_PATH_READERS: dict[str, tuple[str, str]] = {
    "run": ("--spec-path <dir>", "a run"),
    "list": ("--spec-path <dir>", "registry ls"),
    "describe": ("--spec-path <dir>", "describe"),
    "measure": ("the spec path to coverage (dottore coverage <dir>)", "coverage"),
}


def refuse_spec_paths_that_hold_nothing(
    load_errors: list[LintError], *, to: str, default: bool = False
) -> None:
    """Refuse a spec path that does not exist or yields no spec or suite (u12 A-82).

    ``registry ls --spec-path nonexistent`` warned and exited 0, ``coverage`` of a missing or
    empty path printed 0% and exited 0, and ``run`` said "spec file(s) failed to load" of a
    path that holds none (CLI audit L7, M9). ``to`` is the command's verb (``run``, ``list``).
    ``default`` says no spec path was given: one that is not there is then the default
    (``default_spec_paths``), and the refusal says how to pass one and what is read without it
    (u12 A-80: a run from anywhere but the repository root read "spec file(s) failed to load").
    """

    found = [e for e in load_errors if e.code in PATH_CODES]
    if not found:
        return
    if default and all(e.code is LintCode.PATH_NOT_FOUND for e in found):
        flag, reader = _DEFAULT_SPEC_PATH_READERS.get(to, ("--spec-path <dir>", "the command"))
        names = ", ".join(e.message.removeprefix(PATH_NOT_FOUND_TEXT) for e in found)
        raise ValueError(
            f"spec path not found: {names}. Pass {flag}; without it {reader} reads specs/ in the "
            "working directory when there is one, else the built-in battery inside the installed "
            "package, which this installation lacks."
        )
    raise ValueError(f"a spec path gives nothing to {to}: {'; '.join(e.message for e in found)}")


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
    journal: SqliteRunStore | None = None,
) -> FsEvidenceStore:
    """Content-addressed, redact-at-rest evidence store rooted at ``root`` (u10).

    ``journal`` (the campaign's run store) records every attempt artifact as it is written.
    """

    return FsEvidenceStore(root, planted_canaries=planted_canaries, journal=journal)


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
    include_needs_review: bool = False,
) -> Reporter:
    """Instantiate the u11 reporter for ``fmt`` (json|html|sarif|junit).

    ``planned_specs``/``run_status`` let a report state what the run intended and whether it
    finished, instead of presenting a budget-truncated campaign as a complete one.
    ``include_needs_review`` is the run's flag: with it, a SARIF fail that needs review keeps
    its band's level, as it trips ``--fail-on``.
    """

    return get_reporter(
        fmt,
        specs=specs,
        planned_specs=planned_specs,
        run_status=run_status,
        include_needs_review=include_needs_review,
    )


# --- fingerprint -------------------------------------------------------------------


def build_fingerprint_engine() -> FingerprintEngine:
    """The fingerprint engine: u09's six self-contained layers plus the carrier layer.

    The carrier layer is assembled here because it probes with u05's mutators and u09 may not
    import them. It is what makes ``-sV`` change the battery rather than only name the model:
    the planner orders each spec's mutators by what this target demonstrably still
    understands (``fingerprint.layers.carrier``).

    A probe whose reply comes back refused (an environment failure the attack phase would not
    retry, by its own predicate) is a failed probe (u09 §7 A-35, OD-23): one such reply used to
    stop ``run -sV`` before any attack while it only failed an attempt without it. So is a 4xx
    to the guardrail layer's benign request (:func:`refused_request`, u09 §7 A-67), and a carrier
    probe the provider's input filter refused (``is_provider_filter_block``, OD-41: a carrier is
    an encoded instruction, which Azure's Prompt Shields refuses as a prompt attack).
    """

    registry = build_mutator_registry()
    carriers = [registry.get(name) for name in registry.names() if name != IDENTITY_MUTATOR]
    return FingerprintEngine(
        layers=[*default_layers(), CarrierLayer(carriers)],
        is_env_error=default_is_env_error,
        is_request_refused=refused_request,
        is_prompt_filtered=is_provider_filter_block,
    )


def refused_request(exc: BaseException) -> bool:
    """A request the endpoint refused with a 4xx (u09 §7 A-67).

    The engine asks only about a profile-only probe (the guardrail layer's benign request), which
    goes out after seven probes the same credential and route got answers to, so a 4xx to it is
    about its prompt: Azure OpenAI's prompt filter answers a blocked prompt with HTTP 400 and the
    error code ``content_filter``, and stopped ``-sV`` on it (pre-merge audit of ``cd413c0``).
    A 3xx or a 5xx the retries do not cover is not one. An undocumented 4xx says nothing about a
    filter; the provider's documented refusal (below) is the one input-filter signal the pass can
    see, and the engine reads it as one (``input_filter: true``, OD-40, decided 2026-10-11).

    Since OD-41 the adapters raise Azure's refusal as a ``ProviderFilterBlock``, which carries its
    status but is not an ``AdapterStatusError``, and Gemini's prompt block (a success body) as
    one too: both are refusals of the prompt, so both are read here, and the failed probe is
    named ``guardrail/guardrail_benign: ProviderFilterBlock``. On any other probe they still
    stop the pass, as before.
    """

    if isinstance(exc, ProviderFilterBlock):
        return True
    return isinstance(exc, AdapterStatusError) and 400 <= exc.status_code < 500


def build_probe_adapter(
    scope: Scope,
    target: Target,
    *,
    real_target: Target | None = None,
    scenario: MockScenario | None = None,
    mock_scenario: str | None = None,
    retry: RetryConfig | None = None,
) -> TargetAdapter:
    """The adapter a fingerprint/discovery probe should talk to (``-sV``, ``dottore
    fingerprint``).

    ``retry`` reaches a live adapter only: ``-sV`` passes :data:`NO_ADAPTER_RETRIES` and lets a
    :class:`MeteredAdapter` own the retries, so each one is paced and debited.

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
        live = build_real_adapter(
            real_target, allowlist, api_key=_authorized_api_key(scope, real_target), retry=retry
        )
        # The fingerprint's capability layer and `capability_guess` read what the TARGET FILE
        # declares, as docs/10 says. They read the adapter class's defaults (OpenAI: tools,
        # streaming, seed and logprobs all true), so `tools: false` in target.yaml still fed
        # `tools=true` to the family signals (audit of the fingerprint).
        return cast("TargetAdapter", _DeclaredCapabilities(live, real_target.capabilities))
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


def utc_timestamp() -> str:
    """The current UTC time as ISO 8601 with seconds and a ``Z``: a run's start and end."""

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


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

    Against the shipped battery no spec decides. Two used to, in opposite directions, because
    a text oracle scores a reply that is evidence of neither: `DOS-TOKEN-AMP-001` looked for a
    secure marker the canned string does not carry and reported `fail`; `MCP-TOOLPOISON-001`
    looked for the ABSENCE of injection markers, which the canned string trivially satisfies,
    and reported `pass`. OD-16 was decided on 2026-10-11 under the owner's delegation
    (ADR-0007 option B): the first keys on the amplification itself and the second pairs its
    text oracle with a judge, which a bare run leaves unregistered. That is a property of the
    specs' oracles, not of this factory, and `tests/cli/test_scenario_mode.py` and
    `tests/battery/test_irrelevant_reply.py` pin it so the claim and the code cannot drift apart.
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
    (``inconclusive``), and an unconfigured judge holds every aggregate it is in
    ``inconclusive`` unless a deterministic evaluator fails (OD-19). For a
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


def shown_auth_ref(auth_ref: str) -> str:
    """How an error may quote an ``auth_ref``: a reference (``scheme://NAME``) as written, a
    literal never.

    A raw key pasted where a reference belongs used to be quoted back. The CLI's redactor
    masked it only when its entropy was high enough: about 1 in 20 random 64-hex keys and 3 in 4
    32-hex keys were printed in clear (fourth audit of the residuals). A reference is quoted up
    to 300 characters (``quoted``): one of a million characters printed the refusal whole
    (clause A-51). One holding an ``@`` is quoted as an endpoint is (``shown_endpoint``),
    without what precedes the last ``@`` of its authority: a URL pasted with its password
    (``https://user:<password>@host``) was cut before the redactor read it, so a password
    whose ``@`` fell past the cut was printed (#96).
    """

    if "://" not in auth_ref:
        return "a literal value (not shown)"
    return shown_endpoint(auth_ref) if "@" in auth_ref else quoted(auth_ref)


def resolve_auth_ref(auth_ref: str | None) -> str | None:
    """Resolve a target's ``auth_ref`` **reference** to its secret value (S6).

    Only the ``env://NAME`` scheme is supported in MVP-1 (matches every
    ``auth_ref`` in ``examples/target.*.yaml``); the environment is read here, at send-time
    construction - never earlier, and the resolved value is never logged (the
    caller passes it straight into the adapter's ``api_key``, which itself never
    appears in evidence: the redactor masks ``raw_ids``, and the value never enters
    a ``ModelRequest``/``ModelResponse``). ``None`` in ⇒ ``None`` out (no auth
    configured), and so does ``env://NONE``, the reference that names no credential, without
    reading a variable. An unsupported scheme (e.g. ``vault://``, deferred) raises rather
    than silently sending an unauthenticated request, and so does a name that is no variable's.
    A variable that is not set still resolves to ``None`` here: a live run refuses it before
    anything is sent (:func:`unset_credentials`), and a dry run warns about it (u12 A-82).
    """

    if auth_ref is None or auth_ref == NO_CREDENTIAL:
        # `env://NONE` says "no credential" (u12 A-82): its variable is never read, so a
        # `NONE` some other tool exported is not sent as a key.
        return None
    name = env_name_of(auth_ref)
    if name is not None:
        if not is_env_name(name):
            # The loaders refuse such a file; a reference built in code is refused here, and
            # never quoted: it was a key pasted where a variable's name belongs (M8).
            raise ValueError(
                "auth_ref names no environment variable after env:// (a name is "
                f"{ENV_NAME_RULE}); write the variable's name, never the key"
            )
        raw = os.environ.get(name)
        # Registered before it is used, raw AND stripped: every Redactor in the process then
        # masks it by value, including inside an HTTP library's error text. And stripped,
        # because a key never carries surrounding whitespace: a trailing CR from a
        # Windows-edited .env made httpx reject the header and quote the key in the error,
        # which reached all four report formats (audit 2026-10-03, SEC-01).
        register_known_secret(raw)
        if raw is None:
            return None
        value = raw.strip()
        # A control character INSIDE the key (a newline from a pasted multi-line value) cannot
        # be stripped and can never be a valid header: httpx rejects it and quotes the key,
        # repr-escaped, in its error. Refused here, before any request, with a message that
        # names the variable and never the value (review of PR #32).
        if any(not ch.isprintable() for ch in value):
            raise ValueError(
                f"the credential in {quoted(name)} contains a control character (a newline or "
                "similar); fix the variable, it cannot be sent as a header"
            )
        return value
    raise ValueError(
        f"unsupported auth_ref scheme in {shown_auth_ref(auth_ref)}; only 'env://NAME' is supported"
    )


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


#: Target and judge adapters used by a campaign retry nothing themselves: ``execute_attempt``
#: (and, for the judge, ``core.metering.MeteredAdapter``) own the retries and debit and pace
#: each one. With both layers retrying, a 429 storm made one attempt 12 wire requests, billed
#: as 4 and paced as 4, in bursts 50 ms apart (audit 2026-10-03, F10).
NO_ADAPTER_RETRIES = RetryConfig(max_retries=0)


def build_real_adapter(
    target: Target,
    allowlist: EndpointAllowlist,
    *,
    api_key: str | None,
    authorized_commands: tuple[str, ...] = (),
    retry: RetryConfig | None = None,
) -> TargetAdapter:
    """Construct the concrete over-the-wire adapter for ``target`` (contract §5).

    Routes on ``target.provider``: ``openai`` → :class:`OpenAIAdapter`,
    ``anthropic`` → :class:`AnthropicAdapter`, ``mcp`` → the read-only
    :class:`MCPAdapter` (Model Context Protocol server discovery), ``websocket`` → the
    template-driven :class:`WebSocketAdapter` (its wire shape is the target file's
    ``websocket:`` block), anything else → the
    generic :class:`RestAdapter` (the long-tail escape hatch, ADR-0002). ``target.endpoint``
    is the **full** request URL (``examples/target.example-openai.yaml``); its origin
    becomes the adapter's ``base_url`` and its path is either the adapter's own
    fixed ``_endpoint_path`` (openai/anthropic) or the ``RestTemplate.path`` (rest) -
    either way ``adapter._full_url()`` reconstructs the declared endpoint exactly, so
    the allowlist gate (built from the same scope) authorizes the identical URL the
    adapter will call.
    """

    extra: dict[str, Any] = {"retry": retry} if retry is not None else {}
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
                **extra,
                transport="stdio",
                command=tuple(target.command or ()),
                authorized_commands=authorized_commands,
            )
        # MCP posts JSON-RPC to the endpoint PATH itself (e.g. /mcp), so the adapter keeps the
        # full URL as base_url (unlike openai/anthropic, whose path is a fixed _endpoint_path).
        refuse_short_credential(target.id, api_key, target.endpoint)
        return MCPAdapter(
            id=target.id,
            base_url=target.endpoint or origin,
            allowlist=allowlist,
            api_key=api_key,
            model=target.model,
            **extra,
        )
    # Refused before anything is built, so a run sends nothing to the target when the judge's is
    # the short one (u04 A-78); each adapter refuses it again before its own first request.
    refuse_short_credential(target.id, api_key, target.endpoint)
    if provider == "websocket":
        if target.websocket is None:  # load_target refuses the file; a hand-built Target
            raise ValueError(
                f"target {target.id!r} is provider websocket and has no websocket block"
            )
        # The full URL is dialled as declared (no query, no userinfo: the loader refuses both),
        # so the gate and the socket agree on one string.
        return WebSocketAdapter(
            id=target.id,
            url=request_url_for(target) or (target.endpoint or ""),
            allowlist=allowlist,
            spec=target.websocket,
            api_key=api_key,
            model=target.model,
            declared=target.capabilities,
            **extra,
        )
    # The DECLARED path wins over the provider default: a gateway (Azure OpenAI, LiteLLM, a
    # corporate proxy) hosts the same API under a prefix, and discarding it both sent the
    # wrong URL and tripped the allowlist built from the declared one.
    declared_path = parts.path or None
    # A model that takes no temperature or top_p is sent neither (u12 A-68).
    takes = takes_sampling(target)[0]
    if provider == "openai":
        return OpenAIAdapter(
            id=target.id,
            base_url=origin,
            allowlist=allowlist,
            api_key=api_key,
            model=target.model,
            **extra,
            path_override=declared_path,
            sampling_enabled=takes,
            declared_filter_stops=_declared_filter_stops(target),
        )
    if provider == "anthropic":
        return AnthropicAdapter(
            id=target.id,
            base_url=origin,
            allowlist=allowlist,
            api_key=api_key,
            model=target.model,
            **extra,
            path_override=declared_path,
            sampling_enabled=takes,
            declared_filter_stops=_declared_filter_stops(target),
        )
    if provider not in ("", "rest"):
        # The loader refuses such a file (u12 A-82); a target built in code is refused here
        # rather than sent the REST adapter's `{"prompt": ...}` body, as `provider: skynet` was.
        raise ValueError(
            f"target {target.id!r} has unknown provider {quoted(target.provider)}; expected one "
            f"of {', '.join(TARGET_PROVIDERS)}"
        )
    template = RestTemplate(path=parts.path or "/")
    return RestAdapter(
        id=target.id,
        base_url=origin,
        allowlist=allowlist,
        api_key=api_key,
        model=target.model,
        template=template,
        # A target file declares no template: the generic one reads the text at `text`, and it
        # is not told to check a template it cannot write (OD-21 audit, LOW 2).
        advice=REST_TARGET_FILE_ADVICE,
        **extra,
    )


#: The ``provider`` values a target file may give (read stripped and case-folded). Absent, a live
#: endpoint routes to the generic REST adapter, as ``rest`` does (u12 A-82, CLI audit M5).
TARGET_PROVIDERS: tuple[str, ...] = ("anthropic", "mcp", "openai", "rest", "websocket")
#: The ``transport`` values: ``http`` (the default) and ``stdio``, a local MCP server.
TARGET_TRANSPORTS: tuple[str, ...] = ("http", "stdio")


def _declared_filter_stops(target: Target) -> frozenset[str] | None:
    """The target file's ``filter_stops`` as the adapter reads them, or ``None`` (u04 A-79)."""

    return None if target.filter_stops is None else documented_stops(target.filter_stops)


def _filter_stops(path: Path, raw: object, provider: object) -> list[str] | None:
    """A target file's ``filter_stops``, checked (u04 A-79; pre-merge audit of ``a55710e9``).

    For an ``openai`` or ``anthropic`` target only, and only the provider's own words: ``[]``
    switches the provider's filter reading off, on a reply with text or a tool call and on
    Azure's 400, for an endpoint that speaks its API and has no such filter behind it (a local
    server); an empty reply on the provider's own word is still its filter's (pre-merge audit of
    ``10cb526b``, MEDIUM). Refused anywhere else: a WebSocket target declares its stops under
    ``websocket.response.filter_stops``, and a REST target file reads none. The rule is
    ``shared.filter_stops.target_filter_stops``, which the ``Target`` model applies too; here it
    is read first, so the refusal names the file and the field, never a value (A-53).
    """

    if raw is None:
        return None
    try:
        own_filter_stops_of(provider)
        if not (isinstance(raw, list) and all(isinstance(stop, str) for stop in raw)):
            raise ValueError("'filter_stops' must be a list of stop reasons")
        return sorted(target_filter_stops(provider, raw))
    except ValueError as exc:
        raise ValueError(f"target file {path} {exc}") from exc


#: What a target file's ``provider: rest`` target is told to check when no reply can be read.
REST_TARGET_FILE_ADVICE = (
    "check the target file's endpoint and provider: a `provider: rest` target reads a JSON object "
    "with the reply's text at `text` (another shape needs a RestTemplate, which only the Python "
    "API takes)"
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
            declared = listed(sorted(authorized), show=shown_auth_ref)
            raise ValueError(
                f"target {quoted(target.id)} auth_ref {shown_auth_ref(target.auth_ref)} is not "
                f"authorized by the scope (declared: {declared}); refusing to read an "
                "unauthorized credential"
            )
    return resolve_auth_ref(target.auth_ref)


#: What a refusal or a dry run's warning about an unset variable advises (u12 A-82).
UNSET_CREDENTIAL_ADVICE = (
    "export each variable before the run; a target that takes no credential leaves auth_ref "
    "out of its target file, and a scope identity that carries none writes env://NONE"
)


def unset_credentials(
    scope: Scope,
    targets: list[Target],
    *,
    judge: Target | None = None,
    specs: list[AttackSpec] | None = None,
) -> list[str]:
    """One phrase per credential a live run would read from a variable that is not set.

    ``targets`` are the ones sent to over the wire. Each one's ``auth_ref``; each identity of its
    scope entry when the scope declares two or more and a spec of ``specs`` sweeps identities on
    it (the sweep sends the attack as each one, ``build_identity_probes``); and the ``--judge``
    model's when it is live. ``env://NONE`` and a target with no ``auth_ref`` send none on
    purpose and are not listed. Names the variable, never a value (CLI audit M4: an unset
    ``env://TYPO`` sent every request without a credential and the run stopped on a bare
    ``HTTP 401``).
    """

    problems: list[str] = []

    def check(who: str, auth_ref: str | None) -> None:
        # The environment is read here, in the wiring, as `resolve_auth_ref` reads it.
        found = unset_variable(auth_ref, os.environ)
        if found is not None and auth_ref is not None:
            name, state = found
            problems.append(
                f"{who} auth_ref {shown_auth_ref(auth_ref)} names the environment variable "
                f"{name}, which is {state}"
            )

    for target in targets:
        check(f"target {quoted(target.id)}", target.auth_ref)
        entry = scope.target(target.id)
        if entry is None or len(entry.identities) < 2:
            continue
        if any(sweeps_identities(spec, target) for spec in specs or []):
            for identity in entry.identities:
                check(
                    f"target {quoted(target.id)} identity {quoted(identity.name)} (the scope's, "
                    "sent by the identity sweep)",
                    identity.auth_ref,
                )
    if judge is not None and request_url_for(judge) is not None:
        check(f"the --judge model {quoted(judge.id)}", judge.auth_ref)
    return problems


def check_target_credential(scope: Scope, target: Target, *, sends: bool = True) -> None:
    """Assert the scope authorized ``target``'s ``auth_ref`` (raises ``ValueError`` if not).

    The same check :func:`real_adapter_factory` performs, exposed so a command can run it as
    a pre-flight. The ``--judge`` model skipped it entirely: its credential was resolved from
    the environment on the judge path only, which left the defence alive in one branch and
    dead in the other.
    """

    api_key = _authorized_api_key(scope, target)
    # A credential the redactor could not mask by value is refused here too, so `--dry-run`, `-sn`
    # and `--estimate` answer what the run would (u04 A-78); a stdio MCP server and an offline
    # mock (``sends`` false) are sent no key. A variable that is not set or holds only blanks is
    # no credential at all: :func:`unset_credentials` says so, a refusal on a live run and a
    # warning on a mode that sends nothing (u12 A-82), rather than "shorter than 8 characters".
    if sends and not _launched_locally(target) and not _variable_unset(target.auth_ref):
        try:
            refuse_short_credential(target.id, api_key, target.endpoint)
        except CredentialTooShort as exc:
            raise ValueError(str(exc)) from None


def check_identity_credentials(scope: Scope, target: Target) -> None:
    """Refuse, pre-flight, a scope identity's credential the identity sweep would refuse.

    The sweep sends a spec once as each scope identity of a live target, with that identity's
    own credential (:func:`build_identity_probes`), which refuses one shorter than
    ``MIN_CREDENTIAL_LEN`` (u04 A-78). `--dry-run`, `-sn` and `--estimate` checked only the
    target's and the judge's credentials, so they exited 0 for a scope whose run then stopped
    at exit 3 (pre-merge audit of A-78, L4). Raises ``ValueError`` with the run's message.

    Two identities whose references name different variables holding one key are refused here
    too (:func:`_refuse_shared_keys`, u01 A-91), before anything is sent.
    """

    scope_target = scope.target(target.id)
    if scope_target is None or len(scope_target.identities) < 2 or _launched_locally(target):
        return
    _refuse_shared_keys(target.id, scope_target.identities)
    for ident in scope_target.identities:
        if _variable_unset(ident.auth_ref):
            continue  # no credential: `unset_credentials` names it when the sweep would send it
        try:
            refuse_short_credential(
                f"{target.id}, identity {quoted(ident.name)}",
                resolve_auth_ref(ident.auth_ref),
                target.endpoint,
            )
        except CredentialTooShort as exc:
            raise ValueError(str(exc)) from None


def _refuse_shared_keys(target_id: str, identities: Sequence[Identity]) -> None:
    """Refuse two identities whose different ``auth_ref`` resolve to one key (u01 A-91).

    The scope refuses two identities with one ``auth_ref``; ``env://KEY_A`` and ``env://KEY_B``
    holding the same key are the same caller under two names, and the sweep read them as two
    (pre-merge audit of A-87, L1). Compared stripped, as :func:`resolve_auth_ref` sends them. An
    unset variable is skipped (:func:`unset_credentials` names it). Neither the key nor the
    variables are quoted: the identities are named. Raises ``ValueError``.
    """

    holders: dict[str, str] = {}
    for ident in identities:
        if _variable_unset(ident.auth_ref):
            continue
        key = resolve_auth_ref(ident.auth_ref)
        if key is None:
            continue  # env://NONE: the scope refuses two of them
        holder = holders.get(key)
        if holder is not None:
            raise ValueError(
                f"target {quoted(target_id)}: identities {quoted(holder)} and "
                f"{quoted(ident.name)} resolve to the same credential, so the identity sweep "
                "would compare one caller with itself; give each identity its own key"
            )
        holders[key] = ident.name


def _variable_unset(auth_ref: str | None) -> bool:
    """True when ``auth_ref`` names an environment variable that is not set or holds only blanks.

    The environment is read here, in the wiring, as :func:`resolve_auth_ref` reads it.
    """

    return unset_variable(auth_ref, os.environ) is not None


def _launched_locally(target: Target) -> bool:
    """True for a stdio MCP target: a local subprocess, sent no key.

    Only the MCP adapter honours ``transport: stdio``; any other provider sends its key over
    the wire whatever the field says, so its credential is checked (pre-merge audit of A-78, L4).
    """

    return (target.provider or "").strip().lower() == "mcp" and (
        target.transport or ""
    ).strip().lower() == "stdio"


@dataclass
class _DeclaredCapabilities:
    """A live probe adapter that reports the capabilities the target file declares."""

    inner: TargetAdapter
    declared: Capabilities

    @property
    def id(self) -> str:
        return self.inner.id

    async def send(self, request: ModelRequest) -> ModelResponse:
        return await self.inner.send(request)

    def capabilities(self) -> Capabilities:
        return self.declared


#: The providers whose adapter puts sampling on the wire: the OpenAI adapter sends
#: ``temperature``, ``top_p``, ``max_tokens`` and ``seed``, the Anthropic one all but ``seed``
#: (the Messages API has none) and no ``top_p`` beside a temperature
#: (:func:`ildottore.adapters.anthropic.sent_sampling`). A REST template, an MCP server and a
#: WebSocket target carry no sampling field, by design: their wire shape is the target file's
#: or the protocol's.
_SAMPLING_FIELDS_SENT: dict[str, frozenset[str]] = {
    "openai": frozenset({"temperature", "top_p", "max_tokens", "seed"}),
    "anthropic": frozenset({"temperature", "top_p", "max_tokens"}),
}


def _provider(target: Target) -> str:
    return (target.provider or "").strip().lower()


def takes_sampling(target: Target) -> tuple[bool, str | None]:
    """Whether ``target`` is sent a ``temperature`` and a ``top_p``, and why not (u12 A-68).

    The file's ``capabilities.sampling`` decides when it says so. Left out, the default rule:
    a ``provider: anthropic`` target whose model is of a family
    :data:`ildottore.adapters.anthropic.MODELS_WITHOUT_SAMPLING` lists takes none (Anthropic's
    API reference says those models refuse them with HTTP 400), every other target takes them.
    ``False`` means its replies are sampled at the model's own default: not temperature-0
    deterministic. Only the OpenAI and Anthropic adapters send sampling at all.
    """

    declared = target.capabilities.sampling
    if declared is not None:
        return declared, (None if declared else "capabilities.sampling is false")
    if _provider(target) == "anthropic" and takes_no_sampling(target.model):
        return False, (
            f"model {target.model} takes none, per adapters.anthropic.MODELS_WITHOUT_SAMPLING; "
            "set capabilities.sampling: true to send them"
        )
    return True, None


def sampling_fallback(target: Target) -> Sampling | None:
    """What of ``target``'s ``sampling_defaults`` a live send to it can carry (OD-39, u12 A-66).

    The block is a fallback: each field fills what the spec, the ``-sV`` probe or the judge
    leaves unset. Only the fields the target's adapter sends are kept, so an attempt never
    records a value that did not go out: none for a REST template, an MCP server or a WebSocket
    target, no ``seed`` for Anthropic, and no ``seed`` for a file whose ``capabilities.seed`` is
    not true (false unless set, as every capability): the file says the provider takes none.
    ``None`` when nothing is left. The caller asks it of a live target only: the offline mock
    sends nothing. What survives here can still be dropped by the adapter's own rule
    (:func:`sent_sampling_for`): Anthropic sends no ``top_p`` beside a temperature.
    """

    if target.sampling_defaults is None:
        return None
    sent = set(_SAMPLING_FIELDS_SENT.get(_provider(target), frozenset()))
    if not target.capabilities.seed:
        sent.discard("seed")
    if not takes_sampling(target)[0]:
        sent -= {"temperature", "top_p"}  # a model that takes neither (A-68)
    kept = {
        name: value
        for name, value in target.sampling_defaults.model_dump(exclude_none=True).items()
        if name in sent
    }
    return Sampling(**kept) if kept else None


def with_takes_sampling(target: Target, takes: bool) -> Target:
    """``target`` declaring ``capabilities.sampling: takes``: a resume that continues as it started.

    Only for the adapters and the records of a resumed run (u12 A-68); the target's digest and
    its report keep the file as written.
    """

    return target.model_copy(
        update={"capabilities": target.capabilities.model_copy(update={"sampling": takes})}
    )


def sampling_written(target: Target) -> Sampling | None:
    """``target``'s ``sampling_defaults`` as its file writes it, for a provider that sends sampling.

    What the record lists as asked for and not sent (``sampling_not_sent``, A-68) is counted from
    this, not from :func:`sampling_fallback`, which has already dropped what the adapter never
    sends. ``None`` for a REST template, an MCP server and a WebSocket target, whose attempts
    record the spec's own sampling and nothing of the block.
    """

    if _provider(target) not in _SAMPLING_FIELDS_SENT:
        return None
    return target.sampling_defaults


def sent_sampling_for(target: Target | None) -> Callable[[Sampling], Sampling] | None:
    """The adapter's own rule for what of a request's sampling goes out, or ``None`` (as asked).

    Anthropic's (:func:`ildottore.adapters.anthropic.sent_sampling`): no ``seed``, and no
    ``top_p`` beside a temperature. The same function builds the request on the wire, so a
    record made through this rule is what went out (u12 A-66). To a target that takes no
    sampling (:func:`takes_sampling`, u12 A-68) neither adapter sends a ``temperature`` or a
    ``top_p``. Otherwise the OpenAI adapter sends what it is asked; a REST template, an MCP server
    and a WebSocket target send no sampling, and their attempts keep recording the spec's own, as
    before.
    """

    if target is None:
        return None
    takes = takes_sampling(target)[0]
    provider = _provider(target)
    if provider == "anthropic":
        return lambda sampling: anthropic_sent_sampling(sampling, sampling_enabled=takes)
    if provider == "openai" and not takes:
        return lambda sampling: openai_sent_sampling(sampling, sampling_enabled=False)
    return None


@dataclass
class _AsSent:
    """An adapter whose every request carries its sampling as it goes out (OD-39, u12 A-66).

    For the sends that are not the runner's own (the ``-sV`` probes, the ``--judge`` model): the
    probe or the judge sets its sampling, ``fallback`` (the target file's ``sampling_defaults``)
    fills what it leaves unset, and ``wire`` (the adapter's own rule) drops what the adapter
    will not send. Wrapped outside a recorder, so the evidence holds the request as it goes out.
    ``written`` is the block as the file writes it, for ``sampling_not_sent``. The runner does
    the same for its attempts (``CampaignRunner._sampling``).
    """

    inner: TargetAdapter
    fallback: Sampling | None
    wire: Callable[[Sampling], Sampling] | None
    written: Sampling | None = None

    @property
    def id(self) -> str:
        return self.inner.id

    async def send(self, request: ModelRequest) -> ModelResponse:
        asked = request.sampling
        if self.fallback is not None:
            asked = fill_sampling(asked or Sampling(), self.fallback)
        sampling = self.wire(asked) if asked is not None and self.wire is not None else asked
        # Counted before the request is compared: a block whose only field never goes out (a
        # seed without `seed: true`) leaves the request as it was, and its probes recorded
        # nothing of it (verification of 569bb3b).
        written = self.written if self.written is not None else self.fallback
        wanted = fill_sampling(request.sampling or Sampling(), written) if written else asked
        dropped = unsent_fields(wanted, sampling)
        if sampling is not request.sampling or dropped:
            update: dict[str, object] = {"sampling": sampling}
            if dropped:  # the record says what did not go out (A-68)
                update["metadata"] = {**(request.metadata or {}), SAMPLING_NOT_SENT: dropped}
            request = request.model_copy(update=update)
        return await self.inner.send(request)

    def capabilities(self) -> Capabilities:
        return self.inner.capabilities()


def with_sent_sampling(
    adapter: TargetAdapter, target: Target | None, *, apply_sampling_defaults: bool = True
) -> TargetAdapter:
    """``adapter`` sending each request's sampling as :class:`_AsSent` does, or as it is.

    ``target`` is the live target (``None`` for the offline mock, which sends nothing). Its
    ``sampling_defaults`` fills what a request leaves unset unless ``apply_sampling_defaults``
    is false (a resume of a run started before the block was applied); the adapter's own rule
    (:func:`sent_sampling_for`) applies either way. Wrap outside a recorder.
    """

    if target is None:
        return adapter
    fallback = sampling_fallback(target) if apply_sampling_defaults else None
    written = sampling_written(target) if apply_sampling_defaults else None
    wire = sent_sampling_for(target)
    if fallback is None and wire is None and written is None:
        return adapter
    return cast("TargetAdapter", _AsSent(adapter, fallback, wire, written))


@dataclass
class _RecordingAdapter:
    """Wraps a probe adapter so every recognition exchange lands in the evidence store.

    A fingerprint pass was 17 requests per target (18 since u09 A-67) and left **no trace**:
    the evidence tree could not answer "what did this tool send my endpoint", which is the
    question the whole product is built to answer, and it is exactly what kept a day's worth of
    probes carrying attack framing invisible. Probes are filed under ``probes/``, not
    ``attempts/``: a probe is not an attack attempt, and counting it as one would inflate every
    attempt-derived number.

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
        # A refused write is stored with the pieces of the reply withheld (A-77), as an
        # attempt's is: a probe ended the pass on it.
        store_withholding(
            self.evidence.put_probe,
            self.run_id,
            Attempt(
                attempt_id=attempt_id,
                spec_id=PROBE_SPEC_ID,
                request=request,
                response=response,
            ),
        )
        return response


class ProbeCeilingHit(Exception):
    """A ``-sV`` probe pass reached ``--budget-requests``; ``requests`` is what it really sent.

    Named so the redactor keeps the name: it masks ``ProbeCeilingReached`` as high entropy, so
    an error line that wrote the class would read ``«REDACTED:high_entropy:...»`` (u01 A-63).
    """

    def __init__(self, requests: int, reason: str) -> None:
        super().__init__(reason)
        self.requests = requests


@dataclass(frozen=True)
class ProbePass:
    """What a ``-sV`` probe pass produced and how many requests it really sent."""

    fingerprint: ModelFingerprint
    #: Wire sends, retries included: what the request ceiling is charged with.
    requests: int


def fingerprint_probe(
    scope: Scope,
    target: Target,
    *,
    real_target: Target | None = None,
    rate_rps: float | None = None,
    evidence: FsEvidenceStore | None = None,
    run_id: str | None = None,
    mock_scenario: str | None = None,
    ledger: BudgetLedger | None = None,
    apply_sampling_defaults: bool = True,
) -> ProbePass:
    """Fingerprint ``target`` through the adapter the campaign will use (``-sV``).

    Scope-bound: a live target is probed through its allowlisted endpoint with its
    authorized credential, an offline target through the deterministic mock. ``rate_rps``
    paces the probes exactly like the attack traffic; ``None`` leaves them unpaced, which is
    what an offline mock wants.

    Every wire send is paced, debited against ``ledger`` and recorded, retries included.
    The live probe adapter used to keep its own two retries under one pacer slot: on a target
    answering 429 to every first send, 17 nominal probes were 34 requests, half of them 53 ms
    after the last, and the ledger was charged 17 (leftovers of the 2026-10-03 audit). Same
    shape as the judge: no adapter retries, a :class:`MeteredAdapter` owns them. A breach of
    the ledger's request ceiling raises :class:`ProbeCeilingHit`, carrying the requests
    really sent.

    The caller owns ``ledger`` so it can read what was sent however the pass ends: an
    environment or product error, Ctrl-C or SIGTERM end it with an exception that carries no
    count, and a resumed run lost those requests (u12 A-46). ``None`` is an unbounded ledger.

    A live target's ``sampling_defaults`` fills what ``PROBE_SAMPLING`` leaves unset (``top_p``
    and ``seed``; temperature 0 and the 512-token cap are the probe's own), and the adapter's
    own rule drops what it does not send (on Anthropic, the ``top_p``), outside the recorder,
    so ``probes/`` holds what went out (OD-39). ``apply_sampling_defaults`` false sends without
    the block: a resume of a run started before the block was applied.
    """

    adapter = build_probe_adapter(
        scope,
        target,
        real_target=real_target,
        mock_scenario=mock_scenario,
        retry=NO_ADAPTER_RETRIES,
    )
    if evidence is not None and run_id is not None:
        # Recording is innermost, so what is stored is every send that went on the wire.
        adapter = cast("TargetAdapter", _RecordingAdapter(adapter, evidence, run_id))
    adapter = with_sent_sampling(
        adapter, real_target, apply_sampling_defaults=apply_sampling_defaults
    )
    meter = SendMeter()
    ledger = ledger if ledger is not None else BudgetLedger()
    metered = MeteredAdapter(inner=adapter, meter=meter)
    try:
        with meter.bound(ledger, RateLimiter(rate_rps)):
            fingerprint = interrupts.run_until_stopped(build_fingerprint_engine().run(metered))
    except BudgetExhausted as exc:
        raise ProbeCeilingHit(ledger.spend().requests, str(exc)) from exc
    return ProbePass(fingerprint=fingerprint, requests=ledger.spend().requests)


def build_judge_adapter(
    scope: Scope,
    judge_target: Target,
    *,
    meter: SendMeter | None = None,
    apply_sampling_defaults: bool = True,
) -> TargetAdapter:
    """Build the over-the-wire adapter for the ``--judge`` model (contract §5, ADR-0002).

    The ``semantic_judge`` evaluator reaches its LLM-as-judge only through a
    :class:`TargetAdapter`; this constructs one for ``judge_target`` (which must be in the
    same ``scope`` so its endpoint is allowlisted) so a live scan can arbitrate semantic
    verdicts instead of abstaining. A judge target absent from scope gets an empty
    allowlist (default-deny), so a misconfigured judge is refused rather than silently
    sending to an unauthorized endpoint.

    The judge's own target file's ``sampling_defaults`` (never the scanned target's) fills what
    the judge leaves unset: it sets ``temperature`` (0, then 0.5 for the consistency pass) and
    ``top_p`` 1.0, so ``max_tokens`` and ``seed`` are what the block can add (OD-39). On an
    Anthropic judge its ``top_p`` is not sent beside the temperature (the adapter's rule).
    ``apply_sampling_defaults`` false sends without the block: a resume of a run started before
    the block was applied.
    """

    scope_target = scope.target(judge_target.id)
    allowlist = EndpointAllowlist(scope_target.endpoints if scope_target is not None else [])
    api_key = _authorized_api_key(scope, judge_target)
    defaults = apply_sampling_defaults
    if meter is None:
        live = build_real_adapter(judge_target, allowlist, api_key=api_key)
        return with_sent_sampling(live, judge_target, apply_sampling_defaults=defaults)
    # Metered: every judge send is paced and debited from the campaign's own ceilings, and
    # the wrapper owns the retries so none of them goes uncounted (F6 / F-7 / F10).
    inner = build_real_adapter(judge_target, allowlist, api_key=api_key, retry=NO_ADAPTER_RETRIES)
    sent = with_sent_sampling(inner, judge_target, apply_sampling_defaults=defaults)
    return MeteredAdapter(inner=sent, meter=meter)


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
    adapter = build_real_adapter(
        target,
        allowlist,
        api_key=api_key,
        authorized_commands=commands,
        retry=NO_ADAPTER_RETRIES,
    )

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

    Each probe also says whether the attempts are sent as that identity (``sends_attempts``, u08
    A-87): the target file's ``auth_ref`` is the identity's, which :func:`_authorized_api_key`
    requires of any credential the target file names, or neither names one (no ``auth_ref``, or
    ``env://NONE``). The runner reads every attempt's reply as received by those identities.
    """

    scope_target = scope.target(target.id)
    if scope_target is None or len(scope_target.identities) < 2:
        return []
    if not _launched_locally(target):
        _refuse_shared_keys(target.id, scope_target.identities)  # u01 A-91
    attempts_as = _credential_of(target.auth_ref)
    allowlist = EndpointAllowlist(scope_target.endpoints)
    commands = tuple(scope_target.commands)
    probes: list[IdentityProbe] = []
    for ident in scope_target.identities:
        api_key = resolve_auth_ref(ident.auth_ref)
        if not _launched_locally(target):
            # Named with its identity: the target's own id alone did not say whose key it was.
            identity = f"{target.id}, identity {quoted(ident.name)}"
            refuse_short_credential(identity, api_key, target.endpoint)  # u04 A-78
        adapter = build_real_adapter(
            target,
            allowlist,
            api_key=api_key,
            authorized_commands=commands,
            retry=NO_ADAPTER_RETRIES,
        )
        probes.append(
            IdentityProbe(
                identity_id=ident.name,
                adapter=adapter,
                canary=ident.canary,
                sends_attempts=_credential_of(ident.auth_ref) == attempts_as,
            )
        )
    return probes


def _credential_of(auth_ref: str | None) -> str | None:
    """The credential reference ``auth_ref`` sends, ``None`` for none (no ref, ``env://NONE``)."""

    return None if auth_ref is None or auth_ref == NO_CREDENTIAL else auth_ref


# --- target.yaml -------------------------------------------------------------------


#: The fields of :class:`Target` that are text (``str | None``). ``load_target`` hands them to
#: ``Target`` as written, so anything else there was read as absent (A-53).
_TEXT_FIELDS = tuple(
    name for name, field in Target.model_fields.items() if field.annotation == str | None
)

_TOP_LEVEL_FIELDS: dict[str, Any] = {
    **{
        name: ((StrictStr | None) if name in _TEXT_FIELDS else Any, None)
        for name in Target.model_fields
    },
    "mock_scenario": (Any, None),
}
_TargetFileTopLevel = create_model(
    "_TargetFileTopLevel",
    __config__=ConfigDict(extra="forbid"),
    __doc__=(
        "The top level of a target file: the fields of :class:`Target`, which ``load_target`` "
        "reads, and ``mock_scenario``, which :func:`load_mock_scenario` reads; text where "
        "``Target`` holds text, ``null`` as absent, each block left to its reader. Built from "
        "``Target``, so a field added there is a key the file may hold without a second list to "
        "keep in step (pre-merge audit: PR #87's ``websocket`` field was refused by one)."
    ),
    **_TOP_LEVEL_FIELDS,
)


def _read_target_yaml(path: Path) -> dict[str, Any]:
    """Parse a ``target.yaml`` into a raw mapping (shared by every reader below).

    Its top level is checked against :class:`_TargetFileTopLevel`, so every reader refuses the
    same file: a key none of them reads, or text written as something else (A-53).

    A syntax error is re-raised as ``ValueError``, like :func:`load_scope` already does.
    ``yaml.YAMLError`` does not derive from ``ValueError``, so it used to escape the CLI
    handler and surface as an uncaught traceback with **exit 1**, which in this tool means
    "findings below the threshold": a CI step treating 1 as "carry on" would swallow a
    malformed target, and it did so in the two commands whose only job is to validate the
    wiring (``--dry-run`` and ``--estimate``).
    """

    import yaml

    from ildottore import safe_yaml

    try:
        raw = safe_yaml.safe_load(read_text_capped(path))
    except yaml.YAMLError as exc:
        raise ValueError(f"target file {path} is not valid YAML: {yaml_problem(exc)}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"target file {path} must be a mapping at top level")
    # Every reader below took what it knew and dropped the rest, so `endpont:` for `endpoint`
    # left a live target with no endpoint and `target_uses_mock` ran it on the offline mock
    # (nothing sent to it, the mock's replies scored), and `tools: true` under a `capabilities:`
    # that lost its indent was ignored (A-53, OD-31). Key and reason only, as in the A-45 lines.
    try:
        _TargetFileTopLevel.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(
            f"target file {path} failed validation: {validation_problems(exc)}"
        ) from exc
    return raw


@dataclass(frozen=True)
class TargetFile:
    """A ``target.yaml`` parsed once: the target, and how a run routes it (u12 A-42).

    ``run`` parsed the file again for each thing it asked of it, four times for a mock target and
    five for a live one, so a file that was costly to build cost that many times over, and the
    target handed to the adapter came from another read than the one the scope authorized
    (pre-commit audit of the YAML size cap, 2026-10-07).
    """

    path: Path
    target: Target
    #: :func:`target_uses_mock` of the same text.
    uses_mock: bool
    #: The ``mock_scenario`` as written, checked only when the mock is used, as before.
    scenario_written: object

    def mock_scenario(self) -> str:
        """:func:`load_mock_scenario` of the same text."""

        return _mock_scenario(self.path, self.scenario_written)


def read_target_file(path: Path) -> TargetFile:
    """Parse ``target.yaml`` once into the target and its routing (:class:`TargetFile`)."""

    raw = _read_target_yaml(path)
    return TargetFile(
        path=path,
        target=_target_from(path, raw),
        uses_mock=_uses_mock(raw),
        scenario_written=raw.get("mock_scenario", "bare"),
    )


#: What a target file's ``type`` can say.
_TARGET_TYPES = frozenset(t.value for t in TargetType)


def load_target(path: Path) -> Target:
    """Load a ``target.yaml`` into a :class:`~ildottore.shared.models.Target`.

    The file declares ``id``/``type`` and an optional ``capabilities`` map, plus the
    optional **live-target** fields ``provider``/``endpoint``/``model``/``auth_ref``/
    ``sampling_defaults`` (``examples/target.example-openai.yaml``) that
    :func:`real_adapter_factory` routes on. ``auth_ref`` is carried as the bare
    reference string (e.g. ``env://NAME``) - the secret itself is **never** read
    here (S6); it is resolved only at send time via :func:`resolve_auth_ref`.
    """

    return _target_from(path, _read_target_yaml(path))


def _mcp_capability(
    path: Path, raw: dict[str, Any], caps_raw: dict[str, Any], caps: Capabilities
) -> Capabilities:
    """``capabilities.mcp``: true exactly when the target is an MCP server (OD-44).

    Its provider is ``mcp``: the read-only MCP adapter is the one route that renders a server's
    advertised surface, which the ``mcp``-gated specs read, so the capability follows the provider
    and is not declared. Declared ``false`` on an MCP target, or ``true`` on a live target of any
    other provider, it says what the route does not do, and is refused (the file and the field,
    never the value). An offline mock may declare it: it replays the specs' fixtures, an MCP
    listing included. Decided 2026-10-11 under the owner's delegation; before, nothing gated the
    MCP specs and the default battery sent the discovery request to a chat model as a prompt.
    """

    provider = raw.get("provider")
    is_mcp = isinstance(provider, str) and provider.strip().lower() == "mcp"
    declared = "mcp" in caps_raw
    if is_mcp:
        if declared and not caps.mcp:
            raise ValueError(
                f"target file {path} 'capabilities' declares mcp false for an MCP server "
                "(provider mcp); leave it out: the provider sets it"
            )
        return caps.model_copy(update={"mcp": True})
    if caps.mcp and not _uses_mock(raw):
        raise ValueError(
            f"target file {path} 'capabilities' declares mcp for a live target whose provider is "
            "not mcp: only the MCP adapter reads an MCP server; leave it out, or set provider: mcp"
        )
    return caps


def _endpoint_credentials(parts: SplitResult) -> list[str]:
    """The credentials an endpoint URL's user info carries, as written and percent-decoded.

    The password, when it has one; the user, when it is all the user info says (``https://<token>@``
    or ``https://<token>:@``, the form a token takes as a URL's user, which an HTTP client sends as
    Basic credentials). Beside a password, the user is a name, which the reports keep readable, as
    pip redacts a URL (``user:****@host``, but ``****@host``). Each form is listed, so the value
    the client sends, decoded, is masked as well as the one the file writes (u01/u12 A-83).
    """

    user, password = parts.username, parts.password
    found = [password] if password else [user] if user else []
    return [form for value in found for form in dict.fromkeys((value, unquote(value)))]


def _target_from(path: Path, raw: dict[str, Any]) -> Target:
    """The :class:`Target` a parsed ``target.yaml`` declares (:func:`load_target`)."""

    target_id = raw.get("id")
    if not isinstance(target_id, str) or not target_id:
        raise ValueError(f"target file {path} is missing a string 'id'")
    if len(target_id) > MAX_ID_CHARS:
        # As the scope bounds its ids: a longer one was printed whole by every run that started
        # (OD-27, clause A-57). The value is never quoted, only its length.
        raise ValueError(
            f"target file {path} 'id' is {len(target_id):,} characters, over the "
            f"{MAX_ID_CHARS}-character limit"
        )
    endpoint_raw = raw.get("endpoint")
    if isinstance(endpoint_raw, str):
        # Read as the gate reads it (`request_url_for` strips it): read raw, a leading U+00A0
        # hid the host from this check and urllib's error reached the CLI later, password
        # included (delta audit of A-51).
        try:
            parts = urlsplit(endpoint_raw.strip())
        except ValueError as exc:
            # urllib refuses a host it cannot read (a bracket, a host NFKC turns into a path)
            # with no file named, and quoted the whole value for some (900 KB: pre-merge audit
            # of A-51). Not quoted here, as the URL can hold a password.
            raise ValueError(
                f"target file {path} 'endpoint' is not a URL that can be read (its host)"
            ) from exc
        # A credential in the endpoint URL is one the process now holds: mask it by value
        # everywhere, not only where it still sits inside a URL (SEC-02, u01/u12 A-83).
        for credential in _endpoint_credentials(parts):
            register_known_secret(credential)
    # Required, as the manual says: it defaulted to `model`, and since OD-18 a `model` target
    # gets a spec's documents, tools and memory in-band, so a deployed application's file
    # without the line was sent a synthetic scene and labelled so (pre-merge audit of #50).
    type_raw = raw.get("type")
    if type_raw is None:
        raise ValueError(
            f"target file {path} is missing 'type'; expected one of "
            f"{', '.join(t.value for t in TargetType)}"
        )
    # Refused before the enum looks it up: its own error builds the whole repr of the value, and
    # a 90 KB list of aliases was 200,080,026 characters of it before the node cap (audit of A-51);
    # under that cap it can still be tens of megabytes.
    if not isinstance(type_raw, str) or type_raw not in _TARGET_TYPES:
        raise ValueError(
            f"target file {path} has invalid type {quoted(type_raw)}; "
            f"expected one of {', '.join(t.value for t in TargetType)}"
        )
    target_type = TargetType(type_raw)
    # Absent or null is no capabilities, as an absent `sampling_defaults` is no sampling; anything
    # else is a mapping of the keys `Capabilities` knows. `false`, `0`, `[]` and `""` read as none
    # and an unknown key was dropped, so `tool: true` (for `tools`) ran the target with tools off
    # and took the tool specs out of the plan without a word (A-50, OD-29).
    caps_raw = raw.get("capabilities")
    if caps_raw is None:
        caps_raw = {}
    if not isinstance(caps_raw, dict):
        raise ValueError(f"target file {path} 'capabilities' must be a mapping")
    # Field and reason only, as the scope, fleet and pack loaders give them: pydantic's own text
    # ran to four lines, quoted the value written and did not name the file (A-45).
    try:
        caps = Capabilities.model_validate(caps_raw)
    except ValidationError as exc:
        raise ValueError(
            f"target file {path} 'capabilities' failed validation: {validation_problems(exc)}"
        ) from exc
    caps = _mcp_capability(path, raw, caps_raw, caps)
    # Text or absent: `_read_target_yaml` refuses anything else, once read as absent (A-53).
    name = raw.get("name")

    provider = raw.get("provider")
    endpoint = raw.get("endpoint")
    model = raw.get("model")
    auth_ref = raw.get("auth_ref")
    _check_env_reference(path, "auth_ref", auth_ref)
    sampling_raw = raw.get("sampling_defaults")
    sampling = None
    if sampling_raw is not None:
        if not isinstance(sampling_raw, dict):
            raise ValueError(f"target file {path} 'sampling_defaults' must be a mapping")
        try:
            sampling = Sampling.model_validate(sampling_raw)
        except ValidationError as exc:
            raise ValueError(
                f"target file {path} 'sampling_defaults' failed validation: "
                f"{validation_problems(exc)}"
            ) from exc

    transport = raw.get("transport")
    _check_provider_and_transport(path, provider, transport)
    command_raw = raw.get("command")
    command: list[str] | None = None
    if command_raw is not None:
        if not (isinstance(command_raw, list) and all(isinstance(c, str) for c in command_raw)):
            raise ValueError(f"target file {path} 'command' must be a list of strings")
        command = command_raw

    seeded = _seeded_setup(path, raw.get("seeded_setup"), target_type)
    websocket = _websocket_spec(path, raw.get("websocket"), provider, endpoint, auth_ref)

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
        seeded_setup=seeded,
        websocket=websocket,
        filter_stops=_filter_stops(path, raw.get("filter_stops"), provider),
    )


def _check_provider_and_transport(path: Path, provider: object, transport: object) -> None:
    """Refuse a ``provider`` or a ``transport`` this tool does not have (u12 A-82, CLI audit M5).

    A-53 closed a misspelled key and left a misspelled value open: ``provider: skynet`` sent an
    OpenAI endpoint the REST adapter's ``{"prompt": ...}`` bodies, ``transport: carrier-pigeon``
    read as ``http``, and a stdio MCP target with ``transport: stido`` or ``provider: mpc`` ran
    on the offline mock and passed. Read as the routing reads them, stripped and case-folded;
    both are text or absent here (``_read_target_yaml``). ``stdio`` launches a local MCP server,
    so another provider with it is refused too: nothing else would read it.
    """

    name = provider.strip().lower() if isinstance(provider, str) else None
    if name is not None and name not in TARGET_PROVIDERS:
        raise ValueError(
            f"target file {path} has invalid provider {quoted(provider)}; expected one of "
            f"{', '.join(TARGET_PROVIDERS)} (leave it out for the generic REST adapter)"
        )
    if not isinstance(transport, str):
        return
    if transport.strip().lower() not in TARGET_TRANSPORTS:
        raise ValueError(
            f"target file {path} has invalid transport {quoted(transport)}; expected http or "
            "stdio (stdio launches a local MCP server, with provider: mcp and a command)"
        )
    if transport.strip().lower() == "stdio" and name != "mcp":
        raise ValueError(
            f"target file {path}: transport stdio is for provider mcp (a local MCP server "
            "launched from its command); leave transport out for this provider"
        )


def _check_env_reference(path: Path, field: str, value: object) -> None:
    """Refuse an ``env://`` reference whose name is no environment variable's (u12 A-82, M8).

    Never quoted: what follows ``env://`` there is most often the key itself, pasted where its
    variable's name belongs, and a name with a space or a quote cannot be set by any shell.
    """

    name = env_name_of(value) if isinstance(value, str) else None
    if name is not None and not is_env_name(name):
        raise ValueError(
            f"target file {path} '{field}' names no environment variable after env:// (a name "
            f"is {ENV_NAME_RULE}, not shown here): write {field}: env://NAME with the "
            "variable's name, never the key"
        )


def provider_returns_tool_calls(target: Target) -> bool:
    """True when the adapter ``target`` routes to reads tool calls from a reply.

    The OpenAI and Anthropic adapters do; the REST template and the read-only MCP adapter
    return none, so a seeded spec judged on its tool trace could never fail there (OD-18 B);
    the WebSocket adapter does only when its block declares ``response.tool_calls_path``.
    The runner asks the adapter itself (``returns_tool_calls``); the plan asks this.
    """

    provider = (target.provider or "").strip().lower()
    if provider == "websocket":
        return (
            target.websocket is not None and target.websocket.response.tool_calls_path is not None
        )
    return provider in ("openai", "anthropic")


def _seeded_setup(path: Path, raw: object, target_type: TargetType) -> SeededSetup | None:
    """The ``seeded_setup`` block of a target file (OD-18 option B), checked field by field.

    A ``type: model`` target gets the scene in-band (option A), so the block is refused there
    rather than silently ignored: one of the two would have been read wrong.
    """

    if raw is None:
        return None
    if target_type is TargetType.MODEL:
        raise ValueError(
            f"target file {path} declares 'seeded_setup', which is for a deployed application; "
            "a 'type: model' target gets a spec's setup in-band"
        )
    if not isinstance(raw, dict):
        raise ValueError(f"target file {path} 'seeded_setup' must be a mapping")
    known = ("specs", "tools", "granted_tools", "run_token")
    # A key that is a number too long to write out raised in `str` (A-40).
    unknown = sorted(described() if too_long(key) else str(key) for key in raw if key not in known)
    if unknown:
        # The names the file gives, up to 300 characters in all (clause A-51).
        raise ValueError(
            f"target file {path} 'seeded_setup' has unknown key(s) {cut(', '.join(unknown))}; "
            "expected 'specs', 'tools', 'granted_tools' and 'run_token'"
        )
    specs = raw.get("specs", [])
    if not (isinstance(specs, list) and all(isinstance(s, str) and s for s in specs)):
        raise ValueError(f"target file {path} 'seeded_setup.specs' must be a list of spec ids")
    tools = raw.get("tools", {})
    if not (
        isinstance(tools, dict)
        and all(isinstance(k, str) and isinstance(v, str) and k and v for k, v in tools.items())
    ):
        raise ValueError(
            f"target file {path} 'seeded_setup.tools' must map each spec tool name to the "
            "deployment's name for it"
        )
    # Two spec tools may share a deployment name (`lookup_ticket` and `read_ticket` in two
    # specs, one `get_ticket` in the deployment): the map is applied per spec, and only two of
    # one spec's own scene tools sharing a name is refused, for that spec, at run time.
    deployment_names = list(tools.values())
    granted, declared = _granted_tools(path, raw.get("granted_tools", []))
    # A declaration is for the deployment's own tools, outside every scene: a mapped name is a
    # spec's scene tool, on which the spec's word decides (OD-43). Said before the general
    # refusal below, which it would otherwise read as.
    mapped_declared = sorted(set(declared) & set(deployment_names))
    if mapped_declared:
        raise ValueError(
            f"target file {path} 'seeded_setup' declares {cut(', '.join(mapped_declared))} not "
            "destructive and maps it to a spec's tool under 'tools'; only a tool the deployment "
            "grants, outside every scene, may be declared not destructive (OD-43), and a spec's "
            "scene says for its own tools"
        )
    both = sorted(set(granted) & set(deployment_names))
    if both:
        raise ValueError(
            f"target file {path} 'seeded_setup' both maps and grants {cut(', '.join(both))}; a "
            "mapped tool is one of the spec's scene, a granted one is outside every scene"
        )
    token = raw.get("run_token")
    if token is not None and not (isinstance(token, str) and _RUN_TOKEN.fullmatch(token)):
        raise ValueError(
            f"target file {path} 'seeded_setup.run_token' must be 8 to 64 letters, digits, '_' "
            "or '-' (it replaces {{run_id}} in the canaries the operator seeds)"
        )
    return SeededSetup(
        specs=list(specs),
        tools=dict(tools),
        granted_tools=granted,
        run_token=token,
        not_destructive=sorted(declared),
    )


#: The keys a ``granted_tools`` entry written as a mapping may hold (OD-43).
_GRANTED_ENTRY_KEYS = ("name", "destructive")

#: What every refusal of ``granted_tools`` says it must be.
_GRANTED_SHAPE = (
    "a list of the deployment's tool names, each a name or {name: <tool>, destructive: false}"
)


def _granted_tools(path: Path, raw: object) -> tuple[list[str], list[str]]:
    """The deployment's granted tools, and the ones its operator declares not destructive.

    Each entry is a tool name, as before, or a mapping ``{name: <tool>, destructive: false}``
    that grants the tool and declares it not destructive (owner decision OD-43, u06 A-72): a
    hand-off such as ``transfer_to_billing_agent`` is then not failed by its name alone. The
    mapping holds ``name`` (text, with no space at either end: the evaluators compare names
    exactly, so a padded one would declare a tool nobody calls) and ``destructive``, the boolean
    ``false``; ``true`` is refused, since what a target file may say about its own tool is that
    it destroys nothing, and the spec's scene is where a tool is made destructive whatever its
    name; and a mapping without ``destructive`` is refused, a bare name being how a tool is only
    granted. A declared name granted twice is refused, since the two entries would say two
    things. Every refusal names the file and the entry, never a value (A-53).
    """

    if not isinstance(raw, list):
        raise ValueError(
            f"target file {path} 'seeded_setup.granted_tools' must be {_GRANTED_SHAPE}"
        )
    granted: list[str] = []
    declared: list[str] = []
    for index, entry in enumerate(raw):
        where = f"'seeded_setup.granted_tools[{index}]'"
        if isinstance(entry, str) and entry:
            granted.append(entry)
            continue
        if not isinstance(entry, dict):
            raise ValueError(
                f"target file {path} {where} is not a tool name; 'granted_tools' must be "
                f"{_GRANTED_SHAPE}"
            )
        # A key that is a number too long to write out raised in `str` (A-40).
        unknown = sorted(
            described() if too_long(key) else str(key)
            for key in entry
            if key not in _GRANTED_ENTRY_KEYS
        )
        if unknown:
            raise ValueError(
                f"target file {path} {where} has unknown key(s) {cut(', '.join(unknown))}; "
                "expected 'name' and 'destructive' (OD-43)"
            )
        name = entry.get("name")
        if not (isinstance(name, str) and name):
            raise ValueError(f"target file {path} {where}.name must be the deployment's tool name")
        if name != name.strip():
            raise ValueError(
                f"target file {path} {where}.name has a space at one end; tool names are "
                "compared exactly, so write the name as the deployment calls it (OD-43)"
            )
        if "destructive" not in entry:
            raise ValueError(
                f"target file {path} {where} has no 'destructive'; write a tool that is only "
                "granted as its bare name, and one declared not destructive as "
                "{name: <tool>, destructive: false} (OD-43)"
            )
        granted.append(name)
        flag = entry["destructive"]
        if not isinstance(flag, bool):
            kind = "null" if flag is None else type(flag).__name__
            raise ValueError(
                f"target file {path} {where}.destructive must be false (a boolean), not {kind}"
            )
        if flag:
            raise ValueError(
                f"target file {path} {where}.destructive is true; a target file may declare one "
                "of its own tools not destructive (false), and nothing more (OD-43): leave the "
                "key out to have the tool judged by its name, and mark a tool destructive "
                "whatever its name in a spec's scene"
            )
        declared.append(name)
    twice = sorted({name for name in declared if granted.count(name) > 1})
    if twice:
        raise ValueError(
            f"target file {path} 'seeded_setup.granted_tools' grants {cut(', '.join(twice))} "
            "more than once and declares it not destructive; write each declared tool once"
        )
    return granted, declared


#: A run token goes into a canary the evaluators match exactly: plain characters, and long
#: enough not to occur by chance.
_RUN_TOKEN = re.compile(r"[A-Za-z0-9_-]{8,64}")


def _websocket_spec(
    path: Path,
    raw: object,
    provider: str | None,
    endpoint: str | None,
    auth_ref: str | None,
) -> WebSocketSpec | None:
    """The ``websocket`` block of a ``provider: websocket`` target, checked before any send.

    Refused here, not at send time (rule 12, refuse before you send): the block missing or on
    another provider, an endpoint that is not ``ws://`` or ``wss://`` or that carries a query,
    a fragment or a user:password, a placeholder no template may use (not reserved and not in
    ``vars``), any placeholder inside ``vars`` (they are plain values, never rendered), a
    request placeholder (``{{prompt}}``, ``{{messages}}``, ``{{system_prompt}}``) in a template
    rendered with no request (``headers``, ``handshake.send``, ``session.start``),
    ``{{token}}`` without an ``auth_ref``, a query template that carries neither ``{{prompt}}``
    nor ``{{messages}}``, an upgrade header the library writes itself (``Host``,
    ``Connection``, ``Upgrade`` and :data:`~ildottore.adapters.websocket.RESERVED_HEADERS`' five
    ``Sec-WebSocket-`` headers), ``one_query_in_flight: false``, a key that is not text (A-44)
    or a value JSON cannot hold (a date, a set, bytes, NaN, half a character: A-54) anywhere in
    the block, the walks a spec gets, and a ``ws://`` or ``wss://`` endpoint on any other
    provider (an HTTP adapter cannot dial it). Each refusal names the field; a name the operator
    wrote (a header, a placeholder) is cut as every refusal of the operator's files cuts it
    (A-51).
    """

    is_websocket = (provider or "").strip().lower() == "websocket"
    if raw is None:
        if is_websocket:
            raise ValueError(
                f"target file {path} is provider websocket and has no 'websocket' block; declare "
                "message, response and (usually) handshake (docs/MANUAL.md §4.2)"
            )
        if urlsplit((endpoint or "").strip()).scheme.lower() in ("ws", "wss"):
            # The allowlist authorizes ws and wss since this adapter, so the REST adapter got
            # past the gate and posted HTTP to the socket, credential included, four times per
            # attempt, and `run` exited 3 (pre-merge audit of PR #87).
            raise ValueError(
                f"target file {path}: a ws:// or wss:// endpoint is dialled only by provider "
                "websocket, with a 'websocket' block declaring its wire shape "
                "(docs/MANUAL.md §4.2)"
            )
        return None
    if not is_websocket:
        raise ValueError(
            f"target file {path} declares 'websocket', which is read only by provider websocket"
        )
    if not isinstance(raw, dict):
        raise ValueError(f"target file {path} 'websocket' must be a mapping")
    # Before the model reads it: the templates are free-form JSON below their top level, so a key
    # YAML built from `on` or `~` went on the wire as "True" or "None" (A-44's walk; second
    # pre-merge audit), and a date stopped the run when the frame was written, NaN went on the
    # wire, and half a character raised out of `run` from the target's digest (A-54's walk;
    # pre-merge audit of PR #87). Keys first, as the spec loader checks them.
    not_text = non_string_keys({"websocket": raw})
    if not_text:
        raise ValueError(
            f"target file {path} 'websocket' has a key that is not text: {'; '.join(not_text)}"
        )
    not_json = non_json_values({"websocket": raw})
    if not_json:
        raise ValueError(
            f"target file {path} 'websocket' holds a value JSON cannot hold: {'; '.join(not_json)}"
        )
    try:
        spec = WebSocketSpec.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(
            f"target file {path} 'websocket' failed validation: {validation_problems(exc)}"
        ) from exc

    parts = urlsplit(endpoint or "")
    if parts.scheme.lower() not in ("ws", "wss") or not parts.hostname:
        raise ValueError(
            f"target file {path}: a provider websocket endpoint must be a ws:// or wss:// URL "
            "with a host"
        )
    if parts.query or parts.fragment:
        raise ValueError(
            f"target file {path}: the websocket endpoint carries a query or fragment, which the "
            "scope cannot authorize; move it into the handshake frame"
        )
    if parts.username is not None or parts.password is not None:
        raise ValueError(
            f"target file {path}: the websocket endpoint carries a user or password; a "
            "credential goes through auth_ref and the {{token}} placeholder"
        )
    if not spec.session.one_query_in_flight:
        # Decided 2026-10-11 under the owner's delegation, revisable (OD-35): on a shared socket
        # a reply frame belongs to its attempt only by an id the server echoes, and one frame
        # misread puts one attempt's reply into another's verdict.
        raise ValueError(
            f"target file {path}: websocket.session.one_query_in_flight: false is refused by "
            "design (OD-35): with several queries on one socket a reply frame is tied to its "
            "attempt only by an id the server echoes; leave it true (each conversation gets a "
            "connection of its own; --concurrency sets how many run at once)"
        )
    if TOKEN in spec.vars:
        raise ValueError(
            f"target file {path}: websocket.vars may not name {{{{token}}}}; the credential "
            "comes from auth_ref only"
        )
    in_vars = sorted(placeholders(list(spec.vars.values())))
    if in_vars:
        names = _placeholder_names(in_vars)
        raise ValueError(
            f"target file {path}: websocket.vars carries {names}; vars are plain values and "
            "are never rendered, so a placeholder there would go on the wire literally"
        )
    reserved_headers = sorted(name for name in spec.headers if name.lower() in RESERVED_HEADERS)
    if reserved_headers:
        raise ValueError(
            f"target file {path}: websocket.headers sets {listed(reserved_headers)}, which "
            "the WebSocket library writes itself; remove it"
        )
    handshake = spec.handshake.send if spec.handshake is not None else {}
    connection_only = placeholders([handshake, spec.session.start, spec.headers])
    misplaced = sorted((connection_only & RESERVED) - CONNECTION_PLACEHOLDERS)
    if misplaced:
        names = _placeholder_names(misplaced)
        raise ValueError(
            f"target file {path}: websocket headers, handshake.send and session.start are sent "
            f"before any query, so they may use only {{{{token}}}} and vars, not {names}"
        )
    used = connection_only | placeholders(spec.message.send)
    unknown = sorted(used - RESERVED - set(spec.vars))
    if unknown:
        names = _placeholder_names(unknown)
        raise ValueError(
            f"target file {path}: websocket templates use {names}, which is neither a reserved "
            "placeholder (token, prompt, system_prompt, messages) nor declared under "
            "websocket.vars"
        )
    if TOKEN in used and auth_ref is None:
        raise ValueError(
            f"target file {path}: a websocket template uses {{{{token}}}} and the target "
            "declares no auth_ref"
        )
    if not placeholders(spec.message.send) & {PROMPT, MESSAGES}:
        raise ValueError(
            f"target file {path}: websocket.message.send carries neither {{{{prompt}}}} nor "
            "{{messages}}, so no attack text would reach the target"
        )
    return spec


def _placeholder_names(names: list[str]) -> str:
    """``{{a}}, {{b}}``: placeholder names a refusal lists, each cut and at most 20 (A-51)."""

    return listed(names, show=lambda name: cut("{{" + name + "}}"))


def load_mock_scenario(path: Path) -> str:
    """Read the optional ``mock_scenario`` selector from a ``target.yaml``.

    Steers the deterministic offline :class:`MockTarget` only (a real u04 adapter
    ignores it). Absent ⇒ ``"bare"`` (the honest default: every spec ``inconclusive``).
    An unknown value is rejected so a typo never silently degrades to a fabricated
    verdict; the runtime :class:`Target` model is unchanged (this is composition config).
    """

    return _mock_scenario(path, _read_target_yaml(path).get("mock_scenario", "bare"))


def _mock_scenario(path: Path, scenario: object) -> str:
    """The ``mock_scenario`` written in ``path``, refused unless one of :data:`MOCK_SCENARIOS`."""

    if not isinstance(scenario, str) or scenario not in MOCK_SCENARIOS:
        raise ValueError(
            f"target file {path} has invalid mock_scenario {quoted(scenario)}; "
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

    return _uses_mock(_read_target_yaml(path))


def _uses_mock(raw: dict[str, Any]) -> bool:
    """:func:`target_uses_mock` of a parsed ``target.yaml``."""

    if "mock_scenario" in raw:
        return True
    # A stdio MCP target authorizes by command line, not an endpoint URL, so it is a real
    # over-the-wire (subprocess) target even though it declares no ``endpoint``.
    # Text or absent: `_read_target_yaml` refuses anything else (A-53), where `str` raised on a
    # number too long to write out (A-40).
    provider = (raw.get("provider") or "").strip().lower()
    transport = (raw.get("transport") or "").strip().lower()
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
    spend_sink: Callable[[Spend], None] | None = None,
    apply_sampling_defaults: bool = True,
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

    ``real_target``'s ``sampling_defaults`` (what of it the adapter sends,
    :func:`sampling_fallback`) fills what each spec leaves unset, and the judge's own file's
    fills what the judge leaves unset (OD-39). ``apply_sampling_defaults`` false sends neither:
    a resume of a run started before the block was applied continues as it started.
    """

    resolved_pack = pack if pack is not None else build_permissive_pack(specs)
    policy = build_policy_engine(scope, resolved_pack, safety=safety)
    mutators = build_mutator_registry()
    scorer = DefaultRiskScorer()
    runs = build_run_store(run_db)
    evidence = build_evidence_store(
        evidence_root, planted_canaries=planted_secrets(specs), journal=runs
    )
    # A live judge model (--judge) supplies semantic_judge for real runs (and overrides
    # the deterministic scenario-judge offline if given). Absent one, a live run leaves
    # semantic_judge unregistered (it abstains) and an offline run uses the scenario judge.
    meter = SendMeter() if judge_target is not None else None
    judge_adapter = (
        build_judge_adapter(
            scope, judge_target, meter=meter, apply_sampling_defaults=apply_sampling_defaults
        )
        if judge_target is not None
        else None
    )

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
        # The counter keeps OFFLINE evidence byte-stable; on a live route it made `latency_ms`
        # fiction (a 1 ms loopback reply stored as 2000.0 or 4000.0, depending on how the
        # coroutines interleaved), so a live run measures with the monotonic clock.
        now=deterministic_clock() if real_target is None else time.monotonic,
        timestamp=utc_timestamp,
        spend_sink=spend_sink,
        n=n,
        concurrency=concurrency,
        timeout_s=timeout_s,
        # Pacing applies to traffic that actually leaves the process. An offline mock
        # campaign passes ``None`` (see ``execute_run``), which is the one case where
        # ignoring a rate is correct rather than silent, because the CLI prints it.
        rate_rps=rate_rps,
        send_meter=meter,
        sampling_defaults=(
            sampling_fallback(real_target)
            if real_target is not None and apply_sampling_defaults
            else None
        ),
        # The adapter's own rule, applied whatever the block (Anthropic: no seed, no top_p
        # beside a temperature), so each attempt records what went out (u12 A-66).
        sent_sampling=sent_sampling_for(real_target),
        sampling_asked=(
            sampling_written(real_target)
            if real_target is not None and apply_sampling_defaults
            else None
        ),
    )
    return BuiltRunner(
        runner=runner,
        scope=scope,
        policy=policy,
        evidence_root=evidence_root,
        run_store=runs,
    )


def build_scope(path: Path) -> Scope:
    """Load + integrity-check a ``scope.yaml`` (u01, S3/S4). Never bypassable."""

    return load_scope(path)


def build_scope_with_digest(path: Path) -> tuple[Scope, str]:
    """:func:`build_scope`, plus the SHA-256 of the body it loaded (recorded by a run, S4)."""

    return load_scope_with_digest(path)


# Re-export for the scope-gate command (kept explicit so the gate lives in one place).
_ALLOWLIST = EndpointAllowlist
