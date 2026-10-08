"""Policy packs + the :class:`PolicyEngine` decision gate (u01).

A **policy pack** declares which attack categories/specs are permitted for an
engagement (``docs/01 §6``, ``docs/11 §5``). The :class:`PolicyEngine` answers a
single question per attempt - *may this spec run against this endpoint on this
target?* - with a **default-deny** verdict (``docs/02`` S3/S4/S5, contract §2):

1. target in scope?
2. endpoint on the allowlist?
3. spec's category/id enabled by the active pack (and not denied)?
4. a spec in a flagged family (dangerous outside a test) refused unless it is marked
   ``test_only`` (S5, u01 §7). The mark does not switch a spec off; an unmarked one is.
5. layer-B / PII-elicitation specs **off unless the pack enables them**
   (``docs/11`` DL4/DL5).
6. a spec's declared ``requires_policy`` capabilities all present in the pack's
   ``enabled_capabilities`` - offensive-simulation / layer-B PII **off by default**
   (OD-11, ``docs/11 §5`` / ``docs/13 §4``).

Loading a pack performs **no network I/O** (SSRF-safe, ``docs/02 §4``).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ildottore import safe_yaml
from ildottore.config import SafetyFlags
from ildottore.policy.allowlist import EndpointAllowlist
from ildottore.policy.errors import PolicyPackError
from ildottore.policy.scope import Scope
from ildottore.shared.config_errors import quoted, validation_problems, yaml_problem
from ildottore.shared.enums import FLAGGED_FAMILIES, Category
from ildottore.shared.files import read_text_capped
from ildottore.shared.models import AttackSpec

__all__ = [
    "CheckResult",
    "PolicyEngine",
    "PolicyPack",
    "authorize_target",
    "enabled_specs",
    "load_pack",
]

# Tags that make a spec "layer-B" / PII-elicitation, off by default (docs/11 §5 DL4/DL5).
# Compared after :func:`_tag_key`, so ``pii-elicitation`` and ``pii_elicitation`` are the same
# tag: the one shipped PII spec spells it with a hyphen, the gate compared the underscore form,
# and the two-key DL4 gate never fired for it (audit F-22, 2026-10-03).
_LAYER_B_TAG = "layer_b"
_PII_ELICIT_TAG = "pii_elicitation"
# The requires_policy capability that names layer-B PII. A spec declaring it is a
# PII-elicitation spec whatever its tags say, so dropping a tag cannot drop the DL4 gate.
_PII_CAPABILITY = "layer_b_pii"


class PolicyPack(BaseModel):
    """Engagement policy pack (contract §6 wire shape).

    Distinct from the u00 distribution ``shared.schema_export.Pack`` (that is a
    packaging manifest); this is the *engagement authorization* record read by
    the :class:`PolicyEngine`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    allow_categories: list[Category] = Field(default_factory=list)
    allow_specs: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    enable_layer_b: bool = False
    allow_pii_elicitation: bool = False
    enabled_capabilities: list[str] = Field(default_factory=list)
    budgets: dict[str, int] | None = None

    def category_enabled(self, category: Category) -> bool:
        return category in self.allow_categories

    def spec_enabled(self, spec_id: str) -> bool:
        return spec_id in self.allow_specs

    def is_denied(self, spec_id: str, category: Category) -> bool:
        return spec_id in self.deny or category.value in self.deny


def load_pack(path: str | Path) -> PolicyPack:
    """Load and validate a policy pack from YAML (no network I/O)."""

    file_path = Path(path)
    try:
        raw_text = read_text_capped(file_path)
    except OSError as exc:  # over the 1 MiB cap (A-43), or a filesystem error
        raise PolicyPackError(f"cannot read policy pack {file_path}: {exc}") from exc
    try:
        data = safe_yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        # Reason and position, no quoted line, like the scope and target loaders.
        raise PolicyPackError(
            f"invalid YAML in policy pack {file_path}: {yaml_problem(exc)}"
        ) from exc
    if not isinstance(data, dict):
        raise PolicyPackError(f"policy pack {file_path} must be a mapping at top level")
    try:
        return PolicyPack.model_validate(data)
    except ValidationError as exc:  # field and reason, never the value
        raise PolicyPackError(
            f"policy pack {file_path} failed validation: {validation_problems(exc)}"
        ) from exc
    except Exception as exc:  # a validator that raised something pydantic did not wrap
        raise PolicyPackError(f"policy pack {file_path} failed validation: {exc}") from exc


class CheckResult(BaseModel):
    """The outcome of :meth:`PolicyEngine.check` (contract §6 wire shape)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: str  # "allow" | "blocked_by_policy"
    reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


_ALLOW = CheckResult(decision="allow")


def _blocked(reason: str) -> CheckResult:
    return CheckResult(decision="blocked_by_policy", reason=reason)


def _tag_key(tag: str) -> str:
    """Normalise a tag for comparison: case and ``-``/``_`` spelling do not matter."""

    return tag.strip().lower().replace("-", "_")


def _tag_keys(spec: AttackSpec) -> set[str]:
    return {_tag_key(tag) for tag in spec.tags or []}


def _is_layer_b(spec: AttackSpec) -> bool:
    """True if the spec is a layer-B / model-memorization spec (docs/11 §5)."""

    return _LAYER_B_TAG in _tag_keys(spec)


def _is_pii_elicitation(spec: AttackSpec) -> bool:
    """True if the spec elicits PII about individuals (DL4, off by default).

    Either signal is enough: the tag (any spelling) or the ``layer_b_pii`` capability.
    """

    return _PII_ELICIT_TAG in _tag_keys(spec) or _PII_CAPABILITY in spec.requires_policy


def authorize_target(scope: Scope, target_id: str, endpoint: str) -> CheckResult:
    """Steps 1 and 2 of :meth:`PolicyEngine.check`: in scope, and reachable at ``endpoint``?

    Extracted so the pre-flight gate in the CLI and the per-attempt gate in the engine cannot
    drift apart. They already had: the CLI asked only ``scope.target(id) is not None``, which
    is **membership, not reachability**. ``ScopeTarget.endpoints`` defaults to ``[]``, so a
    scope naming the right target id with no endpoint allowlist (or a typo in ``host``) passed
    the CLI gate and was then denied by this engine on every attempt, turning the refusal back
    into the run of unexplained inconclusives the gate exists to prevent.

    ``endpoint`` must be the same string the runner will authorize, which is what
    ``cli.wiring.scope_endpoint_for`` produces: the scope's ``base_url`` for the target, or
    ``stdio://<command line>`` for a stdio MCP target.

    The id and the endpoint are quoted up to 300 characters (``quoted``): a target id of a
    million characters printed the refusal of ``run`` and of ``fingerprint`` at 2 MB, the id
    once in the message and once in this reason (clause A-51).
    """

    target = scope.target(target_id)
    if target is None:
        return _blocked(f"target {quoted(target_id)} not in scope")
    if endpoint.startswith("stdio://"):
        command = endpoint[len("stdio://") :]
        if command not in target.commands:
            return _blocked(f"stdio command not authorized for {quoted(target_id)}")
        return _ALLOW
    allowlist = EndpointAllowlist.from_target(target)
    if not allowlist.is_allowed(endpoint):
        return _blocked(f"endpoint {quoted(endpoint)} not on allowlist for {quoted(target_id)}")
    return _ALLOW


class PolicyEngine:
    """Central authorization gate - ``check`` returns allow / blocked_by_policy.

    Composes a scope (targets + allowlist), an active :class:`PolicyPack` and the
    run-wide :class:`~ildottore.config.SafetyFlags`. The runner (u08) calls
    :meth:`check` before every attempt; adapters (u04) may call the allowlist
    directly. Everything defaults to **deny**.
    """

    def __init__(
        self,
        scope: Scope,
        pack: PolicyPack,
        safety: SafetyFlags | None = None,
    ) -> None:
        self._scope = scope
        self._pack = pack
        self._safety = safety if safety is not None else SafetyFlags()

    def check(self, target_id: str, endpoint: str, spec: AttackSpec) -> CheckResult:
        """Decide whether ``spec`` may run against ``endpoint`` on ``target_id``.

        ``endpoint`` is the concrete request URL the adapter would call.
        """

        # 1-2. target in scope, and authorized to reach it at this endpoint? (S3
        #      default-deny). Shared with the CLI's pre-flight gate via
        #      :func:`authorize_target`, so the two cannot answer differently.
        reachable = authorize_target(self._scope, target_id, endpoint)
        if not reachable.allowed:
            return reachable

        # 3. explicit deny always wins.
        if self._pack.is_denied(spec.id, spec.category):
            return _blocked(f"spec {spec.id!r} denied by policy pack {self._pack.name!r}")

        # 4. spec enabled by the pack? (category OR explicit spec id; default-deny)
        if not (self._pack.category_enabled(spec.category) or self._pack.spec_enabled(spec.id)):
            return _blocked(
                f"spec {spec.id!r} (category {spec.category.value!r}) not enabled by pack"
            )

        # 5. a spec in a flagged family must be marked test_only (S5, u01 §7). The gate used
        #    to treat the mark as rendering-only and allow everything, so a copy of a shipped
        #    spec with the two marking lines deleted (or a third-party pack that never had
        #    them) ran although `dottore lint` reported MISSING_TEST_ONLY (audit SEC-06). The
        #    family comes from the category, which the spec cannot opt out of; the mark is the
        #    author's statement that the payload is meant for a controlled test.
        if spec.category in FLAGGED_FAMILIES and not spec.test_only:
            return _blocked(
                f"spec {spec.id!r} is in the flagged family {spec.category.value!r} but is not "
                "marked test_only (S5); `dottore lint` reports it as MISSING_TEST_ONLY"
            )

        # 6. layer-B specs off unless the pack enables them (docs/11 DL4/DL5).
        if _is_layer_b(spec) and not self._pack.enable_layer_b:
            return _blocked(f"layer-B spec {spec.id!r} requires pack.enable_layer_b")

        # 7. PII-elicitation off unless BOTH the pack and the run flag allow it (DL4).
        if _is_pii_elicitation(spec) and not (
            self._pack.allow_pii_elicitation and self._safety.allow_pii_elicitation
        ):
            return _blocked(
                f"PII-elicitation spec {spec.id!r} needs two keys: the pack's "
                "allow_pii_elicitation and the run's allow_pii_elicitation safety flag (DL4)"
            )

        # 8. declared capability gate (OD-11, docs/11 §5 / docs/13 §4): a spec that
        #    requires_policy capabilities runs only when the pack explicitly opts into
        #    every one of them via enabled_capabilities. Default-deny: an empty
        #    enabled_capabilities blocks any spec that requires a capability, so
        #    offensive-simulation and layer-B PII specs are OFF unless enabled.
        missing = [c for c in spec.requires_policy if c not in self._pack.enabled_capabilities]
        if missing:
            return _blocked(
                f"spec {spec.id!r} requires policy capability(ies) {missing!r} "
                f"not enabled by pack {self._pack.name!r}"
            )

        # A marked test_only spec runs, against a live target too when the operator points `run`
        # at one. (No reporter reads the mark today; the HTML reporter's `unsafe_render` switch
        # governs raw HTML passthrough and has no CLI flag.)
        return _ALLOW

    @property
    def safety(self) -> SafetyFlags:
        return self._safety


def enabled_specs(pack: PolicyPack, specs: Iterable[AttackSpec]) -> list[AttackSpec]:
    """Filter ``specs`` to those the pack enables (category/id, not denied).

    A convenience for the planner (u08) - does **not** apply scope/allowlist
    (those need a concrete endpoint) nor the layer-B/PII gates.
    """

    result: list[AttackSpec] = []
    for spec in specs:
        if pack.is_denied(spec.id, spec.category):
            continue
        if pack.category_enabled(spec.category) or pack.spec_enabled(spec.id):
            result.append(spec)
    return result
