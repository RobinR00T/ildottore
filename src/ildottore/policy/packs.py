"""Policy packs + the :class:`PolicyEngine` decision gate (u01).

A **policy pack** declares which attack categories/specs are permitted for an
engagement (``docs/01 §6``, ``docs/11 §5``). The :class:`PolicyEngine` answers a
single question per attempt — *may this spec run against this endpoint on this
target?* — with a **default-deny** verdict (``docs/02`` S3/S4/S5, contract §2):

1. target in scope?
2. endpoint on the allowlist?
3. spec's category/id enabled by the active pack (and not denied)?
4. dangerous (``test_only``) payload only where the flag surface permits?
5. layer-B / PII-elicitation specs **off unless the pack enables them**
   (``docs/11`` DL4/DL5).

Loading a pack performs **no network I/O** (SSRF-safe, ``docs/02 §4``).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ildottore.config import SafetyFlags
from ildottore.policy.allowlist import EndpointAllowlist
from ildottore.policy.errors import PolicyPackError
from ildottore.policy.scope import Scope
from ildottore.shared.enums import Category
from ildottore.shared.models import AttackSpec

# Categories that constitute "layer-B" / PII-elicitation and are off by default
# (docs/11 §5 DL4/DL5). Layer-B is expressed by the pack's ``enable_layer_b`` flag;
# a spec is treated as layer-B via its ``requires``/tags below.
_LAYER_B_TAG = "layer_b"
_PII_ELICIT_TAG = "pii_elicitation"


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
        raw_text = file_path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem error surface
        raise PolicyPackError(f"cannot read policy pack {file_path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise PolicyPackError(f"invalid YAML in policy pack {file_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyPackError(f"policy pack {file_path} must be a mapping at top level")
    try:
        return PolicyPack.model_validate(data)
    except Exception as exc:  # pydantic.ValidationError → typed PolicyPackError
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


def _is_layer_b(spec: AttackSpec) -> bool:
    """True if the spec is a layer-B / model-memorization spec (docs/11 §5)."""

    tags = spec.tags or []
    return _LAYER_B_TAG in tags


def _is_pii_elicitation(spec: AttackSpec) -> bool:
    """True if the spec elicits PII about individuals (DL4, off by default)."""

    tags = spec.tags or []
    return _PII_ELICIT_TAG in tags


class PolicyEngine:
    """Central authorization gate — ``check`` returns allow / blocked_by_policy.

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

        # 1. target in scope? (default-deny)
        target = self._scope.target(target_id)
        if target is None:
            return _blocked(f"target {target_id!r} not in scope")

        # 2. endpoint on the allowlist? (S3 default-deny)
        allowlist = EndpointAllowlist.from_target(target)
        if not allowlist.is_allowed(endpoint):
            return _blocked(f"endpoint {endpoint!r} not on allowlist for {target_id!r}")

        # 3. explicit deny always wins.
        if self._pack.is_denied(spec.id, spec.category):
            return _blocked(f"spec {spec.id!r} denied by policy pack {self._pack.name!r}")

        # 4. spec enabled by the pack? (category OR explicit spec id; default-deny)
        if not (self._pack.category_enabled(spec.category) or self._pack.spec_enabled(spec.id)):
            return _blocked(
                f"spec {spec.id!r} (category {spec.category.value!r}) not enabled by pack"
            )

        # 5. layer-B specs off unless the pack enables them (docs/11 DL4/DL5).
        if _is_layer_b(spec) and not self._pack.enable_layer_b:
            return _blocked(f"layer-B spec {spec.id!r} requires pack.enable_layer_b")

        # 6. PII-elicitation off unless BOTH the pack and the run flag allow it (DL4).
        if _is_pii_elicitation(spec) and not (
            self._pack.allow_pii_elicitation and self._safety.allow_pii_elicitation
        ):
            return _blocked(
                f"PII-elicitation spec {spec.id!r} requires pack + --allow-pii-elicitation"
            )

        # 7. dangerous payloads must be flagged test_only (S5). A test_only spec is
        #    allowed to *run* (execution is mocked); only its raw *rendering* is
        #    gated by --unsafe-render, which u11 enforces. Nothing to block here.
        return _ALLOW

    @property
    def safety(self) -> SafetyFlags:
        return self._safety


def enabled_specs(pack: PolicyPack, specs: Iterable[AttackSpec]) -> list[AttackSpec]:
    """Filter ``specs`` to those the pack enables (category/id, not denied).

    A convenience for the planner (u08) — does **not** apply scope/allowlist
    (those need a concrete endpoint) nor the layer-B/PII gates.
    """

    result: list[AttackSpec] = []
    for spec in specs:
        if pack.is_denied(spec.id, spec.category):
            continue
        if pack.category_enabled(spec.category) or pack.spec_enabled(spec.id):
            result.append(spec)
    return result
