"""Evaluator registry: built-ins + entry-point discovery (contract §5.1, ``docs/06 §3``).

Mirrors the L3 plugin pattern (``docs/06 §3``): built-in evaluators register by their ``type``
string, third-party evaluators are discovered from the ``dottore.evaluators`` entry-point group
at load. Every candidate — built-in or plugin — is validated against
:class:`ildottore.shared.protocols.Evaluator` at registration; a class that does not satisfy
the protocol raises :class:`EvaluatorProtocolError` with a clear message (never a silent skip —
contract §7 registry test).

Discovery executes no attack and makes no network call: it imports the plugin class and
protocol-checks an instance.

:class:`~ildottore.evaluators.semantic_judge.SemanticJudgeEvaluator` is special: it needs an
injected judge :class:`~ildottore.shared.protocols.TargetAdapter` (u04), so it is registered
**only when a judge adapter is supplied** to :func:`build_default_registry`. Absent a judge the
``semantic_judge`` type is simply not present; a spec referencing it then fails the linter with
a clear "unknown evaluator type" message (never a silent skip).
"""

from __future__ import annotations

from importlib.metadata import entry_points

from ildottore.evaluators.authz_leak import AuthzLeakEvaluator
from ildottore.evaluators.exact import ExactMatchEvaluator
from ildottore.evaluators.logprob_membership import LogprobMembershipEvaluator
from ildottore.evaluators.pii_detector import PIIDetectorEvaluator
from ildottore.evaluators.refusal import RefusalEvaluator
from ildottore.evaluators.regex import RegexAbsenceEvaluator, RegexPresenceEvaluator
from ildottore.evaluators.secret_leakage import SecretLeakageEvaluator
from ildottore.evaluators.secret_shape import SecretShapeEvaluator
from ildottore.evaluators.semantic_judge import SemanticJudgeEvaluator
from ildottore.evaluators.tool_call import ToolCallEvaluator
from ildottore.evaluators.verbatim_overlap import VerbatimOverlapEvaluator
from ildottore.shared.protocols import Evaluator, TargetAdapter

__all__ = [
    "ENTRY_POINT_GROUP",
    "EvaluatorProtocolError",
    "EvaluatorRegistry",
    "build_default_registry",
]

ENTRY_POINT_GROUP = "dottore.evaluators"

# The deterministic + data-leak built-ins (no external injection needed).
_BUILTINS: tuple[type[Evaluator], ...] = (
    RegexAbsenceEvaluator,
    RegexPresenceEvaluator,
    ExactMatchEvaluator,
    RefusalEvaluator,
    SecretLeakageEvaluator,
    ToolCallEvaluator,
    PIIDetectorEvaluator,
    SecretShapeEvaluator,
    VerbatimOverlapEvaluator,
    LogprobMembershipEvaluator,
    AuthzLeakEvaluator,
)


class EvaluatorProtocolError(TypeError):
    """A registered class/instance does not satisfy the :class:`Evaluator` protocol."""


def _validate(instance: object, *, origin: str) -> Evaluator:
    """Protocol-check an instance; raise a clear error on a bad plugin (no silent skip)."""
    type_name = getattr(instance, "type", None)
    if not isinstance(type_name, str) or not type_name:
        raise EvaluatorProtocolError(
            f"evaluator from {origin} is missing a non-empty str 'type' attribute"
        )
    if not callable(getattr(instance, "evaluate", None)):
        raise EvaluatorProtocolError(
            f"evaluator '{type_name}' from {origin} has no callable 'evaluate'"
        )
    if not isinstance(instance, Evaluator):
        raise EvaluatorProtocolError(
            f"evaluator '{type_name}' from {origin} does not satisfy the Evaluator protocol"
        )
    return instance


class EvaluatorRegistry:
    """A ``type``→instance registry of evaluators with protocol validation at insert time."""

    def __init__(self) -> None:
        self._by_type: dict[str, Evaluator] = {}

    def register(
        self, instance: Evaluator, *, origin: str = "manual", replace: bool = False
    ) -> None:
        """Validate then register ``instance`` under its ``type``.

        A duplicate type raises unless ``replace`` is set (built-ins register first; a plugin
        reusing a built-in type is a configuration error surfaced to the operator).
        """
        validated = _validate(instance, origin=origin)
        if validated.type in self._by_type and not replace:
            raise EvaluatorProtocolError(
                f"duplicate evaluator type '{validated.type}' (origin {origin}); "
                "types must be unique across built-ins and plugins"
            )
        self._by_type[validated.type] = validated

    def get(self, type_name: str) -> Evaluator:
        """Return the evaluator registered under ``type_name`` (``KeyError`` if unknown)."""
        return self._by_type[type_name]

    def has(self, type_name: str) -> bool:
        """Whether an evaluator is registered under ``type_name``."""
        return type_name in self._by_type

    def types(self) -> list[str]:
        """Sorted list of registered evaluator types (deterministic ordering)."""
        return sorted(self._by_type)

    def discover_plugins(self) -> list[str]:
        """Load ``dottore.evaluators`` entry points, validate, and register each.

        Returns the list of newly registered plugin types. A plugin that fails protocol
        validation raises :class:`EvaluatorProtocolError` (never a silent skip — contract §7).
        """
        loaded: list[str] = []
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            cls = ep.load()
            instance = cls()
            self.register(instance, origin=f"entry-point '{ep.name}'")
            loaded.append(instance.type)
        return loaded


def build_default_registry(
    *, judge: TargetAdapter | None = None, discover: bool = True
) -> EvaluatorRegistry:
    """Build a registry with the built-ins, the judge (if injected), and (optionally) plugins."""
    registry = EvaluatorRegistry()
    for cls in _BUILTINS:
        registry.register(cls(), origin="builtin")
    if judge is not None:
        registry.register(SemanticJudgeEvaluator(judge), origin="builtin(judge)")
    if discover:
        registry.discover_plugins()
    return registry
