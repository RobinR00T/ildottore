"""Mutator registry: built-ins + entry-point discovery (contract §5.1, docs/06 §3).

The registry mirrors the L3 plugin pattern (``docs/06 §3``): built-in strategies are
registered by their ``type`` string, and third-party strategies are discovered from the
``dottore.mutators`` entry-point group at load. Every candidate - built-in or plugin - is
validated against :class:`ildottore.shared.protocols.Mutator` at registration; a class that
does not satisfy the protocol raises :class:`MutatorProtocolError` with a clear message
(never a silent skip - contract §7 registry test).

Discovery executes no attack and makes no network call; it only imports the plugin class and
protocol-checks an instance.
"""

from __future__ import annotations

from importlib.metadata import entry_points

from ildottore.mutators.adversarial_poetry import AdversarialPoetryMutator
from ildottore.mutators.adversarial_suffix import AdversarialSuffixMutator
from ildottore.mutators.base import Mutator
from ildottore.mutators.base64_wrap import Base64WrapMutator
from ildottore.mutators.comment_carrier import (
    HtmlCommentCarrierMutator,
    MarkdownCommentCarrierMutator,
)
from ildottore.mutators.context_poisoning import ContextPoisoningMutator
from ildottore.mutators.gray_box import GrayBoxMutator
from ildottore.mutators.identity import IdentityMutator
from ildottore.mutators.leetspeak import LeetspeakMutator
from ildottore.mutators.linguistic_confusion import LinguisticConfusionMutator
from ildottore.mutators.math_problem import MathProblemMutator
from ildottore.mutators.nested_instruction import NestedInstructionMutator
from ildottore.mutators.payload_splitting import PayloadSplittingMutator
from ildottore.mutators.refusal_suppression_prefix import RefusalSuppressionPrefixMutator
from ildottore.mutators.roleplay_wrap import RoleplayWrapMutator
from ildottore.mutators.rot13 import Rot13Mutator
from ildottore.mutators.translate import TranslateMutator
from ildottore.mutators.unicode_confusable import UnicodeConfusableMutator
from ildottore.mutators.zero_width_inject import ZeroWidthInjectMutator

__all__ = [
    "ENTRY_POINT_GROUP",
    "MutatorProtocolError",
    "MutatorRegistry",
    "build_default_registry",
]

ENTRY_POINT_GROUP = "dottore.mutators"

# The 19 built-in strategies (docs/03 §4 + docs/14 enhancers + docs/12 P1 adversarial suffix).
# ``markdown_comment_carrier`` + ``html_comment_carrier`` are the two carriers named in the
# docs; ``comment_carrier`` is the owning module (contract §1).
_BUILTINS: tuple[type[Mutator], ...] = (
    IdentityMutator,
    TranslateMutator,
    Base64WrapMutator,
    Rot13Mutator,
    UnicodeConfusableMutator,
    ZeroWidthInjectMutator,
    RoleplayWrapMutator,
    NestedInstructionMutator,
    HtmlCommentCarrierMutator,
    MarkdownCommentCarrierMutator,
    PayloadSplittingMutator,
    RefusalSuppressionPrefixMutator,
    LeetspeakMutator,
    AdversarialPoetryMutator,
    AdversarialSuffixMutator,
    MathProblemMutator,
    GrayBoxMutator,
    LinguisticConfusionMutator,
    ContextPoisoningMutator,
)


class MutatorProtocolError(TypeError):
    """A registered class/instance does not satisfy the :class:`Mutator` protocol."""


def _validate(instance: object, *, origin: str) -> Mutator:
    """Protocol-check an instance; raise a clear error on a bad plugin (no silent skip)."""
    name = getattr(instance, "name", None)
    if not isinstance(name, str) or not name:
        raise MutatorProtocolError(
            f"mutator from {origin} is missing a non-empty str 'name' attribute"
        )
    if not callable(getattr(instance, "mutate", None)):
        raise MutatorProtocolError(f"mutator '{name}' from {origin} has no callable 'mutate'")
    if not isinstance(instance, Mutator):
        raise MutatorProtocolError(
            f"mutator '{name}' from {origin} does not satisfy the Mutator protocol"
        )
    return instance


class MutatorRegistry:
    """A name→instance registry of mutators with protocol validation at insert time."""

    def __init__(self) -> None:
        self._by_name: dict[str, Mutator] = {}

    def register(self, instance: Mutator, *, origin: str = "manual", replace: bool = False) -> None:
        """Validate then register ``instance`` under its ``name``.

        A duplicate name raises unless ``replace`` is set (built-ins register first; a plugin
        reusing a built-in name is a configuration error surfaced to the operator).
        """
        validated = _validate(instance, origin=origin)
        if validated.name in self._by_name and not replace:
            raise MutatorProtocolError(
                f"duplicate mutator name '{validated.name}' (origin {origin}); "
                "names must be unique across built-ins and plugins"
            )
        self._by_name[validated.name] = validated

    def get(self, name: str) -> Mutator:
        """Return the mutator registered under ``name`` (``KeyError`` if unknown)."""
        return self._by_name[name]

    def has(self, name: str) -> bool:
        """Whether a mutator is registered under ``name``."""
        return name in self._by_name

    def names(self) -> list[str]:
        """Sorted list of registered mutator names (deterministic ordering)."""
        return sorted(self._by_name)

    def discover_plugins(self) -> list[str]:
        """Load ``dottore.mutators`` entry points, validate, and register each.

        Returns the list of newly registered plugin names. A plugin that fails protocol
        validation raises :class:`MutatorProtocolError` (never a silent skip - contract §7).
        """
        loaded: list[str] = []
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            cls = ep.load()
            instance = cls()
            self.register(instance, origin=f"entry-point '{ep.name}'")
            loaded.append(instance.name)
        return loaded


def build_default_registry(*, discover: bool = True) -> MutatorRegistry:
    """Build a registry with the 12 built-ins and (optionally) discovered plugins."""
    registry = MutatorRegistry()
    for cls in _BUILTINS:
        registry.register(cls(), origin="builtin")
    if discover:
        registry.discover_plugins()
    return registry
