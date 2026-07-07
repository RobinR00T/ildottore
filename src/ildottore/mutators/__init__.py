"""Prompt Mutator (u05): deterministic, intent-preserving carrier transforms.

Expands one base attack carrier into the declared variants (``docs/03 §4``). Every strategy
is a pure function of ``(text, seed)`` — no I/O, no clock, no unseeded RNG — and satisfies
the shared :class:`ildottore.shared.protocols.Mutator` protocol. Determinism is seeded by the
``(spec.id, mutation.name)`` string the execution engine (u08) passes as ``seed``.

Public surface: the 12 built-in strategy classes, the :class:`MutationResult` shape, and the
:class:`MutatorRegistry` (built-ins + ``dottore.mutators`` entry-point discovery).
"""

from __future__ import annotations

from ildottore.mutators.base import BaseMutator, MutationResult, Mutator, derive_int_seed
from ildottore.mutators.base64_wrap import Base64WrapMutator
from ildottore.mutators.comment_carrier import (
    HtmlCommentCarrierMutator,
    MarkdownCommentCarrierMutator,
)
from ildottore.mutators.identity import IdentityMutator
from ildottore.mutators.nested_instruction import NestedInstructionMutator
from ildottore.mutators.payload_splitting import PayloadSplittingMutator
from ildottore.mutators.refusal_suppression_prefix import RefusalSuppressionPrefixMutator
from ildottore.mutators.registry import (
    ENTRY_POINT_GROUP,
    MutatorProtocolError,
    MutatorRegistry,
    build_default_registry,
)
from ildottore.mutators.roleplay_wrap import RoleplayWrapMutator
from ildottore.mutators.rot13 import Rot13Mutator
from ildottore.mutators.translate import TranslateMutator
from ildottore.mutators.unicode_confusable import UnicodeConfusableMutator
from ildottore.mutators.zero_width_inject import ZeroWidthInjectMutator

__all__ = [
    "ENTRY_POINT_GROUP",
    "Base64WrapMutator",
    "BaseMutator",
    "HtmlCommentCarrierMutator",
    "IdentityMutator",
    "MarkdownCommentCarrierMutator",
    "MutationResult",
    "Mutator",
    "MutatorProtocolError",
    "MutatorRegistry",
    "NestedInstructionMutator",
    "PayloadSplittingMutator",
    "RefusalSuppressionPrefixMutator",
    "RoleplayWrapMutator",
    "Rot13Mutator",
    "TranslateMutator",
    "UnicodeConfusableMutator",
    "ZeroWidthInjectMutator",
    "build_default_registry",
    "derive_int_seed",
]
