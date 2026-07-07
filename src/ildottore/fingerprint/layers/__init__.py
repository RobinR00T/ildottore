"""Signal layers for the fingerprint engine (u09, contract §1).

Each module exposes one :class:`~ildottore.fingerprint.base.FingerprintLayer`
implementation. The engine composes the default set via :func:`default_layers`;
callers may pass their own list for pluggable extension (contract §1).
"""

from __future__ import annotations

from ildottore.fingerprint.base import FingerprintLayer
from ildottore.fingerprint.layers.behavioral import BehavioralLayer
from ildottore.fingerprint.layers.capability import CapabilityLayer
from ildottore.fingerprint.layers.guardrail import GuardrailLayer
from ildottore.fingerprint.layers.metadata import MetadataLayer
from ildottore.fingerprint.layers.statistical import StatisticalLayer
from ildottore.fingerprint.layers.tokenizer import TokenizerLayer

__all__ = [
    "BehavioralLayer",
    "CapabilityLayer",
    "GuardrailLayer",
    "MetadataLayer",
    "StatisticalLayer",
    "TokenizerLayer",
    "default_layers",
]


def default_layers() -> list[FingerprintLayer]:
    """The six default signal layers in a stable order (contract §1, §5).

    Order is deterministic so the assembled evidence list is byte-stable across
    runs (contract §7 determinism). The combiner does not depend on order, but the
    golden fixtures do.
    """

    return [
        MetadataLayer(),
        CapabilityLayer(),
        BehavioralLayer(),
        TokenizerLayer(),
        GuardrailLayer(),
        StatisticalLayer(),
    ]
