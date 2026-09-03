"""Model fingerprinting engine (u09, ``docs/10``, ADR-0006).

Standalone recognition: probe an unknown endpoint with **benign** seeded signals
across six layers (passive/metadata, capability, behavioral, tokenizer, guardrail,
statistical), fuse the weighted evidence and return a
:class:`~ildottore.shared.models.ModelFingerprint` - family/version guesses with
confidence, a ``capability_guess``, a guardrail profile, the evidence trail and
honest ``spoofing_flags`` when self-report contradicts the statistical layer.

Per ADR-0006 this unit **produces the fingerprint only** - it does not build a
``TestPlan`` (that is u08's ``core/planner.py``). Consumes the target exclusively
through the injected :class:`~ildottore.shared.protocols.TargetAdapter`.
"""

from __future__ import annotations

from ildottore.fingerprint.base import FingerprintLayer, ProbeContext, seed_for
from ildottore.fingerprint.combine import CombinedFingerprint, combine
from ildottore.fingerprint.engine import FingerprintEngine, fingerprint
from ildottore.fingerprint.layers import default_layers
from ildottore.fingerprint.probes import (
    BEHAVIORAL_BATTERY,
    STATISTICAL_BATTERY,
    Probe,
    build_request,
)
from ildottore.fingerprint.signatures import (
    CorpusCase,
    SignatureEntry,
    SignaturePack,
    SignaturePackError,
    StatSignature,
    load_corpus,
    load_pack,
)

__all__ = [
    "BEHAVIORAL_BATTERY",
    "STATISTICAL_BATTERY",
    "CombinedFingerprint",
    "CorpusCase",
    "FingerprintEngine",
    "FingerprintLayer",
    "Probe",
    "ProbeContext",
    "SignatureEntry",
    "SignaturePack",
    "SignaturePackError",
    "StatSignature",
    "build_request",
    "combine",
    "default_layers",
    "fingerprint",
    "load_corpus",
    "load_pack",
    "seed_for",
]
