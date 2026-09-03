"""Signature-pack loader + schema/version validation (u09, contract §5 step 1).

The signature "DB" is a **versioned data pack**, not code (``docs/06``, contract §1
Ships): new models = update the pack, not the engine. It ships in-repo under
``src/ildottore/fingerprint/signatures/`` for MVP-1 (contract §9 propose in-repo,
extract later) plus a labeled **self-test corpus** used by the detection gate
(contract §7, ``docs/10 §6``).

A pack is a small Pydantic-validated document (contract §4 KEEP: "loader validates
pack version + schema; a pack update must not silently break the loader"). Each
entry declares, per family/version, the matcher fragments each layer looks for and
a feature-vector centroid for the statistical nearest-neighbor (OD-9 - no embedder
dep). The loader raises :class:`SignaturePackError` on a version mismatch or a
malformed document so a bad pack fails loudly at load, never silently mis-fingerprints.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

__all__ = [
    "CorpusCase",
    "SignatureEntry",
    "SignaturePack",
    "SignaturePackError",
    "StatSignature",
    "load_corpus",
    "load_pack",
]

# The only pack-format version this loader understands. A pack declaring anything
# else is rejected (contract §4 KEEP) - the caller must ship a matching loader.
SUPPORTED_PACK_VERSION = 1

_DEFAULT_PACK = Path(__file__).parent / "signatures" / "pack.yaml"
_DEFAULT_CORPUS = Path(__file__).parent / "signatures" / "corpus.yaml"


class SignaturePackError(Exception):
    """A pack failed version or schema validation (contract §4 KEEP)."""


class StatSignature(BaseModel):
    """Feature-vector centroid for the statistical layer (OD-9, LLMmap-style).

    ``centroid`` is a fixed-length response feature vector (see
    :mod:`ildottore.fingerprint.layers.statistical` for how a response is
    featurized). Nearest-neighbor by Euclidean distance against these centroids
    replaces a heavy/ambiguous-license embedder (``AGENTS.md §3``, OD-9).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    centroid: list[float] = Field(min_length=1)


class SignatureEntry(BaseModel):
    """One family/version signature (contract §6 "Signature pack entry").

    ``signals`` maps a layer name to a list of matcher fragments (substrings the
    layer looks for in that layer's textual signal); ``weights`` maps a layer name
    to the evidence weight a match contributes; ``stat`` carries the statistical
    centroid. ``version`` is optional (a family-only entry has no version guess).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    family: str
    version: str | None = None
    cutoff_hint: str | None = None
    signals: dict[str, list[str]] = Field(default_factory=dict)
    weights: dict[str, float] = Field(default_factory=dict)
    stat: StatSignature | None = None


class SignaturePack(BaseModel):
    """A versioned signature data pack (contract §1 Ships, ``docs/06``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pack_version: int
    name: str
    entries: list[SignatureEntry] = Field(min_length=1)

    def families(self) -> list[str]:
        """Distinct family names in declaration order (stable for determinism)."""

        seen: dict[str, None] = {}
        for entry in self.entries:
            seen.setdefault(entry.family, None)
        return list(seen)


class CorpusCase(BaseModel):
    """One labeled self-test corpus case (contract §7 detection gate).

    A case is a *recorded* target: the responses each battery probe would elicit,
    keyed by probe name, plus HTTP-ish metadata the metadata layer inspects, and
    the ground-truth ``family``/``version`` label. The detection-gate test replays
    these offline through a mock adapter and scores precision/recall + top-k.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    family: str
    version: str | None = None
    # probe-name -> canned response text
    responses: dict[str, str] = Field(default_factory=dict)
    # passive metadata the target would expose (raw_ids/headers/finish_reason echo)
    metadata: dict[str, str] = Field(default_factory=dict)
    finish_reason: str | None = None
    # a deliberately-spoofed self-report (behavioral says X, stats say family) -
    # used by the spoofing-honesty fixtures (contract §7).
    spoofed: bool = False


def _read_yaml(path: Path) -> Any:
    """Parse a YAML document, raising :class:`SignaturePackError` on I/O/parse error."""

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:  # missing/unreadable pack is a hard load failure
        raise SignaturePackError(f"cannot read signature file {path}: {exc}") from exc
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise SignaturePackError(f"invalid YAML in {path}: {exc}") from exc


def load_pack(path: Path | None = None) -> SignaturePack:
    """Load + validate the signature pack (contract §4 KEEP).

    Validates the pack-format version first (a future/unknown ``pack_version`` is
    rejected before schema parsing so the error is precise), then the Pydantic
    schema. Defaults to the in-repo MVP-1 pack.
    """

    doc = _read_yaml(path or _DEFAULT_PACK)
    if not isinstance(doc, dict):
        raise SignaturePackError("signature pack must be a mapping")
    declared = doc.get("pack_version")
    if declared != SUPPORTED_PACK_VERSION:
        raise SignaturePackError(
            f"unsupported pack_version {declared!r}; loader supports {SUPPORTED_PACK_VERSION}"
        )
    try:
        return SignaturePack.model_validate(doc)
    except ValidationError as exc:
        raise SignaturePackError(f"signature pack failed schema validation: {exc}") from exc


def load_corpus(path: Path | None = None) -> list[CorpusCase]:
    """Load + validate the labeled self-test corpus (contract §7)."""

    doc = _read_yaml(path or _DEFAULT_CORPUS)
    if not isinstance(doc, dict) or "cases" not in doc:
        raise SignaturePackError("corpus must be a mapping with a 'cases' list")
    try:
        return [CorpusCase.model_validate(c) for c in doc["cases"]]
    except ValidationError as exc:
        raise SignaturePackError(f"corpus failed schema validation: {exc}") from exc
