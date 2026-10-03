"""Loaded-pack aggregate + flagged-family policy (contract §5.2, §4 KEEP).

A *spec pack* on disk is a directory containing ``pack.yaml`` plus ``attacks/*.yaml`` and
``suites/*.yaml`` (``docs/06 §2``). The manifest model (:class:`~ildottore.shared.Pack`)
and the suite model (:class:`~ildottore.shared.Suite`) are owned by u00 (Pydantic-first,
ADR-0006 / OD-14) - this unit imports them, never redefines them.

:class:`LoadedPack` binds a parsed manifest to the concrete specs and suites discovered
inside its directory, preserving on-disk discovery order so later packs extend - never
silently override - earlier ids (collision handling lives in ``registry.py``).
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ildottore.shared import AttackSpec, Pack, Suite
from ildottore.shared.enums import FLAGGED_FAMILIES

# ``FLAGGED_FAMILIES`` moved to ``shared.enums`` (the policy gate reads it too); re-exported
# here so ``registry.FLAGGED_FAMILIES`` keeps working.
__all__ = ["FLAGGED_FAMILIES", "LoadedPack"]


class LoadedPack(BaseModel):
    """A parsed pack manifest bound to its discovered specs + suites."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    manifest: Pack
    root: Path
    specs: list[AttackSpec] = Field(default_factory=list)
    suites: list[Suite] = Field(default_factory=list)

    @property
    def id(self) -> str:
        """The pack id (from the manifest)."""
        return self.manifest.id

    @property
    def version(self) -> str:
        """The pack version (from the manifest)."""
        return self.manifest.pack_version
