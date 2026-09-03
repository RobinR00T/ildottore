"""Loaded-pack aggregate + flagged-family policy (contract §5.2, §4 KEEP).

A *spec pack* on disk is a directory containing ``pack.yaml`` plus ``attacks/*.yaml`` and
``suites/*.yaml`` (``docs/06 §2``). The manifest model (:class:`~ildottore.shared.Pack`)
and the suite model (:class:`~ildottore.shared.Suite`) are owned by u00 (Pydantic-first,
ADR-0006 / OD-14) — this unit imports them, never redefines them.

:class:`LoadedPack` binds a parsed manifest to the concrete specs and suites discovered
inside its directory, preserving on-disk discovery order so later packs extend — never
silently override — earlier ids (collision handling lives in ``registry.py``).
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ildottore.shared import AttackSpec, Category, Pack, Suite

# Families whose raw payloads are dangerous outside a controlled test and therefore MUST
# carry ``test_only: true`` (contract §4 KEEP; docs/02 S5, docs/03 §2). Decision logged in
# contract §9 / notes: derived from docs/02 S5 "dangerous outside a test" + the shipped
# DOS-TOKEN-FLOOD-001 fixture which sets test_only. Prompt-injection / RAG / output specs
# are diagnostic (they probe handling), so they are not force-flagged.
FLAGGED_FAMILIES: frozenset[Category] = frozenset(
    {
        Category.JAILBREAK,
        Category.DATA_LEAKAGE,
        Category.AGENT_TOOL_ABUSE,
        Category.AVAILABILITY_COST,
        # Harmful-content safety probes carry disallowed requests, so they must be test_only
        # (bias_fairness prompts are benign demographic questions, so they are not flagged).
        Category.SAFETY_CONTENT,
    }
)


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
