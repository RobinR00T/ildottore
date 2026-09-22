"""Content digests for the battery that a run executed (u00 shared, no imports upward).

A resumed campaign reuses the original run id, merges the stored attempts with the fresh
ones and scores the result as one run. That is only sound while both halves ran **the same
specs**. Nothing checked it: editing a prompt, tightening an evaluator or adding a spec
between the halt and the resume produced a single report, under a single id, whose evidence
came from two different batteries, with no marker anywhere saying so.

The digest is taken over the **loaded model**, not the file bytes, so reformatting a YAML
file or editing a comment does not invalidate a resume, while any change that reaches the
wire or the verdict does.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Final

from ildottore.shared.models import AttackSpec

__all__ = ["BATTERY_DIGEST_PREFIX", "battery_digest", "spec_digest", "spec_digests"]

#: Marks a digest as produced by this scheme, so a future scheme change is visible in the
#: stored value instead of silently comparing apples to oranges.
BATTERY_DIGEST_PREFIX: Final = "sha256:"


def spec_digest(spec: AttackSpec) -> str:
    """SHA-256 of one spec's canonical JSON serialization."""

    canonical = json.dumps(
        spec.model_dump(mode="json"),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return BATTERY_DIGEST_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def spec_digests(specs: Iterable[AttackSpec]) -> dict[str, str]:
    """``{spec_id: digest}`` for a battery, so a mismatch can name what changed."""

    return {spec.id: spec_digest(spec) for spec in specs}


def battery_digest(digests: dict[str, str]) -> str:
    """One digest over the whole battery (id + per-spec digest, order-independent)."""

    joined = "\n".join(f"{spec_id}={digest}" for spec_id, digest in sorted(digests.items()))
    return BATTERY_DIGEST_PREFIX + hashlib.sha256(joined.encode("utf-8")).hexdigest()
