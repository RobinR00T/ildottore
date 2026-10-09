"""Content digests for what a run executed (u00 shared, no imports upward).

A resumed campaign reuses the original run id, merges the stored attempts with the fresh ones
and scores the result as one run. That is only sound while both halves ran **the same specs
against the same target**. Nothing checked either: editing a prompt, or pointing the same
target id at a different endpoint, or flipping the offline scenario with a CLI flag, produced
one report, under one id, out of two different campaigns, with no marker anywhere.

Two digests, because they fail differently. The battery digest names *which spec* changed, so
the refusal is actionable. The target digest is one value, because "the target is not the one
this evidence came from" needs no itemisation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any, Final

from ildottore.shared.models import AttackSpec, Target

__all__ = ["DIGEST_PREFIX", "spec_digest", "spec_digests", "target_digest"]

#: Marks a digest as produced by this scheme. A future scheme change is then visible in the
#: stored value instead of silently comparing apples to oranges.
DIGEST_PREFIX: Final = "sha256:v2:"

#: Spec fields deliberately OUTSIDE the digest: they reach neither the wire, nor the verdict,
#: nor any published number. An audit showed that hashing the whole model refused a resume over
#: an edited `description`, which is how a check trains the operator to work around it.
#:
#: The list is short because a second audit shortened it. `tags` was in it and is **load
#: bearing**: `policy/packs.py` reads `layer_b` and `pii_elicitation` off it, so removing a tag
#: turns a policy-blocked spec into traffic on the wire under an unchanged digest, and that is
#: the DL4 safety gate. `nist_ai_rmf` was in it and feeds the `by_framework.nist` rollup, a
#: SARIF tag and an HTML column, which is a published number by this clause's own criterion.
#:
#: `fixtures` is deliberately **inside**. For a live target it is offline self-test data, but
#: the `vulnerable`/`hardened` mock scenarios replay it as the target's own answers, so for an
#: offline run it decides the verdict. Excluding it would be right for one kind of run and a
#: false negative for the other, and a false negative is the direction that costs.
#:
#: `aisvs` is **outside**, and the reason is the same criterion read the other way. It feeds
#: `dottore coverage`, which reads the specs and not a run, so no run artifact carries it, and
#: hashing it made a campaign halted before the AISVS mapping landed unresumable after it, over a
#: field the run never reads (measured 2026-10-03). If the run report ever rolls findings up by
#: AISVS ID, it moves inside.
_COSMETIC_FIELDS: Final = frozenset({"name", "description", "preconditions", "aisvs"})

#: Target fields outside the digest: they say nothing about what is on the other end of the
#: wire. Everything else is in, including `endpoint`, `model`, `provider` and `capabilities`.
_TARGET_COSMETIC: Final = frozenset({"name", "description", "tags"})


def _sha(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return DIGEST_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def spec_digest(spec: AttackSpec) -> str:
    """SHA-256 over one spec's behavioural projection (see :data:`_COSMETIC_FIELDS`)."""

    dumped = spec.model_dump(mode="json")
    return _sha({k: v for k, v in dumped.items() if k not in _COSMETIC_FIELDS})


def spec_digests(specs: Iterable[AttackSpec]) -> dict[str, str]:
    """``{spec_id: digest}`` for a battery, so a mismatch can name what changed."""

    return {spec.id: spec_digest(spec) for spec in specs}


def target_digest(target: Target, *, mock_scenario: str | None = None) -> str:
    """SHA-256 over the target and the route resolved for it.

    ``mock_scenario`` is part of the digest because it is part of what answers: `--resume`
    with `--hardened` flipped the offline replay and published a vulnerable half's criticals
    as a hardened run's findings, without touching a single file. The id matched, the specs
    matched, and the answers came from somewhere else.
    """

    dumped = target.model_dump(mode="json")
    payload = {k: v for k, v in dumped.items() if k not in _TARGET_COSMETIC}
    # Absent, it is left out, so a run stored before the field existed still resumes; present,
    # it is part of what answers (which specs the deployment holds the scene for).
    for optional in ("seeded_setup", "websocket"):
        if payload.get(optional) is None:
            payload.pop(optional, None)
    payload["__route__"] = mock_scenario or "live"
    return _sha(payload)
