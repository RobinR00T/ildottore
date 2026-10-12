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

__all__ = [
    "DIGEST_PREFIX",
    "FIELD_DIGEST_LENGTH",
    "spec_digest",
    "spec_digests",
    "spec_field_digests",
    "target_digest",
    "target_field_digests",
]

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


#: Hex digits of a field digest (:func:`spec_field_digests`): it names the field a refusal
#: blames, while the full digest is what binds, so 32 bits are plenty and a battery's record
#: stays small (about 40 KB for the 75 shipped specs).
FIELD_DIGEST_LENGTH: Final = 8


def _canonical(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _sha(payload: Any) -> str:
    return DIGEST_PREFIX + hashlib.sha256(_canonical(payload)).hexdigest()


def _short(payload: Any) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()[:FIELD_DIGEST_LENGTH]


def _spec_payload(spec: AttackSpec) -> dict[str, Any]:
    dumped = spec.model_dump(mode="json")
    return {k: v for k, v in dumped.items() if k not in _COSMETIC_FIELDS}


def spec_digest(spec: AttackSpec) -> str:
    """SHA-256 over one spec's behavioural projection (see :data:`_COSMETIC_FIELDS`)."""

    return _sha(_spec_payload(spec))


def spec_field_digests(spec: AttackSpec) -> dict[str, str]:
    """``{field: short digest}`` over the same projection, so a refusal can name the field.

    The spec digest says THAT a spec changed; this says WHERE. A resume of a run halted before
    the OD-19 rename read "75 changed", which said neither that ``evaluator_logic`` was the only
    field, nor what to do about it (CLI audit 2026-10-11, M1).
    """

    return {field: _short(value) for field, value in _spec_payload(spec).items()}


def spec_digests(specs: Iterable[AttackSpec]) -> dict[str, str]:
    """``{spec_id: digest}`` for a battery, so a mismatch can name what changed."""

    return {spec.id: spec_digest(spec) for spec in specs}


def _target_payload(target: Target, mock_scenario: str | None) -> dict[str, Any]:
    dumped = target.model_dump(mode="json")
    payload = {k: v for k, v in dumped.items() if k not in _TARGET_COSMETIC}
    # Absent, it is left out, so a run stored before the field existed still resumes; present,
    # it is part of what answers (which specs the deployment holds the scene for).
    for optional in ("seeded_setup", "websocket"):
        if payload.get(optional) is None:
            payload.pop(optional, None)
    # The tools the target file declares not destructive (OD-43, u06 A-72): none declared, the
    # key is left out, so a run stored before a file could declare one still resumes; declared,
    # it is part of what judges, and a resume after a change is refused as another target.
    seeded = payload.get("seeded_setup")
    if isinstance(seeded, dict) and not seeded.get("not_destructive"):
        seeded.pop("not_destructive", None)
    # Likewise `capabilities.sampling` (u12 A-68): not declared, it is left out, so a run stored
    # before the capability existed still resumes; declared, it is part of what answers.
    capabilities = payload.get("capabilities")
    if isinstance(capabilities, dict) and capabilities.get("sampling") is None:
        capabilities.pop("sampling", None)
    # And `capabilities.mcp` (OD-44): false, or set because the provider is `mcp` (already in the
    # digest), it adds nothing, so it is left out and a run stored before it existed resumes;
    # declared by an offline mock of another provider, it is part of what answers.
    provider = str(payload.get("provider") or "").strip().lower()
    if isinstance(capabilities, dict) and (not capabilities.get("mcp") or provider == "mcp"):
        capabilities.pop("mcp", None)
    payload["__route__"] = mock_scenario or "live"
    return payload


def target_digest(target: Target, *, mock_scenario: str | None = None) -> str:
    """SHA-256 over the target and the route resolved for it.

    ``mock_scenario`` is part of the digest because it is part of what answers: `--resume`
    with `--hardened` flipped the offline replay and published a vulnerable half's criticals
    as a hardened run's findings, without touching a single file. The id matched, the specs
    matched, and the answers came from somewhere else.
    """

    return _sha(_target_payload(target, mock_scenario))


def target_field_digests(target: Target, *, mock_scenario: str | None = None) -> dict[str, str]:
    """``{field: short digest}`` over the target digest's payload, ``__route__`` included.

    So a refused resume names what differs: "its endpoint, model, capabilities, sampling_defaults,
    offline scenario or seeded_setup differ" told the operator of a ``--resume --hardened``, whose
    file was unchanged, to "restore the target as it was" (CLI audit 2026-10-11, M1).
    """

    return {field: _short(value) for field, value in _target_payload(target, mock_scenario).items()}
