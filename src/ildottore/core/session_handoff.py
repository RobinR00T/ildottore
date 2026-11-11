"""A session handed from one identity to another (u08 A-134, OD-76, ADR-0026).

A spec that declares ``setup.session_handoff`` asks whether the server binds a conversation to
the identity that opened it. The identity sweep sends it in order: the owner identity sends the
plant (holding the spec's canary) in a conversation of its own, the id of that conversation
travelling in the request body at the target file's ``rest.session.field``; then every other scope
identity sends the attack carrying the owner's id. A server that binds the conversation to its
owner answers them in one of their own, with no canary; one that does not lets them adopt it, and
the owner's canary in their reply is ``authz_leak``'s crossing (CWE-639, CWE-384).

The id is the scanner's (:func:`scanner_session_id`, derived from the run and the spec, so a
replay sends the same one) unless the target file declares ``rest.session.reply_path``: then it is
the one the owner's reply returned, and a reply that returned none sends nobody after it (fail
closed: an adopter sent a made-up id would land in a fresh conversation and read as a pass).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Final, Protocol

from ildottore.shared.models import AttackSpec, Target

__all__ = [
    "NO_ISSUED_ID",
    "OWNER_UNHEARD",
    "carries_session",
    "hands_off",
    "owner_index",
    "scanner_session_id",
    "session_digest",
    "session_gap",
]

#: Why an adopter was not sent, as the sweep's trial says it.
OWNER_UNHEARD: Final = (
    "the owner's plant was not heard, so there was no conversation to adopt, and the reply this "
    "identity would have given may be the one that adopted it"
)
NO_ISSUED_ID: Final = (
    "the owner's reply returned no conversation id at rest.session.reply_path, so there was no id "
    "to hand over, and the reply this identity would have given may be the one that adopted it"
)

#: The domain of the scanner's conversation id, so it shares no bits with a canary's digests.
_DOMAIN: Final = b"ildottore/session-handoff/v1\x00"
_ID_HEX: Final = 32


class _Probe(Protocol):
    @property
    def sends_attempts(self) -> bool: ...


def hands_off(spec: AttackSpec) -> bool:
    """True when ``spec`` hands one identity's session to the others (``setup.session_handoff``)."""

    return spec.setup is not None and spec.setup.session_handoff is not None


def carries_session(target: Target) -> bool:
    """True when the target file says where a conversation id travels (``rest.session``)."""

    return target.rest is not None and target.rest.session is not None


def session_gap(spec: AttackSpec, target: Target) -> str | None:
    """Why ``spec``'s handoff cannot be sent to ``target``, or ``None``.

    A deployment is told the conversation a message belongs to in its own way; the generic REST
    body says it only where the target file declares ``rest.session``. Sent without it, the
    adopters would carry no id at all, and a pass would say nothing about the binding.
    """

    if not hands_off(spec) or carries_session(target):
        return None
    return (
        "session_handoff_unavailable: the spec hands one identity's conversation id to another, "
        "and the target file declares no rest.session (the body field the id travels in) to "
        "carry it"
    )


def scanner_session_id(run_id: str, spec_id: str) -> str:
    """The conversation id the scanner gives the owner: stable per run and spec, unguessable."""

    digest = hashlib.sha256(_DOMAIN + f"{run_id}\x00{spec_id}".encode()).hexdigest()
    return f"dottore-{digest[:_ID_HEX]}"


def session_digest(session_id: str) -> str:
    """What the evidence records of a conversation id: 12 hex digits of its SHA-256, not the id.

    An id the server issued is a credential of the owner's conversation; the digest lets a
    reader match two records of one id without the id being written down.
    """

    return hashlib.sha256(session_id.encode()).hexdigest()[:12]


def owner_index(probes: Sequence[_Probe]) -> int:
    """The probe that owns the conversation: the first the attempts are not sent as.

    The attempts are sent with the target file's credential; an owner sent the attempts would see
    its own canary in them, which is no adoption. With every probe sending the attempts (one
    credential on all of them, which only a locally launched target may declare), the first.
    """

    return next((i for i, probe in enumerate(probes) if not probe.sends_attempts), 0)
