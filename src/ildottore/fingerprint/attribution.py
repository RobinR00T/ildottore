"""Candidate attribution encoding for fingerprint evidence (u09, internal).

``shared.models.FingerprintEvidence`` is the stable wire shape ``{layer, signal,
weight}`` (ADR-0006 / ``docs/10 §2``) — it has no explicit "which candidate does
this support" field. Rather than widen the shared model (owned by u00, must-not-touch),
u09 encodes the supported candidate as a structured, human-readable prefix in the
``signal`` string and decodes it in :mod:`ildottore.fingerprint.combine`.

Encoding: ``"family=<f>|version=<v>|<detail>"`` (``version=`` omitted for a
family-only signal). This keeps the evidence readable in a report *and* machine-
parseable for fusion, without a schema change. The separators (``|`` / ``=``) are
reserved; family/version names in the pack must not contain them (validated by the
pack self-test).
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Attribution", "encode_signal", "parse_signal"]

_FIELD_SEP = "|"
_KV_SEP = "="


@dataclass(frozen=True)
class Attribution:
    """A decoded evidence attribution: which family/version a signal supports."""

    family: str | None
    version: str | None
    detail: str


def encode_signal(family: str, version: str | None, detail: str) -> str:
    """Encode a candidate attribution into a ``FingerprintEvidence.signal`` string."""

    head = f"family{_KV_SEP}{family}"
    if version is not None:
        head += f"{_FIELD_SEP}version{_KV_SEP}{version}"
    return f"{head}{_FIELD_SEP}{detail}"


def parse_signal(signal: str) -> Attribution:
    """Decode a ``signal`` produced by :func:`encode_signal`.

    Tolerant: a signal that does not carry the ``family=`` prefix (e.g. a
    hand-written or legacy signal) decodes to an unattributed ``Attribution`` with
    the whole string as ``detail`` — the combiner then treats it as non-scoring.
    """

    parts = signal.split(_FIELD_SEP)
    family: str | None = None
    version: str | None = None
    detail_parts: list[str] = []
    for part in parts:
        if part.startswith(f"family{_KV_SEP}"):
            family = part[len(f"family{_KV_SEP}") :]
        elif part.startswith(f"version{_KV_SEP}"):
            version = part[len(f"version{_KV_SEP}") :]
        else:
            detail_parts.append(part)
    return Attribution(family=family, version=version, detail=_FIELD_SEP.join(detail_parts))
