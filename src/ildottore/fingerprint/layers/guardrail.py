"""Guardrail signal layer (u09, contract §5 step 4, §7 A-67, ``docs/10 §1``).

Benign boundary nudges only (no jailbreak payload, contract §8). The layer sends the two probes of
:data:`~ildottore.fingerprint.probes.GUARDRAIL_BATTERY`, each of which declares the reply it
expects, and scores a reply against that expectation (OD-40, decided by the owner 2026-10-09):

* ``guardrail_nudge`` asks the model to refuse. A refusal is the model doing as asked, so it is
  never a filter signal: the layer reads its style (``refusal_style``) and the pack's family
  tells from it, as before. Until OD-40 any refusal here was an output filter, and a canned one an
  input filter too, so a model that followed the instruction was reported filtered.
* ``guardrail_benign`` asks for something that should be answered, worded near a boundary. A
  refusal of it is ``benign_refused``: a filter or the model's own alignment, which a benign
  probe cannot tell apart, so neither is claimed.
* A reply the provider stopped with its own filter marker (``content_filter``, or Anthropic's
  ``refusal``) was cut or replaced after the model wrote it: ``output_filter``, on whichever probe
  it lands. A reply cut at the probe's own token cap (``length``) is not one.

The layer emits:

* an unattributed ``guardrail_profile`` evidence carrying that profile (the engine reads it to
  fill ``ModelFingerprint.guardrails``),
* family-attributed evidence where the pack declares ``signals["guardrail"]`` tells, matched
  against the requested refusal only. The benign reply is read for the profile alone
  (:data:`PROFILE_ONLY_PROBES`), so attribution is what it was.

``input_filter`` stays in the profile as ``None``: no benign probe separates an input filter from
the model's own refusal. Latency is read from the replies when the adapter surfaces it
(``usage``); it is ``None`` when unavailable rather than fabricated (contract §4 KEEP: honest low
confidence over invented data).
"""

from __future__ import annotations

import json
from typing import Final

from ildottore.fingerprint.attribution import encode_signal
from ildottore.fingerprint.base import PROBE_SAMPLING, ProbeContext, ProbeFailed, seed_for
from ildottore.fingerprint.probes import GUARDRAIL_BATTERY, build_request
from ildottore.fingerprint.signatures import SignaturePack
from ildottore.shared.amounts import is_amount
from ildottore.shared.models import (
    FingerprintEvidence,
    ModelRequest,
    ModelResponse,
)
from ildottore.shared.protocols import TargetAdapter

__all__ = [
    "BENIGN_REQUEST",
    "GUARDRAIL_PROFILE_DETAIL",
    "PROFILE_ONLY_PROBES",
    "REQUESTED_REFUSAL",
    "GuardrailLayer",
    "classify_refusal",
    "guardrail_profile",
    "reply_outcome",
]

_LAYER = "guardrail"
GUARDRAIL_PROFILE_DETAIL = "guardrail_profile"

#: The probe kinds of the battery: the reply each one expects.
REQUESTED_REFUSAL: Final = "requested_refusal"
BENIGN_REQUEST: Final = "benign_request"

#: Probes whose reply is read for the profile only, never matched against the pack. The engine
#: leaves them out of the constant-target check, as it does the carriers: a reply no layer
#: attributes from cannot show that the attributing replies varied.
PROFILE_ONLY_PROBES: Final = frozenset(
    probe.name for probe in GUARDRAIL_BATTERY if probe.kind == BENIGN_REQUEST
)

#: The stop reasons a provider sets when its own filter cut or replaced the reply, compared in
#: lower case: OpenAI's (and Azure OpenAI's) ``content_filter``, Anthropic's ``refusal``. The
#: adapters pass the provider's value through as ``finish_reason``; a REST template's finish
#: path is compared the same way. ``length`` (the probe's own reply cap) is not among them.
_FILTER_STOPS: Final = frozenset({"content_filter", "refusal"})

# Refusal-phrase tells → style label (checked in order; first hit wins).
_REFUSAL_STYLES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("i can't", "i cannot", "i'm not able", "i am not able"), "polite-explain"),
    (("i won't", "i will not", "i refuse"), "firm"),
    (("as an ai", "i'm just an ai", "i am an ai language model"), "canned"),
)


def classify_refusal(text: str) -> str:
    """Classify refusal-style phrasing (deterministic; ``unknown`` if none match)."""

    low = text.lower()
    for phrases, style in _REFUSAL_STYLES:
        if any(p in low for p in phrases):
            return style
    return "unknown"


def reply_outcome(response: ModelResponse) -> str:
    """What a probe reply is, before it is compared with what its probe expected.

    ``filtered``: the provider stopped it with its own filter marker (cut or replaced);
    ``empty``: no text, which says nothing; ``refused``: a refusal phrase; ``answered``:
    anything else. A filter marker wins over the text, which is then the filter's, not wholly
    the model's.
    """

    if (response.finish_reason or "").lower() in _FILTER_STOPS:
        return "filtered"
    if not response.text.strip():
        return "empty"
    if classify_refusal(response.text) != "unknown":
        return "refused"
    return "answered"


def guardrail_profile(
    requested_refusal: ModelResponse | None, benign_request: ModelResponse | None = None
) -> dict[str, object]:
    """Build the observed guardrail profile from the replies the probes got (``None``: no reply).

    Each reply is scored against what its probe asked for:

    * the requested refusal gives the refusal's style and is never a filter signal (a)
      (``refusal_style`` is ``None`` only when that probe got no reply);
    * the benign request gives ``benign_refused``: ``True`` for a refusal (b), ``False`` for an
      answer, ``None`` with no reply, an empty one or one the filter cut;
    * ``output_filter`` is ``True`` when the provider's filter marker is on either reply (c),
      ``False`` when neither carries it. ``False`` is what these two benign probes saw, not proof
      that there is no filter: one that acts only on harmful content never acts on them.

    ``input_filter`` is ``None``: no benign probe tells an input filter from the model's own
    refusal (it was ``True`` for a canned requested refusal, a refusal the probe asked for).
    Latency is the first figure a reply reports, in send order (never fabricated).
    """

    replies = [r for r in (requested_refusal, benign_request) if r is not None]
    outcomes = {
        REQUESTED_REFUSAL: None if requested_refusal is None else reply_outcome(requested_refusal),
        BENIGN_REQUEST: None if benign_request is None else reply_outcome(benign_request),
    }
    benign = outcomes[BENIGN_REQUEST]
    return {
        "benign_refused": {"refused": True, "answered": False}.get(benign or ""),
        "input_filter": None,
        "output_filter": "filtered" in outcomes.values(),
        "refusal_style": (
            None if requested_refusal is None else classify_refusal(requested_refusal.text)
        ),
        "moderation_latency_ms": next(
            (lat for lat in map(_latency_ms, replies) if lat is not None), None
        ),
    }


class GuardrailLayer:
    """A requested refusal and a benign request → refusal style, refusal of the benign request,
    output-filter stop (contract §5 step 4, §7 A-67)."""

    layer: str = _LAYER
    #: Requests this layer sends, so the CLI can price a ``-sV`` pass without
    #: guessing. It guessed "one per layer" and was wrong for three of six.
    probe_count: int = len(GUARDRAIL_BATTERY)

    async def probe(self, adapter: TargetAdapter, ctx: ProbeContext) -> list[FingerprintEvidence]:
        """Send both probes; emit the profile + any pack tells in the requested refusal."""

        replies: dict[str, ModelResponse] = {}
        for probe in GUARDRAIL_BATTERY:
            request = _seeded(build_request(probe), ctx.target_id, probe.name)
            try:
                replies[probe.kind] = await adapter.send(request)
            except ProbeFailed:
                # Unanswered: the other probe is still sent, and this one says nothing (never
                # read as an empty reply). The engine records the failure (§7 A-35).
                continue
        if not replies:
            # No reply is not "no filter": the guardrails stay unknown.
            return []
        nudge = replies.get(REQUESTED_REFUSAL)
        profile = guardrail_profile(nudge, replies.get(BENIGN_REQUEST))

        out: list[FingerprintEvidence] = [
            FingerprintEvidence(
                layer=_LAYER,
                # Unattributed (no family=) so the combiner ignores it for scoring;
                # the engine parses the JSON detail to populate ``guardrails``.
                signal=f"{GUARDRAIL_PROFILE_DETAIL}={json.dumps(profile, sort_keys=True)}",
                weight=0.0,
            )
        ]

        pack = ctx.signature_pack
        if isinstance(pack, SignaturePack) and nudge is not None:
            haystack = nudge.text.lower()
            for entry in pack.entries:
                fragments = entry.signals.get(_LAYER, [])
                hits = [f for f in fragments if f.lower() in haystack]
                if not hits:
                    continue
                weight = entry.weights.get(_LAYER, 0.0) * (len(hits) / len(fragments))
                out.append(
                    FingerprintEvidence(
                        layer=_LAYER,
                        signal=encode_signal(
                            entry.family, entry.version, f"guardrail tells {hits}"
                        ),
                        weight=round(weight, 6),
                    )
                )
        return out


def _latency_ms(response: ModelResponse) -> float | None:
    """Extract a moderation latency if the adapter reported one; else ``None``.

    The figure is the target's, so it is read only when it is a finite, non-negative number a
    float can hold: a 400-digit integer made ``float()`` raise ``OverflowError`` and
    ``dottore fingerprint`` and ``run -sV`` exit 1, and an infinity, a NaN or a negative
    figure was recorded as a latency (2026-10-07).
    """

    usage = response.usage or {}
    raw = usage.get("moderation_latency_ms")
    if is_amount(raw):
        return float(raw)
    return None


def _seeded(request: ModelRequest, target_id: str, probe_name: str) -> ModelRequest:
    """Fold the deterministic seed into the request metadata (replay-stable)."""

    seed = seed_for(target_id, probe_name)
    meta = dict(request.metadata or {})
    meta["seed"] = seed
    # ``PROBE_SAMPLING`` (temperature 0, a capped reply), as every probe: an empty ``Sampling()``
    # sent no temperature, and a live Ollama sampled these probes at its default of 1.0
    # (first live ``-sV`` pass, 2026-10-07).
    sampling = request.sampling or PROBE_SAMPLING
    return request.model_copy(update={"metadata": meta, "sampling": sampling})
