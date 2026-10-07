"""Fingerprint engine orchestrator (u09, contract §5 step 7, ADR-0006).

Runs the composed signal layers against an injected
:class:`~ildottore.shared.protocols.TargetAdapter`, fuses their evidence
(:mod:`ildottore.fingerprint.combine`) and assembles a
:class:`~ildottore.shared.models.ModelFingerprint` - **and stops** (ADR-0006: u09
produces the fingerprint only; the u08 planner consumes it. There is no
``fingerprint/planner.py`` and this engine never builds a ``TestPlan``).

Standalone recognition is the safe default first step (``docs/10 §1``): benign
probes only, gated by the adapter's scope allowlist (an out-of-scope target has the
adapter raise before any probe leaves, contract §7 safety-negative). Every run is
deterministic: a fixed layer order + a seeded probe battery ⇒ a byte-identical
``ModelFingerprint`` on replay (contract §7).
"""

from __future__ import annotations

import json
from collections.abc import Callable

from ildottore.fingerprint.attribution import parse_signal
from ildottore.fingerprint.base import FingerprintLayer, ProbeContext, ProbeFailed
from ildottore.fingerprint.combine import SPOOF_FLAG, CombinedFingerprint, combine
from ildottore.fingerprint.layers import default_layers
from ildottore.fingerprint.layers.behavioral import SELF_REPORT_DETAIL
from ildottore.fingerprint.layers.capability import capability_guess
from ildottore.fingerprint.layers.carrier import CARRIER_PROBE_DETAIL, effective_mutators
from ildottore.fingerprint.layers.guardrail import GUARDRAIL_PROFILE_DETAIL
from ildottore.fingerprint.signatures import SignaturePack, load_pack
from ildottore.shared.models import (
    Capabilities,
    FingerprintEvidence,
    FingerprintGuess,
    JsonDict,
    ModelFingerprint,
    ModelRequest,
    ModelResponse,
)
from ildottore.shared.protocols import TargetAdapter

__all__ = [
    "PROBES_FAILED_FLAG",
    "PROBE_ERRORS_DETAIL",
    "FingerprintEngine",
    "failed_probes",
    "fingerprint",
]


class FingerprintEngine:
    """Composes signal layers into a :class:`ModelFingerprint` (contract §5 step 7).

    Layers and the signature pack are injected for testability + pluggable
    extension (contract §1); defaults are the six self-contained built-in layers and
    the in-repo MVP-1 pack. The **seventh**, the carrier layer, probes with u05's
    mutators and u09 may not import them, so the composition root
    (``cli.wiring.build_fingerprint_engine``) appends it with the registry injected:
    a ``FingerprintEngine()`` built here therefore has six layers and the one the CLI
    builds has seven. The engine holds no per-run state (a fresh :class:`ProbeContext`
    is built per call) so one engine instance can fingerprint many targets.

    ``is_env_error`` decides, with the ``retryable = False`` marker, which send errors are a
    failed probe rather than the end of the pass (§7 A-35): the composition root injects the
    predicate the attack phase classifies an attempt's error with
    (``core.execute.default_is_env_error``), which u09 may not import. ``None`` isolates
    nothing and every error goes through, as before.
    """

    def __init__(
        self,
        *,
        layers: list[FingerprintLayer] | None = None,
        pack: SignaturePack | None = None,
        is_env_error: Callable[[BaseException], bool] | None = None,
    ) -> None:
        self._layers = layers if layers is not None else default_layers()
        self._pack = pack if pack is not None else load_pack()
        self._is_env_error = is_env_error

    @property
    def layers(self) -> list[FingerprintLayer]:
        """The composed layer list (read-only; the CLI prices a pass off it)."""

        return list(self._layers)

    async def run(self, adapter: TargetAdapter) -> ModelFingerprint:
        """Probe ``adapter`` with every layer and assemble the fingerprint.

        Layer order is fixed (determinism). Any layer's evidence is appended in
        order, so the assembled ``evidence`` list is byte-stable across replays.

        A probe whose reply comes back refused (an environment failure, see ``is_env_error``,
        that a retry would repeat) costs that probe: its layer gets :class:`ProbeFailed` and
        gives no evidence from it (a layer with sibling probes skips it and keeps the others;
        any other layer gives no evidence at all), every other probe is still sent, and the
        failures are recorded in the evidence and flagged. A probe that gets no answer at all
        stops the pass, as any other error does.
        """

        target_id = adapter.id
        ctx = ProbeContext(target_id=target_id, signature_pack=self._pack)

        isolated = _ProbeIsolation(adapter, self._is_env_error)
        # The carrier layer's probes are left out of the check: a target can answer carriers
        # differently (that is what comprehension measures) and every attributing probe alike.
        recorder = _RecordingAdapter(isolated)
        evidence: list[FingerprintEvidence] = []
        for layer in self._layers:
            target_for_layer = isolated if layer.layer == _CARRIER_LAYER else recorder
            isolated.layer = layer.layer
            try:
                evidence.extend(await layer.probe(target_for_layer, ctx))
            except ProbeFailed:
                # A layer that lets a failed probe through loses its own evidence, not the pass:
                # the one-probe layers (metadata, tokenizer, guardrail) and any third-party one.
                # So an unanswered guardrail nudge leaves the guardrails unknown, never "no
                # filter". The failure is already on record.
                continue

        fused = combine(evidence)
        constant = recorder.non_discriminating()
        # Refused replies can leave fewer attributing replies than the constant check needs, and
        # then it never runs: a target answering "I am Llama" to everything, with 8 of its 10
        # attributing replies refused, was named meta-llama at 0.41 where a full pass names
        # nothing (pre-commit audit of OD-23). Too few replies to tell a model from a constant
        # get the constant's treatment, without its flag (``probes_failed`` says why).
        unchecked = bool(isolated.failures) and len(recorder.texts) < _MIN_PROBES_FOR_CONSTANT
        if constant or unchecked:
            # Every attributing probe got the same text, so nothing the text layers matched
            # came from the model: a constant mock was named meta-llama at 0.67 and a
            # refuse-all target llama-3-8b with a 2023-03 cutoff (audit 2026-10-03, R16). The
            # response ENVELOPE (a provider's `model` field) is not text and still counts, so
            # only the metadata layer's evidence is kept; without it, unknown, and said so.
            from_envelope = _from_model_field(evidence)
            cap = self._metadata_weight(from_envelope.family.guess)
            fused = CombinedFingerprint(
                family=_capped(from_envelope.family, cap),
                version=(
                    None if from_envelope.version is None else _capped(from_envelope.version, cap)
                ),
                spoofing_flags=[
                    *fused.spoofing_flags,
                    *([NON_DISCRIMINATING_FLAG] if constant else []),
                ],
            )
        elif _from_envelope_only(evidence, fused.family.guess, fused.spoofing_flags):
            # The same cap when the replies differed but only the envelope named the family (a
            # canned responder whose `model` says gpt-4o was 0.44, surer than a constant one).
            cap = self._metadata_weight(fused.family.guess)
            fused = CombinedFingerprint(
                family=_capped(fused.family, cap),
                version=None if fused.version is None else _capped(fused.version, cap),
                spoofing_flags=fused.spoofing_flags,
            )
        guardrails = _guardrails_from_evidence(evidence)
        caps = capability_guess(adapter.capabilities())
        # The one key the PLANNER reads (``core.planner._order_family_effective``). Without
        # it, adaptive mode reordered nothing and ``-sV`` bought a fingerprint that changed
        # no part of the battery: a probe pass with real cost and no consequence.
        carriers = _carriers_from_evidence(evidence)
        if carriers:
            caps["effective_mutators"] = carriers
        version = _with_cutoff(fused, self._pack)
        flags = list(fused.spoofing_flags)
        if isolated.failures:
            # Unattributed (weight 0.0): which probes went unanswered, never what came back.
            evidence.append(
                FingerprintEvidence(
                    layer=_ENGINE_LAYER,
                    signal=f"{PROBE_ERRORS_DETAIL}={json.dumps(isolated.failures)}",
                    weight=0.0,
                )
            )
            flags.append(PROBES_FAILED_FLAG)

        return ModelFingerprint(
            target_id=target_id,
            family=fused.family,
            version=version,
            capability_guess=caps,
            guardrails=guardrails,
            evidence=evidence,
            spoofing_flags=flags,
            recommended_plan_ref=None,  # ADR-0006: u08 owns plan building.
        )

    def _metadata_weight(self, family: str) -> float:
        """The pack's largest metadata weight for ``family``: the cap of an envelope-only name.

        An attribution from the envelope alone has a share of the mass of 1 by construction
        (nothing else is kept), so a constant target whose envelope said gpt-4o was named at
        0.52 on that one field (audit of the fingerprint).
        """

        return max(
            (e.weights.get(_METADATA_LAYER, 0.0) for e in self._pack.entries if e.family == family),
            default=0.0,
        )


#: Flag set when the target answered every attributing probe identically: the text layers had
#: no signal, so the family comes from the response envelope alone or is unknown.
NON_DISCRIMINATING_FLAG = "non_discriminating_target"

#: Flag set when one or more probes of the pass got no usable reply (§7 A-35): the fingerprint
#: was built from the replies that came back. :func:`failed_probes` lists them.
PROBES_FAILED_FLAG = "probes_failed"

#: The detail of the engine's own evidence that lists the failed probes.
PROBE_ERRORS_DETAIL = "probe_errors"

_CARRIER_LAYER = "carrier"
_METADATA_LAYER = "metadata"
_ENGINE_LAYER = "engine"

#: Fewer answered probes than this is too little to call a target constant.
_MIN_PROBES_FOR_CONSTANT = 3


def _from_envelope_only(evidence: list[FingerprintEvidence], family: str, flags: list[str]) -> bool:
    """True if every counted piece of evidence for ``family`` is from the metadata layer.

    A self-report the combiner left out (it conflicted with the statistical layer) is not
    counted here either.
    """

    excluded_self_report = SPOOF_FLAG in flags
    layers = {
        ev.layer
        for ev in evidence
        if ev.weight > 0
        and parse_signal(ev.signal).family == family
        and not (excluded_self_report and parse_signal(ev.signal).detail == SELF_REPORT_DETAIL)
    }
    return layers == {_METADATA_LAYER}


def _capped(guess: FingerprintGuess, cap: float) -> FingerprintGuess:
    """``guess`` with its confidence lowered to ``cap`` when above it.

    Applied to the version too, so a custom pack cannot make the version surer than the family.
    """

    if guess.confidence <= cap:
        return guess
    return guess.model_copy(update={"confidence": cap})


def _from_model_field(evidence: list[FingerprintEvidence]) -> CombinedFingerprint:
    """Attribute from the envelope's ``model`` field alone, for a target with no text signal.

    Only metadata evidence that matched a ``model=`` fragment names the model. The rest of the
    envelope does not: ``finish_reason=stop`` was in the meta-llama signature (dropped since)
    and every OpenAI-compatible server sends it, so a constant target behind such a server was
    still named meta-llama with a 2023-03 cutoff (re-audit of R16). A version is kept only when one
    clearly leads (the combiner gives none on a tie).
    """

    kept = [
        ev
        for ev in evidence
        if ev.layer == _METADATA_LAYER and "model=" in parse_signal(ev.signal).detail
    ]
    return combine(kept)


def failed_probes(fingerprint: ModelFingerprint) -> list[str]:
    """The probes of the pass that got no usable reply, as ``"<layer>/<probe>: <error class>"``.

    In send order; empty when every probe was answered. The layer is there because two layers
    send the same probe (``metadata`` and ``behavioral`` both send ``self_id``).
    """

    prefix = f"{PROBE_ERRORS_DETAIL}="
    for ev in fingerprint.evidence:
        if ev.layer == _ENGINE_LAYER and ev.signal.startswith(prefix):
            parsed = json.loads(ev.signal.split("=", 1)[1])
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
    return []


class _ProbeIsolation:
    """Turns a refused reply to one probe into :class:`ProbeFailed`, and records it.

    A refused reply is one that came back and cannot be used: an environment failure (the
    injected predicate) marked ``retryable = False``, the marker ``core.execute`` reads (a reply
    over the size cap, one it cannot decode, and ``ResponseTooDeep`` once
    ``fix/target-deep-json`` lands). The target answered, and a retry would get the same reply.
    A probe that got **no answer at all** (a 5xx, a 429, a timeout, a refused connection, still
    failing after the meter's retries) goes through and stops the pass, as before: the target is
    not answering, and isolating it too made a target that never replies cost 17 probes of three
    30 s timeouts each, 25.5 minutes, before an attack that fails the same way, and made
    ``dottore fingerprint`` exit 0 on a closed port (pre-commit audit of OD-23). Anything else
    goes through too: a product error, a refusal by the scope, a budget breach, and every
    ``BaseException`` (an interrupt, a cancellation).
    """

    def __init__(
        self, inner: TargetAdapter, is_env_error: Callable[[BaseException], bool] | None
    ) -> None:
        self._inner = inner
        self._is_env_error = is_env_error
        self.id = inner.id
        #: The layer probing now, set by the engine before each layer runs.
        self.layer = ""
        self.failures: list[str] = []

    async def send(self, request: ModelRequest) -> ModelResponse:
        try:
            return await self._inner.send(request)
        except Exception as exc:
            if not self._refused(exc):
                raise
            failed = ProbeFailed(str((request.metadata or {}).get("probe", "probe")), exc)
            self.failures.append(f"{self.layer}/{failed}")
            raise failed from exc

    def capabilities(self) -> Capabilities:
        return self._inner.capabilities()

    def _refused(self, exc: Exception) -> bool:
        return (
            self._is_env_error is not None
            and self._is_env_error(exc)
            and getattr(exc, "retryable", True) is False
        )


class _RecordingAdapter:
    """Passes every probe through and keeps the reply texts, to see whether they ever differ."""

    def __init__(self, inner: TargetAdapter) -> None:
        self._inner = inner
        self.id = inner.id
        self.texts: list[str] = []

    async def send(self, request: ModelRequest) -> ModelResponse:
        response = await self._inner.send(request)
        self.texts.append((response.text or "").strip())
        return response

    def capabilities(self) -> Capabilities:
        return self._inner.capabilities()

    def non_discriminating(self) -> bool:
        return len(self.texts) >= _MIN_PROBES_FOR_CONSTANT and len(set(self.texts)) <= 1


def _guardrails_from_evidence(evidence: list[FingerprintEvidence]) -> JsonDict:
    """Recover the guardrail profile the guardrail layer emitted (JSON detail)."""

    prefix = f"{GUARDRAIL_PROFILE_DETAIL}="
    for ev in evidence:
        if ev.layer == "guardrail" and ev.signal.startswith(prefix):
            raw = ev.signal.split("=", 1)[1]
            try:
                parsed = json.loads(raw)
            except ValueError:
                return {}
            if isinstance(parsed, dict):
                return parsed
    return {}


def _carriers_from_evidence(evidence: list[FingerprintEvidence]) -> list[str]:
    """Order the carriers this target still understands, best-first (see ``layers/carrier``)."""

    prefix = f"{CARRIER_PROBE_DETAIL}="
    for ev in evidence:
        if ev.layer == "carrier" and ev.signal.startswith(prefix):
            try:
                parsed = json.loads(ev.signal.split("=", 1)[1])
            except ValueError:
                return []
            if isinstance(parsed, dict):
                return effective_mutators(
                    {str(k): float(v) for k, v in parsed.items() if isinstance(v, (int, float))}
                )
    return []


def _with_cutoff(fused: CombinedFingerprint, pack: SignaturePack) -> FingerprintGuess | None:
    """Attach the pack's ``cutoff_hint`` to the version guess when one is known.

    ``combine`` produces the version guess from evidence only; the human-readable
    cutoff hint lives in the pack, so the engine enriches the guess post-fusion
    (keeping ``combine`` pack-free).
    """

    version = fused.version
    if version is None:
        return None
    for entry in pack.entries:
        if (
            entry.family == fused.family.guess
            and entry.version == version.guess
            and entry.cutoff_hint is not None
        ):
            return FingerprintGuess(
                guess=version.guess,
                confidence=version.confidence,
                cutoff_hint=entry.cutoff_hint,
            )
    return version


async def fingerprint(adapter: TargetAdapter) -> ModelFingerprint:
    """Convenience: fingerprint ``adapter`` with the default engine (standalone mode)."""

    return await FingerprintEngine().run(adapter)
