"""Evaluator base: shared verdict construction, masking and text helpers (contract §5.1).

Every evaluator in this package implements :class:`ildottore.shared.protocols.Evaluator`
(``type: str`` + ``async evaluate(ctx) -> Verdict``). This module carries the *shared*,
behaviour-free scaffolding they all reuse so no logic is copy-pasted (AGENTS §3 zero
tech-debt):

* :class:`BaseEvaluator` - a small mixin that pins the ``type`` string, builds
  polarity-correct :class:`~ildottore.shared.models.Verdict` objects (``pass`` = secure,
  ``fail`` = exploited - ``docs/04 §0``) and enforces the closed
  :class:`~ildottore.shared.enums.InconclusiveReason` contract.
* :func:`mask_value` / :func:`mask_values` - type+mask a matched sensitive value for
  storage in ``Verdict.matched`` / evidence, delegating to u01's central
  :class:`~ildottore.redactor.Redactor` so a raw secret/PII value **never** survives
  (``docs/11 §5`` DL2, contract §8). The masking is deterministic and salted-hashable
  for corroboration.
* :func:`shannon_entropy` - stdlib Shannon entropy over a string (bits/char), used by
  ``secret_shape`` and the PII entropy heuristic.

Deterministic evaluators emit confidence ``1.0`` on a clear match and force
``inconclusive`` (confidence ``0.0``) on ambiguity (``docs/04 §3``, contract §4 KEEP).
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable

from ildottore.redactor import Redactor
from ildottore.shared.enums import InconclusiveReason, VerdictStatus
from ildottore.shared.models import EvalContext, Verdict

__all__ = [
    "BaseEvaluator",
    "mask_value",
    "mask_values",
    "shannon_entropy",
]

# A process-wide, unsalted redactor for typing+masking matched values into evidence.
# Callers needing a keyed corroboration hash inject a salted Redactor via ``mask_value``.
_DEFAULT_REDACTOR = Redactor()


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character.

    Empty string ⇒ ``0.0``. Pure and deterministic (no RNG, no I/O).
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def mask_value(value: str, *, type_hint: str, redactor: Redactor | None = None) -> str:
    """Type+mask a sensitive ``value`` for evidence storage (``docs/11 §5`` DL2).

    Returns a ``«REDACTED:<type>[:<hash8>]»`` token; the raw value never survives.
    ``type_hint`` is used verbatim when the central redactor does not recognise the
    value's shape (so a caller-typed hit - e.g. ``iban``, ``card`` - is still typed).
    A salted corroboration hash is appended so two occurrences of the same value can be
    correlated without revealing it.
    """
    red = redactor or _DEFAULT_REDACTOR
    masked = red.redact_text(value)
    if masked != value:
        # The central redactor recognised the shape and typed it.
        return masked
    # Unrecognised by the redactor's pattern set: type it with the caller's hint and a
    # salted hash so the value is never stored raw but stays corroboration-linkable.
    digest = red._digest(value)  # deliberate reuse of the redactor's salted digest.
    return f"«REDACTED:{type_hint}:{digest}»"


def mask_values(
    values: Iterable[str], *, type_hint: str, redactor: Redactor | None = None
) -> list[str]:
    """Mask each value via :func:`mask_value`, preserving order and de-duplicating."""
    seen: dict[str, None] = {}
    for value in values:
        masked = mask_value(value, type_hint=type_hint, redactor=redactor)
        seen.setdefault(masked, None)
    return list(seen)


class BaseEvaluator:
    """Common scaffold for evaluators (satisfies :class:`Evaluator` structurally).

    Subclasses set the class attribute :attr:`type` and implement
    :meth:`evaluate`. The helpers here build polarity-correct verdicts and keep the
    closed-reason invariant of :class:`~ildottore.shared.models.Verdict` (a reason is
    only ever attached to an ``inconclusive`` verdict).
    """

    #: The evaluator ``type`` string (matches ``schemas/attack-spec.schema.json``).
    type: str = ""

    async def evaluate(self, ctx: EvalContext) -> Verdict:  # pragma: no cover - abstract
        """Turn an :class:`EvalContext` into a :class:`Verdict`. Overridden per evaluator."""
        raise NotImplementedError

    # --- verdict builders (polarity fixed: pass = secure, fail = exploited) ----------

    def _verdict(
        self,
        status: VerdictStatus,
        *,
        confidence: float,
        reasoning: str,
        matched: list[str] | None = None,
        inconclusive_reason: InconclusiveReason | None = None,
    ) -> Verdict:
        """Assemble a :class:`Verdict` tagged with this evaluator's ``type``."""
        return Verdict(
            status=status,
            confidence=confidence,
            reasoning=reasoning,
            matched=matched or [],
            evaluator_type=self.type,
            inconclusive_reason=(
                inconclusive_reason if status is VerdictStatus.INCONCLUSIVE else None
            ),
        )

    def _pass(self, reasoning: str, *, confidence: float = 1.0) -> Verdict:
        """A secure verdict (the attack failed)."""
        return self._verdict(VerdictStatus.PASS, confidence=confidence, reasoning=reasoning)

    def _fail(
        self, reasoning: str, *, matched: list[str] | None = None, confidence: float = 1.0
    ) -> Verdict:
        """An exploited verdict (the attack succeeded)."""
        return self._verdict(
            VerdictStatus.FAIL, confidence=confidence, reasoning=reasoning, matched=matched
        )

    def _inconclusive(
        self,
        reasoning: str,
        *,
        reason: InconclusiveReason | None = None,
        matched: list[str] | None = None,
    ) -> Verdict:
        """An inconclusive verdict (never coerced to pass/fail - ``docs/04 §2``)."""
        return self._verdict(
            VerdictStatus.INCONCLUSIVE,
            confidence=0.0,
            reasoning=reasoning,
            matched=matched,
            inconclusive_reason=reason,
        )

    def _needs_review(self, reasoning: str, *, matched: list[str] | None = None) -> Verdict:
        """A format-valid-but-uncorroborated data-leak hit (``docs/11 §4``).

        Represented as ``inconclusive`` (never a confirmed ``fail``): a valid-shape PII
        or secret without a canary / corpus / cross-identity corroboration is *reported*
        but must never be scored as a breach.
        """
        return self._inconclusive(reasoning, matched=matched)
