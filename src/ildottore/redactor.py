"""Central secret / PII redactor (u01, S6 / DL2).

The **single choke point** that masks secrets, keys and PII in logs, console,
evidence and reports. Deliberately **dependency-free** (stdlib ``re``/``hashlib``
/``math`` only) and import-cheap so every layer — including the leaf logging
path — can call it without a dependency cycle.

Design (contract §4, §6; ``docs/11 §5`` DL2):

* Masks by **type**: a hit becomes ``«REDACTED:<type>»``; the raw value never
  survives. Where corroboration is needed a short **salted** hash is appended
  (``«REDACTED:<type>:<hash8>»``) so two occurrences of the same secret can be
  correlated without revealing it.
* **Idempotent**: an already-masked token is left untouched, so
  ``redact(redact(x)) == redact(x)``.
* **Structural**: walks ``dict`` / ``list`` / ``tuple`` / ``set`` preserving
  shape; dict keys are preserved, values redacted.
* **Entropy fallback (OD-15)**: an interim *global* Shannon-entropy threshold
  catches unknown-shape high-entropy tokens. Documented as interim; will reuse
  u06 ``secret_shape`` policy when that lands.

Verifier / pattern set is extensible via :meth:`Redactor.register`.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

_MASK_TEMPLATE: Final = "«REDACTED:{type}»"
_MASK_TEMPLATE_HASHED: Final = "«REDACTED:{type}:{digest}»"

# Matches any token we already produced, so redaction is idempotent.
_ALREADY_MASKED: Final = re.compile(r"«REDACTED:[A-Za-z0-9_]+(?::[0-9a-f]{8})?»")

# A value explicitly labelled as a secret (``the api secret is X``, ``password: X``): mask the
# value (group 1) regardless of its shape/entropy, catching engagement secrets the shape
# detectors miss. Deliberately narrow to a labelled assignment to avoid over-redacting prose.
_LABELED_SECRET: Final = re.compile(
    r"(?i)\b(?:secret|password|passwd|passphrase|api[\s_-]?key|access[\s_-]?key|"
    r"token|credential|client[\s_-]?secret)s?\b"
    r"(?:\s+(?:is|are|was|were|=|:))?[\s\"'`:=]{1,4}([^\s\"'`,;)]{6,})"
)

# A value is "secret-shaped" (worth masking after a label) when it is not a plain lowercase
# word, i.e. it carries a digit, an uppercase letter, or a symbol. This keeps the labelled
# heuristic from masking ordinary prose ("password strength is low").
_PLAIN_WORD: Final = re.compile(r"^[a-z]+$")


@dataclass(frozen=True)
class Pattern:
    """One named detector: a compiled regex + whether to append a salted hash."""

    type: str
    regex: re.Pattern[str]
    hashed: bool = False


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum (card numbers) — reduces valid-shape false positives."""

    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _default_patterns() -> list[Pattern]:
    """The built-in secret + PII detectors (contract §5 step 2, ``docs/11 §2``).

    Ordering matters: the most specific / highest-confidence patterns run first
    so a token is typed by the tightest matching detector.
    """

    return [
        # --- credentials / keys (hashed: allow corroboration without exposure) ---
        Pattern(
            "pem_private_key",
            # Bounded body length (a real key is < a few KB) so the lazy quantifier cannot
            # backtrack across a huge attacker-controlled blob; a global precheck for the
            # END marker (``_redact_pem``) skips it entirely when no match is possible.
            re.compile(
                r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
                r"[\s\S]{0,16384}?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
                re.DOTALL,
            ),
            hashed=True,
        ),
        Pattern(
            "jwt",
            re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
            hashed=True,
        ),
        Pattern("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), hashed=True),
        Pattern("github_token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), hashed=True),
        Pattern("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), hashed=True),
        # Slack bot + user + app tokens (the user/app forms were previously uncovered).
        Pattern("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), hashed=True),
        # --- PII ---
        Pattern("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
        Pattern("iban", re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b")),
        Pattern("card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
        Pattern("national_id", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
        Pattern(
            "ipv4",
            re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        ),
        Pattern("phone", re.compile(r"(?<![\w.])\+?\d[\d\s().-]{7,}\d(?![\w.])")),
    ]


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of ``s`` — 0.0 for empty strings."""

    if not s:
        return 0.0
    length = len(s)
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class Redactor:
    """Masks secrets/PII by type; idempotent and structure-preserving.

    ``salt`` keys the corroboration hash (an env-sourced value in production so
    hashes are not correlatable across engagements). ``entropy_threshold`` /
    ``entropy_min_len`` govern the interim global high-entropy fallback (OD-15).
    """

    _HIGH_ENTROPY_TOKEN: Final = re.compile(r"[A-Za-z0-9+/_=-]{16,}")

    def __init__(
        self,
        *,
        salt: str = "",
        patterns: Sequence[Pattern] | None = None,
        entropy_threshold: float = 3.7,
        entropy_min_len: int = 16,
    ) -> None:
        self._salt = salt.encode("utf-8")
        self._patterns: list[Pattern] = (
            list(patterns) if patterns is not None else _default_patterns()
        )
        self._entropy_threshold = entropy_threshold
        self._entropy_min_len = entropy_min_len

    def register(self, pattern: Pattern) -> None:
        """Add a detector. Registered patterns run **before** the built-ins."""

        self._patterns.insert(0, pattern)

    def _digest(self, value: str) -> str:
        """Short salted HMAC-SHA256 digest for corroboration (never reversible)."""

        return hmac.new(self._salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:8]

    def _mask_token(self, pattern: Pattern, value: str) -> str:
        if pattern.hashed:
            return _MASK_TEMPLATE_HASHED.format(type=pattern.type, digest=self._digest(value))
        return _MASK_TEMPLATE.format(type=pattern.type)

    def redact_text(self, text: str) -> str:
        """Mask every secret/PII occurrence in ``text`` (idempotent)."""

        # Drop NUL bytes up front so an attacker cannot forge the internal stash delimiter.
        text = text.replace("\x00", "")

        # Protect already-masked tokens from being re-scanned (idempotency).
        preserved: dict[str, str] = {}

        def _stash(m: re.Match[str]) -> str:
            token = f"\x00{len(preserved)}\x00"
            preserved[token] = m.group(0)
            return token

        working = _ALREADY_MASKED.sub(_stash, text)

        for pattern in self._patterns:
            if pattern.type == "card":
                working = self._redact_cards(pattern, working)
            elif pattern.type == "pem_private_key":
                working = self._redact_pem(pattern, working)
            else:
                working = pattern.regex.sub(self._make_sub(pattern), working)

        working = self._redact_labeled(working)
        working = self._redact_high_entropy(working)

        for token, original in preserved.items():
            working = working.replace(token, original)
        return working

    def _make_sub(self, pattern: Pattern) -> Callable[[re.Match[str]], str]:
        """Build a substitution callback bound to ``pattern`` (closure-safe)."""

        def _sub(m: re.Match[str]) -> str:
            return self._mask_token(pattern, m.group(0))

        return _sub

    def _redact_pem(self, pattern: Pattern, text: str) -> str:
        """Mask PEM private keys, skipping the scan entirely when no END marker exists.

        Without an END marker the pattern cannot match, so running the DOTALL regex over a
        large ``BEGIN``-only blob is pure wasted (quadratic) backtracking, the precheck
        turns that ReDoS surface into an O(1) substring test (contract: no self-DoS).
        """

        if "-----END" not in text or "PRIVATE KEY-----" not in text:
            return text
        return pattern.regex.sub(self._make_sub(pattern), text)

    def _redact_labeled(self, text: str) -> str:
        """Mask a value explicitly labelled as a secret (the value only, not the label)."""

        def _sub(m: re.Match[str]) -> str:
            value = m.group(1)
            if _PLAIN_WORD.match(value):  # a plain lowercase word is not a secret
                return m.group(0)
            masked = _MASK_TEMPLATE_HASHED.format(type="labeled_secret", digest=self._digest(value))
            return m.group(0).replace(value, masked)

        return _LABELED_SECRET.sub(_sub, text)

    def _redact_cards(self, pattern: Pattern, text: str) -> str:
        """Card matcher with a Luhn guard to cut valid-shape false positives."""

        def _sub(m: re.Match[str]) -> str:
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                return self._mask_token(pattern, m.group(0))
            return m.group(0)

        return pattern.regex.sub(_sub, text)

    def _redact_high_entropy(self, text: str) -> str:
        """Interim global entropy fallback for unknown-shape secrets (OD-15)."""

        def _sub(m: re.Match[str]) -> str:
            token = m.group(0)
            if (
                len(token) >= self._entropy_min_len
                and _shannon_entropy(token) >= self._entropy_threshold
            ):
                return _MASK_TEMPLATE_HASHED.format(type="high_entropy", digest=self._digest(token))
            return token

        return self._HIGH_ENTROPY_TOKEN.sub(_sub, text)

    def redact(self, obj: object) -> object:
        """Redact any value, preserving container shape.

        Strings are masked; ``dict``/``list``/``tuple``/``set`` are walked; other
        scalars (``int``/``float``/``bool``/``None``) pass through unchanged.
        """

        if isinstance(obj, str):
            return self.redact_text(obj)
        if isinstance(obj, Mapping):
            # Values only: masking keys here would rename fields and break callers that
            # re-validate the masked dump against a frozen model (reporting.mask_run). The
            # evidence store, which serializes to JSON without re-validation, masks keys too
            # via its own deep pass (evidence_fs) to close the secret-in-a-key vector (DL2).
            return {key: self.redact(value) for key, value in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            redacted = [self.redact(item) for item in obj]
            if isinstance(obj, tuple):
                return tuple(redacted)
            if isinstance(obj, set):
                return set(redacted)
            return redacted
        return obj


# A process-wide default instance for convenience; callers needing a keyed hash
# (production) construct their own ``Redactor(salt=...)``.
_DEFAULT = Redactor()


def redact(obj: object) -> object:
    """Module-level convenience over the default (unsalted) redactor."""

    return _DEFAULT.redact(obj)
