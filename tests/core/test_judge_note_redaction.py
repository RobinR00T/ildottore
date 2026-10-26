"""A judge's words recorded beside a cut reply are redacted before they are cut (LOW 5).

Audit of main ``de122e26``: ``_judge_record`` and ``_judge_not_consulted`` folded the judge's text
onto one line and cut it at 240 characters, and only the report redacted it after. A secret
across the cut kept its head, which no rule recognises (61 of 305 placements left 6 or more
characters readable), and a credential registered with a tab was shown whole, since the fold
turned the tab into a space and the registered form no longer matched.
"""

from __future__ import annotations

import random
import string

import pytest

from ildottore.core.runner import _JUDGE_NOTE_CHARS, _judge_not_consulted, _judge_record
from ildottore.redactor import Redactor, register_known_secret
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import Verdict

_RNG = random.Random(3)  # noqa: S311 - a seeded fixture, not a secret
_ALNUM = string.ascii_letters + string.digits
_HEAD = "The response reveals the secret, it says " * 10


def _random(alphabet: str, size: int) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(size))


def _secret(kind: str) -> tuple[str, str]:
    """``(the text written, its private part)`` for one kind of secret."""

    if kind == "sk_proj":
        private = _random(_ALNUM + "_-", 40)
        return "sk-proj-" + private, private
    if kind == "registered":
        private = _random(_ALNUM, 24)
        register_known_secret(private)
        return private, private
    if kind == "registered_tab":
        private = "Blue\tHorse" + _random(_ALNUM, 8)
        register_known_secret(private)
        return private, private.replace("\t", " ")
    if kind == "labelled":
        private = _random(_ALNUM + "!#", 14)
        return "password: " + private, private
    private = _random(string.ascii_lowercase, 10)
    return private + "@corp-example.com", private


def _readable(note: str, reasoning: str, private: str) -> bool:
    """Whether six characters of ``private`` read in ``note`` that the redacted text hides."""

    redactor = Redactor()
    shown, reference = redactor.redact_text(note), redactor.redact_text(reasoning)
    return any(
        private[i : i + 6] in shown and private[i : i + 6] not in reference
        for i in range(len(private) - 5)
    )


@pytest.mark.parametrize("kind", ["sk_proj", "registered", "registered_tab", "labelled", "email"])
def test_no_head_of_a_secret_across_the_cut_is_recorded(no_known_secrets: None, kind: str) -> None:
    for offset in range(-30, 31):
        written, private = _secret(kind)
        head = _HEAD[: max(0, _JUDGE_NOTE_CHARS - 3 - len(written) // 2 + offset)]
        reasoning = f"{head}{written} which is a clear leak of protected data."
        verdict = Verdict(
            status=VerdictStatus.FAIL,
            confidence=0.9,
            reasoning=reasoning,
            evaluator_type="semantic_judge",
        )
        note = _judge_record(verdict)
        assert not _readable(note, reasoning, private), (kind, offset, note[-80:])
        assert note.count("«") == note.count("»"), note  # no mask cut in half


def test_a_judge_that_could_not_be_consulted_is_quoted_redacted_too(no_known_secrets: None) -> None:
    secret = "Blue\tHorse" + "Q7x9Lm2V"
    register_known_secret(secret)
    for offset in range(-12, 13):
        message = "x" * (_JUDGE_NOTE_CHARS - 30 + offset) + f" upstream said {secret} bye"
        note = _judge_not_consulted(RuntimeError(message))
        assert "Horse" not in note and "Q7x9" not in note, (offset, note[-60:])
        assert note.endswith(("...", "bye"))


def test_a_cut_moves_before_a_token_rather_than_through_it() -> None:
    # Ordinary words, which no key, hex or entropy rule takes (a run of one letter is a hex run to
    # the key-format rules), so the cut lands in the canary and nowhere else.
    words = ("the judge read the reply and wrote this note " * 10)[: _JUDGE_NOTE_CHARS - 10]
    reasoning = words + " QKZVTRBMXWPL_33vxg8dbtgvs7s7s end"
    note = _judge_record(
        Verdict(status=VerdictStatus.PASS, confidence=0.5, reasoning=reasoning, evaluator_type="j")
    )
    assert note.endswith(" ...") and "QKZVTRB" not in note
