"""Central secret / PII redactor (u01, S6 / DL2).

The **single choke point** that masks secrets, keys and PII in logs, console,
evidence and reports. Deliberately **dependency-free** (stdlib ``re``/``hashlib``
/``math`` only) and import-cheap so every layer - including the leaf logging
path - can call it without a dependency cycle.

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
  u06 ``secret_shape`` policy when that lands. **Separator-structured tokens**
  (a spec id, a model name, a URL path) are exempt *by shape* - they score high
  bits/char without being opaque, and masking one destroys a report join key
  rather than hiding a secret (see ``_ID_SHAPED`` / ``_PATH_SHAPED``). A token that is
  hexadecimal throughout is *not* exempt: that is a key or a digest shape, not an id
  shape (see ``_HEX_SEGMENT``).
* **Dated identifiers**: the ``phone`` detector reads ``-``/``.``/space as digit-group
  separators, which is also how a date, a dated model suffix and a run id are punctuated.
  A match that is entirely a calendar-valid date stamp is likewise exempt *by shape*
  (see ``_DATE_STAMP``), and a short version prefix only behind an identifier
  (``_DATE_SHAPED``); a real number in its usual groupings still gets masked (the known
  exceptions are listed in the CHANGELOG).

Verifier / pattern set is extensible via :meth:`Redactor.register`.
"""

from __future__ import annotations

import bisect
import functools
import hashlib
import heapq
import hmac
import json
import math
import os
import re
import secrets
import threading
from array import array
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Final, Protocol, cast

_MASK_TEMPLATE: Final = "«REDACTED:{type}»"
_MASK_TEMPLATE_HASHED: Final = "«REDACTED:{type}:{digest}»"

#: Delimiters of the internal stash token that keeps a mask out of the next patterns' reach.
_STASH_OPEN: Final = "\x00"
_STASH_CLOSE: Final = "\x01"
_STASH_TOKEN: Final = re.compile(r"\x00(\d+)\x01")
# Matches any token we already produced, so redaction is idempotent; group 1 is the type.
_ALREADY_MASKED: Final = re.compile(r"«REDACTED:([A-Za-z0-9_]+)(?::([0-9a-f]{8}))?»")
#: Mask types the tool writes besides the redactor's patterns': the redactor's own rules, then
#: the type hints the evaluators give ``mask_value`` (a test keeps this list complete).
_OWN_MASK_TYPES: Final = frozenset(
    {
        *("credential", "url_password", "labeled_secret", "high_entropy"),
        *("canary", "shared_line", "tool_arg_injection", "ip", "private_key"),
        # A tool argument's value a spec's forbidden_arg_values matched (u06 A-88).
        "tool_arg_value",
        # A piece of a list's joined text masked where its mask could not be placed (A-77), and
        # an alternative of a token with more masks than an alternative shows (A-86).
        "fragment",
    }
)

#: Name of the branch of a detector regex that matches text to step over, not a hit. A shape
#: that fails from the first start of a run (a run of digits with no end a phone may have, a
#: run of address characters with no ``@`` after it) fails from every later start of that run
#: too, and each of those starts scanned the run to its end: quadratic in text a target writes
#: (99 KB of ``1. 2. 3. `` took 17 s in the phone rule, 100 KB of ``eyJ-`` 1.6 s in the JWT
#: rule). The ``skip`` branch consumes the rest of the run instead, so the scan resumes after it
#: and finds exactly what it found before (pre-commit audit of the hostile-text block). In the
#: email and phone rules it takes only a run of 64 characters or more: a shorter run has at most
#: 63 starts, each scanning that run (and, for an email, the domain after its `@`), so the cost
#: stays linear, while every word of a clean text matched the unbounded branch, a callback each
#: (clean text took a third longer to redact, pre-merge audit).
SKIP: Final = "skip"


def skipped(match: re.Match[str]) -> bool:
    """True for a match of a detector's :data:`SKIP` branch: text stepped over, not a hit."""

    return SKIP in match.re.groupindex and match.group(SKIP) is not None


#: What the stash delimiters in a text are written as: their control-picture characters.
_VISIBLE: Final = str.maketrans({_STASH_OPEN: "\u2400", _STASH_CLOSE: "\u2401"})


def visible_stash_delimiters(text: str) -> str:
    """``text`` with the two characters the redactor reserves for its stash tokens made visible.

    It is what :meth:`Redactor.redact_text` returns when it masks nothing (``␀`` and ``␁``):
    a caller comparing the output with the input to see whether anything was masked compares
    with this instead (``mask_value``). A value holding ``\\x00`` came back changed with nothing
    masked, and was stored raw.
    """

    return text.translate(_VISIBLE)


def _holds_stash_delimiter(text: str) -> bool:
    return _STASH_OPEN in text or _STASH_CLOSE in text


class _Joined:
    """``text`` with its stash delimiters dropped, and where each of its characters is in ``text``.

    The positions are held as the delimiters' places only, in an array of 8-byte integers: a list
    of every kept character's index took about 30 bytes a character, 120 MB for a 4 MB reply
    holding one ``\x00`` (u01 A-83).
    """

    def __init__(self, text: str) -> None:
        self.text = text.replace(_STASH_OPEN, "").replace(_STASH_CLOSE, "")
        # For the j-th delimiter at `at`, the index in the joined text of the character after it.
        self._after = array(
            "q", [m.start() - rank for rank, m in enumerate(_STASH_DELIMITER.finditer(text))]
        )

    def at(self, index: int) -> int:
        """Where character ``index`` of the joined text is in ``text``."""

        return index + bisect.bisect_right(self._after, index)


# --- a registered credential split by characters that do not show -----------------------
#: The control characters: C0, DEL, C1 (U+0085, the next-line control, among them), the line and
#: paragraph separators, and lone surrogates. A terminal or a CI log reader acts on them instead of
#: showing them. A Linux file name with a byte that is not UTF-8 arrives as a lone surrogate, which
#: a strict stream cannot encode and a `surrogateescape` stream writes back as the raw byte, a C1
#: control for 0x80 to 0x9f.
_CONTROL_RANGES: Final = ((0x00, 0x1F), (0x7F, 0x9F), (0x2028, 0x2029), (0xD800, 0xDFFF))
#: The format characters, Unicode category Cf as of Unicode 16.0: the soft hyphen, the zero-width
#: space, joiners and word joiner, the bidi marks, embeddings, overrides and isolates, the byte
#: order mark, the interlinear annotation and some script-specific marks, and the tag characters
#: (invisible ASCII). Pinned, not read from `unicodedata`, so a mask does not depend on the
#: Python's Unicode version (3.11 has 14.0); a test checks it holds every Cf of the Python it runs.
#: A terminal shows none of them: a bidi control reorders what is read (Trojan Source,
#: CVE-2021-42574), and a zero-width or a tag character hides text (decided by the owner on
#: 2026-10-07: written out like the controls). In three kinds, the one list for every reader that
#: tells them apart (``shared.provider_filter.blank_text``, pre-merge audit of ``3f7b1254``):
#: :data:`EMPTY_FORMAT_RANGES` show nothing and carry nothing; :data:`FORMAT_SIGN_RANGES` are the
#: 13 prepended concatenation marks, signs a font draws as a glyph (the Arabic number signs, the
#: end of ayah, the Syriac abbreviation mark, the Arabic pound and piastre marks, the Kaithi
#: number signs);
#: :data:`TAG_RANGES` spell ASCII that no one sees (ASCII smuggling).
EMPTY_FORMAT_RANGES: Final = (
    *((0x00AD, 0x00AD), (0x061C, 0x061C), (0x180E, 0x180E), (0x200B, 0x200F)),
    *((0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F), (0xFEFF, 0xFEFF)),
    *((0xFFF9, 0xFFFB), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A)),
)
FORMAT_SIGN_RANGES: Final = (
    *((0x0600, 0x0605), (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891)),
    *((0x08E2, 0x08E2), (0x110BD, 0x110BD), (0x110CD, 0x110CD)),
)
TAG_RANGES: Final = ((0xE0001, 0xE0001), (0xE0020, 0xE007F))
_FORMAT_RANGES: Final = (*EMPTY_FORMAT_RANGES, *FORMAT_SIGN_RANGES, *TAG_RANGES)
#: U+FFFD, the replacement character: half a character in a target's reply (a lone surrogate) is
#: read as one where the reply is parsed (u04 A-47), before the redactor sees it, so a credential
#: split by half a character arrives split by U+FFFD, or by a run of them (an MCP SSE stream reads
#: each raw byte of the half as one). Unlike the others it shows: it stands where half a character
#: was, or where the target wrote one itself, which splits a credential the same way.
_REPLACEMENT_RANGES: Final = ((0xFFFD, 0xFFFD),)
_INVISIBLE_RANGES: Final = (*_CONTROL_RANGES, *_FORMAT_RANGES, *_REPLACEMENT_RANGES)
#: Every one of them, for ``str.translate`` to drop from a credential (a regex ``sub`` took 9 MB
#: a megabyte, ``translate`` allocates only what it returns).
_DROP_INVISIBLE: Final = dict.fromkeys(
    code for low, high in _INVISIBLE_RANGES for code in range(low, high + 1)
)
#: The same, but the stash delimiters, for the text: inside ``_redact_once`` a ``\x00`` or a
#: ``\x01`` is always part of a stash token (``redact_text`` drops them from its input first, or
#: writes them out), and a token is a mask, so no credential may run through it.
_DROP_SPLITTERS: Final = {
    code: None for code in _DROP_INVISIBLE if chr(code) not in (_STASH_OPEN, _STASH_CLOSE)
}
_SPLITTER_RUN: Final = re.compile(
    "["
    + "".join(
        f"{chr(max(low, 0x02))}-{chr(high)}" for low, high in _INVISIBLE_RANGES if high >= 0x02
    )
    + "]+"
)


class _PositionsInText:
    """Where an index of ``text`` with its splitters dropped lies in ``text``, asked in order.

    Walks the runs of splitters once, as the indices asked grow, and holds nothing else: a
    table of every piece's offset, built for every text, took about 140 MB a megabyte of control
    characters in the terminal-only version of this match (pre-commit audit of PR #51).
    """

    def __init__(self, text: str) -> None:
        self._runs = _SPLITTER_RUN.finditer(text)
        self._next = next(self._runs, None)
        self._dropped = 0

    def at(self, index: int) -> int:
        """The position in the text of ``index``, no smaller than the one asked before."""

        # A run sits before the index its start has once the earlier runs are dropped.
        while self._next is not None and self._next.start() - self._dropped <= index:
            self._dropped += self._next.end() - self._next.start()
            self._next = next(self._runs, None)
        return index + self._dropped


@functools.lru_cache(maxsize=256)
def _smallest_period(form: str) -> int:
    """The smallest shift that maps ``form`` onto itself (read off the KMP failure function).

    An occurrence of ``form`` that overlaps another starts at least this far past it.
    """

    border = [0] * len(form)
    length = 0
    for i in range(1, len(form)):
        while length and form[i] != form[length]:
            length = border[length - 1]
        if form[i] == form[length]:
            length += 1
        border[i] = length
    return len(form) - border[-1]


def _overlap_step(joined: str) -> int:
    """How far past an occurrence of ``joined`` the next one may start, overlapping it or not.

    A smallest period on. One that repeats a piece more than twice over (`ab12ab12ab12`,
    `aaaa...`) is matched without overlaps, as the match by value does: following every overlap
    cost a ``find`` of the whole credential per character, 11 s on 4 MB for `a` written 1,000
    times (pre-commit audit).
    """

    period = _smallest_period(joined)
    return period if 2 * period >= len(joined) else len(joined)


@functools.lru_cache(maxsize=256)
def _visible_length(secret: str) -> int:
    """How many characters of ``secret`` show: no splitter, no whitespace at either end."""

    return len(secret.translate(_DROP_INVISIBLE).strip())


def _longest(first: str, then: str) -> str:
    """The credential that names an overlapping group: the longest as it shows, the first on a tie.

    The one rule for a run, matched as written (``_credential_runs``, A-31) or split (A-32).
    Counted with its invisible characters, `abcdefgh` and five zero-width spaces named a group
    over `abcdefghijkl` (pre-merge audit).
    """

    return then if _visible_length(then) > _visible_length(first) else first


def _stretches(clean: str, joined: str, secret: str) -> Iterator[tuple[int, int, str]]:
    """Each stretch of ``clean`` that ``joined`` covers, in order, overlapping ones as one.

    A credential overlapping itself (`hunter2hunter2` twice in a row) is one stretch as it is
    found, so a text that repeats it costs one stretch, not one per occurrence.
    """

    step = _overlap_step(joined)
    found = clean.find(joined)
    start = end = found
    while found != -1:
        if end > start and found >= end:  # a stretch is open and this one does not touch it
            yield start, end, secret
            start = found
        end = found + len(joined)
        found = clean.find(joined, found + step)
    if end > start:
        yield start, end, secret


_STASH_DELIMITER: Final = re.compile(r"[\x00\x01]")


# --- what a terminal acts on instead of showing ------------------------------------------
#: The control and the format characters, not U+FFFD: it splits a credential for the match by
#: value (`_INVISIBLE_RANGES`, A-32) but shows, so it is printed as it is.
_TERMINAL_RANGES: Final = (*_CONTROL_RANGES, *_FORMAT_RANGES)
_TERMINAL_CONTROLS: Final = re.compile(
    "[" + "".join(f"{chr(low)}-{chr(high)}" for low, high in _TERMINAL_RANGES) + "]"
)


def _visible_control(match: re.Match[str]) -> str:
    code = ord(match.group(0))
    if code < 0x20:
        return chr(0x2400 + code)  # its control picture, as the stash delimiters are written
    if code == 0x7F:
        return "\u2421"
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"


#: The second ``#`` of a log command a CI runner reads anywhere in a line, not only at its start:
#: GitHub Actions' legacy ``##[error]...`` (``ActionCommand.TryParse`` looks for ``##[`` with
#: ``IndexOf``) and Azure Pipelines' ``##vso[task.setvariable ...]...`` (``Command.TryParse``,
#: the same). Verified on 2026-10-07 by feeding what ``dottore`` printed to the runner's own
#: ``OutputManager``: a pack's file or spec name raised annotations, masked ``FAIL`` in every
#: later line of the log and set a step output. Any ``##<letters>[`` is matched, the shape of
#: both; that ``#`` is written as ``\x23``, so no ``##`` is followed by ``<letters>[`` any more.
_LOG_COMMAND: Final = re.compile(r"(?<=#)#(?=[A-Za-z]*\[)")


def visible_controls(text: str) -> str:
    """``text`` with every character a terminal acts on written out, for printing.

    A C0 control and DEL become their control pictures (``\\n`` is ``␊``, ``ESC`` is ``␛``, DEL
    is ``␡``), as :func:`visible_stash_delimiters` writes ``\\x00`` and ``\\x01`` (``␀``,
    ``␁``). A C1 control, a separator, a lone surrogate and a format character (Unicode
    Cf: a zero-width space, a soft hyphen, a bidi control, a tag character), which have no
    picture, become the escape Python writes for them (``\\x85``, ``\\u2028``, ``\\udc9b``,
    ``\\u200b``, ``\\xad``, ``\\U000e0041``): a bidi control reorders what is read and a
    format character hides text. A spec file named
    ``x\\n::error ...`` printed a line GitHub Actions reads as a workflow command (pre-merge
    audit of PR #49). A CI log reader also acts on a command in the middle of a line
    (:data:`_LOG_COMMAND`): ``##[error]`` is written ``#\\x23[error]``. The result holds no
    character of :data:`_TERMINAL_CONTROLS` and no such command, so it is its own fixed point.
    It runs after the redactor: escaping first would hide from it a credential split by a
    control character, and it would read the escapes as text.
    """

    return _LOG_COMMAND.sub(r"\\x23", _TERMINAL_CONTROLS.sub(_visible_control, text))


def log_safe_json(text: str) -> str:
    """``text``, a JSON document, with the second ``#`` of each ``##<letters>[`` as ``\\u0023``.

    The JSON outputs (``lint --json``, ``coverage --json``, ``dottore fingerprint``, ``schema
    export``, the JSON and SARIF reports) keep every value as it is, so printed to a CI log a pack's
    file name or a target id holding ``##[error ...]`` or ``##vso[...]`` was still a command to
    the runner (OD-20, open until 2026-10-11). ``\\u0023`` is JSON's own escape for ``#`` (RFC 8259
    §7), so every JSON reader parses the same value, and serializing it again with the same
    options gives the plain bytes back. In a JSON text a ``#`` stands only inside a string and is
    never the character after an escaping backslash (``\\#`` is no JSON escape), so the rewrite
    cannot touch anything else. The ``::`` form needs the start of a line, which a value never
    gets in JSON (a newline in it is written ``\\n``). Decided under the owner's delegation (best
    practice), revisable: the same ``#`` the text outputs write as ``\\x23``. A text with no
    ``##`` is returned as it is, unscanned by the rule (pre-merge audit of 598f0858, LOW 5).
    """

    if "##" not in text:
        return text
    return _LOG_COMMAND.sub(r"\\u0023", text)


def log_safe_xml(text: str) -> str:
    """``text``, an XML document, with the second ``#`` of each ``##<letters>[`` as ``&#35;``.

    The JUnit XML report is a machine output a CI runner may print too, so it follows the rule of
    every JSON output (OD-20; pre-merge audit of 598f0858, LOW 4): ``&#35;`` is the character
    reference every XML parser reads as ``#``. The report is written by ``ElementTree``, which
    puts a ``#`` only in text or an attribute value (no CDATA section, no comment, and the one
    character reference it writes, ``&#10;``, holds a single ``#``), where a reference is read.
    The HTML report is not rewritten: it is a page for a browser, and inside a raw-text element
    (``<script>``, ``<style>``) a character reference is not decoded.
    """

    if "##" not in text:
        return text
    return _LOG_COMMAND.sub("&#35;", text)


#: The email shape; a ``skip`` match is a run of address characters with no address in it.
EMAIL: Final = re.compile(
    r"\b(?:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|(?P<skip>[A-Za-z0-9._%+-]{64,}))"
)

# A value explicitly labelled as a secret (``the api secret is X``, ``password: X``): mask the
# value (group 1) regardless of its shape/entropy, catching engagement secrets the shape
# detectors miss. Deliberately narrow to a labelled assignment to avoid over-redacting prose.
#
# A run of labels is consumed as one (``token=token=token= X``, ``password: password: X``)
# and the value may not itself be a label: the first version captured the SECOND label as
# the value, masked the label words and left the real secret in clear, and on the first
# input it never reached a fixed point, which tripped the store's fail-closed guard and
# aborted the whole campaign over one reply (audit 2026-10-03, F17).
#
# The run is BOUNDED (at most three more labels). Unbounded, every start position consumed
# the rest of a long run of label words and backtracked through all of it: 48 KB of
# ``token token ...`` took 4.9 s, 96 KB took 20 s, and a target controls that text (review of
# PR #32). A longer run still masks its value, from a later start position. A value is
# refused only when it is a label FOLLOWED by a separator or the end, so ``Password!2026x``
# after ``password:`` is a value again (the first fix left it in clear).
_LABEL_WORDS: Final = (
    r"(?:secret|password|passwd|passphrase|api[\s_-]?key|access[\s_-]?key|"
    r"token|credential|client[\s_-]?secret)s?"
)
_LABEL_SEP: Final = r"[\s\"'`:=]"
_LABELED_SECRET: Final = re.compile(
    rf"(?i)\b{_LABEL_WORDS}\b(?:{_LABEL_SEP}{{1,4}}{_LABEL_WORDS}\b){{0,3}}"
    rf"(?:\s+(?:is|are|was|were|=|:))?{_LABEL_SEP}{{1,4}}"
    rf"(?!{_LABEL_WORDS}(?:{_LABEL_SEP}|$))([^\s\"'`,;)\x00\x01]{{6,}})"
)

# --- phone and card numbers glued to their own label ------------------------------------
# The phone and card patterns refuse to start inside a word (``(?<![\w.])``, ``\b``), so that
# version strings, numeric ids and digests are not masked as numbers. That also let a number glued
# to its own label through: ``Tel.555-123-4567``, ``tel_4155550142``, ``card_4111111111111111``. The
# label decides it: right after a phone or card word (not inside a longer word), a digit run is
# masked whatever glues it. The label has to start a word (not after a letter, a digit or ``_``:
# a label in the middle of an opaque token would cut a number out of it and leave the rest
# readable, where the entropy rule masks the whole token). A mask's own type name is no label:
# earlier masks are set aside before the patterns run, and a mask holds no digit run. An
# unlabelled run glued to a word (``user_4155550142``) is still left alone: by shape it is an
# id as often as a number.
_LABEL_TAIL: Final = r"(?:[\s._:=#-]{0,3}(?:no|nr|num|number)\.?)?[\s._:=#-]{0,3}"
_PHONE_WORDS: Final = (
    r"(?:tel|telf|tlf|tfno|phone|mobile|mob|movil|móvil|cell|fax|telefono|teléfono)"
)
LABELLED_PHONE: Final = re.compile(
    rf"(?i)(?<!\w){_PHONE_WORDS}{_LABEL_TAIL}(\+?\d[\d\s().-]{{7,}}\d)(?!\d)"
)
# The same label, ending right where a phone match starts (``follows_phone_label``).
_PHONE_LABEL_BEFORE: Final = re.compile(rf"(?i)(?<!\w){_PHONE_WORDS}{_LABEL_TAIL}\Z")
LABELLED_CARD: Final = re.compile(
    r"(?i)(?<!\w)(?:card|cc|pan|visa|mastercard|amex|tarjeta)"
    rf"{_LABEL_TAIL}((?:\d[ -]?){{12,18}}\d)(?!\d)"
)

# --- credentials the tool itself has read ----------------------------------------------
# The shape detectors above guess. A credential this process resolved (an API key read from
# ``env://``, a password in an endpoint URL) does not need guessing: it is masked by VALUE,
# in every Redactor instance, wherever it appears. Before this, a lowercase segmented key, a
# key under 16 characters or a ``bearer`` value passed unmasked, and a key with a trailing CR
# reached all four report formats inside an HTTP library's error message (audit 2026-10-03,
# SEC-01 and SEC-05). Values shorter than ``_KNOWN_MIN_LEN`` are not registered: masking a
# four-letter string everywhere would rewrite ordinary words in every report.
_KNOWN_SECRETS: set[str] = set()
_KNOWN_LOCK: Final = threading.Lock()

_KNOWN_MIN_LEN: Final = 8
#: The same floor, for an adapter that refuses a shorter credential before sending it (u04 A-78).
KNOWN_SECRET_MIN_LEN: Final = _KNOWN_MIN_LEN


def _escaped_forms(value: str) -> set[str]:
    """The forms ``value`` takes when a library quotes it: ``repr`` and JSON escaping.

    An HTTP library rejecting a header quotes it repr-escaped (``b'Bearer a\\nb'``, with a
    literal backslash-n), so the raw value with a real newline never matched and the key
    reached stderr, every report format and the evidence (review of PR #32).
    """

    forms = {value, value.strip()}
    for form in list(forms):
        forms.add(repr(form)[1:-1])
        forms.add(json.dumps(form)[1:-1])
    return forms


def register_known_secret(value: str | None) -> None:
    """Mask ``value`` (stripped, and as a library would quote it) by value in every Redactor."""

    if not value:
        return
    # A form holding a stash delimiter is not registered. The text is read without them, so it
    # never matches the text as written, only across a stash token's edges: that broke the token
    # (a raw NUL in the output, no fixed point and the evidence store refusing the reply;
    # pre-commit audits of this block and of the split-credential block, A-32) or took a mask
    # with the text after it. Read without them instead, it could cross a URL's separators and
    # leave the password readable where main's URL rule masked it (pre-merge audit). Its `repr`
    # and JSON forms, as a library quotes it, hold no delimiter and are registered.
    with _KNOWN_LOCK:
        for candidate in _escaped_forms(value):
            if len(candidate) >= _KNOWN_MIN_LEN and not _STASH_DELIMITER.search(candidate):
                _KNOWN_SECRETS.add(candidate)


# A password embedded in a URL (``https://user:pass@host``). Only the password is masked:
# the user and host are what makes an endpoint readable in a report. ``--dry-run``, ``-sn``
# and ``-v`` printed the whole URL and the JSON report stored it (audit 2026-10-03, SEC-02).
# A stash token (a mask set aside earlier in the pass) may stand in the user or the password:
# a registered credential as the user is set aside before this rule runs, the rule refused a
# user holding one, and the password stayed readable; a dotted host hid it only because the
# email rule then took ``password@host`` (pre-commit audit of the control-characters block).
# The user may be empty (``redis://:password@host``, Redis's own form, kept the password).
# Possessive throughout: the delimiter after each part is outside it, so giving characters back
# never finds a match, and with an alternation the engine kept a frame per character (a 4 MB
# reply took 640 MB; pre-commit audit of this fix).
_STASHED: Final = r"\x00\d++\x01"
_URL_USERINFO: Final = re.compile(
    rf"(://(?:[^/\s:@\x00\x01]++|{_STASHED})*+:)((?:[^/\s@\x00\x01]++|{_STASHED})++)(@)"
)

# --- a URL whose separator a registered credential holds (#96) -----------------------------
#: Where a labelled value ends: the first character its pattern does not take.
_LABELLED_VALUE_END: Final = re.compile(r"[\s\"'`,;)\x00\x01]")
#: A URL mask's stash token and its `@`, after which a labelled value it took the head of goes on.
_URL_MASK_AT: Final = re.compile(r"\x00(\d++)\x01@")
#: What the URL rule needs after a `://`, written in the text: a `:` and then an `@`, before any
#: whitespace. A mask only ever hides characters, so a URL the rule reads there in this pass, or in
#: the next once this pass's masks are stash tokens, has both in the text as it is now.
_NEXT_PASS_USERINFO: Final = re.compile(r"[^\s:]*+:[^\s@]*+@")
_URL_PASSWORD_MASK: Final = _MASK_TEMPLATE.format(type="url_password")
#: The URL rule over the text as written (``Redactor._url_passwords_as_written``): every
#: registered credential written out, every other mask one :data:`_NEUTRAL` character.
_URL_AS_WRITTEN: Final = re.compile(r"://[^/\s:@]*+:([^/\s@]++)@")
_NEUTRAL: Final = "\x02"
#: An email mask read as written: an address, so an `@` between two neutral characters. Where the
#: URL rule found no URL, the email rule took the password's tail and a dotted host as one
#: address (`<tail>@db.example.com`), and the password's head was readable (pre-merge audit).
_EMAIL_AS_WRITTEN: Final = "\x02@\x02"
_EMAIL_MASK: Final = "«REDACTED:email»"
#: A stash token, or a mask written in the text this pass (a pattern's own, kept as one piece).
_TOKEN_OR_MASK: Final = re.compile(r"\x00(\d++)\x01|«REDACTED:([A-Za-z0-9_]+)(?::[0-9a-f]{8})?»")
#: What a registered credential must hold for the URL rule to read a URL differently as written.
_URL_PARTS: Final = frozenset(":/@")


def _labelled_value_across(url: re.Match[str]) -> str | None:
    """The labelled value whose label the URL mask of ``url`` takes and that runs on past its
    ``@``, or None.

    ``url`` is a match of :data:`_URL_USERINFO` whose user or password holds a registered
    credential holding an `@`. As written, the URL ends at that `@`; the URL rule reads on to a
    later one, and when that `@` is a labelled value's (`redis://ops:Adm1n@2026-db:6379,password=
    Secr3t@Value99xyz` with `Adm1n@2026` registered, or `redis://ops@corp;password:Secr3t@
    Value99xyz` with `ops@corp`) the URL mask took the label and the value's head, and the tail
    was readable, where the redactor before A-31, whose URL rule refused a mask in the userinfo,
    masked the value whole (#96). The label and its value come after the last mask in the
    userinfo, since neither holds one, so only that stretch is searched, and the value is read up
    to 6 characters past the `@` (its pattern takes 6 or more), which keeps the search linear;
    the value's end is searched for only when one is found.
    """

    text, at = url.string, url.end(2)
    start = text.rindex(_STASH_CLOSE, url.start(), at) + 1
    # No match starts past the `@`: one takes 12 characters or more (a label, a separator and 6).
    for found in _LABELED_SECRET.finditer(text, start, min(len(text), at + 6)):
        if found.start(1) <= at < found.end(1):
            end = _LABELLED_VALUE_END.search(text, at)
            return text[found.start(1) : len(text) if end is None else end.start()]
    return None


def _value_tail_end(text: str, start: int) -> int:
    """Where the rest of a labelled value that goes on at ``start`` ends.

    Where the value ends (:data:`_LABELLED_VALUE_END`), or before its first `://` when what the URL
    rule needs there follows it (:data:`_NEXT_PASS_USERINFO`): a URL can be read at that `://`,
    in this pass or, once this pass's masks are stash tokens, in the next. Taken into this mask,
    such a `://` kept the next pass from reading the URL, and what its password mask would have
    taken was readable (pre-commit differential fuzz); stopped only where the URL rule reads a URL
    in this pass, 3 texts of 300,000 showed text main masks. Any other `://` is part of the value:
    stopped at every `://`, `password=Secr3t@hunter2://Secr3tTail99` kept `://Secr3tTail99`
    readable (pre-merge audit of #96), and stopped at every `://` an `@` followed, so did
    `...://Secr3tTail99@h` (re-audit). Linear: the value holds no whitespace, so one possessive
    match past its first `://` decides for every `://` in it.
    """

    found = _LABELLED_VALUE_END.search(text, start)
    end = len(text) if found is None else found.start()
    scheme = text.find("://", start, end)
    if scheme >= 0 and _NEXT_PASS_USERINFO.match(text, scheme + 3):
        return scheme
    return end


class _AsWritten:
    """A text read as written: every registered credential's mask written out, every other mask
    one :data:`_NEUTRAL` character (``Redactor._url_passwords_as_written``, #96).

    Holds the text it reads (``view``) and, for each mask, where it is there and in the text,
    in four arrays of 8-byte integers: one entry a mask, and nothing for the text between masks,
    which is the same in both. A list of tuples for every piece took the process to 270 MB on
    4 MB of a reply echoing a registered credential that holds an `@`, where main's redactor
    took 122 MB (182 MB now).
    """

    def __init__(self, text: str, shown: Callable[[re.Match[str]], str | None]) -> None:
        self.starts, self.ends = array("q"), array("q")  # each mask, in the view
        self.text_starts, self.text_ends = array("q"), array("q")  # each mask, in the text
        shift = 0  # how much longer the view is than the text up to here

        def _read(m: re.Match[str]) -> str:
            nonlocal shift
            written = shown(m)
            if written is None:  # read as text
                return m.group(0)
            self.starts.append(m.start() + shift)
            shift += len(written) - (m.end() - m.start())
            self.ends.append(m.end() + shift)
            self.text_starts.append(m.start())
            self.text_ends.append(m.end())
            return written

        self.view = _TOKEN_OR_MASK.sub(_read, text)

    def _before(self, index: int) -> int:
        """How far the text between masks ``index - 1`` and ``index`` is shifted in the view."""

        return self.ends[index - 1] - self.text_ends[index - 1] if index else 0

    def in_text(self, first: int, after: int) -> int | None:
        """Where ``view[first:after]`` is in the text, if no mask is in it; else None."""

        index = bisect.bisect_right(self.starts, after - 1)  # the masks starting before `after`
        if index and self.ends[index - 1] > first:
            return None
        return first - self._before(index)

    def in_view(self, at: int) -> int:
        """Where text position ``at``, outside every mask, is in the view."""

        return at + self._before(bisect.bisect_right(self.text_starts, at))

    def readable(self, first: int, after: int) -> tuple[int, int] | None:
        """Where, in the text, the password at ``view[first:after]`` is masked.

        From its first readable character to its last, with the masks between them, and without
        a mask it shares with what lies outside it (a credential across the password's `:` or
        `@`), which stays as it is; None when nothing of it is readable.
        """

        begin = end = -1
        readable = False
        index = bisect.bisect_right(self.starts, first) - 1  # the last mask starting by `first`
        if index < 0 or self.ends[index] <= first:
            index += 1  # `first` is in the text between masks
        at = first
        while at < after:
            if index < len(self.starts) and self.starts[index] <= at:  # a mask, at `at` or cut
                if self.starts[index] < first or self.ends[index] > after:  # cut by an edge
                    at = self.ends[index]
                else:
                    begin = self.text_starts[index] if begin < 0 else begin
                    end = self.text_ends[index]
                    at = self.ends[index]
                index += 1
                continue
            stop = min(after, self.starts[index] if index < len(self.starts) else after)
            shift = self._before(index)
            begin = at - shift if begin < 0 else begin
            end = stop - shift
            readable = True
            at = stop
        return (begin, end) if readable else None


def overlaps_known_secret(value: str) -> bool:
    """True if ``value`` is, contains, or is part of a credential this process registered.

    Part of one only from ``_KNOWN_MIN_LEN`` characters, the floor below which nothing is
    registered either: a caller masking `x` because a password holds an `x` would tell the
    reader so (pre-commit audit of the spec file names).
    """

    with _KNOWN_LOCK:
        return any(
            secret in value or (len(value) >= _KNOWN_MIN_LEN and value in secret)
            for secret in _KNOWN_SECRETS
        )


#: The mask for a value a caller keeps out of the redactor that is part of a registered
#: credential. Written outright: the entropy rule passes an id-shaped name such as a spec file's.
CREDENTIAL_MASK: Final = _MASK_TEMPLATE.format(type="credential")


def known_secret_parts() -> frozenset[str]:
    """Every run of ``_KNOWN_MIN_LEN`` characters of a registered credential, as one set.

    For a caller that checks many texts against them (:func:`holds_known_secret_part`): built
    once, then one set lookup per position of each text. Checking every part of every value
    against every kept path cost 55 s on a 1 MiB error with a 2,000-character credential
    (pre-merge audit of A-38).
    """

    with _KNOWN_LOCK:
        secrets = list(_KNOWN_SECRETS)
    return frozenset(
        secret[i : i + _KNOWN_MIN_LEN]
        for secret in secrets
        for i in range(len(secret) - _KNOWN_MIN_LEN + 1)
    )


def holds_known_secret_part(value: str, parts: frozenset[str]) -> bool:
    """True if ``value`` holds ``_KNOWN_MIN_LEN`` consecutive characters of a registered
    credential, ``parts`` being :func:`known_secret_parts`.

    :func:`overlaps_known_secret` misses a part glued to other text (``report-<part>.json`` is
    neither inside the key nor holds it), so the CLI, which keeps an existing path out of the
    entropy rule, printed one (delta audit of A-38).
    """

    return any(
        value[i : i + _KNOWN_MIN_LEN] in parts for i in range(len(value) - _KNOWN_MIN_LEN + 1)
    )


def registered_secrets() -> tuple[str, ...]:
    """Every registered credential (and the forms a library quotes it in), longest first.

    For a caller that must not cut one in two before redacting (the excerpt an unreadable reply
    keeps, ``adapters.base.reply_excerpt``: a credential read in part is not recognised).
    """

    return tuple(_known_secrets())


def _known_secrets() -> list[str]:
    # Longest first, then by value: a set's iteration order changes with PYTHONHASHSEED, and two
    # credentials of one length came in either order (pre-commit audit of the control-characters
    # block). Nothing the redactor writes may depend on it.
    with _KNOWN_LOCK:
        return sorted(_KNOWN_SECRETS, key=lambda secret: (-len(secret), secret))


def _credential_runs(
    text: str, registered: Sequence[str] | None = None
) -> list[tuple[int, int, str]]:
    """Where the registered credentials are in ``text``, as ``(start, end, credential)`` runs.

    Every occurrence counts, and occurrences that overlap make one run, named after its longest
    credential as it shows (of two of one length, the one that starts first: ``_longest``, the
    rule the split match uses too). Replacing one credential after the other masked whichever a
    set's order gave first and left the other's tail readable (``12345678ab87654321`` with
    ``12345678ab`` and ``ab87654321`` registered), and a credential overlapping itself
    (``abababab`` in ``ababababab``) left its last characters. ``registered`` is the list
    ``_known_secrets`` returns, read once by the caller.
    """

    spans: list[tuple[int, int, str]] = []
    for secret in _known_secrets() if registered is None else registered:
        found = text.find(secret)
        while found != -1:
            end = found + len(secret)
            # Where it overlaps itself it is one span already: a run of it has one per character.
            if spans and spans[-1][2] == secret and found < spans[-1][1]:
                spans[-1] = (spans[-1][0], end, secret)
            else:
                spans.append((found, end, secret))
            found = text.find(secret, found + 1)
    runs: list[tuple[int, int, str]] = []
    for start, end, secret in sorted(spans):
        if runs and start < runs[-1][1]:
            first, last, named = runs[-1]
            runs[-1] = (first, max(last, end), _longest(named, secret))
        else:
            runs.append((start, end, secret))
    return runs


# The corroboration digest is 32 bits of an HMAC. Unsalted, anyone holding a report could
# confirm a guessed password offline by computing the same 32 bits, so the default salt is
# random per process (two occurrences in one run still correlate) unless the operator pins
# one with ``ILDOTTORE_REDACTION_SALT`` to correlate across runs on purpose.
_PROCESS_SALT: Final = os.environ.get("ILDOTTORE_REDACTION_SALT") or secrets.token_hex(16)

# A value is "secret-shaped" (worth masking after a label) when it is not a plain lowercase
# word, i.e. it carries a digit, an uppercase letter, or a symbol. This keeps the labelled
# heuristic from masking ordinary prose ("password strength is low").
_PLAIN_WORD: Final = re.compile(r"^[a-z]+$")

# --- structured-identifier exemptions for the entropy fallback (OD-15) ----------------
# The entropy fallback must fire on *opaque* tokens only. A separator-structured token -
# a spec id (``AG-TOOLCHAIN-EXFIL-001``), a model name (``qwen2.5-coder-32b-instruct``), a
# URL path carrying a port (``11434/v1/chat/completions``) - scores high bits/char purely
# because its short segments barely repeat a character: 15 of the 75 shipped spec ids sat
# at 3.72-3.94 bits/char, i.e. over the 3.7 threshold. Masking one hides nothing and
# destroys a join key (``spec_id`` drives ``dottore diff`` and the SARIF rule id), so both
# shapes are exempted **by shape** - not by raising the global threshold, which would also
# stop catching short real secrets (a random 20-char base64 token averages ~4.04 bits/char).
#
# Mirrors ``shared.models._ID_PATTERN`` (the schema's id shape), narrowed to segments that
# are a whole WORD or a whole NUMBER - which every shipped id is (``MM-AUD-PROMPTINJECT-001``).
# A segment mixing letters and digits is the shape of a key, not of an id, so an id-looking
# credential (``ZYNAP-CANARY-ABCDEF123456``, a license key ``AB1CD-2EF3G-H4IJK``) is **not**
# exempt. Neither is a mixed-case marker (``CANARY-8f3a-secret-token-42``) nor an underscored
# canary stem (``ZYNAP_CANARY_...``): both stay maskable.
_ID_SHAPED: Final = re.compile(r"[A-Z]+(?:-(?:[A-Z]+|[0-9]+))+")
# Lowercase/digit segments joined by ``-``/``_``/``/``: lowercase ids, model names, URL
# paths and ports. An uppercase letter anywhere disqualifies the token, and a base64 key of
# this length is never all-lowercase, so this cannot exempt a real credential.
# An optional leading and trailing ``/`` is part of the shape: an absolute URL path
# (``/v1/chat/completions``) inside a transport error was masked as high entropy once the run
# status reason started going through the redactor (2026-10-03).
_PATH_SHAPED: Final = re.compile(r"/?[a-z0-9]+(?:[-_/][a-z0-9]+)+/?")
_SEGMENT_SPLIT: Final = re.compile(r"[-_/]")
# Counter-rule to the two shapes above: a separator-structured token that is hexadecimal all
# the way through is not an identifier we owe anything to, it is the shape of a UUID-format
# credential or a hyphen-grouped digest (``da39a3ee-5e6b-4b0d-3255-bfef95601890``), which a
# model can emit unlabelled and which the labelled-secret rule therefore never sees. Nothing
# the exemption exists to protect is hex all through: a spec id carries a non-hex letter
# (``AG-TOOLCHAIN-EXFIL-001``), so does a model name (``qwen2.5-coder-32b-instruct``) and so
# does a URL path (``11434/v1/chat/completions``). Digits alone cannot reach the bits/char
# threshold (base 10 caps at 3.32), so this only ever bites tokens mixing ``a``-``f`` with
# digits, i.e. the hash and UUID shapes.
_HEX_SEGMENT: Final = re.compile(r"[0-9a-fA-F]+")
_HEX_EXEMPTION_MIN_LEN: Final = 16
# --- hex runs and UUIDs, masked whatever their bits/char (u01 A-78) ---------------------
# Hexadecimal caps at 4 bits/char and a short sample seldom shows all 16 digits, so the 3.7
# threshold left most random hex keys readable: 74.7% of 32-digit ones (the shape of an Azure
# key), 47.5% of 40-digit ones, 5.5% of 64-digit ones and 47.7% of v4 UUIDs (pre-merge security
# audit of 2026-10-11, MEDIUM 4, 2,000 draws each). A run of 32 or more hex digits (a `0x` in
# front included) is masked by the entropy fallback whatever its entropy, inside any token the
# rule does not mask whole, a separator-structured one too, so it only adds to what the rule
# masked before; and whatever keeps a value out of that rule keeps it out of this one (the CLI
# keeps the digests it computed, the evidence names and an existing path out of it; a model
# name keeps its form). Nothing cuts such a run before the rule reads it: every earlier pattern
# starts and ends where a run of letters and digits does. The UUID shape (8-4-4-4-12 hex digits,
# any version) is one of the late patterns (``_late_patterns``), and what the phone and card
# rules read of one is held in stand-ins it is read back from (``_Cuts``): they read its
# digit-only groups (`-6819-4748-`) as a number and the rest of it stayed readable. The tool
# writes no UUID of its own; what it computes in hex (an evidence or media sha256, the scope
# digest) is put back, or kept out of the rule, where the tool writes it (A-78 lists each place).
_HEX_RUN: Final = re.compile(r"(?<![A-Za-z0-9])(?:0[xX])?[0-9A-Fa-f]{32,}+(?![A-Za-z0-9])")
#: Either shape is 32 characters or more: a shorter token holds neither.
_SHAPE_MIN_LEN: Final = 32
_UUID: Final = re.compile(
    r"(?<![A-Za-z0-9])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
    r"(?![A-Za-z0-9])"
)
#: A UUID's length: one holding a match starts at most this much before it.
_UUID_LEN: Final = 36

# --- the number a number rule read inside a UUID (u01 A-78) ------------------------------
# The card and the phone rules read a UUID's digit-only groups as a number (`-6819-4748-`).
# Main masked that number where it read it, and every rule after them read the text with the
# mask in it: a later number rule stopped at it, a labelled value ran through it, and the
# entropy rule read the token in the pieces between such masks. The UUID itself was cut, and
# what of it lay between the masks was readable. Here the number inside a UUID is written in
# stand-ins of the same length instead (one character for each of its characters, taken from a
# block of the Private Use Area the text does not use), which every rule reads as main read its
# mask: neither a letter nor a digit nor a space, a character a labelled value takes, one the
# entropy rule does not. Read back (``_Cuts.decode``), the text is the text the number rules
# had, every UUID whole and at the same place, so the late pattern masks it whole; and the
# entropy rule judges exactly the pieces main judged, once each (``Redactor._cut_spans``). A
# stand-in no mask has taken at the end of the pass becomes the number's mask, as main wrote
# it. With no free block (a text holding a character of each), the number is masked as main
# masked it.
_STAND_IN_CHARS: Final = "0123456789-"
_STAND_IN_KINDS: Final = ("card", "phone")
#: One stand-in for each character, number type, hashed or not, and first character of a number
#: or not: 88 of a block's 128.
_STAND_IN_BLOCK: Final = 128
_PRIVATE_USE: Final = ((0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD))
_PRIVATE_USE_CHAR: Final = re.compile(
    "|".join(f"[{chr(first)}-{chr(last)}]" for first, last in _PRIVATE_USE)
)


class _Cuts:
    """The stand-ins of one pass, in one free block of the Private Use Area (u01 A-78)."""

    _BY_BASE: ClassVar[dict[int, _Cuts]] = {}

    def __init__(self, base: int) -> None:
        first, last = chr(base), chr(base + _STAND_IN_BLOCK - 1)
        self._base = base
        self._decode = {
            base + self._code(kind, hashed, start, char): _STAND_IN_CHARS[char]
            for kind in range(len(_STAND_IN_KINDS))
            for hashed in (False, True)
            for start in (False, True)
            for char in range(len(_STAND_IN_CHARS))
        }
        # The stand-ins of each number type, hashed or not: one table for a number's first
        # character, one for the rest (`str.translate`, so a number costs one pass in C).
        self._encode = {
            (kind, hashed): tuple(
                {
                    ord(c): chr(base + self._code(kind, hashed, start, char))
                    for char, c in enumerate(_STAND_IN_CHARS)
                }
                for start in (True, False)
            )
            for kind in range(len(_STAND_IN_KINDS))
            for hashed in (False, True)
        }
        #: A run of stand-ins: one number or more, glued.
        self.run = re.compile(f"[{first}-{last}]++")
        #: The entropy rule's token, read on through stand-ins (each piece is judged on its own).
        self.token = re.compile(f"[A-Za-z0-9+/_={first}-{last}-]{{16,}}")

    @staticmethod
    def _code(kind: int, hashed: bool, start: bool, char: int) -> int:
        return ((kind * 2 + hashed) * 2 + start) * len(_STAND_IN_CHARS) + char

    @classmethod
    def for_text(cls, text: str) -> _Cuts | None:
        """The stand-ins for a pass over ``text``: a block it holds no character of, or None."""

        # The blocks the text uses, in one pass: testing every block against every character the
        # text holds took 2.2 s on the 137,468 characters of the Private Use Area (round 2, R2-L2).
        # A text holding one character of each of the 1,072 blocks gets no stand-ins: its numbers
        # are masked as main masked them, a UUID's included (`Redactor._number_mask`).
        used = {
            (first, (code - first) // _STAND_IN_BLOCK)
            for code in map(ord, _PRIVATE_USE_CHAR.findall(text))
            for first, last in _PRIVATE_USE
            if first <= code <= last
        }
        for first, last in _PRIVATE_USE:
            for block in range((last + 1 - first) // _STAND_IN_BLOCK):
                if (first, block) in used:
                    continue
                base = first + block * _STAND_IN_BLOCK
                cuts = cls._BY_BASE.get(base)
                if cuts is None:
                    cuts = cls._BY_BASE[base] = cls(base)
                return cuts
        return None

    def encode(self, number: str, pattern: Pattern) -> str:
        """``number``, read inside a UUID by ``pattern``, the card or the phone rule, in stand-ins.

        The part of a number inside a UUID holds only digits and `-` (a number rule takes digits,
        spaces and `().-`, a UUID hex digits and `-`), each of which has a stand-in.
        """

        first, rest = self._encode[_STAND_IN_KINDS.index(pattern.type), pattern.hashed]
        return number[0].translate(first) + number[1:].translate(rest)

    def decode(self, text: str) -> str:
        """``text`` with every stand-in read back: the same length, every UUID whole."""

        return text.translate(self._decode) if self.run.search(text) else text

    def numbers(self, run: str) -> list[tuple[str, bool, str]]:
        """The numbers a run of stand-ins holds: (type, hashed, the number as written)."""

        out: list[tuple[str, bool, str]] = []
        for c in run:
            code = ord(c) - self._base
            char, rest = code % len(_STAND_IN_CHARS), code // len(_STAND_IN_CHARS)
            start, rest = rest % 2, rest // 2
            hashed, kind = rest % 2, rest // 2
            if start or not out:
                out.append((_STAND_IN_KINDS[kind], bool(hashed), ""))
            kind_name, was_hashed, number = out[-1]
            out[-1] = (kind_name, was_hashed, number + _STAND_IN_CHARS[char])
        return out


class UuidCuts:
    """The stand-ins of a text masked in two passes, one with the number rules and one with the
    entropy rule (the CLI's error masking, ``cli.app._masked``; u01/u12 A-83).

    Within one pass the number rules write what they read inside a UUID in stand-ins, which the
    entropy rule reads as main read their masks and the late pattern reads back (:class:`_Cuts`).
    Two redactors given the same ``UuidCuts`` share them across passes: the first, which has no
    entropy rule, leaves them in its output; the second, which has one, masks each UUID they are
    in whole, with the pieces main masked around it, and masks a stand-in left over as the number
    main masked there. The block is chosen from ``text``, the text the first pass reads, so in
    what it writes every character of it is a stand-in; None when ``text`` uses every block, and
    the numbers are masked as main masked them.
    """

    def __init__(self, text: str) -> None:
        self.cuts = _Cuts.for_text(text)

    def read_back(self, text: str) -> str:
        """``text``, written by a pass sharing these stand-ins, with each read back: the same
        length, every UUID as written."""

        return text if self.cuts is None else self.cuts.decode(text)


def _matches(pattern: Pattern, text: str) -> bool:
    """True if ``pattern`` finds a match in ``text`` (a ``skip`` match is none)."""

    return pattern.may_match(text) and any(not skipped(m) for m in pattern.regex.finditer(text))


def _uuids_overlapping(
    text: str, start: int, end: int, cuts: _Cuts | None = None
) -> list[tuple[int, int]]:
    """Each UUID-shaped run of ``text`` that ``text[start:end]`` overlaps, in order (A-78).

    Read with its stand-ins read back (``cuts``), so a UUID a number rule already cut is still
    one. Searched only within 36 characters of the stretch, so a text of numbers costs a bounded
    search each: the window starts one character before the first a UUID can start at, so its
    lookbehind reads the text's own character, and ends one past the last a UUID can end at.
    """

    low = max(0, start - _UUID_LEN - 1)
    window = text[low : min(len(text), end + _UUID_LEN + 1)]
    if cuts is not None:
        window = cuts.decode(window)
    return [
        (low + m.start(), low + m.end())
        for m in _UUID.finditer(window, max(0, start - _UUID_LEN - low))
        if low + m.start() < end and start < low + m.end()
    ]


def _gaps(text: str, run: re.Pattern[str]) -> Iterator[tuple[int, int]]:
    """Each stretch of ``text`` between two matches of ``run`` (empty ones included)."""

    cursor = 0
    for m in run.finditer(text):
        yield cursor, m.start()
        cursor = m.end()
    yield cursor, len(text)


def _merged(spans: Iterable[tuple[int, int, bool]]) -> list[tuple[int, int, bool]]:
    """``spans`` merged where they overlap, each flag the OR of the flags merged into it."""

    out: list[tuple[int, int, bool]] = []
    for start, end, flag in sorted(spans):
        if out and start < out[-1][1]:
            first, last, held = out[-1]
            out[-1] = (first, max(last, end), held or flag)
        else:
            out.append((start, end, flag))
    return out


#: The shortest token the entropy rule reads (``Redactor._HIGH_ENTROPY_TOKEN``).
_ENTROPY_TOKEN_MIN: Final = 16


# --- date-shape exemption for the ``phone`` and ``card`` detectors ---------------------
# The phone pattern accepts ``-``/``.``/space as group separators, which is exactly how a
# dated identifier is punctuated, so ``2026-09-20``, ``gpt-4.1-2025-04-14``,
# ``claude-opus-4-1-20250805`` and ``run-20260920-143000`` all read as phone numbers and
# rendered as ``claude-opus-«REDACTED:phone»`` in every report. The model name reaches a
# report via ``Target.model`` / ``Target.name`` and the run's date fields, so the report
# could not name the model it had just tested. A dashed date-time has the length of a card
# and passes Luhn for 6 seconds values in 60.
#
# Same remedy as the entropy fallback above: exempt **by shape**, never by loosening the
# detector. A candidate is exempt only when the whole match is a calendar-valid date stamp
# (``YYYY-MM-DD`` or ``YYYYMMDD``) followed by at most one clock time (``-143000`` in a run
# id, ``-13-20-51`` in a directory stamped ``2026-07-09-13-20-51``), or two dates joined by
# ``-`` or a space (a range). Only when the match is glued to an identifier, a letter or digit
# then ``-`` right before it (``claude-opus-4-1-20250805``), may up to three version segments
# of one or two digits precede the date (``4-1-``, ``4.1-``), the first without a leading
# zero. Standalone, or with a leading zero, that prefix is the shape of a real number: a Dutch
# mobile is written ``06-20120512``; and four-digit segments let a phone or the tail of a card
# ride in front of a date, ``415-555-0142-2026-09-20`` (audits of 2026-10-05).
#
# The bound is that no segment can carry a phone: the date stamp is exactly 8 digits with a
# ``19``/``20`` century, a valid month and a valid day; a version segment is at most 2 digits
# and only behind an identifier; a clock is a valid ``HH``/``HHMM``/``HHMMSS`` (its parts
# optionally joined by ``-`` or ``:``). So a real number keeps its mask - ``555-123-4567``
# has no 4-digit year, ``+34 600 123 456`` and ``+1 (555) 123-4567`` carry a ``+``/parens the
# shape does not admit - and a long opaque run cannot ride along behind a date
# (``20250805-600123456789`` is masked whole, as ``600123456789`` is no clock).
_DATE: Final = (
    r"(?:(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"  # YYYY-MM-DD
    r"|(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))"  # YYYYMMDD
)
_CLOCK: Final = r"(?:[-_ T](?:[01]\d|2[0-3])(?:[-:]?[0-5]\d){0,2})?"  # HH / HH-MM / HH-MM-SS
_DATE_STAMP: Final = re.compile(rf"{_DATE}{_CLOCK}|{_DATE}[- ]{_DATE}")
# Behind an identifier only; the first segment has no leading zero, which a phone prefix has
# (`06-20120512`, a Dutch mobile).
_DATE_SHAPED: Final = re.compile(rf"(?:(?:0|[1-9]\d?)[.-](?:\d{{1,2}}[.-]){{0,2}})?{_DATE}{_CLOCK}")
_GLUE: Final = frozenset("-")


def is_date_stamp(text: str, *, after_identifier: bool = False) -> bool:
    """True if ``text`` (a separator at either end aside) is a date stamp the redactor exempts.

    ``after_identifier`` admits the short version prefix (``4-1-20250805``); see
    :func:`glued_to_identifier`. Shared by the redactor's phone and card rules and by the
    ``pii_detector`` evaluator, which flagged ``claude-sonnet-4-5-20250929`` as a phone and a
    dashed date-time as a card or a phone.
    """

    core = text.strip(" -")
    if _DATE_STAMP.fullmatch(core):
        return True
    return after_identifier and _DATE_SHAPED.fullmatch(core) is not None


def follows_phone_label(text: str, start: int) -> bool:
    """True if the text right before ``start`` is a phone label (``tel-``, ``Phone number: ``).

    A prefixed date right after a label is a number, not a dated id: the ``pii_detector`` uses this
    to keep a date-shaped one (``tel-49-30-20120512``) a phone hit, as the redactor masks it.
    """

    return _PHONE_LABEL_BEFORE.search(text[max(0, start - 40) : start]) is not None


def glued_to_identifier(text: str, start: int) -> bool:
    """True if the match at ``start`` follows a letter or digit and a ``-`` (an id)."""

    return start >= 2 and text[start - 1] in _GLUE and text[start - 2].isalnum()


@dataclass(frozen=True)
class Pattern:
    """One named detector: a compiled regex + whether to append a salted hash."""

    type: str
    regex: re.Pattern[str]
    hashed: bool = False
    #: Literals a match always holds one of: a text holding none is not searched (empty: every
    #: text is). The late patterns run over whole texts and inside tokens (A-78), so each is
    #: tried only where it can match.
    hints: tuple[str, ...] = ()

    def may_match(self, text: str) -> bool:
        """False only when ``text`` holds none of :attr:`hints`."""

        return not self.hints or any(hint in text for hint in self.hints)


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum (card numbers) - reduces valid-shape false positives."""

    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


#: Where a key's documented prefix may start: not right after a letter or a digit (u01 A-78).
#: ``\b`` refused a key after ``_`` too, a word character: `_` written 30 times before a
#: ``ghp_`` token left it to the entropy rule, which the run of `_` diluted below its threshold
#: (155 of 200 random tokens printed), and the same for ``AKIA``, ``glpat-`` and ``hf_`` (200 of
#: 200), for ``AIza``, ``glpat-`` and ``hf_`` between runs of 20 `=`, and for ``glpat-`` after 20
#: `-` (pre-merge security audit of 2026-10-11, MEDIUM 4). A key glued to a letter or a digit is
#: still left to the entropy rule: there the prefix is the middle of a longer word.
_KEY_START: Final = r"(?<![A-Za-z0-9])"
#: What the entropy fallback writes for a hex run (A-78), hashed as a key pattern's mask is.
_HEX_TOKEN: Final = Pattern("hex_token", _HEX_RUN, hashed=True)
#: The UUID shape, a late pattern, whose mask the fallback writes too (``Redactor._cut_spans``).
_UUID_PATTERN: Final = Pattern("uuid", _UUID, hashed=True, hints=("-",))


def _key(body: str) -> re.Pattern[str]:
    """A key format: its prefix and body ``body``, starting where :data:`_KEY_START` lets it."""

    return re.compile(_KEY_START + body)


def _late_patterns() -> list[Pattern]:
    """The documented key formats, the JWT and the UUID, masked whatever their entropy (A-78).

    They run last in a pass, after the labelled rule, the entropy rule and the URL rule as
    written (``Redactor.redact_late``), on what those left readable, so each only adds a mask: run
    before them, a key glued to a word, a label or padding took less than the entropy rule took of
    its token (`x_<key>` showed `x_`, `-x-api key : <secret>` lost the label to a greedy body and
    showed the secret), a UUID in an address cut it, and a mask's `:` made the URL rule as written
    take a URL for one its rule had read (pre-commit differential fuzz of this clause, against
    main's redactor). A token the
    entropy rule masks whole is typed by the format inside it (``_entropy_spans``). The four rules
    the redactor had (``sk-``, ``ghp_``, ``AKIA``, ``xox``) still run where they ran, as they
    were; here they are started with ``_KEY_START`` and cover every documented form.

    Every body is a run the pattern takes greedily, so a key followed by more characters of its
    own alphabet is masked with them rather than cut, and each start fails or matches in one
    scan of its run. The sources, read on 2026-10-11: OpenAI (``sk-``, ``sk-proj-``,
    ``sk-svcacct-``, ``sk-admin-``, ``sk-None-``; its developer forum and GitHub's
    secret-scanning partner list, ``openai_api_key``: OpenAI's own reference pages refused the
    read), Anthropic (``sk-ant-``, the Admin API's ``partial_key_hint`` reads
    ``sk-ant-api03-R2D...igAA``), GitHub ("GitHub's token formats": ``ghp_``, ``github_pat_``,
    ``gho_``, ``ghu_``, ``ghs_``, ``ghr_``), GitLab ("Token prefixes": ``glpat-``, ``gloas-``,
    ``gldt-``, ``glrt-``, ``glrtr-``, ``glcbt-``, ``glptt-``, ``glft-``, ``glimt-``,
    ``glagent-``, ``glwt-``, ``glsoat-``, ``glffct-``), AWS ("Understanding unique ID
    prefixes": ``AKIA`` access keys, ``ASIA`` temporary ones, ``ABIA`` STS bearer tokens,
    ``ACCA`` context-specific credentials, each 20 characters), Google Cloud ("API keys", its
    example ``AIza`` key of 39 characters), Hugging Face (User Access Tokens, ``hf_``), Slack
    ("Tokens": ``xoxb-``, ``xoxp-``, ``xapp-``, ``xoxe.xapp-``, ``xwfp-``; "Using token
    rotation": ``xoxe.xoxb-``, ``xoxe.xoxp-``, ``xoxe-``; and the legacy ``xoxa-``, ``xoxr-``,
    ``xoxs-`` the rule already took), Stripe ("API keys": ``sk_live_``, ``sk_test_``,
    ``rk_live_``, ``rk_test_``, ``sk_org_``; "Webhooks": ``whsec_``; the publishable ``pk_``
    key is safe to expose and not taken), npm (the token format of 2021, ``npm_`` and 36
    characters ending in a CRC32 checksum) and PyPI (``pypi-``, Help).
    """

    return [
        Pattern(
            "anthropic_key", _key(r"sk-ant-[A-Za-z0-9_-]{20,}"), hashed=True, hints=("sk-ant-",)
        ),
        # The legacy body is letters and digits only; a typed key's (`sk-proj-`) holds `-` and
        # `_`, which cut the first rule (`\bsk-[A-Za-z0-9]{20,}\b`) at its `proj`.
        Pattern(
            "openai_key",
            _key(r"sk-(?:(?:proj|svcacct|admin|None)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})"),
            hashed=True,
            hints=("sk-",),
        ),
        Pattern(
            "github_token",
            _key(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
            hashed=True,
            hints=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
        ),
        Pattern(
            "gitlab_token",
            _key(r"gl(?:pat|oas|dt|rtr|rt|cbt|ptt|ft|imt|agent|wt|soat|ffct)-[A-Za-z0-9_-]{20,}"),
            hashed=True,
            hints=tuple(
                f"gl{kind}-"
                for kind in (
                    *("pat", "oas", "dt", "rtr", "rt", "cbt", "ptt"),
                    *("ft", "imt", "agent", "wt", "soat", "ffct"),
                )
            ),
        ),
        Pattern(
            "aws_access_key",
            _key(r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
            hashed=True,
            hints=("AKIA", "ASIA", "ABIA", "ACCA"),
        ),
        Pattern("google_api_key", _key(r"AIza[A-Za-z0-9_-]{35,}"), hashed=True, hints=("AIza",)),
        Pattern("huggingface_token", _key(r"hf_[A-Za-z0-9]{30,}"), hashed=True, hints=("hf_",)),
        # Slack bot + user + app tokens (the user/app forms were previously uncovered), and
        # the rotating forms.
        Pattern(
            "slack_token",
            _key(r"(?:xoxe\.(?:xox[bp]|xapp)|xox[abeprs]|xapp|xwfp)-[A-Za-z0-9-]{10,}"),
            hashed=True,
            hints=("xox", "xapp-", "xwfp-"),
        ),
        Pattern(
            "stripe_key",
            _key(r"(?:(?:sk|rk)_(?:live|test|org)_[A-Za-z0-9_]{20,}|whsec_[A-Za-z0-9_+/=-]{20,})"),
            hashed=True,
            hints=("_live_", "_test_", "_org_", "whsec_"),
        ),
        Pattern("npm_token", _key(r"npm_[A-Za-z0-9]{36,}"), hashed=True, hints=("npm_",)),
        Pattern("pypi_token", _key(r"pypi-[A-Za-z0-9_-]{50,}"), hashed=True, hints=("pypi-",)),
        Pattern(
            "jwt",
            # Started as the key formats are: after `_` a JWT is still one, as in GitHub's
            # `ghs_<app id>_<JWT>` installation tokens (the rule above starts at `\b`).
            _key(
                r"(?:eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
                r"|(?P<skip>eyJ[A-Za-z0-9_-]*))"
            ),
            hashed=True,
            hints=("eyJ",),
        ),
        _UUID_PATTERN,
    ]


_CARD: Final = Pattern("card", re.compile(r"\b(?:\d[ -]?){13,19}\b"))
_PHONE: Final = Pattern(
    "phone",
    re.compile(r"(?<![\w.])(?:\+?\d[\d\s().-]{7,}\d(?![\w.])|(?P<skip>\+?\d[\d\s().-]{63,}))"),
)


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
            re.compile(
                r"\b(?:eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
                r"|(?P<skip>eyJ[A-Za-z0-9_-]*))"
            ),
            hashed=True,
        ),
        # The four key rules as they were; every documented format is a late pattern (A-78).
        Pattern("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), hashed=True),
        Pattern("github_token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), hashed=True),
        Pattern("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), hashed=True),
        # Slack bot + user + app tokens (the user/app forms were previously uncovered).
        Pattern("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), hashed=True),
        # --- PII ---
        # With a `skip` branch (SKIP): every start of a long run with no `@` was tried and
        # scanned to its end (100 KB of `1-` took about 7 s, in text the target controls).
        Pattern("email", EMAIL),
        Pattern("iban", re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b")),
        _CARD,
        Pattern("national_id", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
        Pattern(
            "ipv4",
            re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        ),
        _PHONE,
    ]


#: The mask types A-78 added. A mask of one is kept as written, as a mask of the tool's older
#: types is; the labelled rule alone reads one as text, as the redactor before A-78 read it
#: (``Redactor._redact_once``, pre-merge audit of A-78, L3 and round 2, R2-H1).
_LATE_MASK_TYPES: Final = tuple(
    sorted(
        {_HEX_TOKEN.type, *(pattern.type for pattern in _late_patterns())}
        - {pattern.type for pattern in _default_patterns()}
    )
)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of ``s`` - 0.0 for empty strings."""

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
    ``entropy_min_len`` govern the interim global high-entropy fallback (OD-15). ``late``
    runs the documented key formats, the JWT and the UUID after the labelled and the entropy
    rules (``_late_patterns``, u01 A-78), all of them or only the types it names; the CLI turns
    them off on the redactor it runs before its own entropy pass, keeps the UUID on that pass,
    and runs the rest after it. ``uuid_cuts`` shares the stand-ins of a UUID a number rule reads
    with a redactor of a later pass (:class:`UuidCuts`).
    """

    _HIGH_ENTROPY_TOKEN: Final = re.compile(r"[A-Za-z0-9+/_=-]{16,}")

    def __init__(
        self,
        *,
        salt: str | None = None,
        patterns: Sequence[Pattern] | None = None,
        entropy_threshold: float = 3.7,
        entropy_min_len: int = 16,
        late: bool | frozenset[str] = True,
        uuid_cuts: UuidCuts | None = None,
    ) -> None:
        self._salt = (_PROCESS_SALT if salt is None else salt).encode("utf-8")
        self._patterns: list[Pattern] = (
            list(patterns) if patterns is not None else _default_patterns()
        )
        if isinstance(late, bool):
            self._set_late(_late_patterns() if late else [])
        elif isinstance(late, frozenset):
            # A set of types, so a bare string is refused, not read as the types it holds.
            self._set_late([pattern for pattern in _late_patterns() if pattern.type in late])
        else:
            raise TypeError("late is a bool or a frozenset of late pattern types")
        self._uuid_cuts = uuid_cuts
        # The mask types kept as written (`_redact_once`), kept in step with `register`: the
        # tool's own rules', its patterns', and the A-78 types whichever redactor wrote them.
        self._mask_types = (
            _OWN_MASK_TYPES | {pattern.type for pattern in self._patterns} | set(_LATE_MASK_TYPES)
        )
        self._entropy_threshold = entropy_threshold
        self._entropy_min_len = entropy_min_len
        # The hex run is part of the entropy fallback (A-78): a redactor built without it
        # (`without_entropy`, an infinite threshold) does not mask one, so whatever keeps a
        # value out of that rule (the CLI's carried digests, an existing path, a model name)
        # keeps it out of this one too.
        self._hex_runs = math.isfinite(entropy_threshold)

    def _set_late(self, patterns: list[Pattern]) -> None:
        self._late = patterns
        # Whether the UUID pattern is one of them, by identity: `in` on the list compared each
        # pattern by value, a dataclass `__eq__` call each, on every pass (CI of #113).
        self._uuid_late = any(pattern is _UUID_PATTERN for pattern in patterns)
        # Every hint of the late patterns, searched once in a token before any of them is tried.
        hints = [hint for pattern in self._late for hint in pattern.hints]
        self._late_hint = (
            re.compile("|".join(map(re.escape, hints)))
            if self._late and all(pattern.hints for pattern in self._late)
            else None
        )

    def register(self, pattern: Pattern) -> None:
        """Add a detector. Registered patterns run **before** the built-ins."""

        self._patterns.insert(0, pattern)
        self._mask_types = self._mask_types | {pattern.type}

    def without_entropy(self) -> Redactor:
        """This redactor minus the entropy fallback: same salt, patterns and known credentials.

        For values that are identifiers by construction and that the entropy rule mangles, such
        as a provider's model name (`meta-llama/Meta-Llama-3-8B-Instruct` has mixed case, so it
        is not exempt as a path). The UUID pattern, which masks a shape whatever its entropy
        rather than a documented format, goes with it (u01 A-78): a deployment's model name
        holding one (`my-deploy-<uuid>`) reads as it did before A-78, for the fingerprint's
        metadata layer (pre-merge audit of A-78, L5). The key formats and the JWT stay.
        """

        twin = Redactor(
            patterns=self._patterns,
            entropy_threshold=math.inf,
            entropy_min_len=self._entropy_min_len,
            late=bool(self._late),
        )
        twin._set_late([pattern for pattern in self._late if pattern is not _UUID_PATTERN])
        twin._salt = self._salt
        return twin

    def _digest(self, value: str) -> str:
        """Short salted HMAC-SHA256 digest for corroboration (never reversible)."""

        # `surrogatepass`: a lone surrogate (an undecodable byte of a file name) in a labelled
        # value or a PEM body raised `UnicodeEncodeError` here, and the CLI then printed the
        # error it was masking as a traceback, credential included (pre-commit audit of the
        # control-characters block). Text without one encodes to the same bytes as before.
        return hmac.new(
            self._salt, value.encode("utf-8", "surrogatepass"), hashlib.sha256
        ).hexdigest()[:8]

    def _mask_token(self, pattern: Pattern, value: str) -> str:
        if pattern.hashed:
            return self._hashed_mask(pattern.type, value)
        return _MASK_TEMPLATE.format(type=pattern.type)

    def _hashed_mask(self, kind: str, value: str) -> str:
        """The hashed mask of ``value``, typed ``kind``."""

        return _MASK_TEMPLATE_HASHED.format(type=kind, digest=self._digest(value))

    def redact_text(self, text: str) -> str:
        """Mask every secret/PII occurrence in ``text`` (idempotent).

        Runs to a **fixed point** (bounded): one pass can expose a value a previous mask was
        sitting next to, and the evidence store refuses to persist anything for which
        ``redact(redact(x)) != redact(x)``, so a single reply that needed two passes used to
        abort the campaign.
        """

        if not _holds_stash_delimiter(text):
            return self._to_fixed_point(text)
        # A text holding a stash delimiter is read two ways, and what either masks is masked
        # (u01 A-83). With them dropped, an attacker cannot forge a token, and a secret split by
        # them is whole again: `AKIA\x00IOSF...` and a key read as UTF-16 with Latin-1
        # (`s\x00k\x00-\x00...`). With them made visible, a word they end stays a word, so what
        # joining glued to its neighbour is masked: `bob@corp.io\x00_` is no email once joined,
        # nor `x\x01credential: <value>` a label. The output is the text with them made visible
        # and both readings' masks in place, so two names that differ only by one (`cmd`,
        # `cmd\x01`) stay two keys in the stored evidence. The first version returned the joined
        # reading whenever it masked anything and the visible one otherwise, so what a text was
        # masked as depended on whether anything at all was masked in it, however far away: a UUID
        # in one line showed the labelled secret of the next (pre-merge audits of A-78, F2).
        visible = visible_stash_delimiters(text)
        read: dict[str, str] = {}

        def _reading(form: str) -> str:
            read[form] = self._read_back(form)
            return read[form]

        out = read_both_ways(_reading, text)
        # Neither reading masked anything, or the joined one masked nothing the visible one did not
        # (a delimiter far from every secret): the visible reading is the result, a fixed point.
        # A pass that leaves stand-ins wrote them back as text, and reads the result again.
        if out == visible or (out == read.get(visible) and not self._leaves_cuts):
            return out
        # The masks of one reading can stand where the other reading wrote text, so the whole is
        # read once more, which only adds masks, and the result is a fixed point.
        return self._to_fixed_point(out)

    def _read_back(self, text: str) -> str:
        """``text`` to a fixed point, with any stand-in this pass leaves read back (A-83).

        The both-ways reading places the masks of each reading in the text as written, which a
        stand-in is not; the last pass over the result writes them again.
        """

        out = self._to_fixed_point(text)
        if self._leaves_cuts and self._uuid_cuts is not None and self._uuid_cuts.cuts is not None:
            return self._uuid_cuts.cuts.decode(out)
        return out

    @property
    def _leaves_cuts(self) -> bool:
        """True for the first of two passes sharing stand-ins: no entropy rule here reads them."""

        return self._uuid_cuts is not None and not self._hex_runs

    def for_terminal(self, text: str) -> str:
        """``text`` redacted, its control and format characters written out, for printing.

        :meth:`redact_text`, which masks a registered credential those characters split (A-32),
        then :func:`visible_controls`. Errors and warnings quote a target's reply, a report's
        reason or a pack's file names, and reached stderr with their control characters raw.
        """

        return visible_controls(self.redact_text(text))

    def _to_fixed_point(self, text: str) -> str:
        current = text
        for _ in range(4):
            nxt = self._redact_once(current)
            if nxt == current:
                return nxt
            current = nxt
        return current

    def _redact_once(self, text: str) -> str:
        # Protect already-masked tokens from being re-scanned (idempotency). This runs FIRST:
        # a registered credential that is a substring of the mask itself (``credential``)
        # used to be replaced inside the previous pass's mask, nesting it on every pass, and
        # the store's fixed-point guard then aborted the campaign (review of PR #32).
        # Distinct opening and closing delimiters: with one character for both, the close of a
        # stash token, a digit of the text and the open of the next one formed another token
        # (`«a»«b»0«c»` came back as `«a»«a»1\x002\x00`), so a target echoing masks could make
        # the output change on every pass, and the store's fixed-point guard aborted the
        # campaign (audit of the labelled-number block).
        preserved: list[str] = []
        # What each stash token stands for in the text. A digest over a stretch holding one is
        # the digest of what was written there, not of the token, whose number counts the masks
        # set aside before it: a private key's digest changed with the text before the key, and
        # with PYTHONHASHSEED (pre-commit audit of the control-characters block).
        written: list[str] = []

        def _keep(mask: str, original: str | None = None) -> str:
            preserved.append(mask)
            written.append(mask if original is None else original)
            return f"{_STASH_OPEN}{len(preserved) - 1}{_STASH_CLOSE}"

        # The stand-ins of this pass (A-78, `_Cuts`): only a redactor whose entropy rule masks a
        # UUID cut by a number rule whole, and whose late pattern masks any other, uses them.
        # A UUID holds a `-`: a text with none needs no stand-ins, nor the scan for a free block.
        # Shared with another pass (A-83, `UuidCuts`), they are the ones it chose: a text whose
        # every `-` a number rule took holds none, and its stand-ins are still to be read.
        if self._uuid_cuts is not None:
            cuts = self._uuid_cuts.cuts
        else:
            cuts = (
                _Cuts.for_text(text) if self._hex_runs and self._uuid_late and "-" in text else None
            )

        def _as_written(stretch: str) -> str:
            if cuts is not None:
                stretch = cuts.decode(stretch)
            if _STASH_OPEN not in stretch:
                return stretch
            return _STASH_TOKEN.sub(lambda m: written[int(m.group(1))], stretch)

        # A mask is kept aside only when its type is one the tool writes: a target writing
        # `«REDACTED:<the operator's key>»` had the key kept as a mask and printed in the reports
        # (pre-commit audit of this block). Any other mask is read as text, so what it wraps is
        # masked by whichever rule applies, with the text around it (a label, a URL) included;
        # checking the type on its own missed `password: «REDACTED:<the password>»` (delta audit).
        # Its digest is no hiding place either: a registered credential of 8 hex digits written
        # as one (`«REDACTED:card:<it>»`) was kept (pre-merge audit). A registered value is at
        # least 8 characters, so it fits in a digest only by being it. A longer one split over
        # several digests still goes through, as one split by spaces does.
        known: set[str] | None = None

        # The stash tokens of the masks of an A-78 type kept here: the labelled rule reads them as
        # text (below).
        late_kept: set[int] = set()

        def _keep_mask(m: re.Match[str]) -> str:
            nonlocal known
            kind, digest = m.group(1), m.group(2)
            if kind not in self._mask_types:
                return m.group(0)
            if digest is not None:
                known = set(_known_secrets()) if known is None else known
                if digest in known:
                    return m.group(0)
            token = _keep(m.group(0))
            if kind in _LATE_MASK_TYPES:
                late_kept.add(len(preserved) - 1)
            return token

        working = _ALREADY_MASKED.sub(_keep_mask, text)

        # Credentials the tool read, by value, before the URL rule: a password containing a
        # raw ``@`` is matched whole here, where the URL rule would stop at the first ``@``.
        # In a text holding a control or a format character, or U+FFFD, the whole match runs on the
        # text with them dropped (`_redact_split_credentials`, A-32). In any other the registered
        # forms are matched as written first, every occurrence, overlapping ones as one run
        # (`_credential_runs`, A-31), and the split match then finds only a credential registered
        # with such a character inside it.
        registered = _known_secrets()
        split = bool(registered) and _SPLITTER_RUN.search(working) is not None
        first_credential = len(preserved)  # the tokens from here to the URL rule are credentials
        runs = [] if split else _credential_runs(working, registered)
        if runs:
            # One token for every run of the same text, as one `replace` per credential gave:
            # a token each took 44% more time and 83% more memory than main on a reply
            # repeating a credential 55,000 times.
            tokens: dict[str, str] = {}
            pieces: list[str] = []
            cursor = 0
            for start, end, secret in runs:
                stretch = working[start:end]
                token = tokens.get(stretch)
                if token is None:
                    digest = self._digest(secret)
                    mask = _MASK_TEMPLATE_HASHED.format(type="credential", digest=digest)
                    token = tokens[stretch] = _keep(mask, _as_written(stretch))
                pieces += (working[cursor:start], token)
                cursor = end
            working = "".join(pieces) + working[cursor:]
        working = self._redact_split_credentials(working, _keep, registered, split=split)
        credentials = range(first_credential, len(preserved))
        # The URL masks that took the head of a labelled value, and the value as written (#96).
        heads: dict[int, str] = {}

        def _url_password(m: re.Match[str]) -> str:
            password = m.group(2)
            if _STASH_TOKEN.fullmatch(password):  # a mask already (a registered password)
                return m.group(0)
            mask = _keep(_URL_PASSWORD_MASK, _as_written(password))
            # Read on past an `@` a registered credential in the userinfo holds: as written, the
            # URL ended there.
            userinfo = m.group(0)[:-1]
            if _STASH_OPEN in userinfo and any(
                "@" in written[int(token.group(1))] for token in _STASH_TOKEN.finditer(userinfo)
            ):
                value = _labelled_value_across(m)
                if value is not None:
                    heads[len(preserved) - 1] = value
            return m.group(1) + mask + m.group(3)

        working = _URL_USERINFO.sub(_url_password, working)

        for pattern in self._patterns:
            # A labelled number first, whole: the plain pattern would take its unglued tail and
            # leave the head (`fax.0034-` before a masked `600-123456`).
            if pattern.type == "card":
                working = self._redact_labelled_number(pattern, LABELLED_CARD, working, cuts)
                working = self._redact_cards(pattern, working, cuts)
            elif pattern.type == "pem_private_key":
                working = self._redact_pem(pattern, working, _as_written)
            elif pattern.type == "phone":
                working = self._redact_labelled_number(pattern, LABELLED_PHONE, working, cuts)
                working = self._redact_phones(pattern, working, cuts)
            else:
                working = pattern.regex.sub(self._make_sub(pattern, _as_written), working)

        # A mask of an A-78 type the text holds is kept as written, as a mask of an older type is,
        # so a second pass, the evidence store's check, a report and a resume in another process
        # leave it as it is; but the labelled rule reads it as text, as the redactor before A-78
        # read it: kept, `password: «REDACTED:uuid»<secret>` in a reply ended the labelled value and
        # showed the secret, which main masked (pre-merge audit of A-78, L3). The redactor writes
        # none where the labelled rule would take it (it takes a value of hex letters too,
        # `_redact_labeled`), so its own masks are read the same in every pass and every process:
        # first kept only when the process had written them, they were forgotten under a long
        # campaign and changed when read again, and the store refused the write (round 2, R2-H1).
        def _late_as_text(stretch: str) -> str:
            return _STASH_TOKEN.sub(
                lambda m: preserved[i] if (i := int(m.group(1))) in late_kept else m.group(0),
                stretch,
            )

        def _late_kept_again(stretch: str) -> str:
            return _ALREADY_MASKED.sub(
                lambda m: _keep_mask(m) if m.group(1) in _LATE_MASK_TYPES else m.group(0),
                stretch,
            )

        if late_kept:
            working = _late_as_text(working)
        if heads:
            working = self._redact_labelled_after_urls(working, heads, cuts)
            if late_kept:
                working = _late_kept_again(working)
        else:
            working = self._redact_labeled(working, cuts)
            if late_kept:
                working = _late_kept_again(working)
            working = self._redact_high_entropy(working, cuts)
        held = set("".join(written[index] for index in credentials))
        if _EMAIL_MASK in working:  # an address the email rule took holds an `@`
            held.add("@")
        if held & _URL_PARTS and all(part in held or part in working for part in _URL_PARTS):
            working = self._url_passwords_as_written(
                working, _keep, _as_written, written, credentials
            )
        # Last, after the URL rule as written too, which reads a mask's `:` as a userinfo's and
        # takes the URL for one its rule read (u01 A-78; pre-commit differential fuzz).
        working = self.redact_late(working, _as_written)
        if cuts is not None and not self._leaves_cuts:  # a number no mask took, as main masked it
            working = cuts.run.sub(lambda m: self._number_masks(cuts, m.group(0)), working)

        # One pass: a `str.replace` per kept mask was quadratic with thousands of them.
        return _STASH_TOKEN.sub(lambda m: preserved[int(m.group(1))], working)

    def _number_masks(self, cuts: _Cuts, run: str) -> str:
        """The masks of the numbers a run of stand-ins holds, as main wrote them (A-78)."""

        return "".join(
            _MASK_TEMPLATE_HASHED.format(type=kind, digest=self._digest(number))
            if hashed
            else _MASK_TEMPLATE.format(type=kind)
            for kind, hashed, number in cuts.numbers(run)
        )

    def _redact_split_credentials(
        self, text: str, keep: Callable[[str, str], str], registered: Sequence[str], *, split: bool
    ) -> str:
        """Mask every registered credential, split by control, format or U+FFFD characters or not.

        In a text holding one of those characters (``split``) this is the whole match by value:
        a credential split by a newline, a tab or a zero-width space was kept in two readable
        halves in every report, in the evidence and on the terminal (audit of PR #51; split by a
        stash delimiter it was masked, as ``redact_text`` drops those first). Each credential is
        matched in the text with every such character dropped (``_SPLITTER_RUN``, the stash
        delimiters aside: a stash token is a mask, so no credential runs through it), and the
        stretch of the text from its first character to its last, the characters inside
        included, becomes the mask it gets in one piece: same type, same digest, kept aside as a
        mask. What lies outside the stretch stays where it is. Overlapping occurrences, of one
        credential or of two, are masked as one, named by the longest as it shows (the first to
        start on a tie): masking one first would leave the other's head or tail readable (an
        unsplit short one taken first left 8 of a split long one's 12 characters, pre-commit
        review of this block). A credential
        registered with such a character inside it matches as written without it, under the
        registered form's digest, and a key read with a trailing CR, registered stripped too, is
        named by its stripped form.

        In a text without one, the caller has matched every registered form as written, exactly
        as before, and only a credential registered with such a character inside it can still
        match here, written without it. Linear in the text: the dropped copy, a ``find`` per
        credential, and one pass over the splitters to place the matches.
        """

        # Whitespace at the ends goes too, as `register_known_secret` strips it, so that a short
        # value with spaces around it (` # back \r`) cannot mask the prose it reads as (pre-commit
        # audit). Ties go by value: the order of `registered` among equal lengths follows the
        # set's, which changes with the hash seed, and so did the digest (pre-commit audit).
        wanted: dict[str, str] = {}
        short: list[str] = []
        for secret in sorted(registered, key=lambda value: (-len(value), value)):
            joined = secret.translate(_DROP_INVISIBLE).strip()
            if len(joined) >= _KNOWN_MIN_LEN:
                if joined == secret or joined not in wanted:
                    wanted[joined] = secret
            elif split:
                short.append(secret)
        if not split:  # every credential as registered is masked already
            wanted = {joined: secret for joined, secret in wanted.items() if joined != secret}
        if wanted or short:
            text = self._mask_matches(text, keep, registered, wanted, short, split=split)
        return text

    def _mask_matches(
        self,
        text: str,
        keep: Callable[[str, str], str],
        registered: Sequence[str],
        wanted: Mapping[str, str],
        short: Sequence[str],
        *,
        split: bool,
    ) -> str:
        """Mask, once per overlapping group, what the ``wanted`` and the ``short`` forms cover.

        ``wanted`` maps a form without the splitters to the registered credential it names, and
        is matched in the text with them dropped. A ``short`` form is too short without them to
        be matched so (it would mask a word), so only as written, as the caller does in a text
        without them: left out, one registered as `ab\tcd\tefg` was kept raw (pre-commit
        audit). Both kinds of match are placed in the text and their union is masked: replaced
        before the longer matches, a short form took a longer credential's head and left its
        tail (delta audit), and replaced after them, it kept up to 6 characters they had not
        taken (pre-merge audit).
        """

        def _joined() -> Iterator[tuple[int, int, str]]:
            # Merged where they were found, so each group is placed with indices that only grow.
            # Nothing is built for a text that holds none of them.
            clean = text.translate(_DROP_SPLITTERS) if split and wanted else text
            stretches = heapq.merge(*(_stretches(clean, form, wanted[form]) for form in wanted))
            group = next(stretches, None)
            if group is None:
                return
            positions = _PositionsInText(text)
            for start, end, secret in stretches:
                if start < group[1]:
                    group = (group[0], max(group[1], end), _longest(group[2], secret))
                    continue
                yield positions.at(group[0]), positions.at(group[1] - 1) + 1, group[2]
                group = (start, end, secret)
            yield positions.at(group[0]), positions.at(group[1] - 1) + 1, group[2]

        def _as_registered(secret: str) -> Iterator[tuple[int, int, str]]:
            # Every occurrence, overlapping ones as one span: taking them without overlaps, the
            # second of two overlapping ones was lost when a longer match covered the first, and
            # its tail stayed readable (delta audit of the pre-merge follow-ups). A value with
            # nothing visible leaves nothing readable either way, and following its overlaps costs
            # a search per character of a text made of it.
            step = _smallest_period(secret) if _visible_length(secret) else len(secret)
            found = text.find(secret)
            start = end = found
            while found != -1:
                if end > start and found >= end:
                    yield start, end, secret
                    start = found
                end = found + len(secret)
                found = text.find(secret, found + step)
            if end > start:
                yield start, end, secret

        spans = heapq.merge(_joined(), *(_as_registered(secret) for secret in short))
        current = next(spans, None)
        if current is None:
            return text
        # One stash token a stretch, as the match by value uses: a text repeating a split
        # credential costs a list entry per occurrence, not a mask and a token each. The token
        # records the stretch as written (A-31), so a private key holding a split credential is
        # digested over the key as written, as it is when the credential is not split.
        tokens: dict[str, str] = {}
        exact = frozenset(registered)
        out: list[str] = []
        cursor = 0

        def _mask(first: int, after: int, secret: str) -> None:
            nonlocal cursor
            # A stretch written exactly as a registered form gets that form's digest, as the
            # match by value gave it; any other is named by the credential it was matched as.
            written = text[first:after]
            token = tokens.get(written)
            if token is None:
                name = written if written in exact else secret
                mask = _MASK_TEMPLATE_HASHED.format(type="credential", digest=self._digest(name))
                token = tokens[written] = keep(mask, written)
            out.append(text[cursor:first])
            out.append(token)
            cursor = after

        for first, after, secret in spans:
            if first < current[1]:
                current = (current[0], max(current[1], after), _longest(current[2], secret))
                continue
            _mask(*current)
            current = (first, after, secret)
        _mask(*current)
        out.append(text[cursor:])
        return "".join(out)

    def _make_sub(
        self, pattern: Pattern, as_written: Callable[[str], str]
    ) -> Callable[[re.Match[str]], str]:
        """Build a substitution callback bound to ``pattern`` (closure-safe).

        A hashed mask digests the match as written (``as_written``): a pattern that can span a
        stash token (a private key's body can) digested the token's number instead.
        """

        def _sub(m: re.Match[str]) -> str:
            if skipped(m):
                return m.group(0)
            value = m.group(0)
            return self._mask_token(pattern, as_written(value) if pattern.hashed else value)

        return _sub

    def redact_late(self, text: str, as_written: Callable[[str], str] | None = None) -> str:
        """Mask the late patterns (:func:`_late_patterns`, A-78) in what ``text`` shows.

        The last rule of a pass, after the labelled, the entropy and the URL-as-written rules. No
        late pattern matches inside a mask (none starts with a letter of one, or holds a ``«``, a
        ``:`` or a ``»``). ``as_written`` writes out a stash token a match holds (the pass's own);
        the CLI calls it on its own on each stretch of the message it prints that it does not
        keep, after its entropy pass (``cli.app._masked``). In a pass, the entropy rule has
        masked every UUID a number rule read a number in (``_cut_spans``), so no stand-in is left
        for them.
        """

        # One search for a literal some late pattern needs, before any is tried: a short text
        # holding none (an address, a word) cost each pattern's own check, 1.7 times main's time
        # on 24,000 evidence keys (CI of #113).
        if self._late_hint is not None and self._late_hint.search(text) is None:
            return text
        written = as_written or (lambda stretch: stretch)
        for pattern in self._late:
            if pattern.may_match(text):
                text = pattern.regex.sub(self._make_sub(pattern, written), text)
        return text

    def _redact_pem(self, pattern: Pattern, text: str, as_written: Callable[[str], str]) -> str:
        """Mask PEM private keys, skipping the scan entirely when no END marker exists.

        Without an END marker the pattern cannot match, so running the DOTALL regex over a
        large ``BEGIN``-only blob is pure wasted (quadratic) backtracking, the precheck
        turns that ReDoS surface into an O(1) substring test (contract: no self-DoS).
        """

        if "-----END" not in text or "PRIVATE KEY-----" not in text:
            return text
        return pattern.regex.sub(self._make_sub(pattern, as_written), text)

    def _plain_word(self, value: str) -> bool:
        """True if the labelled rule leaves ``value`` as a plain lowercase word.

        Not 32 hex letters or more, which the hex rule masks (A-78): left to that rule, the value
        became `«REDACTED:hex_token:...»` after its label, which the labelled rule reads as text in
        the next pass and masks, so a pass of the redactor's own output changed it.
        """

        return _PLAIN_WORD.match(value) is not None and not (
            self._hex_runs and _HEX_RUN.fullmatch(value) is not None
        )

    def _redact_labeled(self, text: str, cuts: _Cuts | None = None) -> str:
        """Mask a value explicitly labelled as a secret (the value only, not the label).

        The digest is the value's as written: stand-ins (``cuts``, A-78) read back.
        """

        def _sub(m: re.Match[str]) -> str:
            value = m.group(1)
            if self._plain_word(value):  # a plain lowercase word is not a secret
                return m.group(0)
            written = value if cuts is None else cuts.decode(value)
            masked = _MASK_TEMPLATE_HASHED.format(
                type="labeled_secret", digest=self._digest(written)
            )
            # Replace the VALUE's span only. ``str.replace`` over the whole match also
            # rewrote the label whenever the label text equalled the value.
            start, end = m.start(1) - m.start(0), m.end(1) - m.start(0)
            whole = m.group(0)
            return whole[:start] + masked + whole[end:]

        return _LABELED_SECRET.sub(_sub, text)

    def _redact_labelled_after_urls(
        self, text: str, heads: Mapping[int, str], cuts: _Cuts | None = None
    ) -> str:
        """The labelled and the entropy rules, and the rest of the labelled values whose head a URL
        mask took (``heads``, #96).

        ``heads`` maps the stash token of each such URL mask to the value as written. The two
        rules mask exactly what ``_redact_labeled``, then ``_redact_high_entropy`` on its result,
        mask, and then, only where they left text readable:

        - what follows the mask's `@` up to where the value ends (``_value_tail_end``) is masked as
          that value is, with its digest:
          ``redis://ops:«REDACTED:url_password»@«REDACTED:labeled_secret:<digest>»``;
        - from there to the next such mask, the labelled rule is run again, on the text as it was
          before it ran, so the value's tail is not read for a label, as the redactor before A-31,
          which matched the value whole, did not read it. Read for one, a label in the tail
          (`x-token abcdef/secret="Hunter2Secret99"`) took the next label into its value, and the
          secret after that next label was readable (pre-merge audit of #96).

        Laid before the two rules, the tail took a label written after the value
        (`...@BT8Ibd/&TOKEN: <secret>`) and the secret was readable (pre-commit differential
        fuzz), so these masks only fill what the two rules left. Their masks never touch: a
        labelled mask holds no run of 16 characters the entropy rule reads. Linear: each rule reads
        the text once, the stretch after each URL mask is read once more, and the masks are held in
        arrays of 8-byte integers with one mask text a value (a list of tuples and a mask each took
        39 bytes a character on 2 MB echoing such a URL 70,000 times).
        """

        labelled: dict[str, str] = {}  # one mask a value: a reply can repeat one 70,000 times

        def _labelled(value: str) -> str:
            mask = labelled.get(value)
            if mask is None:
                digest = self._digest(value if cuts is None else cuts.decode(value))
                mask = labelled[value] = _MASK_TEMPLATE_HASHED.format(
                    type="labeled_secret", digest=digest
                )
            return mask

        # The labelled rule, as `_redact_labeled` applies it, and the entropy rule on the text it
        # wrote, placed back in this text: where each mask starts and ends, and the mask.
        starts, ends, masks = array("q"), array("q"), []
        for m in _LABELED_SECRET.finditer(text):
            if not self._plain_word(m.group(1)):
                starts.append(m.start(1))
                ends.append(m.end(1))
                masks.append(_labelled(m.group(1)))
        parts: list[str] = []
        written_ends, shifts = array("q"), array("q")  # each labelled mask in the text it wrote
        cursor = shift = 0
        for start, end, mask in zip(starts, ends, masks, strict=True):
            parts += (text[cursor:start], mask)
            shift += len(mask) - (end - start)
            written_ends.append(end + shift)
            shifts.append(shift)
            cursor = end
        parts.append(text[cursor:])
        written = "".join(parts)
        del parts
        entropy: list[tuple[int, int, str]] = []
        tokens = self._HIGH_ENTROPY_TOKEN if cuts is None else cuts.token
        for m in tokens.finditer(written):
            spans = self._entropy_spans(m.group(0), cuts)
            if not spans:
                continue
            # A token lies between two labelled masks (none holds a token character), so one
            # shift places all of its spans.
            index = bisect.bisect_right(written_ends, m.start())
            at = m.start() - (shifts[index - 1] if index else 0)
            entropy += [(at + start, at + end, mask) for start, end, mask in spans]
        del written, written_ends, shifts
        ruled = sorted([*zip(starts, ends, masks, strict=True), *entropy])
        ruled_starts = array("q", (start for start, _end, _mask in ruled))
        # What the two rules left readable of each value whose head a URL mask took, and of the
        # values the labelled rule finds after it when it does not read its tail, in order.
        added_starts, added_ends, added = array("q"), array("q"), []

        def _add(first: int, last: int, mask: str) -> None:
            index = max(0, bisect.bisect_right(ruled_starts, first) - 1)
            at = first
            while at < last:
                if index < len(ruled) and ruled[index][0] <= at:  # masked by the two rules
                    at = max(at, ruled[index][1])
                    index += 1
                    continue
                stop = min(last, ruled[index][0]) if index < len(ruled) else last
                added_starts.append(at)
                added_ends.append(stop)
                added.append(mask)
                at = stop

        def _after(start: int, stop: int, value: str) -> None:
            end = _value_tail_end(text, start)
            _add(start, end, _labelled(value))
            # Read on from where the value ends, not from where its tail stops: from a `://` the
            # tail stopped before, the rest of the value was read for a label, which took the next
            # label into its value (`...@x://h@y-token abc123/secret="<secret>"`, re-audit of #96).
            found = _LABELLED_VALUE_END.search(text, start)
            rest = len(text) if found is None else found.start()
            for m in _LABELED_SECRET.finditer(text, rest, min(len(text), stop + 1)):
                if not self._plain_word(m.group(1)):
                    _add(m.start(1), m.end(1), _labelled(m.group(1)))

        pending: tuple[int, str] | None = None  # the URL mask before this one: its `@`, its value
        for url in _URL_MASK_AT.finditer(text):
            value = heads.get(int(url.group(1)))
            if value is None:
                continue
            if pending is not None:
                _after(pending[0], url.start(), pending[1])
            pending = (url.end(), value)
        if pending is not None:
            _after(pending[0], len(text), pending[1])
        out: list[str] = []
        cursor = 0

        def _put(start: int, end: int, mask: str) -> None:
            nonlocal cursor
            start = max(start, cursor)  # a guard: no two masks laid here share a character
            if start < end:
                out.extend((text[cursor:start], mask))
                cursor = end

        added_at = 0
        for start, end, mask in ruled:
            while added_at < len(added) and added_starts[added_at] < start:
                _put(added_starts[added_at], added_ends[added_at], added[added_at])
                added_at += 1
            _put(start, end, mask)
        for index in range(added_at, len(added)):
            _put(added_starts[index], added_ends[index], added[index])
        out.append(text[cursor:])
        return "".join(out)

    def _url_passwords_as_written(
        self,
        text: str,
        keep: Callable[[str, str], str],
        as_written: Callable[[str], str],
        written: Sequence[str],
        credentials: range,
    ) -> str:
        """Mask the password of a URL the URL rule could not read because a registered credential
        holds one of its separators (#96).

        The URL rule runs on the text with every registered credential set aside as a stash
        token, so a credential holding the URL's `://` or its `:` stops it, and one across the
        password's `@` with no later `@` does too: the password, or its part outside the
        credential, stayed readable. Two overlapping credentials masked as one run made it
        reachable where the one-at-a-time replacement before A-31 had left the `://` showing
        (`key-ABCD1234` and `1234://bob` registered: ``x key-ABCD1234://bob:<password>@localhost``).

        This reads the URL in the text as written, every registered credential written out and
        every other mask one neutral character (an email mask an `@` between two: where the URL
        rule found no URL, the email rule took the password's tail and a dotted host as one
        address), and masks what of the password is still readable. A URL the URL rule read, at
        a `://` that is in the text as it reads, is left as that rule masked it, and the `:`
        after the user of a URL the next pass can read is left out of the mask. It runs last in
        the pass, after every rule, so it only adds to what they masked: a mask laid before them
        could take a label, or the start of a match, from another rule (the pass PR #56 backed
        out joined the password to the credential before the other rules ran, and swallowed a
        labelled secret after the URL). A credential cut by the password's edges stays its own
        mask, and what of the password lies between masks becomes one ``url_password`` mask.
        Linear: two passes to read the text, two searches, and the URL rule tried once at each
        `://` in the text as it reads.
        """

        def _shown(m: re.Match[str]) -> str | None:
            index, kind = m.group(1), m.group(2)
            if index is None:  # a mask a pattern wrote, or text in that shape (`_keep_mask`)
                if kind == "email":  # it took an `@`: the password's, past a dotted host
                    return _EMAIL_AS_WRITTEN
                return _NEUTRAL if kind in self._mask_types else None
            return written[int(index)] if int(index) in credentials else _NEUTRAL

        def _readable(stretch: str) -> bool:
            """True if ``stretch`` holds text that is not a mask (a mask of an unknown type is)."""

            return any(_shown(m) is None for m in _TOKEN_OR_MASK.finditer(stretch)) or bool(
                _TOKEN_OR_MASK.sub("", stretch)
            )

        def _as_token(m: re.Match[str]) -> str | None:
            return _NEUTRAL if m.group(1) or m.group(2) in self._mask_types else None

        read = _AsWritten(text, _shown)
        # The `:` after the user of each URL the next pass can read, once this pass's masks are
        # stash tokens: the URL rule reads it on to a later `@`, and masked here, that `:` kept it
        # from reading it, and what its mask would have taken was readable (pre-commit
        # differential fuzz). Such a `:` is left out of a mask laid here.
        later = _AsWritten(text, _as_token)
        kept = [
            at
            for url in _URL_AS_WRITTEN.finditer(later.view)
            if (at := later.in_text(url.start(1) - 1, url.start(1))) is not None
        ]
        out: list[str] = []
        done = 0
        for url in _URL_AS_WRITTEN.finditer(read.view):
            # The URL rule read this one: its password is a mask of this pass, and the URL reads
            # with every mask one neutral character. Read on the text, a mask laid after that
            # rule gave it the `:` it lacked, and the password stayed readable: a phone mask's
            # before A-78, a hex run's or a UUID's since (pre-merge audit of A-78, L2).
            # Both views hold the same masks (`_shown` and `_as_token` read the same as masks), so a
            # `://` outside one in the first is outside one in the second.
            at = read.in_text(url.start(), url.start() + 3)
            if at is not None and _URL_USERINFO.match(later.view, later.in_view(at)):
                continue
            stretch = read.readable(*url.span(1))
            if stretch is None:
                continue
            first, after = stretch
            index = bisect.bisect_left(kept, first)
            while index < len(kept) and kept[index] < after:
                if _readable(text[first : kept[index]]):
                    piece = as_written(text[first : kept[index]])
                    out += (text[done:first], keep(_URL_PASSWORD_MASK, piece))
                    done = kept[index]
                first = kept[index] + 1
                index += 1
            if not _readable(text[first:after]):  # nothing readable left
                continue
            out += (text[done:first], keep(_URL_PASSWORD_MASK, as_written(text[first:after])))
            done = after
        if not out:
            return text
        out.append(text[done:])
        return "".join(out)

    def _redact_labelled_number(
        self, pattern: Pattern, labelled: re.Pattern[str], text: str, cuts: _Cuts | None = None
    ) -> str:
        """Mask the number glued to a phone or card label (the number only, not the label).

        Runs with the matching detector, so a redactor built without it does not grow it. A
        card still has to pass Luhn, and a plain date stamp is still not a number; the version
        prefix a date may carry behind an identifier is not admitted after a label
        (``tel-49-30-20120512`` is a phone), as ``pii_detector`` reads it.
        """

        def _sub(m: re.Match[str]) -> str:
            number = m.group(1)
            if is_date_stamp(number):
                return m.group(0)
            if pattern.type == "card" and not _luhn_ok(re.sub(r"\D", "", number)):
                return m.group(0)
            start, end = m.start(1) - m.start(0), m.end(1) - m.start(0)
            whole = m.group(0)
            mask = self._number_mask(pattern, text, m.start(1), m.end(1), cuts)
            return whole[:start] + mask + whole[end:]

        return labelled.sub(_sub, text)

    def _number_mask(
        self, pattern: Pattern, text: str, start: int, end: int, cuts: _Cuts | None = None
    ) -> str:
        """The mask of the number at ``text[start:end]``, what of it a UUID holds in stand-ins
        (A-78, :class:`_Cuts`).

        The card and phone rules read a UUID's digit-only groups as a number, and a number
        written before or after a UUID could run into it (`tel +34 600 123 456` and a line break
        before a UUID starting with a digit): masked, the rest of the UUID was readable. What of
        the number lies inside a UUID is written in stand-ins, which the rules after this one
        read as they read main's mask and the late pattern reads back, so the UUID is masked
        whole; what lies outside it is masked as before. Without ``cuts`` (a redactor without
        the late patterns, or a text with no free block) the number is masked as main masked it.
        """

        if cuts is None:
            return self._mask_token(pattern, text[start:end])
        uuids = _uuids_overlapping(text, start, end, cuts)
        if not uuids:
            return self._mask_token(pattern, text[start:end])
        out: list[str] = []
        cursor = start
        for begin, finish in uuids:
            first, last = max(begin, start), min(finish, end)
            if cursor < first:
                out.append(self._mask_token(pattern, text[cursor:first]))
            out.append(cuts.encode(text[first:last], pattern))
            cursor = last
        if cursor < end:
            out.append(self._mask_token(pattern, text[cursor:end]))
        return "".join(out)

    def _redact_cards(self, pattern: Pattern, text: str, cuts: _Cuts | None = None) -> str:
        """Card matcher with a Luhn guard to cut valid-shape false positives."""

        def _sub(m: re.Match[str]) -> str:
            if not self._is_card(m, text):
                return m.group(0)
            return self._number_mask(pattern, text, m.start(), m.end(), cuts)

        return pattern.regex.sub(_sub, text)

    @staticmethod
    def _is_card(m: re.Match[str], text: str) -> bool:
        """True if the card rule masks its match ``m`` of ``text``."""

        digits = re.sub(r"\D", "", m.group(0))
        # A date-time stamp (`2026-07-09-13-20-01`, 14 digits) passes Luhn for 6 seconds in
        # 60; the date shape exempts it here as it does from the phone rule.
        # The match can take a trailing - or space; a version prefix only behind an id.
        if is_date_stamp(m.group(0), after_identifier=glued_to_identifier(text, m.start())):
            return False
        return 13 <= len(digits) <= 19 and _luhn_ok(digits)

    def _redact_phones(self, pattern: Pattern, text: str, cuts: _Cuts | None = None) -> str:
        """Phone matcher with a date-shape guard to cut dated-identifier false positives.

        A match that is entirely a date / dated version suffix / run id (:func:`is_date_stamp`)
        is left as written; everything else is masked exactly as before.
        """

        def _sub(m: re.Match[str]) -> str:
            if not self._is_phone(m, text):
                return m.group(0)
            return self._number_mask(pattern, text, m.start(), m.end(), cuts)

        return pattern.regex.sub(_sub, text)

    @staticmethod
    def _is_phone(m: re.Match[str], text: str) -> bool:
        """True if the phone rule masks its match ``m`` of ``text``."""

        if skipped(m):
            return False
        return not is_date_stamp(m.group(0), after_identifier=glued_to_identifier(text, m.start()))

    def _cut_spans(self, token: str, cuts: _Cuts) -> list[tuple[int, int, str]]:
        """What the entropy fallback masks of a ``token`` holding stand-ins (A-78, :class:`_Cuts`).

        Main read such a token in the pieces between its number masks, and masked each piece the
        rule masks whole; each is judged here once, as main judged it (linear: the pieces do not
        overlap). Each UUID a stand-in is in is masked whole, with every such piece that overlaps
        it, as one ``uuid`` mask; a piece that overlaps none keeps the mask main gave it, typed by
        the first late pattern it holds. Then, as in any token, each hex run outside those and
        outside a late pattern's match. The whole token, stand-ins read back, is judged first, as
        any token is (:meth:`_entropy_spans`).
        """

        whole = cuts.decode(token)
        if _UUID.fullmatch(whole):  # stand-ins exist only beside the UUID pattern
            return [(0, len(token), self._mask_token(_UUID_PATTERN, whole))]
        if self._masks_whole(whole):
            return [(0, len(token), self._typed_mask(whole))]
        pieces = [
            (start, end)
            for start, end in _gaps(token, cuts.run)
            if end - start >= _ENTROPY_TOKEN_MIN and self._masks_whole(token[start:end])
        ]
        uuids = [m.span() for m in _UUID.finditer(whole) if cuts.run.search(token, *m.span())]
        spans: list[tuple[int, int, str]] = []
        taken: list[tuple[int, int]] = []
        for start, end, holds_uuid in _merged(
            [*((a, b, True) for a, b in uuids), *((a, b, False) for a, b in pieces)]
        ):
            stretch = whole[start:end]
            mask = (
                self._mask_token(_UUID_PATTERN, stretch)
                if holds_uuid
                else self._typed_mask(stretch)
            )
            spans.append((start, end, mask))
            taken.append((start, end))
        spans += self._hex_run_spans(whole, taken)
        return sorted(spans)

    def _is_structured(self, token: str) -> bool:
        """True when ``token`` is a structured identifier/path rather than an opaque blob.

        Both exempt shapes additionally require **every** segment to be shorter than
        ``entropy_min_len``, so an identifier-looking wrapper around a long opaque run
        (``ZYNAP-CANARY-A1B2C3D4E5F6G7H8``) is still masked *as a whole* - an exemption can
        never expose part of a secret. An all-hexadecimal token of ``entropy_min_len`` or more
        hex digits is excluded outright (``_HEX_SEGMENT``): that is a UUID-format key or a
        grouped digest, not an identifier.
        """

        if not (_ID_SHAPED.fullmatch(token) or _PATH_SHAPED.fullmatch(token)):
            return False
        segments = _SEGMENT_SPLIT.split(token)
        if not all(len(segment) < self._entropy_min_len for segment in segments):
            return False
        hex_len = sum(len(segment) for segment in segments)
        return not (
            hex_len >= _HEX_EXEMPTION_MIN_LEN
            and all(_HEX_SEGMENT.fullmatch(segment) for segment in segments)
        )

    def _masks_whole(self, token: str) -> bool:
        """True if the entropy rule masks ``token`` whole (not structured, long, high entropy)."""

        return (
            not self._is_structured(token)
            and len(token) >= self._entropy_min_len
            and _shannon_entropy(token) >= self._entropy_threshold
        )

    def _entropy_spans(self, token: str, cuts: _Cuts | None = None) -> list[tuple[int, int, str]]:
        """What the entropy fallback masks of ``token``, as ``(start, end, mask)`` in it.

        The whole token when the rule masks it whole (:meth:`_masks_whole`), typed by the first
        late pattern it holds (A-78: the same mask, named better). Otherwise, when the fallback
        is on, each run of :data:`_HEX_RUN` outside a late pattern's match, which the late pass
        masks with its type (masked here, `sk-proj-` and `a` written 156 times read
        `sk-proj-«REDACTED:hex_token»`). A token holding stand-ins (``cuts``) is read in the
        pieces main read (:meth:`_cut_spans`).
        """

        if cuts is not None and self._hex_runs and cuts.run.search(token):
            return self._cut_spans(token, cuts)
        if self._hex_runs and self._uuid_late and _UUID.fullmatch(token):
            # A UUID alone: masked whole either way, as the late pattern masks it.
            return [(0, len(token), self._mask_token(_UUID_PATTERN, token))]
        if self._masks_whole(token):
            return [(0, len(token), self._typed_mask(token))]
        return self._hex_run_spans(token, []) if self._hex_runs else []

    def _typed_mask(self, token: str) -> str:
        """The entropy rule's mask of ``token``, typed by the first late pattern it holds."""

        hinted = self._late_hint is None or self._late_hint.search(token) is not None
        kind = next(
            (late.type for late in self._late if hinted and _matches(late, token)),
            "high_entropy",
        )
        return self._hashed_mask(kind, token)

    def _hex_run_spans(
        self, token: str, taken: Sequence[tuple[int, int]]
    ) -> list[tuple[int, int, str]]:
        """Each hex run of ``token`` outside ``taken`` and outside a late pattern's match."""

        if len(token) < _SHAPE_MIN_LEN:
            return []
        runs = list(_HEX_RUN.finditer(token))
        if not runs:
            return []
        hinted = self._late_hint is None or self._late_hint.search(token) is not None
        keys = (
            [
                m.span()
                for late in self._late
                if late.may_match(token)
                for m in late.regex.finditer(token)
                if not skipped(m)
            ]
            if hinted
            else []
        )
        # One sweep: the runs and the stretches taken are both in order, so each is read once.
        covered = [
            (start, end) for start, end, _ in _merged((a, b, False) for a, b in (*taken, *keys))
        ]
        out: list[tuple[int, int, str]] = []
        index = 0
        for m in runs:
            while index < len(covered) and covered[index][1] <= m.start():
                index += 1
            if index < len(covered) and covered[index][0] < m.end():
                continue
            out.append((m.start(), m.end(), self._mask_token(_HEX_TOKEN, m[0])))
        return out

    def _redact_high_entropy(self, text: str, cuts: _Cuts | None = None) -> str:
        """Interim global entropy fallback for unknown-shape secrets (OD-15).

        Structured identifiers/paths are skipped (:meth:`_is_structured`); everything else
        is masked once it clears both the length and the bits/char threshold. A run of 32 hex
        digits or more is masked whatever its entropy (A-78).
        """

        def _sub(m: re.Match[str]) -> str:
            token = m.group(0)
            spans = self._entropy_spans(token, cuts)
            if not spans:
                return token
            out: list[str] = []
            cursor = 0
            for start, end, mask in spans:
                out += (token[cursor:start], mask)
                cursor = end
            out.append(token[cursor:])
            return "".join(out)

        return (self._HIGH_ENTROPY_TOKEN if cuts is None else cuts.token).sub(_sub, text)

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
            # evidence store masks every key of what it writes, and the reports the keys of an
            # attempt's free-form fields, through :func:`mask_keys` (DL2).
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
    """Module-level convenience over the process-salted default redactor."""

    return _DEFAULT.redact(obj)


#: A FIXED salt for identifiers that are compared across processes, not for secrets. The run
#: store masks a stored ``target_id`` (a tenant-shaped id can look like a key), and ``--resume``
#: recomputes that mask to check the campaign is resumed against the same target. With the
#: process-random salt above the two digests would never match, and with no digest at all two
#: different tenants would mask to the same string and the check would pass for both.
_IDENTITY = Redactor(salt="ildottore:identity:v1")


#: The identity masks as the redactor before u01 A-78 wrote them (:func:`identity_masks`): the
#: same patterns, no late pass, no hex rule, numbers inside a UUID read as numbers.
_IDENTITY_BEFORE_A78 = Redactor(salt="ildottore:identity:v1", late=False)
_IDENTITY_BEFORE_A78._hex_runs = False


_SHA256_HEX_RE: Final = re.compile(r"[0-9a-f]{64}")


class _Redacts(Protocol):
    def redact(self, obj: object) -> object: ...


def redact_evidence_ref(redactor: _Redacts, ref: Mapping[str, object]) -> dict[str, object]:
    """Mask an evidence reference, keeping only what the tool itself generated.

    The digest is kept when it is a plain sha256, and the uri when it is the store's own
    canonical ``.../<sha256>.json`` for that digest: those point at the evidence and are not
    secrets. Anything else in the reference is masked like any other value, so a reference
    that did carry foreign text (a planted canary in a uri) is still masked (audit 2026-10-03,
    R1 and F12: masked digests cut reports off from their proof and blinded the manifest).
    """

    masked = redactor.redact(dict(ref))
    if not isinstance(masked, dict):  # pragma: no cover - redact preserves shape
        raise TypeError("redactor changed the shape of an evidence reference")
    sha = ref.get("sha256")
    if isinstance(sha, str) and _SHA256_HEX_RE.fullmatch(sha):
        masked["sha256"] = sha
        uri = ref.get("uri")
        if isinstance(uri, str) and uri.endswith(f"{sha}.json"):
            masked["uri"] = uri
    return masked


def redact_identity(value: str) -> str:
    """Mask an identifier with the fixed identity salt, so the mask is comparable later."""

    return _IDENTITY.redact_text(value)


def credential_patterns() -> list[Pattern]:
    """The built-in credential detectors (PEM keys, JWTs, provider key formats), without the PII
    ones (an email, a card, an IP address, a phone number).

    For a caller that asks whether a value is shaped like a key, not whether it is personal data:
    a fleet file's endpoint and a scaffold's family (u12 A-82), where the phone rule read
    `CVE-2021-44228` and the email rule `alice@example.com` as secrets. A UUID is left out: the
    redactor masks one (u01 A-78), but it names a tenant or a record, and no key format is one.
    """

    return [
        pattern
        for pattern in _default_patterns()
        if pattern.hashed and pattern is not _UUID_PATTERN
    ]


def key_format_patterns() -> list[Pattern]:
    """The documented key formats and the JWT (A-78) without the UUID: the one list both the
    redactor's late pass and the ``secret_shape`` evaluator read (u08 A-85), so a format added
    there is detected wherever it is masked. A UUID names a tenant or a record, not a key.
    """

    return [pattern for pattern in _late_patterns() if pattern is not _UUID_PATTERN]


def report_identity(value: str) -> str:
    """How a report names a target: by the rules before u01 A-78, with the fixed identity salt.

    A report masks what the operator wrote, the target id included (a tenant-shaped id can read
    as a key), and masked it with the process-random salt, so a high-entropy id had another mask
    in every run and ``dottore diff`` refused two reports of one target as two targets. A-78
    extended that to every id holding a UUID, a hex run or a key shape (`tenant-<uuid>`), which
    the reports before it showed as written (pre-merge audit of A-78, H1). The id is now masked
    by the rules before A-78 (:data:`_IDENTITY_BEFORE_A78`): the text a report written before
    A-78 holds, where that one held no digest, and the same text in every run where it held one.
    """

    return _IDENTITY_BEFORE_A78.redact_text(value)


def identity_masks(value: str) -> tuple[str, ...]:
    """Every mask a run store may hold for ``value``: :func:`redact_identity`'s, then the one it
    wrote before u01 A-78, when they differ.

    The key formats, the hex run and the UUID changed the identity mask of an id that holds one
    (a UUID was stored with a phone mask in its digit-only groups, or as written, and is
    ``«REDACTED:uuid:...»`` now), so a run halted before them was refused on resume as made
    against another target, and a resume keyed its findings anew beside the old rows. The resume
    checks and the run store accept both, and the store keeps the current one.
    """

    current = _IDENTITY.redact_text(value)
    before = _IDENTITY_BEFORE_A78.redact_text(value)
    return (current,) if before == current else (current, before)


# --- a reply kept in pieces (A-77) -----------------------------------------------------------
# A reply reaches the evidence in pieces as well as whole: OpenAI's logprobs hold its text as
# tokens of 1 to 4 characters, each with its alternatives, and a WebSocket transcript holds it as
# the deltas it was streamed in. Each piece was masked on its own, too short for any rule, so a
# key, a registered credential or the run's canary was rebuilt by joining the `token` fields of
# the evidence or of the JSON report while `response.text` read masked (audit of main de122e26,
# HIGH 1). The pieces are kept, since they are the reply as the target sent it (the figures the
# membership evaluator reads, the transcript a reviewer reads), and are masked as the text they
# make: the pieces of one stream are joined in order, the joined text is redacted once, the first
# piece a mask covers shows it and every piece it covers loses the text under it. Joined, the
# pieces never show more than the redacted text, and show less only where a literal between two
# masks could stand in more than one place: the masks then merge and that literal goes (8 of
# 1,500 realistic replies and 309 of 1,500 hostile ones, second pre-merge audit of the branch;
# always towards masking more). A mask repeated in every piece it covered read, joined,
# `user:«REDACTED:url_password»«REDACTED:url_password»@host`, which the URL rule masks again as
# one, and the store's guard refused a reply it had masked correctly (pre-merge audit of
# c4bd2012, HIGH 1). Two streams are read as such, where the data says what they are: a
# logprob list's tokens (an alternative shows the masks of the token it stands beside; its rank
# is no stream: alternatives side by side are text no one wrote, and joining a rank masked 6.9%
# of all the alternatives of clean replies, 5,794 of 83,950, each beside a token that was kept,
# LOW 5) and a WebSocket transcript (the fields of the frames
# received that are not the protocol's, which the transcript names). Any other list is a list of
# records, each string masked on its own: joining every list read the `type` of a transcript's
# frames as `auth_oksessiondeltaping...`, one high-entropy token, and masked every frame's type.

#: A mask, with the openers of masks a later pass of the CLI rewrote glued before it
#: (`«REDACTED:«REDACTED:url_password»`: the URL rule read `«REDACTED` as a URL's user).
_MASK_AFTER_OPENERS: Final = re.compile("(?:«REDACTED:)*" + _ALREADY_MASKED.pattern)
#: The mask a piece shows when the redactor masked its stream's joined text and where it masked
#: could not be placed: every piece of that stream shows it. Each alternative of a token with more
#: masks than :data:`_ALTERNATIVE_MASKS` shows it too (A-86).
_FRAGMENT_MASK: Final = _MASK_TEMPLATE.format(type="fragment")
#: How many passes a value gets at most, as ``redact_text`` reads a text to a fixed point.
_SPLIT_ROUNDS: Final = 4
#: The most masks an alternative of a masked token shows (u01 A-86). A token past it lies where
#: many masks merged into one stretch (secrets glued together, or read both ways), and each of its
#: alternatives shows ``«REDACTED:fragment»`` alone: every alternative of every token there showed
#: every mask of the stretch, so the output grew as tokens times masks (64 KiB of `ghp_` keys glued
#: by U+0000 in 4-character tokens, one alternative each, wrote 840 MB, pre-merge audit of A-83).
_ALTERNATIVE_MASKS: Final = 4
#: A logprob item's token and its figure (ADR-0005 ``TokenLogprob``, and OpenAI's wire shape).
_TOKEN: Final = "token"  # noqa: S105 - a field name, not a credential
_LOGPROB: Final = "logprob"
_BYTES: Final = "bytes"
#: Where a logprob item keeps its alternatives: a list there is the candidates for one piece, not
#: a stream, though OpenAI writes each as a logprob item (``top_logprobs``).
_ALTERNATIVES: Final = frozenset({"top", "top_logprobs"})
#: A WebSocket transcript (``raw_ids["websocket"]``, OD-34): its frames, each ``{"direction",
#: "frame"}``, and the dotted paths of the frame fields the target file declares as the
#: protocol's (the frame type, the final marker, an error, ids, usage, tool calls).
TRANSCRIPT_FRAMES: Final = "frames"
TRANSCRIPT_PROTOCOL_PATHS: Final = "protocol_paths"
_RECEIVED: Final = "received"
_DIRECTION: Final = "direction"
_FRAME: Final = "frame"
#: The frame type's path when a transcript names no protocol paths (``type_path``'s default).
_DEFAULT_PROTOCOL: Final = ("type",)

#: Where a string sits inside one item of a list: the keys and indices that lead to it.
_LeafPath = tuple[object, ...]
#: One stream: the strings to read joined, each with the item it sits in and where.
_Stream = list[tuple[int, _LeafPath, str]]


class _RedactsText(Protocol):
    def redact_text(self, text: str) -> str: ...


class _RedactsBoth(_Redacts, _RedactsText, Protocol): ...


def _string_leaves(node: object, path: _LeafPath = ()) -> Iterator[tuple[_LeafPath, str]]:
    """Every string value under ``node`` (a key is not one), with where it sits."""

    if isinstance(node, str):
        yield path, node
    elif isinstance(node, Mapping):
        for key, value in node.items():
            yield from _string_leaves(value, (*path, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _string_leaves(value, (*path, index))


def _is_logprob_list(items: Sequence[object], *, minimum: int = 2) -> bool:
    """True for a list of logprob items: each an object with a string token and a figure (at
    least ``minimum`` of them: one is no stream, but its ``bytes`` still spell its token)."""

    return len(items) >= minimum and all(
        isinstance(item, Mapping) and isinstance(item.get(_TOKEN), str) and _LOGPROB in item
        for item in items
    )


def _logprob_streams(items: Sequence[object]) -> list[_Stream]:
    """The tokens of a logprob list, as one stream (its alternatives are not one, LOW 5)."""

    tokens: _Stream = [
        (index, (_TOKEN,), cast("str", cast("Mapping[str, object]", item)[_TOKEN]))
        for index, item in enumerate(items)
    ]
    return [tokens] if len(tokens) > 1 else []


def _protocol_paths(node: Mapping[object, object]) -> list[list[str]] | None:
    """The protocol paths of a transcript, split into segments, or None if ``node`` is not one.

    A transcript is an object whose ``frames`` are all ``{"direction", "frame"}`` records. One
    that names no protocol paths (stored before they were recorded, or built by hand) is read with
    the frame type at ``type``, the default of the target file's ``type_path``: its content is
    joined rather than left in pieces.
    """

    frames, declared = node.get(TRANSCRIPT_FRAMES), node.get(TRANSCRIPT_PROTOCOL_PATHS)
    if not isinstance(frames, list) or not frames:
        return None
    if not all(
        isinstance(entry, Mapping) and _DIRECTION in entry and _FRAME in entry for entry in frames
    ):
        return None
    if isinstance(declared, list) and all(isinstance(path, str) for path in declared):
        return [path.split(".") for path in declared if isinstance(path, str)]
    return [list(_DEFAULT_PROTOCOL)]


def _transcript_streams(
    frames: Sequence[object], protocol: list[list[str]], *, minimum: int = 2
) -> list[_Stream]:
    """The content of the frames received, one stream per field, the protocol's fields aside
    (a field in fewer than ``minimum`` frames is no stream to join), and a logprob item's
    alternatives aside: they are no stream there either (found with the fourth pre-merge audit's
    fix: an event stream of OpenAI chunks with logprobs joined each rank of them across the
    chunks, and masked clean replies)."""

    streams: dict[_LeafPath, _Stream] = {}
    for index, entry in enumerate(frames):
        if not isinstance(entry, Mapping) or entry.get(_DIRECTION) != _RECEIVED:
            continue
        for path, text in _string_leaves(entry.get(_FRAME), (_FRAME,)):
            segments = [str(step) for step in path[1:]]
            if any(segments[: len(declared)] == declared for declared in protocol):
                continue
            if any(step in _ALTERNATIVES for step in path):  # no stream, as in a logprob list
                continue
            streams.setdefault(path, []).append((index, path, text))
    return [stream for stream in streams.values() if len(stream) >= minimum]


def split_texts(obj: object, *, alternatives: bool = False) -> Iterator[str]:
    """Every text a stream of ``obj`` makes joined: a logprob list's, a transcript's (A-77).

    For the evidence store's fail-closed guard, which redacts each and refuses a write when one
    changes (a secret in pieces survived), as it redacts each string on its own.
    """

    if isinstance(obj, Mapping):
        for key, value in obj.items():
            yield from split_texts(value, alternatives=key in _ALTERNATIVES)
        protocol = _protocol_paths(obj)
        if protocol is not None:
            for stream in _transcript_streams(obj[TRANSCRIPT_FRAMES], protocol):
                yield "".join(text for _, _, text in stream)
    elif isinstance(obj, list):
        for item in obj:
            yield from split_texts(item)
        if not alternatives and _is_logprob_list(obj):
            for stream in _logprob_streams(obj):
                yield "".join(text for _, _, text in stream)


def _placed_masks(
    text: str, redacted: str, *, tolerant: bool = False
) -> list[tuple[int, int, str]] | None:
    """Where in ``text`` each mask of ``redacted`` may stand, or None when that cannot be said.

    ``redacted`` is ``text`` with stretches replaced by masks, so it reads ``L0 M1 L1 ... Mn Ln``
    where each ``L`` is text as written and each mask stands for a stretch of one character or
    more. The literals are placed as early as they can be, left to right, and as late as they
    can be, right to left; every placement the text allows lies between the two, so mask ``i``
    stands somewhere from where literal ``i - 1`` ends at the earliest to where literal ``i``
    starts at the latest, and that span holds it in any placement. A character outside every
    span is in a literal in every placement: it is text the redacted copy shows. A literal not
    found means ``redacted`` is not of that form, and None sends the caller to mask everything.

    ``tolerant`` reads a literal between two masks that is not found, in order, as part of the
    masked stretch: the two masks stand as one for what lies between the literals around them, and
    the literal is not shown (u01 A-83). The CLI masks in passes, and a later one can rewrite part
    of a mask an earlier one wrote (`«REDACTED:«REDACTED:url_password»@`), so its output holds text
    the message does not. Shown with the masks, the literal showed text of the message that this
    reading left readable and the other reading masked (differential fuzz of A-83).
    """

    literals: list[str] = []
    masks: list[str] = []
    cursor = 0
    for match in (_MASK_AFTER_OPENERS if tolerant else _ALREADY_MASKED).finditer(redacted):
        literals.append(redacted[cursor : match.start()])
        masks.append(match.group(0))
        cursor = match.end()
    literals.append(redacted[cursor:])
    if tolerant and masks:
        literals, masks = _found_in_order(text, literals, masks)
    count = len(masks)
    if not count or not text.startswith(literals[0]) or not text.endswith(literals[-1]):
        return None
    earliest = [0] * (count + 1)
    cursor = len(literals[0])
    for index in range(1, count):
        found = text.find(literals[index], cursor + 1)
        if found == -1:
            return None
        earliest[index] = found
        cursor = found + len(literals[index])
    tail = len(text) - len(literals[-1])
    if tail < cursor + 1:
        return None
    earliest[count] = tail
    latest = [0] * (count + 1)
    latest[count] = bound = tail
    for index in range(count - 1, 0, -1):
        # The earliest placement fits, so a latest one is found at or after it.
        bound = latest[index] = text.rfind(literals[index], earliest[index], bound - 1)
    return [
        (earliest[index - 1] + len(literals[index - 1]), latest[index], masks[index - 1])
        for index in range(1, count + 1)
    ]


def read_both_ways(redact: Callable[[str], str], text: str) -> str:
    """``redact(text)``, or, for a text holding a stash delimiter, the text with them made visible
    and the masks ``redact`` gives it read either way (:func:`_spans_both_ways`, u01 A-83).

    For a caller that masks in passes of its own (``cli.app._masked``), as
    :meth:`Redactor.redact_text` reads a text; ``redact`` is given a text holding no delimiter.
    """

    if not _holds_stash_delimiter(text):
        return redact(text)
    visible = visible_stash_delimiters(text)
    pieces: list[str] = []
    cursor = 0
    for start, end, shown in _spans_both_ways(redact, text, tolerant=True):
        pieces += (visible[cursor:start], "".join(shown))
        cursor = end
    pieces.append(visible[cursor:])
    return "".join(pieces)


def _found_in_order(
    text: str, literals: list[str], masks: list[str]
) -> tuple[list[str], list[str]]:
    """``literals`` and ``masks`` with each middle literal ``text`` does not hold, in order,
    dropped, and the masks on either side of it shown as one (``_placed_masks``, ``tolerant``)."""

    # An end that is not the text's own is part of the mask beside it, and not shown.
    kept, shown = [literals[0] if text.startswith(literals[0]) else ""], [masks[0]]
    last = literals[-1] if text.endswith(literals[-1]) else ""
    cursor = len(kept[0])
    for index in range(1, len(masks)):
        found = text.find(literals[index], cursor + 1)
        if found == -1:
            shown[-1] += masks[index]
            continue
        kept.append(literals[index])
        shown.append(masks[index])
        cursor = found + len(literals[index])
    kept.append(last)
    return kept, shown


def _mask_spans(redactor: _RedactsText, joined: str) -> list[tuple[int, int, tuple[str, ...]]]:
    """The stretches of ``joined`` the redactor masks, merged, with the masks each shows.

    A text holding a stash delimiter is read both ways, as ``redact_text`` reads it
    (:func:`_spans_both_ways`).
    """

    return _spans_both_ways(redactor.redact_text, joined)


def _spans_both_ways(
    redact: Callable[[str], str], text: str, *, tolerant: bool = False
) -> list[tuple[int, int, tuple[str, ...]]]:
    """The stretches of ``text`` that ``redact`` masks, merged, with the masks each shows.

    ``redact`` is given a text holding no stash delimiter only. A text holding one is read with
    them dropped, each mask placed back through the positions of the characters it keeps, and
    with them made visible (``␀``, ``␁``); what either reading masks is masked (u01 A-83). A
    reading whose masks cannot be placed masks the whole text (``fragment``).
    """

    joined = _Joined(text) if _holds_stash_delimiter(text) else None
    forms: list[tuple[str, _Joined | None]] = (
        [(text, None)]
        if joined is None
        else [(joined.text, joined), (visible_stash_delimiters(text), None)]
    )
    spans: list[tuple[int, int, str]] = []
    for form, positions in forms:
        redacted = redact(form)
        if redacted == form:
            continue
        placed = _placed_masks(form, redacted, tolerant=tolerant)
        for start, end, mask in placed or [(0, len(form), _FRAGMENT_MASK)]:
            if positions is not None:
                start, end = positions.at(start), positions.at(end - 1) + 1
            spans.append((start, end, mask))
    spans.sort(key=lambda span: (span[0], span[1]))
    # Each merged stretch keeps its masks in an ordered set (a dict's keys): a tuple rebuilt and
    # searched for every mask merged into it took time in the square of their number, 177 s on
    # 4 MiB of 32-hex runs glued by U+0000 where main took 0.73 s (pre-merge audit of A-83, HIGH 1).
    merged: list[tuple[int, list[int], dict[str, None]]] = []
    for start, end, mask in spans:
        if merged and start < merged[-1][1][0]:
            last = merged[-1][1]
            last[0] = max(last[0], end)
            merged[-1][2].setdefault(mask, None)
        else:
            merged.append((start, [end], {mask: None}))
    return [(first, last[0], tuple(shown)) for first, last, shown in merged]


def _masked_pieces(
    redactor: _RedactsText, pieces: Sequence[str]
) -> list[tuple[str, tuple[str, ...]]]:
    """``pieces`` with the stretches the redactor masks in their joined text masked, each with
    the masks of the stretches it lies in.

    The first piece a masked stretch covers shows its masks in place of the part it covers; every
    later piece it covers loses the part it covers (a piece it covers whole is empty). Joined
    again, the pieces show each mask once and never more than the redacted text; they show less
    where a literal between two masks could stand in more than one place, since the stretches
    then merge and that literal goes (``_placed_masks``). Shown in every piece, a mask the URL
    rule had set read joined as a run of masks behind `user:`, which the rule masked again as
    one, and the store's guard refused the reply (pre-merge audit of c4bd2012, HIGH 1).
    """

    joined = "".join(pieces)
    spans = _mask_spans(redactor, joined)
    if not spans:
        return [(piece, ()) for piece in pieces]
    out: list[tuple[str, tuple[str, ...]]] = []
    start = first = 0
    for piece in pieces:
        end = start + len(piece)
        while first < len(spans) and spans[first][1] <= start:
            first += 1
        parts: list[str] = []
        # The masks of the stretches the piece lies in. A piece inside one stretch shares that
        # stretch's own tuple, which holds no mask twice; only a piece across several builds one,
        # in order and without repeats. A copy for every piece took memory in pieces times masks:
        # 4.19 GB on 256 KiB of a logprob stream of `ghp_` keys glued by U+0000, and searched as a
        # list, time in its square too (pre-merge audits of A-83, HIGH 1 and round 2, MEDIUM 1).
        touched: list[tuple[str, ...]] = []
        cursor, index = start, first
        while start < end and index < len(spans) and spans[index][0] < end:
            span_start, span_end, shown = spans[index]
            if span_start > cursor:
                parts.append(joined[cursor:span_start])
            if span_start >= start:  # this piece is the first the stretch covers
                parts.append("".join(shown))
            touched.append(shown)
            cursor = min(max(cursor, span_end), end)
            if span_end > end:  # it goes on into the next piece
                break
            index += 1
        if not touched:
            out.append((piece, ()))
        else:
            if cursor < end:
                parts.append(joined[cursor:end])
            masks = (
                touched[0]
                if len(touched) == 1
                else tuple(dict.fromkeys(mask for shown in touched for mask in shown))
            )
            out.append(("".join(parts), masks))
        start = end
    return out


def _thawed(node: object) -> object:
    """A copy of ``node``'s dicts and lists (its strings and scalars shared), to edit in place."""

    if isinstance(node, Mapping):
        return {key: _thawed(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_thawed(value) for value in node]
    return node


def _with_leaf(node: object, path: _LeafPath, value: str) -> object:
    """``node`` (a thawed copy) with the string at ``path`` replaced by ``value``."""

    if not path:
        return value
    holder: Any = node
    for step in path[:-1]:
        holder = holder[step]
    holder[path[-1]] = value
    return node


def _mask_alternatives(item: object, token: str, shown: str, masks: tuple[str, ...]) -> None:
    """Mask the alternatives of a logprob item whose token, ``token``, a mask covers (in place).

    A token a mask covers is a piece of a secret, and its alternatives are what the model weighed
    for that same piece: other pieces of the secret, often, which no join of them reads whole. An
    alternative written as the token was shows what the token shows now (``shown``); any other
    shows the token's masks. Called once an item's every edit is made, so nothing written after
    undoes it (pre-merge audit of c4bd2012, MEDIUM 2). A token with more masks than
    :data:`_ALTERNATIVE_MASKS` has every alternative show one ``«REDACTED:fragment»``, whatever it
    was written as, so what an alternative shows is bounded and shows no text the token's masks
    hide (u01 A-86).
    """

    if not isinstance(item, dict):  # pragma: no cover - a thawed logprob item is a dict
        return
    if len(masks) > _ALTERNATIVE_MASKS:
        shown = stands_for = _FRAGMENT_MASK
    else:
        stands_for = "".join(masks)
    pairs = item.get("top")
    if isinstance(pairs, list):
        for pair in pairs:
            if isinstance(pair, list) and pair and isinstance(pair[0], str):
                pair[0] = shown if pair[0] == token else stands_for
    alternatives = item.get("top_logprobs")
    if isinstance(alternatives, list):
        for alternative in alternatives:
            if isinstance(alternative, dict) and isinstance(alternative.get(_TOKEN), str):
                written = alternative[_TOKEN]
                alternative[_TOKEN] = shown if written == token else stands_for
                if alternative.get(_BYTES) is not None:  # they spell what was written (LOW 4)
                    alternative[_BYTES] = None


def _spelled(redactor: _RedactsText, entry: Mapping[object, object]) -> bool:
    """Whether a logprob entry's ``bytes`` spell what is masked: its token is or will be."""

    token = entry.get(_TOKEN)
    if not isinstance(token, str) or entry.get(_BYTES) is None:
        return False
    return _ALREADY_MASKED.search(token) is not None or redactor.redact_text(token) != token


def _drop_spelled_bytes(redactor: _RedactsText, items: list[object]) -> list[object] | None:
    """``items`` with the ``bytes`` of every masked token and alternative dropped, or None.

    OpenAI writes each token's UTF-8 as a list of numbers beside it, which an unreadable reply's
    excerpt quotes: the numbers spell a token whatever its text shows, so wherever a token, or an
    alternative's, is masked, by its stream or on its own, they go (pre-merge audit of c4bd2012,
    LOW 4). A list with no ``bytes`` (the stored ``TokenLogprob``) costs one look per item.
    """

    out: list[object] | None = None
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):  # pragma: no cover - a logprob list holds objects
            continue
        alternatives = item.get("top_logprobs")
        listed = alternatives if isinstance(alternatives, list) else []
        spelled = [isinstance(alt, Mapping) and _spelled(redactor, alt) for alt in listed]
        if not _spelled(redactor, item) and not any(spelled):
            continue
        thawed = cast("dict[object, object]", _thawed(item))
        if _spelled(redactor, item):
            thawed[_BYTES] = None
        for alternative, drop in zip(
            cast("list[object]", thawed.get("top_logprobs") or []), spelled, strict=False
        ):
            if drop and isinstance(alternative, dict):
                alternative[_BYTES] = None
        out = list(items) if out is None else out
        out[index] = thawed
    return out


def _mask_streams_of(
    redactor: _RedactsText, items: list[object], streams: list[_Stream], *, logprobs: bool
) -> list[object] | None:
    """``items`` with each stream masked as one text (a copy), or None when nothing is masked."""

    edits: dict[int, list[tuple[_LeafPath, str, str, tuple[str, ...]]]] = {}
    for stream in streams:
        masked = _masked_pieces(redactor, [text for _, _, text in stream])
        for (index, path, text), (piece, masks) in zip(stream, masked, strict=True):
            if masks:
                edits.setdefault(index, []).append((path, text, piece, masks))
    if not edits:
        return None
    out = list(items)
    for index, leaves in edits.items():
        item = _thawed(out[index])
        for path, _text, piece, _masks in leaves:
            item = _with_leaf(item, path, piece)
        for path, text, piece, masks in leaves:
            holder = _logprob_holder(item, path, logprobs=logprobs)
            if holder is not None:
                _mask_alternatives(holder, text, piece, masks)
                if holder.get(_BYTES) is not None:
                    holder[_BYTES] = None
        out[index] = item
    return out


def _logprob_holder(
    item: object, path: _LeafPath, *, logprobs: bool
) -> dict[object, object] | None:
    """The logprob item whose token sits at ``path`` in ``item``, or None.

    In a logprob list the item is ``item`` itself; in a transcript, a frame may hold one (an
    OpenAI chunk streamed with logprobs, one token in each), whose ``bytes`` spell the token and
    whose alternatives are weighed for it, so they are masked with it as a list's are (found
    with the fourth pre-merge audit's fix: the chunks' ``bytes`` spelled a key their tokens no
    longer showed, in the excerpt of an event stream).
    """

    if not path or path[-1] != _TOKEN or (logprobs and path != (_TOKEN,)):
        return None
    holder = _leaf(item, path[:-1])
    if isinstance(holder, dict) and _LOGPROB in holder:
        return holder
    return None


def _mask_streams(
    redactor: _RedactsText, node: object, *, alternatives: bool = False
) -> tuple[object, bool]:
    """One pass over ``node``: each stream in it masked as one text, inner ones first.

    Returns ``node`` itself when nothing is masked, and whether anything was.
    """

    if isinstance(node, Mapping):
        changed = False
        out: dict[object, object] = {}
        for key, value in node.items():
            out[key], hit = _mask_streams(redactor, value, alternatives=key in _ALTERNATIVES)
            changed = changed or hit
        result: Mapping[object, object] = out if changed else node
        protocol = _protocol_paths(result)
        if protocol is not None:
            frames = cast("list[object]", result[TRANSCRIPT_FRAMES])
            masked = _mask_streams_of(
                redactor, frames, _transcript_streams(frames, protocol), logprobs=False
            )
            if masked is not None:
                result, changed = {**result, TRANSCRIPT_FRAMES: masked}, True
        return result, changed
    if not isinstance(node, list):
        return node, False
    items: list[object] = []
    changed = False
    for value in node:
        item, hit = _mask_streams(redactor, value)
        items.append(item)
        changed = changed or hit
    if not alternatives and _is_logprob_list(items, minimum=1):
        if _is_logprob_list(items):
            masked = _mask_streams_of(redactor, items, _logprob_streams(items), logprobs=True)
            if masked is not None:
                items, changed = masked, True
        unspelled = _drop_spelled_bytes(redactor, items)
        if unspelled is not None:
            items, changed = unspelled, True
    return (items if changed else node), changed


def _blank_leaves(items: list[object], streams: list[_Stream], *, logprobs: bool) -> list[object]:
    """``items`` (a copy) with every piece of ``streams`` empty, and a token's alternatives and
    ``bytes`` too, in a logprob list or in a transcript's frame (:func:`_logprob_holder`)."""

    out = list(items)
    for index in sorted({index for stream in streams for index, _, _ in stream}):
        item = _thawed(out[index])
        paths = [path for stream in streams for at, path, _ in stream if at == index]
        for path in paths:
            item = _with_leaf(item, path, "")
        for path in paths:
            holder = _logprob_holder(item, path, logprobs=logprobs)
            if holder is not None:
                _blank_beside(holder)
        out[index] = item
    return out


def _blank_beside(holder: dict[object, object]) -> None:
    """Empty what spells a logprob item's token beside it, its alternatives and its ``bytes``
    (in place), once the token is emptied."""

    _mask_alternatives(holder, "", "", ())
    if holder.get(_BYTES) is not None:
        holder[_BYTES] = None


def _withheld(node: object, *, alternatives: bool = False) -> tuple[object, bool]:
    """``node`` with every piece of every stream in it empty, and whether there was one."""

    if isinstance(node, Mapping):
        changed = False
        out: dict[object, object] = {}
        for key, value in node.items():
            out[key], hit = _withheld(value, alternatives=key in _ALTERNATIVES)
            changed = changed or hit
        result: Mapping[object, object] = out if changed else node
        protocol = _protocol_paths(result)
        if protocol is not None:
            frames = cast("list[object]", result[TRANSCRIPT_FRAMES])
            streams = _transcript_streams(frames, protocol)
            if streams:
                blank = _blank_leaves(frames, streams, logprobs=False)
                result, changed = {**result, TRANSCRIPT_FRAMES: blank}, True
        return result, changed
    if not isinstance(node, list):
        return node, False
    items: list[object] = []
    changed = False
    for value in node:
        item, hit = _withheld(value)
        items.append(item)
        changed = changed or hit
    if not alternatives and _is_logprob_list(items):
        items, changed = _blank_leaves(items, _logprob_streams(items), logprobs=True), True
    return (items if changed else node), changed


def withhold_split(obj: object) -> object:
    """``obj`` with every piece of its streams withheld: each token, alternative and content
    field of a transcript empty, the figures, the shape and the protocol's fields kept (A-77).

    For an attempt the evidence store refused to write because a joined text of its streams was
    still not a fixed point of the redactor: the pieces are what it could not prove masked, so
    they are left out and the rest, the reply's text included, is stored (pre-merge audit of
    c4bd2012, HIGH 1: one such refusal ended the campaign). ``obj`` itself comes back when it
    holds no stream.
    """

    return _withheld(obj)[0]


def _leaf(node: object, path: _LeafPath) -> object:
    """What sits at ``path`` in ``node`` (the same structure the path was read from)."""

    holder: Any = node
    for step in path:
        holder = holder[step]
    return holder


def mask_split(redactor: _RedactsText, obj: object) -> object:
    """``obj`` with every stream in it masked as the text its pieces make (A-77).

    ``obj`` is JSON-shaped (dicts, lists, strings and scalars) and is not changed: what is
    masked is copied, and ``obj`` itself comes back when nothing is. A stream is a logprob
    list's tokens or a WebSocket transcript's received content field by field (see the block
    comment above; alternatives are no stream); its pieces are joined in order and redacted once,
    the first piece a mask covers shows that mask and the others lose the text under it, and a
    token a mask covers has its alternatives masked and its ``bytes`` dropped. Inner streams are
    read first, and the whole is read again until
    nothing more is masked, as ``redact_text`` reads a text to a fixed point. Only the joined
    texts are masked here: each string on its own is left to :meth:`Redactor.redact`
    (:func:`redact_split` does both).
    """

    current = obj
    for _ in range(_SPLIT_ROUNDS):
        current, changed = _mask_streams(redactor, current)
        if not changed:
            break
    return current


def redact_split(redactor: _RedactsBoth, obj: object) -> object:
    """``redactor.redact(obj)``, with every stream masked as the text it makes too (A-77).

    The joined texts are read first, as the target wrote them (:func:`mask_split`), then every
    string on its own, and the two again while either masks something more, so the result is
    a fixed point of both: the evidence store's guard redacts each string and each joined text
    of what it stores (:func:`split_texts`) and refuses the write when one changes.
    """

    masked, changed = _mask_streams(redactor, obj)
    current = redactor.redact(masked)
    for _ in range(_SPLIT_ROUNDS - 1):
        if not changed:
            break
        masked, changed = _mask_streams(redactor, current)
        if changed:
            current = redactor.redact(masked)
    return current


class KeysNotDistinct(ValueError):
    """Two keys of one mapping still read alike once masked, whatever number the second got."""


def mask_keys(redactor: _RedactsText, obj: object) -> object:
    """``obj`` with the keys of its mappings redacted, values as they are (DL2, MEDIUM 2).

    :meth:`Redactor.redact` masks values only, so a secret written as a key (a model-controlled
    tool-call argument name, a usage field, a WebSocket frame's) is masked here. Two keys can
    mask to one (`a@x.io` and `b@y.io` both read `«REDACTED:email»`): the second used to replace
    the first, and one value was gone (pre-merge audit of the hostile-text block). A later one
    is numbered instead, and the numbered name is redacted itself: a suffix changes what the
    rules see (` (2)` after a date made a phone, ` #10000` after a label word a labelled secret,
    and `, #2` after `password: Secret` let the label rule take a value it refuses at the end),
    so a name that was not a fixed point made the evidence guard refuse the reply. Each base
    counts on from its last number, so many colliding keys stay linear. More tries than names
    taken means the redaction swallows the number (from 10^8 it reads as a phone):
    :class:`KeysNotDistinct` rather than a loop (no reply holds that many).
    """

    if isinstance(obj, Mapping):
        masked: dict[str, object] = {}
        last: dict[str, int] = {}
        for key, value in obj.items():
            name = base = redactor.redact_text(str(key))
            for _ in range(len(masked) + 1):
                if name not in masked:
                    break
                last[base] = last.get(base, 1) + 1
                name = redactor.redact_text(f"{base}, #{last[base]}")
            else:
                raise KeysNotDistinct("keys could not be told apart once masked")
            masked[name] = mask_keys(redactor, value)
        return masked
    if isinstance(obj, list):
        return [mask_keys(redactor, item) for item in obj]
    return obj
