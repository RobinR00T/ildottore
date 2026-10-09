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
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

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


def _without_stash_delimiters(text: str) -> str:
    return text.replace(_STASH_OPEN, "").replace(_STASH_CLOSE, "")


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
#: 2026-10-07: written out like the controls).
_FORMAT_RANGES: Final = (
    *((0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD)),
    *((0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E)),
    *((0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F)),
    *((0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD)),
    *((0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0001, 0xE0001)),
    (0xE0020, 0xE007F),
)
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
#: A URL mask's stash token, its `@` and what follows of a labelled value it took the head of.
_URL_MASK_TAIL: Final = re.compile(r"\x00(\d++)\x01@((?:[^\s\"'`,;):\x00\x01]++|:(?!//))++)")
#: The URL rule over the text as written (``Redactor._url_passwords_as_written``): every
#: registered credential written out, every other mask one :data:`_NEUTRAL` character.
_URL_AS_WRITTEN: Final = re.compile(r"://[^/\s:@]*+:([^/\s@]++)@")
_NEUTRAL: Final = "\x02"
#: A stash token, or a mask written in the text this pass (a pattern's own, kept as one piece).
_TOKEN_OR_MASK: Final = re.compile(r"\x00(\d++)\x01|«REDACTED:([A-Za-z0-9_]+)(?::[0-9a-f]{8})?»")
#: What a registered credential must hold for the URL rule to read a URL differently as written.
_URL_PARTS: Final = frozenset(":/@")


def _labelled_value_across(url: re.Match[str]) -> str | None:
    """The labelled value whose label the password of ``url`` takes and that runs on past its
    ``@``, or None.

    ``url`` is a match of :data:`_URL_USERINFO` whose password holds a registered credential
    holding an `@`. As written, the URL ends at that `@`; the URL rule reads on to a later one,
    and when that `@` is a labelled value's (`redis://ops:Adm1n@2026-db:6379,password=Secr3t@
    Value99xyz` with `Adm1n@2026` registered) the URL mask took the label and the value's head,
    and the tail was readable, where the redactor before A-31, whose URL rule refused a mask in
    the password, masked the value whole (#96). The label and its value come after the last mask
    in the password, since neither holds one, so only that stretch is searched, and the value is
    read up to 6 characters past the `@` (its pattern takes 6 or more), which keeps the search
    linear; the value's end is searched for only when one is found.
    """

    text, at = url.string, url.end(2)
    start = url.start(2) + url.group(2).rindex(_STASH_CLOSE) + 1
    # No match starts past the `@`: one takes 12 characters or more (a label, a separator and 6).
    for found in _LABELED_SECRET.finditer(text, start, min(len(text), at + 6)):
        if found.start(1) <= at < found.end(1):
            end = _LABELLED_VALUE_END.search(text, at)
            return text[found.start(1) : len(text) if end is None else end.start()]
    return None


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


def mask_url_passwords(text: str) -> str:
    """Mask only the password of every ``scheme://user:password@host`` in ``text``."""

    return _URL_USERINFO.sub(
        lambda m: m.group(1) + _MASK_TEMPLATE.format(type="url_password") + m.group(3), text
    )


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
        Pattern("card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
        Pattern("national_id", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
        Pattern(
            "ipv4",
            re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        ),
        Pattern(
            "phone",
            re.compile(
                r"(?<![\w.])(?:\+?\d[\d\s().-]{7,}\d(?![\w.])|(?P<skip>\+?\d[\d\s().-]{63,}))"
            ),
        ),
    ]


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
    ``entropy_min_len`` govern the interim global high-entropy fallback (OD-15).
    """

    _HIGH_ENTROPY_TOKEN: Final = re.compile(r"[A-Za-z0-9+/_=-]{16,}")

    def __init__(
        self,
        *,
        salt: str | None = None,
        patterns: Sequence[Pattern] | None = None,
        entropy_threshold: float = 3.7,
        entropy_min_len: int = 16,
    ) -> None:
        self._salt = (_PROCESS_SALT if salt is None else salt).encode("utf-8")
        self._patterns: list[Pattern] = (
            list(patterns) if patterns is not None else _default_patterns()
        )
        # The mask types kept as written (`_redact_once`), kept in step with `register`.
        self._mask_types = _OWN_MASK_TYPES | {pattern.type for pattern in self._patterns}
        self._entropy_threshold = entropy_threshold
        self._entropy_min_len = entropy_min_len

    def register(self, pattern: Pattern) -> None:
        """Add a detector. Registered patterns run **before** the built-ins."""

        self._patterns.insert(0, pattern)
        self._mask_types = self._mask_types | {pattern.type}

    def without_entropy(self) -> Redactor:
        """This redactor minus the entropy fallback: same salt, patterns and known credentials.

        For values that are identifiers by construction and that the entropy rule mangles, such
        as a provider's model name (`meta-llama/Meta-Llama-3-8B-Instruct` has mixed case, so it
        is not exempt as a path).
        """

        twin = Redactor(
            patterns=self._patterns,
            entropy_threshold=math.inf,
            entropy_min_len=self._entropy_min_len,
        )
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
            return _MASK_TEMPLATE_HASHED.format(type=pattern.type, digest=self._digest(value))
        return _MASK_TEMPLATE.format(type=pattern.type)

    def redact_text(self, text: str) -> str:
        """Mask every secret/PII occurrence in ``text`` (idempotent).

        Runs to a **fixed point** (bounded): one pass can expose a value a previous mask was
        sitting next to, and the evidence store refuses to persist anything for which
        ``redact(redact(x)) != redact(x)``, so a single reply that needed two passes used to
        abort the campaign.
        """

        # The stash delimiters are dropped first, so an attacker cannot forge a token, and a
        # secret split by them is whole again: `AKIA\x00IOSF...` and a key read as UTF-16 with
        # Latin-1 (`s\x00k\x00-\x00...`) are masked. When nothing is masked, the input is
        # redacted again with them made visible instead, so two names that differ only by one
        # (`cmd`, `cmd\x01`) stay two keys in the stored evidence, and what joining the pieces
        # hid is masked: `bob@corp.io\x00_` is no email once joined (pre-merge audit).
        stripped = _without_stash_delimiters(text)
        joined = self._to_fixed_point(stripped)
        if joined != stripped or stripped == text:  # masked, or no delimiter to show
            return joined
        return self._to_fixed_point(visible_stash_delimiters(text))

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

        def _as_written(stretch: str) -> str:
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

        def _keep_mask(m: re.Match[str]) -> str:
            nonlocal known
            kind, digest = m.group(1), m.group(2)
            if kind not in self._mask_types:
                return m.group(0)
            if digest is not None:
                known = set(_known_secrets()) if known is None else known
                if digest in known:
                    return m.group(0)
            return _keep(m.group(0))

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
            mask = _keep(_MASK_TEMPLATE.format(type="url_password"), _as_written(password))
            # Read on past an `@` a registered credential holds: as written, the URL ended there.
            if _STASH_OPEN in password and any(
                "@" in written[int(token.group(1))] for token in _STASH_TOKEN.finditer(password)
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
                working = self._redact_labelled_number(pattern, LABELLED_CARD, working)
                working = self._redact_cards(pattern, working)
            elif pattern.type == "pem_private_key":
                working = self._redact_pem(pattern, working, _as_written)
            elif pattern.type == "phone":
                working = self._redact_labelled_number(pattern, LABELLED_PHONE, working)
                working = self._redact_phones(pattern, working)
            else:
                working = pattern.regex.sub(self._make_sub(pattern, _as_written), working)

        working = self._redact_labeled(working)
        working = self._redact_high_entropy(working)
        if heads:
            working = self._redact_labelled_tails(working, heads)
        held = set("".join(written[index] for index in credentials))
        if held & _URL_PARTS and all(part in held or part in working for part in _URL_PARTS):
            working = self._url_passwords_as_written(
                working, _keep, _as_written, written, credentials
            )

        # One pass: a `str.replace` per kept mask was quadratic with thousands of them.
        return _STASH_TOKEN.sub(lambda m: preserved[int(m.group(1))], working)

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

    def _redact_pem(self, pattern: Pattern, text: str, as_written: Callable[[str], str]) -> str:
        """Mask PEM private keys, skipping the scan entirely when no END marker exists.

        Without an END marker the pattern cannot match, so running the DOTALL regex over a
        large ``BEGIN``-only blob is pure wasted (quadratic) backtracking, the precheck
        turns that ReDoS surface into an O(1) substring test (contract: no self-DoS).
        """

        if "-----END" not in text or "PRIVATE KEY-----" not in text:
            return text
        return pattern.regex.sub(self._make_sub(pattern, as_written), text)

    def _redact_labeled(self, text: str) -> str:
        """Mask a value explicitly labelled as a secret (the value only, not the label)."""

        def _sub(m: re.Match[str]) -> str:
            value = m.group(1)
            if _PLAIN_WORD.match(value):  # a plain lowercase word is not a secret
                return m.group(0)
            masked = _MASK_TEMPLATE_HASHED.format(type="labeled_secret", digest=self._digest(value))
            # Replace the VALUE's span only. ``str.replace`` over the whole match also
            # rewrote the label whenever the label text equalled the value.
            start, end = m.start(1) - m.start(0), m.end(1) - m.start(0)
            whole = m.group(0)
            return whole[:start] + masked + whole[end:]

        return _LABELED_SECRET.sub(_sub, text)

    def _redact_labelled_tails(self, text: str, heads: Mapping[int, str]) -> str:
        """Mask the rest of a labelled value whose head a URL mask took (``heads``, #96).

        ``heads`` maps the stash token of each such URL mask to the value as written, and what
        follows the mask's `@` up to where the value ends is masked as that value is, with its
        digest: ``redis://ops:«REDACTED:url_password»@«REDACTED:labeled_secret:<digest>»``, the
        digest the redactor before A-31 gave the value. It runs after every other rule of the
        pass and stops before a `://`, so it takes nothing another rule reads: run before the
        labelled rule it took a label written after the value (`...@BT8Ibd/&TOKEN: <secret>`)
        and that secret was readable, and running on through a `://` it took the next URL's
        scheme, which the URL rule reads in the next pass (pre-commit differential fuzz). What
        the patterns masked in the tail (a phone number, a private key) is taken into this mask.
        """

        def _sub(m: re.Match[str]) -> str:
            value = heads.get(int(m.group(1)))
            if value is None:
                return m.group(0)
            digest = self._digest(value)
            return m.group(0)[: m.start(2) - m.start(0)] + _MASK_TEMPLATE_HASHED.format(
                type="labeled_secret", digest=digest
            )

        return _URL_MASK_TAIL.sub(_sub, text)

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
        every other mask one neutral character, and masks what of the password is still
        readable. A URL the URL rule read, at a `://` that is in the text as it reads, is left
        as that rule masked it. It runs last in the pass, after every rule, so it only adds to
        what they masked: a mask laid before them could take a label, or the start of a match,
        from another rule (the pass PR #56 backed out joined the password to the credential
        before the other rules ran, and swallowed a labelled secret after the URL). A
        credential cut by the password's edges stays its own mask, and what of the password
        lies between masks becomes one ``url_password`` mask. Linear: one pass to read the
        text, one search, and the URL rule tried once at each `://` in the text as it reads.
        """

        def _shown(m: re.Match[str]) -> str | None:
            index, kind = m.group(1), m.group(2)
            if index is None:  # a mask a pattern wrote, or text in that shape (`_keep_mask`)
                return _NEUTRAL if kind in self._mask_types else None
            return written[int(index)] if int(index) in credentials else _NEUTRAL

        read = _AsWritten(text, _shown)
        out: list[str] = []
        done = 0
        for url in _URL_AS_WRITTEN.finditer(read.view):
            at = read.in_text(url.start(), url.start() + 3)
            if at is not None and _URL_USERINFO.match(text, at):  # the URL rule read this one
                continue
            stretch = read.readable(*url.span(1))
            if stretch is None:
                continue
            first, after = stretch
            mask = keep(_MASK_TEMPLATE.format(type="url_password"), as_written(text[first:after]))
            out += (text[done:first], mask)
            done = after
        if not out:
            return text
        out.append(text[done:])
        return "".join(out)

    def _redact_labelled_number(
        self, pattern: Pattern, labelled: re.Pattern[str], text: str
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
            return whole[:start] + self._mask_token(pattern, number) + whole[end:]

        return labelled.sub(_sub, text)

    def _redact_cards(self, pattern: Pattern, text: str) -> str:
        """Card matcher with a Luhn guard to cut valid-shape false positives."""

        def _sub(m: re.Match[str]) -> str:
            digits = re.sub(r"\D", "", m.group(0))
            # A date-time stamp (`2026-07-09-13-20-01`, 14 digits) passes Luhn for 6 seconds in
            # 60; the date shape exempts it here as it does from the phone rule.
            # The match can take a trailing - or space; a version prefix only behind an id.
            if is_date_stamp(m.group(0), after_identifier=glued_to_identifier(text, m.start())):
                return m.group(0)
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                return self._mask_token(pattern, m.group(0))
            return m.group(0)

        return pattern.regex.sub(_sub, text)

    def _redact_phones(self, pattern: Pattern, text: str) -> str:
        """Phone matcher with a date-shape guard to cut dated-identifier false positives.

        A match that is entirely a date / dated version suffix / run id (:func:`is_date_stamp`)
        is left as written; everything else is masked exactly as before.
        """

        def _sub(m: re.Match[str]) -> str:
            if skipped(m):
                return m.group(0)
            if is_date_stamp(m.group(0), after_identifier=glued_to_identifier(text, m.start())):
                return m.group(0)
            return self._mask_token(pattern, m.group(0))

        return pattern.regex.sub(_sub, text)

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

    def _redact_high_entropy(self, text: str) -> str:
        """Interim global entropy fallback for unknown-shape secrets (OD-15).

        Structured identifiers/paths are skipped (:meth:`_is_structured`); everything else
        is masked once it clears both the length and the bits/char threshold.
        """

        def _sub(m: re.Match[str]) -> str:
            token = m.group(0)
            if self._is_structured(token):
                return token
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
    """Module-level convenience over the process-salted default redactor."""

    return _DEFAULT.redact(obj)


#: A FIXED salt for identifiers that are compared across processes, not for secrets. The run
#: store masks a stored ``target_id`` (a tenant-shaped id can look like a key), and ``--resume``
#: recomputes that mask to check the campaign is resumed against the same target. With the
#: process-random salt above the two digests would never match, and with no digest at all two
#: different tenants would mask to the same string and the check would pass for both.
_IDENTITY = Redactor(salt="ildottore:identity:v1")


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
