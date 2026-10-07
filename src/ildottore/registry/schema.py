"""Safe YAML load + JSON-Schema validation (contract §5.1, §4 KEEP).

The load path is strictly **parse → schema-validate → model-construct**. Parsing uses PyYAML's
safe loader only: ``!!python/...`` tags and arbitrary object construction are rejected, and no
``eval``/``import``/socket is ever touched here. A spec pack can come from a third party, so a
file is read only when it is a regular file inside its pack and at most 1 MiB, a document is
refused when it expands, counting every alias where it is used, past a fixed budget (100,000
nodes, a long text counting one node per 64 characters), and a YAML error never quotes a line of
the file (audit SEC-09 of 2026-10-03: seven 50-byte alias lines made a 4 KB spec print 52 MB of
schema errors). The budget and its measure are ``safe_yaml``'s, shared since 2026-10-07 with
the loaders of the operator's own files, which had none. A JSON-schema message can still quote
the offending value, cut at 300 characters.

``schemas/attack-spec.schema.json`` is the hand-authored oracle for attack specs; the
``suite`` and ``pack`` schemas are Pydantic-first (ADR-0006 / OD-14) and generated from the
u00 models, so those are validated by constructing the model, not against a JSON file.
"""

from __future__ import annotations

import datetime
import json
import math
import os
import stat
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from ildottore.safe_yaml import SafeValueLoader, check_expanded
from ildottore.shared.config_errors import yaml_problem
from ildottore.shared.digits import described, path_text, too_long_paths

# Repo layout: <root>/schemas/attack-spec.schema.json ; this file lives at
# <root>/src/ildottore/registry/schema.py → three parents up to the package src root,
# then two more to the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_ATTACK_SPEC_SCHEMA = _REPO_ROOT / "schemas" / "attack-spec.schema.json"


#: Larger than any spec needs (the biggest shipped spec is under 5 KB; media assets are files).
MAX_YAML_BYTES = 1024 * 1024
#: A schema message quotes the offending value; past this length it is cut.
_MAX_MESSAGE_CHARS = 300
#: Schema errors reported per spec; the rest are counted, not listed.
_MAX_SCHEMA_ERRORS = 20


class SafeLoadError(Exception):
    """Raised when a document cannot be safely parsed (bad YAML / unsafe tag / too large)."""


def safe_load_yaml(text: str) -> Any:
    """Parse a YAML document with the safe loader only.

    The safe loader refuses ``!!python/object`` and other code-constructing tags, raising
    ``yaml.YAMLError``; it is re-raised as :class:`SafeLoadError` so callers get one exception
    type. No code is executed and no import is triggered. The document is composed first and
    its size and depth measured with every alias expanded (``safe_yaml.check_expanded``),
    before anything is built from it: aliases are shared references, so parsing stays cheap
    and the amplification only appears when the value is walked (by the schema validator and
    its messages).
    """

    if len(text) > MAX_YAML_BYTES:
        raise SafeLoadError(
            f"document is {len(text)} characters, over the {MAX_YAML_BYTES}-character cap"
        )
    try:
        # Inside the try: the reader rejects a control character as it is built, and that
        # ReaderError used to escape as a traceback (pre-commit audit of this block).
        loader = SafeValueLoader(text)
    except yaml.YAMLError as exc:
        raise SafeLoadError(yaml_problem(exc)) from exc
    try:
        node = loader.get_single_node()
        if node is None:
            return None
        check_expanded(node)
        return loader.construct_document(node)  # type: ignore[no-untyped-call,unused-ignore]
    except yaml.YAMLError as exc:  # includes ConstructorError for unsafe tags
        # Reason and position only: PyYAML's own text quotes a snippet of the line, which for
        # a file that is not what it claims to be can be someone's credentials.
        raise SafeLoadError(yaml_problem(exc)) from exc
    except RecursionError as exc:
        raise SafeLoadError("document is nested too deeply") from exc
    finally:
        loader.dispose()  # type: ignore[no-untyped-call,unused-ignore]


def _check_readable(info: os.stat_result) -> None:
    """Refuse anything but a regular file of at most :data:`MAX_YAML_BYTES`."""

    if not stat.S_ISREG(info.st_mode):
        raise SafeLoadError("not a regular file")
    if info.st_size > MAX_YAML_BYTES:
        raise SafeLoadError(f"file is {info.st_size} bytes, over the {MAX_YAML_BYTES}-byte cap")


def load_yaml_file(path: Path, *, root: Path | None = None) -> Any:
    """Read + safe-parse a YAML file from disk (no network, no code exec).

    Only a regular file, at most :data:`MAX_YAML_BYTES`, is read, and with ``root`` (the pack
    directory, or the directory a loose spec was found in) only one that resolves inside it. A
    symlink to ``/dev/zero`` passed the size check at 0 bytes and was read without end, and one
    to a file outside the pack was parsed and its first line quoted in the error (pre-commit
    audit of this block).
    """

    try:
        real = path.resolve(strict=True)
        info = os.stat(real)
    except (OSError, RuntimeError) as exc:
        raise SafeLoadError(
            f"cannot read the file: {getattr(exc, 'strerror', None) or exc}"
        ) from exc
    if root is not None and not real.is_relative_to(root.resolve()):
        raise SafeLoadError("the file resolves outside its directory (a symlink?)")
    _check_readable(info)
    # Opened without following a link and without blocking, then checked again on the open
    # descriptor: a file swapped for a pipe or a link after the checks above cannot hang the
    # read or redirect it (delta audit of this block).
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)  # Windows would stop a text-mode read at a 0x1A byte
    )
    try:
        descriptor = os.open(real, flags)
    except OSError as exc:
        raise SafeLoadError(f"cannot read the file: {exc.strerror or exc}") from exc
    try:
        _check_readable(os.fstat(descriptor))
        # Blocking again for the read: O_NONBLOCK was for the open, and a mount that answered
        # "try again" would otherwise give a short or empty read (pre-merge audit of #39).
        if getattr(os, "O_NONBLOCK", 0):  # Windows has no O_NONBLOCK and no set_blocking on files
            os.set_blocking(descriptor, True)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1  # closed by the handle from here on
            raw = handle.read(MAX_YAML_BYTES + 1)
    except OSError as exc:
        raise SafeLoadError(f"cannot read the file: {exc.strerror or exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > MAX_YAML_BYTES:
        raise SafeLoadError(f"file is over the {MAX_YAML_BYTES}-byte cap")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SafeLoadError(f"not UTF-8 text (byte {exc.start})") from exc
    return safe_load_yaml(text)


@lru_cache(maxsize=1)
def _attack_spec_validator() -> Draft202012Validator:
    """Compile the hand-authored attack-spec validator once."""
    schema = json.loads(_ATTACK_SPEC_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_attack_spec_schema(data: object) -> list[str]:
    """Validate a parsed spec dict against the JSON Schema.

    Returns a list of human-readable error messages (empty ⇒ schema-valid). Sorting by
    JSON path keeps the output deterministic for golden comparisons. At most
    :data:`_MAX_SCHEMA_ERRORS` are listed and the rest counted: a 99,000-item list of the wrong
    type printed 5.7 MB (pre-commit audit of the SEC-09 fix).

    A number too long to write out is reported where it is, and nothing else is checked: every
    jsonschema message that quotes a value raised on it, a lint traceback with exit 1, and one
    the schema accepted failed later where the run wrote it (A-40).

    A value JSON cannot hold is reported where it is, and nothing else is checked: a spec is a
    JSON document, but YAML builds a date from an unquoted ``2026-01-01``, a set from ``!!set``,
    a tuple from each entry of ``!!omap`` and ``!!pairs``, bytes from ``!!binary``, and from
    ``.nan`` and ``.inf`` floats no JSON number writes. The schema leaves a tool's ``returns``
    and a fixture's tool-call arguments free-form, so such a value passed lint, and ``run`` died
    where it first turned it into JSON: ``TypeError``, a traceback and exit 1 (A-54).
    """
    too_long = list(too_long_paths(data))
    if too_long:
        shown = [
            f"{_cut(path_text(path))}: {'a key that is ' if is_key else ''}{described()}"
            for path, is_key in too_long[:_MAX_SCHEMA_ERRORS]
        ]
        if len(too_long) > _MAX_SCHEMA_ERRORS:
            more = len(too_long) - _MAX_SCHEMA_ERRORS
            shown.append(f"<root>: and {more} more numbers too long to write out")
        return shown
    not_json = _non_json_values(data)
    if not_json:
        return not_json
    validator = _attack_spec_validator()
    errors: list[ValidationError] = sorted(
        validator.iter_errors(data), key=lambda e: list(e.absolute_path)
    )
    shown = [_format_error(e) for e in errors[:_MAX_SCHEMA_ERRORS]]
    if len(errors) > _MAX_SCHEMA_ERRORS:
        shown.append(f"<root>: and {len(errors) - _MAX_SCHEMA_ERRORS} more schema errors")
    return shown


def _format_error(err: ValidationError) -> str:
    """Render a ``jsonschema`` error as a stable ``<path>: <message>`` string.

    The message quotes the offending value, so it is cut at a fixed length: the path and the
    reason are what an author needs, and a large value repeated per error was the amplifier.
    """

    location = "/".join(str(p) for p in err.absolute_path) or "<root>"
    return f"{location}: {_cut(err.message)}"


def _cut(text: str) -> str:
    """``text`` cut at :data:`_MAX_MESSAGE_CHARS`, saying how long it was."""

    if len(text) <= _MAX_MESSAGE_CHARS:
        return text
    return text[:_MAX_MESSAGE_CHARS] + f"... ({len(text)} characters)"


_CANNOT_HOLD = "which JSON cannot hold"
_QUOTED = "write it in quotes, without a tag"
_HALF_CHARACTER = (
    "half a character (a lone surrogate, which YAML builds from an escape between U+D800 and "
    f"U+DFFF, even from a pair of them), {_CANNOT_HOLD}; write the character itself"
)
#: What a value YAML builds and JSON cannot hold is, checked in order (a timestamp is a date),
#: and what to write instead.
_NOT_JSON: tuple[tuple[type | tuple[type, ...], str, str], ...] = (
    (datetime.datetime, "a timestamp (YAML reads an unquoted 2026-01-01T10:00:00 as one)", _QUOTED),
    (datetime.date, "a date (YAML reads an unquoted 2026-01-01 as one)", _QUOTED),
    ((set, frozenset), "a set (!!set)", "write a list or a mapping"),
    (tuple, "a key and value pair (an entry of !!omap or !!pairs)", "write a list or a mapping"),
    ((bytes, bytearray), "binary data (!!binary)", "write it as text"),
)


def _non_json_values(data: object) -> list[str]:
    """A message per value in ``data`` that JSON cannot hold, in document order.

    What JSON holds is kept (a mapping, a list, a string, a number, a boolean, null) and anything
    else is reported, rather than a list of what it does not hold. At most
    :data:`_MAX_SCHEMA_ERRORS` are listed and the rest counted. A set or a pair is the finding,
    and what it holds is not walked. Text, a value or a key, holding half a character (a lone
    surrogate) is reported too: UTF-8 cannot write it, so lint passed and the run stopped where
    it encoded the request (pre-commit audit of A-54); a key that is not text is A-44's.
    A container that YAML shares
    through an alias is entered once (where the walk first meets it), so the walk visits each
    node once whatever the aliases repeat. Walked without recursion, one iterator per open
    container, so what it holds beyond the ids of the containers entered follows the depth
    of the document: on specs of about 90,000 nodes it peaked at 3.1 MiB with 30,000
    containers and 8.4 MiB with 89,000 (a first version that kept a link per node, 10.4 and
    16.4 MiB).
    """

    if not isinstance(data, dict | list):
        problem = _not_json(data)
        return [] if problem is None else [f"<root>: {problem}"]
    found: list[str] = []
    count = 0

    def report(path: list[object], problem: str) -> None:
        nonlocal count
        count += 1
        if len(found) < _MAX_SCHEMA_ERRORS:
            found.append(f"{_location(path)}: {problem}")

    entered = {id(data)}
    keys: list[object] = []  # the key of each open container but the document
    walks = [_entries(data)]
    while walks:
        step = next(walks[-1], None)
        if step is None:
            walks.pop()
            if keys:
                keys.pop()
            continue
        key, value = step
        if isinstance(key, str) and not encodes_utf8(key):
            report([*keys, key], f"a key holding {_HALF_CHARACTER}")
        if isinstance(value, dict | list):
            if id(value) not in entered:
                entered.add(id(value))
                keys.append(key)
                walks.append(_entries(value))
            continue
        problem = _not_json(value)
        if problem is not None:
            report([*keys, key], problem)
    if count > len(found):
        found.append(f"<root>: and {count - len(found)} more values that JSON cannot hold")
    return found


def _entries(container: dict[Any, Any] | list[Any]) -> Iterator[tuple[object, object]]:
    """``(key, value)`` of a mapping, ``(index, value)`` of a list."""

    return iter(container.items()) if isinstance(container, dict) else enumerate(container)


def _not_json(value: object) -> str | None:
    """What ``value`` is and what to write instead, or None when JSON holds it."""

    if value is None or isinstance(value, int):  # a bool is an int
        return None
    if isinstance(value, str):
        return None if encodes_utf8(value) else f"text holding {_HALF_CHARACTER}"
    if isinstance(value, float):
        if math.isfinite(value):
            return None
        kind = (
            "NaN (YAML reads .nan as one)"
            if math.isnan(value)
            else "an infinity (YAML reads .inf or -.inf as one)"
        )
        return f"{kind}, {_CANNOT_HOLD}; {_QUOTED}"
    for cls, kind, advice in _NOT_JSON:
        if isinstance(value, cls):
            return f"{kind}, {_CANNOT_HOLD}; {advice}"
    return f"a value of type {type(value).__name__}, {_CANNOT_HOLD}; write a JSON value"


def encodes_utf8(text: str) -> bool:
    """Whether UTF-8, the encoding of a JSON document and of the terminal, can write ``text``.

    Not when it holds half a character (a lone surrogate): a spec value, and an id printed in a
    finding header, raised ``UnicodeEncodeError`` where they were written (A-54).
    """

    if text.isascii():
        return True
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate
        return False
    return True


def _location(path: list[object]) -> str:
    """``a/b/0/c`` for the keys and indexes of ``path``, cut when long.

    A key is a string from the spec, printed as written when it is printable; any other part is
    written as its ``repr``, so a key holding an escape sequence or a newline cannot forge a
    finding line, and a key that is not text (A-44's finding) never breaks the path.
    """

    parts: list[str] = []
    for part in path:
        try:
            parts.append(part if isinstance(part, str) and part.isprintable() else repr(part))
        except ValueError:  # an int key past the interpreter's digit limit for text (A-40)
            parts.append("<number>")
    return _cut("/".join(parts))
