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

import json
import os
import stat
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from ildottore.safe_yaml import SafeValueLoader, check_expanded
from ildottore.shared.config_errors import yaml_problem

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
    """
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
    message = err.message
    if len(message) > _MAX_MESSAGE_CHARS:
        message = message[:_MAX_MESSAGE_CHARS] + f"... ({len(err.message)} characters)"
    return f"{location}: {message}"
