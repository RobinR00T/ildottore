"""What an ``env://NAME`` credential reference may name, and how a run reads it (u12 A-82).

A target file's ``auth_ref``, a scope identity's ``auth_ref`` and a fleet entry's
``api_key_env`` name an environment variable; the key itself is read only at send time. Two
things went wrong with the name (CLI audit of 2026-10-11, M4 and M8):

* nothing checked that it was one: ``api_key_env: "sk-ant-..."`` (the key pasted where its
  variable's name belongs) became ``auth_ref: env://sk-ant-...`` in the scope and the target
  file ``dottore fleet`` wrote, exit 0, and ``env://OPENAI_API_KEY `` (a trailing space) named
  a variable no shell can set;
* a variable that was not set read as "no credential": ``auth_ref: env://TYPO`` sent every
  request without one, and the run stopped on ``non-retryable HTTP 401`` naming nothing.

A name is now :data:`ENV_NAME` (POSIX's portable shape: letters, digits and ``_``, not starting
with a digit) wherever a file writes one, and a live run refuses an unset or empty variable
before anything is sent, naming the variable, never a value. ``env://NONE`` is the one
reference that says "no credential": its variable is never read. A target file that takes no
credential leaves ``auth_ref`` out; a scope identity, which must carry an ``auth_ref``, writes
``env://NONE`` (what ``dottore fleet`` writes for an entry with no ``api_key_env``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

__all__ = [
    "ENV_NAME",
    "ENV_NAME_RULE",
    "ENV_SCHEME",
    "NO_CREDENTIAL",
    "NO_CREDENTIAL_NAME",
    "env_name_of",
    "is_env_name",
    "unset_variable",
]

#: The one scheme ``resolve_auth_ref`` reads.
ENV_SCHEME: Final = "env://"
#: An environment variable's name: POSIX's portable shape (IEEE Std 1003.1, "Environment
#: Variables"), which every shell can export.
ENV_NAME: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
#: How a refusal says what a name is.
ENV_NAME_RULE: Final = "letters, digits and _, not starting with a digit"
#: The reference that names no credential; its variable is never read.
NO_CREDENTIAL_NAME: Final = "NONE"
NO_CREDENTIAL: Final = ENV_SCHEME + NO_CREDENTIAL_NAME


def is_env_name(name: str) -> bool:
    """Whether ``name`` is an environment variable's name (:data:`ENV_NAME`)."""

    return ENV_NAME.fullmatch(name) is not None


def env_name_of(auth_ref: str) -> str | None:
    """The variable an ``env://`` reference names, or ``None`` for any other text."""

    return auth_ref[len(ENV_SCHEME) :] if auth_ref.startswith(ENV_SCHEME) else None


def unset_variable(auth_ref: str | None, environ: Mapping[str, str]) -> tuple[str, str] | None:
    """``(name, "not set" | "set but empty")`` when ``auth_ref`` names a variable a run cannot
    send, else ``None``.

    ``environ`` is the environment to look in, which the caller reads: the CLI's wiring passes
    the process's, as it alone reads it. ``None``, :data:`NO_CREDENTIAL`, another scheme and a
    literal are not this question: the first two send no credential on purpose, the last two are
    refused where the reference is read. A value of whitespace only is empty: the resolver strips
    it.
    """

    if auth_ref is None:
        return None
    name = env_name_of(auth_ref)
    if name is None or name == NO_CREDENTIAL_NAME or not is_env_name(name):
        return None
    value = environ.get(name)
    if value is None:
        return name, "not set"
    if not value.strip():
        return name, "set but empty"
    return None
