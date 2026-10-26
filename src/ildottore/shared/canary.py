"""The per-run placeholders a planted canary holds, and what they bind to (u08 A-100, OD-58).

A spec's canary is written ``{{canary_prefix}}{{canary_body}}``. Both are read from a binding:
the run id, or ``<run_token>-<spec id>`` for a spec an operator seeds (``core.setup_delivery``),
the same string ``{{run_id}}`` binds to. ``{{canary_prefix}}`` binds to 12 capital letters and
``_``, ``{{canary_body}}`` to 16 characters of a lowercase base-32 alphabet, each from its own
SHA-256 of the binding, so no part of the string a target sees is a constant, nor the run id or
the spec id a vendor could filter or read: the battery's canary was ``ZYNAP_CANARY_<run id>``
until 2026-10-26. The derivation is a function of the binding, so the runner, a resume of the
run and the evidence store all reach the same canary without storing it; an operator who seeds a
canary may fix the prefix instead (``seeded_setup.canary_prefix``). Here, in ``shared``, because
the runner binds it and the evidence store, which imports no ``core``, masks it.
"""

from __future__ import annotations

import hashlib
import string
from typing import Final

__all__ = [
    "CANARY_BODY_PLACEHOLDER",
    "CANARY_PREFIX_PLACEHOLDER",
    "RUN_ID_PLACEHOLDER",
    "bind_canary",
    "derived_body",
    "derived_prefix",
    "holds_placeholder",
]

#: Bound to the run id, or to the seeded binding, at run time.
RUN_ID_PLACEHOLDER: Final = "{{run_id}}"
#: Bound to :func:`derived_prefix` of what ``{{run_id}}`` binds to, or to the operator's prefix.
CANARY_PREFIX_PLACEHOLDER: Final = "{{canary_prefix}}"
#: Bound to :func:`derived_body` of what ``{{run_id}}`` binds to.
CANARY_BODY_PLACEHOLDER: Final = "{{canary_body}}"

#: The derived prefix has 12 capital letters and ``_``: as long as the old ``ZYNAP_CANARY_``, so a
#: request that carries it, and the tokens reserved for it, are as long in every run as before.
_LETTERS: Final = 12
_DOMAIN: Final = b"ildottore canary prefix\x00"
#: The body has 16 characters, as long as the run id it replaces (``run-`` and 12 hex digits), so
#: the canary keeps the old one's length. Crockford's base-32 alphabet, lowercase: no ``i``,
#: ``l``, ``o`` or ``u``, so a canary a vision model reads off an image is not misread.
_BODY_LENGTH: Final = 16
_BODY_ALPHABET: Final = "0123456789abcdefghjkmnpqrstvwxyz"
_BODY_DOMAIN: Final = b"ildottore canary body\x00"


def derived_prefix(binding: str) -> str:
    """The ``{{canary_prefix}}`` of a canary whose ``{{run_id}}`` binds to ``binding``.

    Capital letters and a closing ``_``, read from a SHA-256 of ``binding``: the same binding
    always gives the same prefix (a resume, the evidence store), two bindings almost never do.
    """

    digest = hashlib.sha256(_DOMAIN + binding.encode("utf-8")).digest()
    letters = string.ascii_uppercase
    return "".join(letters[byte % len(letters)] for byte in digest[:_LETTERS]) + "_"


def derived_body(binding: str) -> str:
    """The ``{{canary_body}}`` of a canary whose ``{{run_id}}`` binds to ``binding``.

    Read from a SHA-256 of ``binding`` under a domain of its own, so it shares no bits with the
    prefix: 80 bits, and neither the run id nor the spec id can be read back from it.
    """

    digest = hashlib.sha256(_BODY_DOMAIN + binding.encode("utf-8")).digest()
    value = int.from_bytes(digest[:10], "big")
    chars = []
    for _ in range(_BODY_LENGTH):
        value, index = divmod(value, len(_BODY_ALPHABET))
        chars.append(_BODY_ALPHABET[index])
    return "".join(chars)


def holds_placeholder(text: str) -> bool:
    """True when ``text`` holds any per-run placeholder."""

    return any(
        placeholder in text
        for placeholder in (RUN_ID_PLACEHOLDER, CANARY_PREFIX_PLACEHOLDER, CANARY_BODY_PLACEHOLDER)
    )


def bind_canary(text: str, binding: str, prefix: str | None = None) -> str:
    """``text`` with its per-run placeholders bound.

    ``{{run_id}}`` to ``binding``, ``{{canary_body}}`` to :func:`derived_body` of it and
    ``{{canary_prefix}}`` to ``prefix``, which left out is :func:`derived_prefix` of ``binding``.
    """

    if CANARY_PREFIX_PLACEHOLDER in text:
        bound = derived_prefix(binding) if prefix is None else prefix
        text = text.replace(CANARY_PREFIX_PLACEHOLDER, bound)
    if CANARY_BODY_PLACEHOLDER in text:
        text = text.replace(CANARY_BODY_PLACEHOLDER, derived_body(binding))
    return text.replace(RUN_ID_PLACEHOLDER, binding)
