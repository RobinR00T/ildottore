"""An offline target that actually *decodes* what is sent to it (u04, test-support).

``-sV``'s carrier layer orders the battery by which transformations a target still
understands. Against every other offline scenario that measurement cannot run: the canned
reply is the same string whatever arrives, so no carrier is ever comprehended, the ordering
hint comes back empty and CI exercises the plumbing while the measurement itself, the part
that decides what gets sent first at a customer's endpoint, is never asserted end to end.

This adapter closes that. It is a **simulated decoder**, not a model: it strips zero-width
padding, tries rot13 and base64, and if the instruction survives in plain text it follows it.
So it comprehends the encodings it implements and fails the ones it does not, which is the
split the layer is built to detect. Character substitution (`leetspeak`, `unicode_confusable`)
is always opaque to it. `translate` depends on the target id, because the carrier's seed
derives from it and the offline gloss picks a language accordingly: for some ids it leaves
"exactly the word" in English and the decoder follows it, for others it does not. The split is
therefore at least three comprehended and at least two opaque, never all of one kind, and the
tests assert membership rather than a count for exactly that reason.

What it therefore proves, stated narrowly: that a target which comprehends some carriers and
not others makes the plan come out in a different order, through the real layer, the real
planner and the real CLI. It proves nothing about how any actual model behaves. That still
needs a live run, and the docs say so.

Pure: no I/O, no clock, no RNG, no network. Two instances answer identically.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from typing import Final

from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse

__all__ = ["COMPREHENDING_REFUSAL", "ComprehendingMock"]

#: What the emulated target says when it cannot recover an instruction. Deliberately not the
#: marker and deliberately short: it must read as "I did not understand", not as an echo.
COMPREHENDING_REFUSAL: Final = "I do not understand the request."

#: The instruction shape this target knows how to obey: "reply with exactly the word FOO".
#: Matched on the DECODED text, so a carrier that leaves the English readable is followed and
#: one that rewrites its characters is not.
_INSTRUCTION: Final = re.compile(r"exactly the word\s+([A-Za-z]{3,16})", re.IGNORECASE)

_ZERO_WIDTH: Final = str.maketrans(dict.fromkeys("​‌‍﻿"))

#: Long-enough base64 runs, so a stray word is not mistaken for an encoded payload.
_B64_RUN: Final = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _candidates(prompt: str) -> list[str]:
    """The readings this target can produce of one prompt (itself, then its decodings)."""

    plain = prompt.translate(_ZERO_WIDTH)
    readings = [plain, codecs.encode(plain, "rot13")]
    for run in _B64_RUN.findall(plain):
        try:
            readings.append(base64.b64decode(run, validate=True).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
    return readings


class ComprehendingMock:
    """A deterministic offline target that follows a decodable instruction."""

    id: str

    def __init__(self, *, id: str = "mock", capabilities: Capabilities | None = None) -> None:
        self.id = id
        self._capabilities = capabilities if capabilities is not None else Capabilities()

    def capabilities(self) -> Capabilities:
        return self._capabilities

    async def send(self, request: ModelRequest) -> ModelResponse:
        """Answer the marker when the instruction survives, else say it did not.

        ``async`` only to satisfy the adapter protocol: the body awaits nothing.
        """

        for reading in _candidates(request.prompt or ""):
            match = _INSTRUCTION.search(reading)
            if match is not None:
                # Exactly the word, nothing else: the probe asks for that, and a reply that
                # runs on is not compliance. Upper-cased because the marker is.
                return ModelResponse(text=match.group(1).upper())
        return ModelResponse(text=COMPREHENDING_REFUSAL)
