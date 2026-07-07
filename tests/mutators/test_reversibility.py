"""Reversibility tests: reversible encodings decode back to the payload (contract §7).

``base64_wrap`` / ``rot13`` / ``zero_width_inject`` outputs must reconstruct the original
payload; ``payload_splitting`` fragments concatenate back to the original. Asserted
programmatically from the recorded provenance / documented decode.
"""

from __future__ import annotations

import base64
import codecs

from hypothesis import given
from hypothesis import strategies as st

from ildottore.mutators import (
    Base64WrapMutator,
    PayloadSplittingMutator,
    Rot13Mutator,
    ZeroWidthInjectMutator,
)
from ildottore.mutators.zero_width_inject import strip_zero_width

_text = st.text(min_size=1, max_size=200)
SEED = "SPEC:x"


@given(text=_text)
def test_rot13_round_trips(text: str) -> None:
    out = Rot13Mutator().mutate(text, SEED)
    assert codecs.decode(out, "rot_13") == text


@given(text=_text)
def test_base64_wrap_payload_decodes_back(text: str) -> None:
    result = Base64WrapMutator().mutate_result(text, SEED)
    blob = result.provenance["payload_b64"]
    assert isinstance(blob, str)
    assert base64.b64decode(blob).decode("utf-8") == text


@given(text=_text)
def test_zero_width_strips_back_to_original(text: str) -> None:
    out = ZeroWidthInjectMutator().mutate(text, SEED)
    assert strip_zero_width(out) == text
    assert out == text or len(out) >= len(text)


@given(text=_text)
def test_payload_splitting_fragments_reassemble(text: str) -> None:
    result = PayloadSplittingMutator().mutate_result(text, SEED)
    fragments = result.provenance["fragments"]
    assert isinstance(fragments, list)
    assert "".join(fragments) == text


def test_reversible_flags_are_declared() -> None:
    assert Base64WrapMutator().reversible is True
    assert Rot13Mutator().reversible is True
    assert ZeroWidthInjectMutator().reversible is True
    assert PayloadSplittingMutator().reversible is True
