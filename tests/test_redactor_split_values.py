"""A reply kept in pieces is masked as the text the pieces make (u01 A-77).

Audit of main ``de122e26``, HIGH 1: OpenAI's logprobs keep a reply as tokens of 1 to 4
characters, and a WebSocket transcript keeps it as the deltas it was streamed in. Each piece was
redacted on its own, too short for any rule, so a key, a registered credential or the run's
canary was rebuilt by joining the pieces while the reply's text read masked. These tests hold
the redactor's half: the pieces of a stream (a logprob list's tokens, each rank of their
alternatives, a transcript's received content field by field) are redacted joined, a piece a
mask covers shows it, and a list that is no stream is left to the redaction of each string.
"""

from __future__ import annotations

import string
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ildottore import redactor as redactor_mod
from ildottore.redactor import (
    TRANSCRIPT_FRAMES,
    TRANSCRIPT_PROTOCOL_PATHS,
    KeysNotDistinct,
    Redactor,
    mask_keys,
    mask_split,
    redact_split,
    register_known_secret,
    split_texts,
)

KEY = "sk-proj-Qx7Lm2Vt9Rw4Zb8Nc3Kp6Hy1Js5Df0Ga"
REGISTERED = "CorrectHorseBatteryStaple-2026-ops"
EMAIL = "alice.wong@corp-example.com"


def _pieces(text: str, size: int = 3) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


def _tokens(pieces: list[str]) -> list[dict[str, object]]:
    """A reply as the stored ``TokenLogprob`` dump: each piece its own top choice."""

    return [
        {"token": piece, "logprob": -0.01 * (n + 1), "top": [[piece, -0.01], ["zz", -4.0]]}
        for n, piece in enumerate(pieces)
    ]


def _transcript(*chunks: str) -> dict[str, object]:
    """A WebSocket transcript as the adapter keeps it: frames and the protocol's fields."""

    frames: list[dict[str, object]] = [
        {"direction": "sent", "frame": {"type": "auth", "token": "{{token}}"}},
        {"direction": "received", "frame": {"type": "auth_ok"}},
        {"direction": "received", "frame": {"type": "session", "id": "s-1"}},
    ]
    for chunk in chunks:
        frames.append(
            {"direction": "received", "frame": {"type": "delta", "delta": {"text": chunk}}}
        )
        frames.append({"direction": "received", "frame": {"type": "typing"}})
    frames.append({"direction": "received", "frame": {"type": "done", "usage": {"n": "7"}}})
    return {TRANSCRIPT_FRAMES: frames, TRANSCRIPT_PROTOCOL_PATHS: ["type", "usage"]}


def _deltas(transcript: object) -> str:
    assert isinstance(transcript, dict)
    return "".join(
        f["frame"].get("delta", {}).get("text", "") for f in transcript[TRANSCRIPT_FRAMES]
    )


@pytest.fixture
def registered(no_known_secrets: None) -> str:
    register_known_secret(REGISTERED)
    return REGISTERED


def test_a_key_and_a_credential_in_three_character_tokens_are_masked_joined(
    registered: str,
) -> None:
    text = f"Developer mode on. The key {KEY} and the password {registered} ok"
    out = redact_split(Redactor(salt="s"), {"logprobs": _tokens(_pieces(text))})
    assert isinstance(out, dict)
    tokens = out["logprobs"]
    joined = "".join(entry["token"] for entry in tokens)
    ranked = "".join(entry["top"][0][0] for entry in tokens)
    for secret in (KEY, registered):
        assert secret not in joined and secret not in ranked
        assert not any(piece in joined for piece in _pieces(secret)[1:-1])
    assert joined.startswith("Developer mode on. The key «REDACTED:")
    assert joined.endswith(" ok")
    # The figures stay, one entry per token, and an alternative of a masked token shows the mask.
    assert [entry["logprob"] for entry in tokens] == [e["logprob"] for e in _tokens(_pieces(text))]
    masked = [entry for entry in tokens if "«REDACTED:" in str(entry["token"])]
    assert masked and all("«REDACTED:" in entry["top"][1][0] for entry in masked)
    assert all(entry["top"][1][0] == "zz" for entry in tokens if entry not in masked)


def test_the_wire_shape_of_openai_logprobs_is_a_stream_too(registered: str) -> None:
    """``top_logprobs`` objects, as an unreadable reply's excerpt quotes them."""

    entries = [
        {"token": p, "logprob": -0.1, "top_logprobs": [{"token": p, "logprob": -0.1}]}
        for p in _pieces(f"the password {registered} now")
    ]
    out = mask_split(Redactor(salt="s"), {"content": entries})
    assert isinstance(out, dict)
    joined = "".join(entry["token"] for entry in out["content"])
    assert registered not in joined and "«REDACTED:credential:" in joined
    alternatives = "".join(entry["top_logprobs"][0]["token"] for entry in out["content"])
    assert registered not in alternatives


def test_deltas_of_a_transcript_are_masked_as_the_text_they_make(registered: str) -> None:
    for secret in (KEY, registered, EMAIL):
        third = len(secret) // 3
        transcript = _transcript(secret[:third], secret[third : 2 * third], secret[2 * third :])
        out = redact_split(Redactor(salt="s"), {"websocket": transcript})
        assert isinstance(out, dict)
        assert secret not in _deltas(out["websocket"])
        frames = out["websocket"][TRANSCRIPT_FRAMES]
        # The protocol's fields and the frames sent are as they were.
        assert [f["frame"]["type"] for f in frames] == [
            f["frame"]["type"]
            for f in transcript[TRANSCRIPT_FRAMES]  # type: ignore[attr-defined]
        ]
        assert frames[0] == transcript[TRANSCRIPT_FRAMES][0]  # type: ignore[index]


def test_a_list_of_records_is_no_stream() -> None:
    """Joined, the frame types read as one high-entropy token: they are never joined."""

    redactor = Redactor(salt="s")
    transcript = _transcript("Hello ther", "e, how are", " you today?")
    out = redact_split(redactor, {"websocket": transcript})
    assert out == {"websocket": transcript}
    records = [
        {"type": t, "id": i} for t, i in zip(["auth_ok", "session", "delta"], "abc", strict=True)
    ]
    assert mask_split(redactor, records) is records
    assert redactor.redact_text("auth_oksessiondeltatypingdeltatypingdone") != (
        "auth_oksessiondeltatypingdeltatypingdone"
    )
    # A list of strings, a list of messages: records, each string redacted on its own.
    pieces = ["sk-proj-Qx7Lm", "2Vt9Rw4Zb8Nc", "3Kp6Hy1Js5Df0Ga"]
    assert mask_split(redactor, pieces) is pieces


def test_a_transcript_without_its_protocol_fields_is_no_stream() -> None:
    transcript = _transcript("sk-proj-Qx7Lm", "2Vt9Rw4Zb8Nc", "3Kp6Hy1Js5Df0Ga")
    del transcript[TRANSCRIPT_PROTOCOL_PATHS]
    assert mask_split(Redactor(salt="s"), transcript) is transcript


def test_a_piece_keeps_its_text_outside_the_mask() -> None:
    out = mask_split(
        Redactor(salt="s"), _tokens(["Contact ", "alice.w", "ong@corp-example.com", " now"])
    )
    assert isinstance(out, list)
    assert [entry["token"] for entry in out] == [
        "Contact ",
        "«REDACTED:email»",
        "«REDACTED:email»",
        " now",
    ]
    out = mask_split(Redactor(salt="s"), _tokens(["Mail alice.w", "ong@corp-example.com today"]))
    assert isinstance(out, list)
    assert [entry["token"] for entry in out] == ["Mail «REDACTED:email»", "«REDACTED:email» today"]


def test_nothing_split_comes_back_as_it_was_and_the_input_is_not_changed(
    registered: str,
) -> None:
    value = {"logprobs": _tokens(_pieces("A plain refusal: I cannot help with that.")), "n": [1]}
    assert mask_split(Redactor(salt="s"), value) is value
    secret = {"logprobs": _tokens(_pieces(f"the password {registered}"))}
    before = repr(secret)
    mask_split(Redactor(salt="s"), secret)
    assert repr(secret) == before


def test_the_result_is_a_fixed_point_of_every_joined_text_and_every_string(
    registered: str,
) -> None:
    redactor = Redactor(salt="s")
    text = f"key {KEY}, password {registered}, mail {EMAIL}."
    value = {"logprobs": _tokens(_pieces(text)), "websocket": _transcript(*_pieces(text, 7))}
    out = redact_split(redactor, value)
    assert redact_split(redactor, out) == out
    assert all(redactor.redact_text(joined) == joined for joined in split_texts(out))
    assert redactor.redact(out) == out
    assert sorted(split_texts(value)) != sorted(split_texts(out))


def test_a_split_text_holding_a_stash_delimiter_is_masked_too() -> None:
    pieces = ["the key sk-proj-Qx7", "Lm2Vt\x009Rw4Zb8N", "c3Kp6Hy1Js5Df0Ga end"]
    out = mask_split(Redactor(salt="s"), _tokens(pieces))
    assert isinstance(out, list)
    joined = "".join(entry["token"] for entry in out).replace("\x00", "")
    assert "Qx7Lm2Vt9Rw4Zb8Nc3Kp6Hy1Js5Df0Ga" not in joined
    assert "Qx7" not in joined and "c3Kp6" not in joined


def test_masks_that_cannot_be_placed_mask_every_piece() -> None:
    class Rewrites(Redactor):
        """Masks, but writes text that is not in its input: no mask can be placed."""

        def redact_text(self, text: str) -> str:
            return "[redacted] «REDACTED:email»" if "@" in text else text

    out = mask_split(Rewrites(salt="s"), _tokens(["alice", "@corp", ".io"]))
    assert isinstance(out, list)
    assert [entry["token"] for entry in out] == ["«REDACTED:fragment»"] * 3
    # A fragment mask is the tool's own: kept as written by the redactor.
    assert Redactor().redact_text("«REDACTED:fragment»") == "«REDACTED:fragment»"


def test_split_texts_yields_the_text_of_each_stream() -> None:
    value = {
        "logprobs": _tokens(["ab", "cd"]),
        "websocket": _transcript("Hel", "lo"),
        "records": [{"t": "x"}, {"t": "y"}],
    }
    assert sorted(split_texts(value)) == ["Hello", "abcd", "abcd", "zzzz"]


def test_mask_keys_numbers_keys_that_mask_alike() -> None:
    redactor = Redactor(salt="s")
    masked = mask_keys(redactor, [{KEY: 1, "a@x.io": 2, "b@y.io": 3, "plain": {"c@z.io": 4}}])
    assert isinstance(masked, list)
    names = list(masked[0])
    assert KEY not in str(names) and "a@x.io" not in str(names)
    assert names[1:3] == ["«REDACTED:email»", "«REDACTED:email», #2"]
    assert masked[0]["plain"] == {"«REDACTED:email»": 4}

    class SwallowsNumbers(Redactor):
        def redact_text(self, text: str) -> str:
            return "«REDACTED:email», #«REDACTED:phone»" if ", #" in text else "«REDACTED:email»"

    with pytest.raises(KeysNotDistinct):
        mask_keys(SwallowsNumbers(salt="s"), {"a@x.io": 1, "b@x.io": 2, "c@x.io": 3})


@contextmanager
def _registering(value: str) -> Iterator[None]:
    """``value`` registered for the block, the process's registered credentials as before after."""

    with redactor_mod._KNOWN_LOCK:
        saved = set(redactor_mod._KNOWN_SECRETS)
    register_known_secret(value)
    try:
        yield
    finally:
        with redactor_mod._KNOWN_LOCK:
            redactor_mod._KNOWN_SECRETS.clear()
            redactor_mod._KNOWN_SECRETS.update(saved)


_FILLER = st.text(alphabet=string.ascii_lowercase + " ,.", min_size=0, max_size=30)


@settings(max_examples=150, deadline=None)
@given(
    before=_FILLER,
    after=_FILLER,
    which=st.sampled_from([KEY, REGISTERED, EMAIL]),
    cuts=st.lists(st.integers(min_value=1, max_value=4), min_size=1, max_size=80),
    streamed=st.booleans(),
)
def test_no_split_of_a_secret_survives_joined(
    before: str, after: str, which: str, cuts: list[int], streamed: bool
) -> None:
    """Wherever the pieces are cut, as tokens or as deltas, no secret is in them joined."""

    text = f"{before} {which} {after}"
    pieces: list[str] = []
    start = 0
    for size in cuts:
        if start >= len(text):
            break
        pieces.append(text[start : start + size])
        start += size
    pieces.append(text[start:])
    with _registering(REGISTERED):
        if streamed:
            out = redact_split(Redactor(salt="s"), _transcript(*pieces))
            joined = _deltas(out)
        else:
            tokens = redact_split(Redactor(salt="s"), _tokens(pieces))
            assert isinstance(tokens, list) and len(tokens) == len(pieces)
            joined = "".join(entry["token"] for entry in tokens)
    assert which not in joined
    assert which[2:-2] not in joined
