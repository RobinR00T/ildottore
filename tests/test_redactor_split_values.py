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

import random
import re
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
    withhold_split,
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
    # Joined, the tokens read as the reply's redacted text, each mask once.
    assert joined == Redactor(salt="s").redact_text(text)
    # The figures stay, one entry per token; an alternative of a covered token shows its masks,
    # and one written as the token shows what the token shows now.
    original = _pieces(text)
    assert [entry["logprob"] for entry in tokens] == [e["logprob"] for e in _tokens(original)]
    covered = [i for i, entry in enumerate(tokens) if entry["token"] != original[i]]
    assert covered
    for i, entry in enumerate(tokens):
        if i in covered:
            assert entry["top"][0][0] == entry["token"] and "«REDACTED:" in entry["top"][1][0]
        else:
            assert entry["top"] == [[original[i], -0.01], ["zz", -4.0]]


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


def test_a_transcript_that_names_no_protocol_fields_is_read_with_the_default_type() -> None:
    """Stored before ``protocol_paths`` (or built by hand): the content is still joined."""

    transcript = _transcript("sk-proj-Qx7Lm", "2Vt9Rw4Zb8Nc", "3Kp6Hy1Js5Df0Ga")
    del transcript[TRANSCRIPT_PROTOCOL_PATHS]
    out = mask_split(Redactor(salt="s"), transcript)
    assert "Qx7Lm2Vt9Rw4Zb8Nc3Kp6Hy1Js5Df0Ga" not in _deltas(out)
    assert isinstance(out, dict)
    assert [f["frame"]["type"] for f in out[TRANSCRIPT_FRAMES]] == [
        f["frame"]["type"]
        for f in transcript[TRANSCRIPT_FRAMES]  # type: ignore[attr-defined]
    ]
    # Frames that are not all {direction, frame} records are no transcript.
    records = {TRANSCRIPT_FRAMES: [{"delta": "sk-proj-Qx7Lm"}, {"delta": "2Vt9Rw4Zb8Nc3Kp6Hy1J"}]}
    assert mask_split(Redactor(salt="s"), records) is records


def test_a_piece_keeps_its_text_outside_the_mask() -> None:
    out = mask_split(
        Redactor(salt="s"), _tokens(["Contact ", "alice.w", "ong@corp-example.com", " now"])
    )
    assert isinstance(out, list)
    assert [entry["token"] for entry in out] == ["Contact ", "«REDACTED:email»", "", " now"]
    out = mask_split(Redactor(salt="s"), _tokens(["Mail alice.w", "ong@corp-example.com today"]))
    assert isinstance(out, list)
    assert [entry["token"] for entry in out] == ["Mail «REDACTED:email»", " today"]


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
    assert [entry["token"] for entry in out] == ["«REDACTED:fragment»", "", ""]
    # A fragment mask is the tool's own: kept as written by the redactor.
    assert Redactor().redact_text("«REDACTED:fragment»") == "«REDACTED:fragment»"


def test_split_texts_yields_the_text_of_each_stream() -> None:
    value = {
        "logprobs": _tokens(["ab", "cd"]),
        "websocket": _transcript("Hel", "lo"),
        "records": [{"t": "x"}, {"t": "y"}],
    }
    # A rank of alternatives is no stream: side by side they are text no one wrote (LOW 5).
    assert sorted(split_texts(value)) == ["Hello", "abcd"]


def test_an_alternative_keeps_nothing_of_a_masked_token(no_known_secrets: None) -> None:
    """The alternatives are masked once every edit of the item is made (audit of c4bd2012, M2).

    A rank's own edit used to land after them and leave 10 characters of a labelled password in
    an alternative the model weighed for the same piece.
    """

    key = "sk-bWvZb09c2UtWLhweqZ9hEafMIF4SMdBEE9pt8JmK"
    pieces = ["the", " password", ": vA4z", "IISwZmSo#K", " " + key[:12], key[12:24], key[24:]]
    items = _tokens([*pieces, " end"])
    items[3]["top"] = [["IISwZmSo#K", -0.1], ["IISwZmSo#K " + key[:30], -1.0]]
    out = redact_split(Redactor(salt="s"), {"lp": items})
    assert isinstance(out, dict)
    for entry in out["lp"]:
        for alternative, _ in entry["top"]:
            assert "vA4zIISwZmSo" not in alternative and "IISwZmSo" not in alternative
            assert key[:12] not in alternative


def test_a_clean_reply_s_alternatives_are_kept_as_they_came() -> None:
    """A rank of alternatives is not joined: side by side they read as a key (LOW 5)."""

    rng = random.Random(7)  # noqa: S311 - a seeded fixture, not a secret
    text = "The answer depends on the configuration you chose earlier today."
    pieces = _pieces(text)
    items = [
        {
            "token": piece,
            "logprob": -0.2,
            "top": [
                [piece, -0.2],
                ["".join(rng.choice(string.ascii_letters) for _ in range(4)), -3],
            ],
        }
        for piece in pieces
    ]
    assert redactor_mod._shannon_entropy("".join(i["top"][1][0] for i in items)) > 4.0
    assert mask_split(Redactor(salt="s"), items) is items


def test_the_bytes_of_a_masked_token_or_alternative_are_dropped() -> None:
    """OpenAI's `bytes` spell a token whatever its text shows (audit of c4bd2012, LOW 4)."""

    def entry(token: str, alternative: str) -> dict[str, object]:
        return {
            "token": token,
            "logprob": -0.1,
            "bytes": list(token.encode()),
            "top_logprobs": [
                {"token": token, "logprob": -0.1, "bytes": list(token.encode())},
                {"token": alternative, "logprob": -1.0, "bytes": list(alternative.encode())},
            ],
        }

    items = [entry("Mail ", "x"), entry(EMAIL, "y"), entry(" or", KEY), entry(" now", "z")]
    out = redact_split(Redactor(salt="s"), {"content": items})
    assert isinstance(out, dict)
    kept = out["content"]
    assert kept[1]["bytes"] is None and kept[1]["top_logprobs"][0]["bytes"] is None
    assert kept[2]["bytes"] == list(b" or") and kept[2]["top_logprobs"][1]["bytes"] is None
    assert kept[2]["top_logprobs"][0] == {"token": " or", "logprob": -0.1, "bytes": list(b" or")}
    assert kept[0]["bytes"] == list(b"Mail ") and kept[3]["top_logprobs"][1]["bytes"] == [122]
    spelled = bytes(b for e in kept for a in (e, *e["top_logprobs"]) for b in a["bytes"] or [])
    assert EMAIL.encode() not in spelled and KEY.encode() not in spelled


def test_withholding_empties_every_piece_and_keeps_the_rest() -> None:
    value = {
        "text": "kept as it is",
        "logprobs": _tokens(["ab", "cd"]),
        "raw_ids": {"id": "r-1", "websocket": _transcript("Hel", "lo")},
    }
    out = withhold_split(value)
    assert isinstance(out, dict)
    assert out["text"] == "kept as it is" and out["raw_ids"]["id"] == "r-1"
    assert [e["token"] for e in out["logprobs"]] == ["", ""]
    assert [e["top"] for e in out["logprobs"]] == [[["", -0.01], ["", -4.0]]] * 2
    assert [e["logprob"] for e in out["logprobs"]] == [-0.01, -0.02]
    assert _deltas(out["raw_ids"]["websocket"]) == ""
    frames = out["raw_ids"]["websocket"][TRANSCRIPT_FRAMES]
    assert [f["frame"]["type"] for f in frames] == [
        f["frame"]["type"]
        for f in value["raw_ids"]["websocket"][TRANSCRIPT_FRAMES]  # type: ignore[index]
    ]
    assert list(split_texts(out)) == ["", ""]
    plain = {"text": "x", "tool_calls": [{"name": "a"}, {"name": "b"}]}
    assert withhold_split(plain) is plain


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


#: URLs whose password the URL rule masks, by the password (pre-merge audit of c4bd2012, HIGH 1).
_URLS = {
    "postgresql://user:password@localhost:5432/mydb": "password",
    "redis://:hunter2hunter2@cache:6379/0": "hunter2hunter2",
    "postgresql://u:longpassword123@h/x": "longpassword123",
    "mongodb+srv://admin:S3cr3tPass@cluster0.example.net/db": "S3cr3tPass",
}

_FILLER = st.text(alphabet=string.ascii_lowercase + " ,.", min_size=0, max_size=30)


@settings(max_examples=150, deadline=None)
@given(
    before=_FILLER,
    after=_FILLER,
    which=st.sampled_from([KEY, REGISTERED, EMAIL, *_URLS]),
    cuts=st.lists(st.integers(min_value=1, max_value=4), min_size=1, max_size=80),
    streamed=st.booleans(),
)
def test_no_split_of_a_secret_survives_joined(
    before: str, after: str, which: str, cuts: list[int], streamed: bool
) -> None:
    """Wherever the pieces are cut, as tokens or as deltas, no secret is in them joined, and
    every joined text is a fixed point: a URL password masked in pieces read as a run of masks
    the URL rule masked again, and the store's guard refused it (audit of c4bd2012, HIGH 1)."""

    text = f"{before} {which} {after}"
    pieces: list[str] = []
    start = 0
    for size in cuts:
        if start >= len(text):
            break
        pieces.append(text[start : start + size])
        start += size
    pieces.append(text[start:])
    redactor = Redactor(salt="s")
    with _registering(REGISTERED):
        if streamed:
            out: object = redact_split(redactor, _transcript(*pieces))
            joined = _deltas(out)
        else:
            out = redact_split(redactor, _tokens(pieces))
            assert isinstance(out, list) and len(out) == len(pieces)
            joined = "".join(entry["token"] for entry in out)
        assert all(redactor.redact_text(text) == text for text in split_texts(out))
    private = _URLS.get(which, which)
    bare = re.sub(r"«REDACTED:[^»]*»", "", joined)  # `url_password` names a mask, not a value
    assert private not in bare
    assert private[2:-2] not in bare
