"""A reply split into pieces is masked as the text the pieces make where adapters keep it (A-77).

Audit of main ``de122e26``, HIGH 1: the WebSocket adapter kept each delta of a turn in
``raw_ids.websocket.frames`` redacted on its own, and quoted the frames of a turn it could not
read (``json.dumps`` of them) in the excerpt, so a secret streamed in three deltas was rebuilt
from either. A reply in the wrong shape is quoted as its body, which has the same hole for a
value an HTTP target split over a list.
"""

from __future__ import annotations

import contextlib
import json
import random
import re
import string
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from ildottore.adapters.base import ResponseMalformed, _split_masked, reply_excerpt
from ildottore.redactor import Redactor, register_known_secret
from ildottore.shared.models import Attempt, ModelRequest
from ildottore.store import FsEvidenceStore
from tests.adapters.test_websocket import _adapter, _spec
from tests.ws_chat_server import TOKEN, FakeChatServer

KEY = "sk-proj-Qx7Lm2Vt9Rw4Zb8Nc3Kp6Hy1Js5Df0Ga"
REGISTERED = "CorrectHorseBatteryStaple-2026-ops"
EMAIL = "alice.wong@corp-example.com"
SECRETS = (KEY, REGISTERED, EMAIL)


def _thirds(text: str) -> list[str]:
    """The three deltas the fake server streams ``text`` in."""

    third = max(1, len(text) // 3)
    return [text[:third], text[third : 2 * third], text[2 * third :]]


@pytest.fixture
def registered(no_known_secrets: None) -> None:
    register_known_secret(TOKEN)
    register_known_secret(REGISTERED)


@pytest.mark.parametrize("secret", SECRETS)
async def test_a_streamed_secret_is_masked_in_the_transcript_and_the_evidence(
    registered: None, secret: str, tmp_path: Path
) -> None:
    with FakeChatServer("echo") as server:
        response = await _adapter(server).send(ModelRequest(prompt=secret))
    assert response.text == secret  # in memory, the reply the evaluators read is whole
    frames = response.raw_ids["websocket"]["frames"]
    deltas = [f["frame"]["delta"]["text"] for f in frames if "delta" in f["frame"]]
    assert len(deltas) == 3
    assert secret not in "".join(deltas)
    assert not any(chunk in "".join(deltas) for chunk in _thirds(secret))
    attempt = Attempt(
        attempt_id="a-ws",
        spec_id="PI-DEMO-001",
        request=ModelRequest(prompt="x"),
        response=response,
    )
    ref = FsEvidenceStore(tmp_path, redactor=Redactor(salt="s")).put("run-ws", attempt)
    doc = json.loads((tmp_path / ref.uri).read_text(encoding="utf-8"))
    kept = doc["response"]["raw_ids"]["websocket"]["frames"]
    joined = "".join(f["frame"].get("delta", {}).get("text", "") for f in kept)
    assert secret not in joined and "«REDACTED:" in joined


@pytest.mark.parametrize("secret", SECRETS)
async def test_the_excerpt_of_a_turn_with_no_text_does_not_rebuild_a_streamed_secret(
    registered: None, secret: str
) -> None:
    """The text sits off ``text_path``: the turn is unreadable and its frames are quoted."""

    with FakeChatServer("echo") as server:
        adapter = _adapter(server, _spec(response={"text_path": "delta.content"}))
        with pytest.raises(ResponseMalformed) as caught:
            await adapter.send(ModelRequest(prompt=secret))
    excerpt = caught.value.excerpt
    assert excerpt is not None and "REDACTED:" in excerpt
    assert not any(chunk in excerpt for chunk in _thirds(secret))
    # The protocol's fields stay readable: they are what tells the operator where the text is.
    frames = json.loads(excerpt)
    assert [frame["type"] for frame in frames] == [
        "auth_ok",
        "session",
        "delta",
        "ping",
        "delta",
        "typing",
        "delta",
        "done",
    ]


def _openai_body(text: str, content: object) -> bytes:
    """An OpenAI reply whose message the adapter cannot read, with its logprobs in 5s."""

    pieces = [text[i : i + 5] for i in range(0, len(text), 5)]
    tokens = [
        {
            "token": p,
            "logprob": -0.1,
            "bytes": list(p.encode()),
            "top_logprobs": [{"token": p, "logprob": -0.1, "bytes": list(p.encode())}],
        }
        for p in pieces
    ]
    choice = {"index": 0, "message": {"role": "assistant", "content": content}}
    return json.dumps({"choices": [{**choice, "logprobs": {"content": tokens}}]}).encode()


def test_an_http_body_in_the_wrong_shape_is_quoted_with_its_logprobs_masked(
    registered: None,
) -> None:
    text = f"the key {KEY} pw {REGISTERED} ok"
    body = _openai_body(text, [{"type": "text", "text": text}])
    excerpt, size = reply_excerpt(body, Redactor(salt="s"))
    assert size == len(body)
    entries = json.loads(excerpt)["choices"][0]["logprobs"]["content"]
    for field in ("token", "alternative"):
        joined = "".join(
            e["token"] if field == "token" else e["top_logprobs"][0]["token"] for e in entries
        )
        assert KEY not in joined and REGISTERED not in joined and "REDACTED:" in joined
        assert joined.startswith("the key ") and joined.endswith(" ok")
    # The UTF-8 numbers OpenAI writes beside a token spell it: dropped where it is masked.
    spelled = bytes(b for e in entries for b in (e["bytes"] or [])).decode()
    assert spelled.startswith("the k") and KEY not in spelled and REGISTERED not in spelled
    assert all(e["bytes"] is None for e in entries if "REDACTED:" in e["token"])
    # A body that is not JSON, or holds nothing split, is quoted as it came.
    for unchanged in (
        b"<html>sk-proj-Qx7 Lm2Vt9</html>",
        json.dumps({"chunks": ["sk-proj-Qx7", "Lm2Vt9"]}).encode(),
        _openai_body("I cannot help with that.", None),
    ):
        assert reply_excerpt(unchanged, Redactor(salt="s"))[0] == unchanged.decode()


@pytest.mark.parametrize("secret", SECRETS)
def test_an_event_stream_s_excerpt_does_not_rebuild_a_streamed_secret(
    registered: None, secret: str
) -> None:
    """A reply streamed as server-sent events when none was asked for is not JSON: it was quoted
    as it came, each delta redacted alone (pre-merge audit of c4bd2012, MEDIUM 3)."""

    text = f"Sure, here it is: {secret} done"
    chunks = [text[i : i + 3] for i in range(0, len(text), 3)]
    events = [
        {"id": "c1", "object": "chat.completion.chunk", "choices": [{"delta": {"content": c}}]}
        for c in chunks
    ]
    body = "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n"
    excerpt, size = reply_excerpt(body.encode(), Redactor(salt="s"))
    assert size == len(body.encode())
    lines = [line for line in excerpt.splitlines() if line.startswith("data: {")]
    deltas = "".join(json.loads(line[6:])["choices"][0]["delta"]["content"] for line in lines)
    assert secret not in deltas and "REDACTED:" in deltas
    assert deltas.startswith("Sure, here it is: ") and deltas.endswith(" done")
    # The protocol's fields stay as the server wrote them, and so do the lines that are no event.
    assert {json.loads(line[6:])["object"] for line in lines} == {"chat.completion.chunk"}
    assert excerpt.rstrip().endswith("data: [DONE]")
    clean = "".join(f"data: {json.dumps({'type': 'delta', 'text': c})}\n\n" for c in "a b c")
    assert reply_excerpt(clean, Redactor(salt="s"))[0] == clean


#: Numbers grouped the French way, with a no-break space (U+00A0) or a narrow one (U+202F): the
#: phone and card rules read them raw, never ``\u00a0``-escaped.
_GROUPED = (
    (
        "phone, no-break spaces",
        "Appelez le +33\u00a06\u00a012\u00a034\u00a056\u00a078 merci.",
        "12",
    ),
    ("card, narrow no-break spaces", "Votre carte : 4111\u202f1111\u202f1111\u202f1111.", "1111"),
    ("card, no-break spaces", "Votre carte : 4111\u00a01111\u00a01111\u00a01111.", "1111"),
)


def _digits(excerpt: str) -> str:
    """The excerpt with every JSON string decoded and every space dropped, to read a number in."""

    decoded = excerpt
    for value in re.findall(r'"((?:[^"\\]|\\.)*)"', excerpt):
        with contextlib.suppress(ValueError):
            decoded += "\n" + json.loads('"' + value + '"')
    return re.sub(r"[\s\u00a0\u202f\u2009]", "", decoded)


@pytest.mark.parametrize(("name", "text", "group"), _GROUPED, ids=[g[0] for g in _GROUPED])
def test_a_json_body_rewritten_for_its_logprobs_keeps_a_grouped_number_masked(
    name: str, text: str, group: str
) -> None:
    """Rewritten with ``ensure_ascii``, the text outside the stream reached redaction escaped and
    the phone and card rules missed it, where main masked it (second pre-merge audit, MEDIUM 1)."""

    body = _openai_body(text, [{"type": "text", "text": text}])
    excerpt, _ = reply_excerpt(body, Redactor(salt="s"))
    digits = re.sub(r"\D", "", text)
    assert digits[2:] not in _digits(excerpt), excerpt[:300]
    assert "\\u00a0" not in excerpt and "\\u202f" not in excerpt


@pytest.mark.parametrize(("name", "text", "group"), _GROUPED, ids=[g[0] for g in _GROUPED])
def test_an_event_stream_rewritten_keeps_a_grouped_number_masked(
    name: str, text: str, group: str
) -> None:
    deltas = "".join(
        f"data: {json.dumps({'choices': [{'delta': {'content': c}}]})}\n\n"
        for c in [KEY[i : i + 3] for i in range(0, len(KEY), 3)]
    )
    note = f"data: {json.dumps({'error': {'message': text}}, ensure_ascii=False)}\n\n"
    excerpt, _ = reply_excerpt(note + deltas, Redactor(salt="s"))
    assert KEY not in _digits(excerpt)
    assert re.sub(r"\D", "", text)[2:] not in _digits(excerpt), excerpt[:300]


def _oai(chunk: str, **extra: object) -> str:
    return json.dumps(
        {"object": "chat.completion.chunk", "choices": [{"delta": {"content": chunk}}]} | extra
    )


#: Event streams the format allows, and Ollama's NDJSON, each streaming a text in 3-character
#: deltas (second pre-merge audit, MEDIUM 2: all but the first were rebuilt from the excerpt).
_STREAMS = {
    "one JSON object per event": lambda cs: "".join(f"data: {_oai(c)}\n\n" for c in cs),
    "CR only": lambda cs: "".join(f"data: {_oai(c)}\r\r" for c in cs),
    "a byte order mark first": lambda cs: "﻿" + "".join(f"data: {_oai(c)}\n\n" for c in cs),
    "an event's JSON over two data lines": lambda cs: "".join(
        "data: " + _oai(c).replace(', "choices"', ',\ndata: "choices"', 1) + "\n\n" for c in cs
    ),
    "U+2028 raw in each event's JSON": lambda cs: "".join(
        f"data: {_oai(c, note=chr(0x2028))}\n\n".replace("\\u2028", chr(0x2028)) for c in cs
    ),
    "U+0085 raw in each event's JSON": lambda cs: "".join(
        f"data: {_oai(c, note=chr(0x85))}\n\n".replace("\\u0085", chr(0x85)) for c in cs
    ),
    "plain-text data": lambda cs: "".join(f"data: {c}\n\n" for c in cs),
    "JSON-string data": lambda cs: "".join(f"data: {json.dumps(c)}\n\n" for c in cs),
    "a log page of data lines": lambda cs: (
        "log\n" + "".join(f"data: {json.dumps({'m': c})}\n" for c in cs)
    ),
    "NDJSON, as Ollama streams": lambda cs: "".join(
        json.dumps(
            {"model": "llama3", "message": {"role": "assistant", "content": c}, "done": False}
        )
        + "\n"
        for c in cs
    ),
}


def _rebuilt(excerpt: str) -> str:
    """Every string the excerpt quotes, decoded, and every line's data, joined in order."""

    values = []
    for value in re.findall(r'"(?:content|m)": "((?:[^"\\]|\\.)*)"', excerpt):
        values.append(json.loads('"' + value + '"'))
    for line in re.split("\r\n|\r|\n", excerpt.removeprefix("﻿")):
        if line.startswith("data:"):
            data = line[5:].strip()
            with contextlib.suppress(ValueError):
                data = json.loads(data) if data.startswith('"') else data
            values.append(data if isinstance(data, str) else "")
    return "".join(values)


@pytest.mark.parametrize("shape", list(_STREAMS))
@pytest.mark.parametrize("secret", [KEY, REGISTERED])
def test_a_streamed_secret_is_masked_in_every_shape_of_event_stream(
    registered: None, secret: str, shape: str
) -> None:
    text = f"Sure, here it is: {secret} done"
    body = _STREAMS[shape]([text[i : i + 3] for i in range(0, len(text), 3)])
    excerpt, size = reply_excerpt(body.encode(), Redactor(salt="s"))
    assert size == len(body.encode())
    assert secret[8:20] not in _rebuilt(excerpt), excerpt[:400]
    assert "REDACTED:" in excerpt
    # Nothing to mask: quoted as it came.
    clean = _STREAMS[shape]([text[i : i + 3] for i in range(0, 18, 3)])
    assert reply_excerpt(clean.encode(), Redactor(salt="s"))[0] == clean


def test_a_json_lines_log_is_records_and_quoted_as_main_quotes_it() -> None:
    """Read as a stream, a log's fields were joined across its records and masked: 181 of 217
    clean logs were quoted otherwise than by main (third pre-merge audit, LOW 2)."""

    words = ["debug", "r7", "Kx", "info", "Wq3", "auth", "Zp", "ok9"]  # joined: high entropy
    body = "".join(
        json.dumps(
            {"ts": f"2026-10-12T08:00:{i:02d}Z", "msg": w, "req": f"r{i}"}, separators=(",", ":")
        )
        + "\n"
        for i, w in enumerate(words * 3)
    )
    assert _split_masked(body, Redactor(salt="s")) is body
    excerpt, _ = reply_excerpt(body, Redactor(salt="s"))
    assert excerpt == Redactor(salt="s").redact_text(body)
    # OpenAI chunks written as JSON lines are a stream, as Ollama's lines are.
    text = f"Sure: {KEY} ok"
    chunks = "".join(
        json.dumps({"object": "chat.completion.chunk", "choices": [{"delta": {"content": c}}]})
        + "\n"
        for c in [text[i : i + 3] for i in range(0, len(text), 3)]
    )
    assert KEY[8:20] not in _rebuilt(reply_excerpt(chunks, Redactor(salt="s"))[0])


def test_a_block_of_data_lines_is_read_line_by_line_beside_a_masked_event(
    registered: None,
) -> None:
    """The line-by-line reading ran only when the format's masked nothing (LOW 3)."""

    email = "alice.wong@corp-example.com"
    text = f"Here: {KEY} ok"
    body = (
        f"data: {_oai('mail ' + email[:10])}\n\ndata: {_oai(email[10:])}\n\n"
        + "".join(f"data: {text[i : i + 3]}\n" for i in range(0, len(text), 3))
        + "\n"
    )
    excerpt, _ = reply_excerpt(body, Redactor(salt="s"))
    assert email not in _rebuilt(excerpt) and KEY[8:20] not in _rebuilt(excerpt)


def test_only_the_head_the_excerpt_reads_is_read_and_a_secret_past_it_is_left_out(
    no_known_secrets: None,
) -> None:
    """A 4 MiB stream of tiny events cost up to 12.8 s (LOW 4). Read up to its window, a
    registered credential whose deltas run past the window is not shown in part: the streamed
    text of a body the window cuts is withheld."""

    import time

    hostile = "data\n\n" * (4 * 1024 * 1024 // 6)
    started = time.perf_counter()
    reply_excerpt(hostile, Redactor(salt="s"))
    assert time.perf_counter() - started < 2.0
    # Words no rule masks in part: nothing keeps their head out of the excerpt but withholding.
    secret = "correct horse battery staple and a quiet harbour"
    register_known_secret(secret)
    pad = "p" * 1200  # each delta's event carries this much else, as a target may write it
    body = "".join(
        f"data: {json.dumps({'choices': [{'delta': {'content': c}}], 'pad': pad})}\n\n"
        for c in secret + " outro"
    )
    assert len(body) > 40_000  # the credential's deltas run past the window
    excerpt, _ = reply_excerpt(body, Redactor(salt="s"))
    assert secret[:3] not in _rebuilt(excerpt), excerpt[:200]
    assert '"content": ""' in excerpt  # withheld, not masked: the window read only its head
    # A clean stream longer than the window has its text withheld too, its structure kept.
    words = ("the reply goes on and on " * 3000).split(" ")
    clean = "".join(
        "event: content_block_delta\ndata: "
        + json.dumps({"type": "content_block_delta", "delta": {"type": "text_delta", "text": w}})
        + "\n\n"
        for w in words
    )
    assert len(clean) > 200_000
    withheld = cast("str", _split_masked(clean, Redactor(salt="s")))
    assert withheld.startswith("[il dottore: ") and '"text": "the"' not in withheld
    assert '"type": "text_delta"' in withheld


#: Stream shapes in which a secret straddling the window's cut showed its beginning (fourth
#: pre-merge audit, MEDIUM: window_attacks.py, case A).
_CUT_SHAPES = {
    "plain-text data": lambda c: f"data: {c}\n\n",
    "NDJSON, as Ollama streams": lambda c: (
        json.dumps(
            {"model": "llama3", "message": {"role": "assistant", "content": c}, "done": False}
        )
        + "\n"
    ),
    "NDJSON, OpenAI chunks": lambda c: _oai(c) + "\n",
}
URL_PASSWORD = "Corr3ct!Horse#Batt3ry$Stapl3"


def _shows(excerpt: str, private: str) -> bool:
    """Whether six characters in a row of ``private`` are in what the excerpt quotes, joined."""

    joined = re.sub("«REDACTED:[A-Za-z0-9_]+(?::[0-9a-f]{8})?»", "\0", _rebuilt(excerpt))
    return any(private[i : i + 6] in joined for i in range(len(private) - 5))


def _straddling(write: Callable[[str], str], text: str, k: int, seed: int) -> str:
    """A body whose window's cut falls inside ``text``'s ``k``-th 3-character delta, after a
    blob in 1,000-character deltas that masking collapses to one mask, so what lay near the cut
    moves up into the 4 KiB the excerpt shows."""

    from ildottore.adapters.base import _stream_window

    rng = random.Random(seed)  # noqa: S311 - a seeded fixture, not a secret
    alphabet = string.ascii_letters + string.digits
    window, _ = _stream_window()
    pieces = [text[i : i + 3] for i in range(0, len(text), 3)]
    head = "".join(write(piece) for piece in pieces[:k])
    target = window - len(head) - len(write(pieces[k])) // 2
    blob, size = [], 0
    while target - size > 2200:
        blob.append(write("".join(rng.choice(alphabet) for _ in range(1000))))
        size += len(blob[-1])
    rest = target - size - len(write(""))
    blob.append(write("".join(rng.choice(alphabet) for _ in range(max(1, rest)))))
    return "".join(blob) + head + "".join(write(piece) for piece in pieces[k:])


@pytest.mark.parametrize("shape", list(_CUT_SHAPES))
def test_a_secret_straddling_the_window_s_cut_shows_no_beginning(
    no_known_secrets: None, shape: str
) -> None:
    """Masks shortened the window's text, so its second half reached the excerpt, and the open
    tail stopped at a symbol: a URL password showed `Corr3ct!` at 7 of 31 cuts."""

    text = f" the key is https://ops:{URL_PASSWORD}@db.internal:5432/v1 and more"
    for k in range(1, len(text) // 3):
        body = _straddling(_CUT_SHAPES[shape], text, k, seed=k)
        excerpt, _ = reply_excerpt(body, Redactor(salt="s"))
        assert not _shows(excerpt, URL_PASSWORD), (k, excerpt[-300:])


def test_a_long_registered_credential_straddling_the_cut_shows_no_beginning(
    no_known_secrets: None,
) -> None:
    """A 300-character registered credential with symbols and spaces, partly masked by the
    entropy rule, no longer ended the masked text as written: 70 of 111 cuts showed part of it."""

    rng = random.Random(5)  # noqa: S311 - a seeded fixture, not a secret
    secret = "".join(rng.choice(string.ascii_letters + string.digits + "!#$% ") for _ in range(300))
    register_known_secret(secret)
    text = f" the key is {secret} and more"
    for k in range(4, len(text) // 3, 3):
        body = _straddling(_CUT_SHAPES["plain-text data"], text, k, seed=k)
        excerpt, _ = reply_excerpt(body, Redactor(salt="s"))
        assert not _shows(excerpt, secret), (k, excerpt[-300:])


def test_a_secret_from_the_shown_half_past_the_cut_shows_no_beginning(
    no_known_secrets: None,
) -> None:
    """Pieces that reach from the window's first half past its cut: a registered credential in
    1-character deltas each carrying 100 characters more, and a URL password whose beginning is
    glued to a run of 300 letters, which the run of key characters was too long to be read as."""

    from ildottore.adapters.base import _stream_window

    rng = random.Random(4)  # noqa: S311 - a seeded fixture, not a secret
    alphabet = string.ascii_letters + string.digits
    secret = "".join(rng.choice(alphabet + "!#$% ") for _ in range(300))
    register_known_secret(secret)
    _, settled = _stream_window()

    def event(content: str, pad: str = "") -> str:
        return f"data: {json.dumps({'choices': [{'delta': {'content': content}}], 'pad': pad})}\n\n"

    def blob(before: int) -> str:
        out = ""
        while settled - before - len(out) > 1500:
            out += event("".join(rng.choice(alphabet) for _ in range(1000)))
        return out

    spread = "".join(event(c, "p" * 100) for c in secret)
    body = blob(600) + event(" the key is ") + spread + event(" done")
    excerpt, _ = reply_excerpt(body, Redactor(salt="s"))
    assert not _shows(excerpt, secret), excerpt[-300:]
    glue = "".join(rng.choice(string.ascii_lowercase) for _ in range(300))
    head = "".join(event(c) for c in ("htt", "ps:", "//o", "ps:", "Cor", "r3c", "t!"))
    tail = "".join(event(c, "p" * 1200) for c in "Horse#Batt3ry$Stapl3@db.internal:5432/v1")
    pre = event(" the key is " + glue) + head
    body = blob(len(pre) + 300) + pre + tail + event(" done")
    excerpt, _ = reply_excerpt(body, Redactor(salt="s"))
    assert not _shows(excerpt, URL_PASSWORD), excerpt[-300:]


def _chunk_with_logprobs(piece: str, alternative: str) -> str:
    """An OpenAI chunk as streamed with logprobs: the token's UTF-8 beside it, an alternative."""

    item = {
        "token": piece,
        "logprob": -0.01,
        "bytes": list(piece.encode()),
        "top_logprobs": [
            {"token": alternative, "logprob": -2.5, "bytes": list(alternative.encode())}
        ],
    }
    choice = {"index": 0, "delta": {"content": piece}, "logprobs": {"content": [item]}}
    return f"data: {_oai(piece, choices=[choice])}\n\n"


def _spelled(excerpt: str) -> tuple[str, str]:
    """What the excerpt's chunks spell: their tokens' ``bytes``, and their alternatives joined."""

    numbers: list[int] = []
    alternatives = ""
    for line in excerpt.split("\n"):
        with contextlib.suppress(ValueError):
            item = json.loads(line.removeprefix("data: "))["choices"][0]["logprobs"]["content"][0]
            numbers += item.get("bytes") or []
            alternatives += item["top_logprobs"][0]["token"]
    return bytes(numbers).decode("utf-8", "replace"), alternatives


def test_an_event_stream_s_logprobs_spell_no_masked_token(no_known_secrets: None) -> None:
    """Each chunk's logprob list holds one token, so it was no logprob list: the tokens were
    masked as the transcript's stream, but their ``bytes`` stayed and spelled the key, and each
    rank of alternatives was joined across the chunks as a stream of its own, which A-77 says
    alternatives are not (masking clean replies)."""

    text = f"Sure, here it is: {KEY} done"
    pieces = [text[i : i + 3] for i in range(0, len(text), 3)]
    body = "".join(_chunk_with_logprobs(piece, piece) for piece in pieces)
    excerpt, _ = reply_excerpt(body, Redactor(salt="s"))
    spelled, alternatives = _spelled(excerpt)
    assert KEY[8:20] not in _rebuilt(excerpt)
    assert KEY[8:20] not in spelled, spelled
    assert KEY[8:20] not in alternatives
    # A key in one token, masked on its own: its bytes go too.
    body = "".join(_chunk_with_logprobs(piece, "x") for piece in ("Here: ", KEY, " ok"))
    assert KEY[8:20] not in _spelled(reply_excerpt(body, Redactor(salt="s"))[0])[0]
    # Alternatives no join masks: a clean reply is quoted as it came.
    words = ["Paris", "is", "the", "capital", "of", "France", "and", "it", "has", "many"]
    pairs = zip(words, words[::-1], strict=True)
    clean = "".join(_chunk_with_logprobs(" " + word, other) for word, other in pairs)
    assert _split_masked(clean, Redactor(salt="s")) is clean


def test_what_is_no_stream_is_quoted_as_it_came() -> None:
    """One event, JSON lines that are arrays, Ollama's lines with blank lines between them."""

    single = f"data: {_oai(KEY[:10])}\n\n"
    assert _split_masked(single, Redactor(salt="s")) is single
    arrays = "".join(json.dumps([KEY[i : i + 3]]) + "\n" for i in range(0, len(KEY), 3))
    assert _split_masked(arrays, Redactor(salt="s")) is arrays
    spaced = "".join(
        json.dumps({"message": {"content": KEY[i : i + 3]}, "done": False}) + "\n\n"
        for i in range(0, len(KEY), 3)
    )
    excerpt, _ = reply_excerpt(spaced, Redactor(salt="s"))
    assert KEY[8:20] not in _rebuilt(excerpt) and "\n\n" in excerpt
