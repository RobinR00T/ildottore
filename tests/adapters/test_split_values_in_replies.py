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
import re
from pathlib import Path

import pytest

from ildottore.adapters.base import ResponseMalformed, reply_excerpt
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
