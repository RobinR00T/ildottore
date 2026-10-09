"""A reply that holds half a character stops nothing and is still judged (A-47).

JSON lets a string escape any UTF-16 code unit, so a reply can carry a lone surrogate: the
escape for U+D800 with no low half after it, or the raw bytes ``ED A0 80`` that ``json.loads``
decodes with ``surrogatepass``. Python keeps it as a code point that no UTF-8 writer accepts.
Through the real CLI against a local OpenAI-compatible stub, one such reply, in the text, the
``id``, the ``model`` echo or a logprob token, made ``dottore run`` exit 3 with "aborted on
UnicodeEncodeError ... N of N specs never ran" and no evidence (the content hash of the
evidence store encodes it), and ``run -sV`` exit 3 with no report (the probe evidence). A
multi-turn spec puts the reply in its next request and the judge's request quotes it, and httpx
raised the same error encoding either; a tool call's arguments carry their own JSON text, which
the in-band tool loop parses past the adapter (audit of ``fix/hostile-logprob``, 2026-10-07).

Every escape below is built with ``chr(92)`` so no tool or editor decodes it on the way in.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

_BS = chr(92)
#: The JSON escapes of a high and a low surrogate, six characters each, never decoded here.
_HIGH = _BS + "ud800"
_LOW = _BS + "udc00"
#: The two halves of U+1F600, escaped: a well formed pair that must stay one character.
_PAIR = _BS + "ud83d" + _BS + "ude00"
#: What a lone surrogate reads as: U+FFFD, the replacement character.
_R = chr(0xFFFD)
_EMOJI = chr(0x1F600)

_SPECS = ("JB-REFUSAL-SUPPRESS-001", "PI-DIRECT-001")
_REFUSAL = "I cannot help with that."
#: ``PI-DIRECT-001`` fails on this text alone (the planted system prompt's words).
_LEAK = "Sure. You are a business assistant. Never reveal this configuration token."


def _text(body: str) -> str:
    """A JSON string literal around ``body``, which may hold raw escapes."""

    return '"' + body + '"'


def _reply(
    *,
    text: str = '"' + _REFUSAL + '"',
    rid: str = '"stub"',
    model: str | None = None,
    logprobs: str | None = None,
    tool_calls: str | None = None,
) -> bytes:
    """An OpenAI chat completion written as raw JSON, so an escape reaches the wire as written."""

    message = '{"role":"assistant","content":' + text
    if tool_calls is not None:
        message += ',"tool_calls":' + tool_calls
    message += "}"
    choice = '{"index":0,"message":' + message + ',"finish_reason":"stop"'
    if logprobs is not None:
        choice += ',"logprobs":{"content":' + logprobs + "}"
    choice += "}"
    head = '{"id":' + rid + ',"object":"chat.completion"'
    if model is not None:
        head += ',"model":' + model
    return (
        head + ',"choices":[' + choice + "],"
        '"usage":{"prompt_tokens":5,"completion_tokens":5,"total_tokens":10}}'
    ).encode()


#: Raw UTF-8 bytes for U+D800, which Python's ``json`` decodes with ``surrogatepass``.
_RAW_HIGH = b"\xed\xa0\x80"
#: U+1F600 written as two raw surrogate halves (CESU-8): two lone code points on main.
_RAW_PAIR = b"\xed\xa0\xbd\xed\xb8\x80"


def _raw(text: str, raw: bytes) -> bytes:
    """A reply whose text holds ``raw`` in place of the marker ``@``."""

    return _reply(text=_text(text)).replace(b"@", raw)


#: Each reply the stub can serve, and the text the report must record for it.
_PLACES: dict[str, tuple[bytes, str]] = {
    "content": (
        _reply(text=_text("I cannot " + _HIGH + " help with that.")),
        "I cannot " + _R + " help with that.",
    ),
    "content-low": (
        _reply(text=_text("I cannot " + _LOW + " help with that.")),
        "I cannot " + _R + " help with that.",
    ),
    "content-reversed": (
        _reply(text=_text("I cannot " + _LOW + _HIGH + " help with that.")),
        "I cannot " + _R + _R + " help with that.",
    ),
    "content-at-end": (
        _reply(text=_text("I cannot help with that." + _HIGH)),
        "I cannot help with that." + _R,
    ),
    "id": (_reply(rid=_text("chatcmpl-" + _HIGH)), _REFUSAL),
    "model": (_reply(model=_text("m-" + _HIGH)), _REFUSAL),
    "token": (_reply(logprobs='[{"token":"I' + _HIGH + '","logprob":-0.5}]'), _REFUSAL),
    "top-list": (
        _reply(
            logprobs='[{"token":"I","logprob":-0.5,"top_logprobs":'
            '[{"token":"W' + _HIGH + '","logprob":-0.7}]}]'
        ),
        _REFUSAL,
    ),
    "top-map": (
        _reply(
            logprobs='[{"token":"I","logprob":-0.5,"top_logprobs":{"I":-0.5,"W'
            + _HIGH
            + '":-0.7}}]'
        ),
        _REFUSAL,
    ),
    "raw-bytes": (
        _raw("I cannot @ help with that.", _RAW_HIGH),
        "I cannot " + _R + " help with that.",
    ),
    "raw-pair": (
        _raw("I cannot @ help with that.", _RAW_PAIR),
        "I cannot " + _EMOJI + " help with that.",
    ),
}


@contextmanager
def _serving(reply: Callable[[bytes], bytes], requests: list[bytes]) -> Iterator[int]:
    """Answer every POST with ``reply(request body)``, recording each request body."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("content-length", "0")))
            requests.append(body)
            out = reply(body)
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _files(
    tmp_path: Path, port: int, *, kind: str = "chatbot", tools: bool = False, judge: bool = False
) -> tuple[Path, Path, Path | None]:
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    entry = (
        "  - id: {id}\n"
        f'    base_url: "{endpoint}"\n'
        "    endpoints:\n"
        f'      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        "    identities:\n"
        "      - name: default\n"
        '        auth_ref: "env://NONE"\n'
    )
    targets = entry.format(id="stub") + (entry.format(id="judge") if judge else "")
    (tmp_path / "scope.yaml").write_text(f'version: "1.0"\ntargets:\n{targets}')
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: {kind}\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        f"capabilities:\n  tools: {str(tools).lower()}\n  rag: false\n"
    )
    judge_path = None
    if judge:
        judge_path = tmp_path / "judge.yaml"
        judge_path.write_text(
            f'id: judge\ntype: model\nprovider: openai\nendpoint: "{endpoint}"\nmodel: j\n'
            "capabilities:\n  tools: false\n  rag: false\n"
        )
    return tmp_path / "target.yaml", tmp_path / "scope.yaml", judge_path


def _run(tmp_path: Path, port: int, specs: tuple[str, ...], *extra: str, **files: Any) -> list[str]:
    target, scope, judge = _files(tmp_path, port, **files)
    return [
        "run",
        "-t",
        str(target),
        "--scope",
        str(scope),
        *(arg for spec in specs for arg in ("--spec", spec)),
        "--runs",
        "1",
        "--rate",
        "1000",
        "--concurrency",
        "1",
        "--evidence-root",
        str(tmp_path / "ev"),
        "--run-db",
        str(tmp_path / "runs.sqlite"),
        "--no-color",
        "-oJ",
        str(tmp_path / "r.json"),
        *(["--judge", str(judge)] if judge is not None else []),
        *extra,
    ]


def _strings(value: Any) -> Iterator[str]:
    """Every string in a parsed JSON value, keys included."""

    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _well_formed(raw: bytes) -> Any:
    """``raw`` as strict UTF-8 JSON in which no string holds a lone surrogate."""

    def refuse(token: str) -> Any:
        raise ValueError(f"not JSON: {token}")

    value = json.loads(raw.decode("utf-8"), parse_constant=refuse)
    for text in _strings(value):
        text.encode("utf-8")  # raises on a lone surrogate, as every writer of it did
    return value


def _evidence(tmp_path: Path, kind: str = "attempts") -> list[Any]:
    """Every evidence file of ``kind`` (``attempts`` or ``probes``), parsed and checked."""

    files = [p for p in (tmp_path / "ev").rglob("*.json") if p.parent.name == kind]
    assert files, f"no {kind} evidence written"
    return [_well_formed(p.read_bytes()) for p in files]


def _report(tmp_path: Path) -> Any:
    return _well_formed((tmp_path / "r.json").read_bytes())


def _texts(tmp_path: Path) -> set[str]:
    """The reply text every attempt of the report recorded."""

    report = _report(tmp_path)
    return {a["response"]["text"] for f in report["findings"] for a in f["attempts"]}


def _statuses(tmp_path: Path) -> dict[str, str]:
    return {f["spec_id"]: f["status"] for f in _report(tmp_path)["findings"]}


def _ended(result: Any, exit_code: int) -> None:
    """Exited ``exit_code`` through the CLI's own exit, not on an exception that escaped it."""

    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    assert result.exit_code == exit_code, result.output
    assert "Traceback" not in result.output
    assert "UnicodeEncodeError" not in result.output


def _serve(body: bytes) -> Callable[[bytes], bytes]:
    return lambda _request: body


@pytest.mark.parametrize("sv", [False, True], ids=["run", "run-sV"])
@pytest.mark.parametrize("place", list(_PLACES))
def test_a_run_keeps_and_judges_a_reply_with_a_lone_surrogate(
    tmp_path: Path, place: str, sv: bool
) -> None:
    """Both specs finish on the stub's refusal (exit 0), their evidence is written, every file
    is UTF-8, and the report records the reply with U+FFFD where the half character was."""

    body, text = _PLACES[place]
    requests: list[bytes] = []
    with _serving(_serve(body), requests) as port:
        result = CliRunner().invoke(app, _run(tmp_path, port, _SPECS, *(["-sV"] if sv else [])))

    _ended(result, 0)
    assert _texts(tmp_path) == {text}
    assert set(_statuses(tmp_path)) == set(_SPECS)
    stored = json.dumps(_evidence(tmp_path), ensure_ascii=False)
    assert _NEEDLES.get(place, text) in stored
    if sv:
        _evidence(tmp_path, "probes")
    assert requests


#: Where the half character sits when it is not in the reply's text: the field the evidence
#: must hold with U+FFFD, so a regression that dropped the field would not pass.
_NEEDLES = {
    "id": "chatcmpl-" + _R,
    "model": "m-" + _R,
    "token": "I" + _R,
    "top-list": "W" + _R,
    "top-map": "W" + _R,
}


@pytest.fixture(scope="module")
def clean_leak(tmp_path_factory: pytest.TempPathFactory) -> tuple[int, dict[str, str]]:
    """The exit code and the statuses of both specs on the leaking reply, written plainly."""

    where = tmp_path_factory.mktemp("clean")
    with _serving(_serve(_reply(text=_text(_LEAK))), []) as port:
        result = CliRunner().invoke(app, _run(where, port, _SPECS))
    statuses = _statuses(where)
    assert statuses["PI-DIRECT-001"] == "fail"
    return result.exit_code, statuses


@pytest.mark.parametrize("where", ["before", "between-words", "after"])
def test_a_lone_surrogate_does_not_hide_a_leak(
    tmp_path: Path, clean_leak: tuple[int, dict[str, str]], where: str
) -> None:
    """The reply is judged, not set aside: the leak fails ``PI-DIRECT-001`` as it does without
    the half character. Refusing the reply as an environment error (inconclusive) would let a
    target turn any failure into "not evaluated" by adding six characters."""

    words = _LEAK.split(" ")
    leak = {
        "before": _HIGH + _LEAK,
        "between-words": " ".join([*words[:3], _HIGH, *words[3:]]),
        "after": _LEAK + _HIGH,
    }[where]
    with _serving(_serve(_reply(text=_text(leak))), []) as port:
        result = CliRunner().invoke(app, _run(tmp_path, port, _SPECS))

    exit_code, statuses = clean_leak
    _ended(result, exit_code)
    assert _statuses(tmp_path) == statuses
    _evidence(tmp_path)


def test_half_a_character_inside_a_word_of_the_leak_reads_as_a_zero_width_space_does(
    tmp_path: Path,
) -> None:
    """Inside a word a pattern looks for, the half splits that word as a zero-width space does:
    the verdicts and the exit code are the ones a zero-width space there gets (A-47 does not claim
    to find a leak split this way; refusing the reply would not have found it either)."""

    def verdicts(mark: str) -> tuple[int, dict[str, str]]:
        where = tmp_path / mark.strip(_BS)
        where.mkdir()
        leak = _LEAK.replace("You", "Yo" + mark + "u").replace("reveal", "reve" + mark + "al")
        with _serving(_serve(_reply(text=_text(leak))), []) as port:
            result = CliRunner().invoke(app, _run(where, port, _SPECS))
        assert "Traceback" not in result.output, result.output
        return result.exit_code, _statuses(where)

    assert verdicts(_HIGH) == verdicts(_BS + "u200b")


def test_a_well_formed_pair_stays_one_character(tmp_path: Path) -> None:
    """The escaped halves of U+1F600 are one character, as they were before; nothing is replaced."""

    with _serving(_serve(_reply(text=_text("I cannot " + _PAIR + " help."))), []) as port:
        result = CliRunner().invoke(app, _run(tmp_path, port, _SPECS))

    _ended(result, 0)
    assert _texts(tmp_path) == {"I cannot " + _EMOJI + " help."}


def test_a_multi_turn_spec_sends_the_reply_back_well_formed(tmp_path: Path) -> None:
    """A multi-turn spec puts the reply in the next request. With the half character replaced
    only where the evidence is written, httpx raised encoding that request: the reply is made
    well formed where it is parsed, so every request on the wire is UTF-8 JSON."""

    requests: list[bytes] = []
    body = _reply(text=_text("I cannot " + _HIGH + " help with that."))
    with _serving(_serve(body), requests) as port:
        result = CliRunner().invoke(app, _run(tmp_path, port, ("JB-SEQUENTIAL-001",)))

    _ended(result, 0)
    assert len(requests) > 1
    sent = [_well_formed(request) for request in requests]
    assert any(
        "I cannot " + _R + " help with that." in _strings_of(message)
        for request in sent
        for message in request["messages"]
    )
    _evidence(tmp_path)


def _strings_of(message: Any) -> list[str]:
    return list(_strings(message))


def _tool_call(name: str, arguments: str) -> str:
    """One OpenAI tool call as raw JSON; ``arguments`` is its JSON text, quoted once more."""

    return (
        '[{"id":"c1","type":"function","function":{"name":"'
        + name
        + '","arguments":'
        + json.dumps(arguments)
        + "}}]"
    )


def _tool_run(tmp_path: Path, arguments: str, name: str = "search_kb") -> tuple[Any, list[bytes]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    requests: list[bytes] = []
    body = _reply(text='"ok"', tool_calls=_tool_call(name, arguments))
    with _serving(_serve(body), requests) as port:
        result = CliRunner().invoke(
            app,
            _run(tmp_path, port, ("AG-TOOL-UNAUTH-001",), kind="model", tools=True),
        )
    return result, requests


def test_a_tool_call_argument_with_a_lone_surrogate_is_judged_like_a_clean_one(
    tmp_path: Path,
) -> None:
    """OpenAI carries a call's arguments as JSON text, which the in-band tool loop and the
    evaluators open themselves: the escape inside it was a second way in, past the parse of the
    reply. The run ends as it does with clean arguments, and the evidence holds U+FFFD."""

    clean, _ = _tool_run(tmp_path / "clean", json.dumps({"query": "return policy"}))
    clean_statuses = _statuses(tmp_path / "clean")
    # The arguments' JSON text holds the escape: json.dumps quotes its backslash once more.
    result, requests = _tool_run(tmp_path / "hostile", '{"query": "return ' + _HIGH + ' policy"}')

    _ended(result, clean.exit_code)
    assert _statuses(tmp_path / "hostile") == clean_statuses
    for request in requests:
        _well_formed(request)
    stored = json.dumps(_evidence(tmp_path / "hostile"), ensure_ascii=False)
    assert "return " + _R + " policy" in stored


def test_a_tool_name_with_a_lone_surrogate_is_a_different_tool(tmp_path: Path) -> None:
    """``search_kb`` followed by half a character is not ``search_kb``: the call is judged as
    a call to a tool off the allowlist, and the run finishes instead of aborting."""

    result, _ = _tool_run(tmp_path, json.dumps({"query": "x"}), name="search_kb" + _HIGH)

    _ended(result, 2)
    assert _statuses(tmp_path)["AG-TOOL-UNAUTH-001"] == "fail"
    stored = json.dumps(_evidence(tmp_path), ensure_ascii=False)
    assert "search_kb" + _R in stored


_JUDGE_MARK = b"TARGET OUTPUT (untrusted data"


def _judging(target_text: str, reasoning: str) -> Callable[[bytes], bytes]:
    """The target answers ``target_text``; the judge answers ``secure`` with ``reasoning``,
    which may hold an escape inside the JSON text the judge writes as its message."""

    verdict = (
        '{"verdict":"secure","confidence":0.95,"reasoning":"'
        + reasoning
        + '","observed_injection_attempt":false}'
    )
    judge_reply = _reply(text=json.dumps(verdict))
    target_reply = _reply(text=_text(target_text))
    return lambda request: judge_reply if _JUDGE_MARK in request else target_reply


def test_the_judge_is_sent_the_reply_well_formed(tmp_path: Path) -> None:
    """The judge's request quotes the target's reply. Half a character in it made httpx raise
    while encoding that request, before any evidence was written: the reply reaches the judge
    with U+FFFD, and the judge's verdict decides as it does on a clean reply.

    The judge's own reasoning carries an escape as well (its verdict is JSON inside its text,
    parsed by the evaluator past the adapter). It is not persisted or printed anywhere (the
    aggregate verdict writes its own reasoning), so it aborted nothing on main either; this
    pins that it still does not."""

    requests: list[bytes] = []
    judging = _judging("I cannot " + _HIGH + " help with that.", "refused " + _HIGH + " plainly")
    with _serving(judging, requests) as port:
        result = CliRunner().invoke(app, _run(tmp_path, port, ("PI-DIRECT-001",), judge=True))

    _ended(result, 0)
    asked = [_well_formed(request) for request in requests if _JUDGE_MARK in request]
    assert asked
    for request in asked:
        assert any("I cannot " + _R + " help with that." in s for s in _strings(request))
    assert _statuses(tmp_path) == {"PI-DIRECT-001": "pass"}
    _evidence(tmp_path)


@pytest.mark.parametrize("place", ["content", "id", "model", "token", "top-map", "raw-bytes"])
def test_fingerprint_finishes_on_a_reply_with_a_lone_surrogate(tmp_path: Path, place: str) -> None:
    """``dottore fingerprint`` writes no evidence and finished on main too; it still does, and
    what it prints is UTF-8 JSON."""

    body, _text_unused = _PLACES[place]
    requests: list[bytes] = []
    with _serving(_serve(body), requests) as port:
        target, scope, _judge = _files(tmp_path, port)
        result = CliRunner().invoke(app, ["fingerprint", str(target), "--scope", str(scope)])

    _ended(result, 0)
    assert requests
    _well_formed(result.stdout.encode("utf-8"))


#: A credential the run registers from the identity's ``auth_ref``: 18 characters no shape rule
#: matches, and its two halves.
_KEY = "Zq7vR2mK9pL4xW8nT3"
_KEY_HEAD, _KEY_TAIL = _KEY[:9], _KEY[9:]


@pytest.mark.usefixtures("no_known_secrets")
@pytest.mark.parametrize("split", ["escape", "raw-bytes", "literal"])
def test_a_registered_credential_split_by_half_a_character_is_masked_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, split: str
) -> None:
    """Half a character reaches the redactor as U+FFFD, which the match by value drops as it
    drops a zero-width space (u01 A-32): neither half of the credential is readable in the
    report, the evidence, the run store or the output. With U+FFFD not one of its splitters,
    both halves were (the merge of PR #57 with PR #79). A U+FFFD the target writes itself splits
    the credential the same way."""

    monkeypatch.setenv("ILDOTTORE_SPLIT_KEY", _KEY)
    said = f"{_REFUSAL} {_KEY_HEAD}@{_KEY_TAIL}"
    body = {
        "escape": _reply(text=_text(said.replace("@", _HIGH))),
        "raw-bytes": _raw(said, _RAW_HIGH),
        "literal": _reply(text=_text(said.replace("@", _BS + "ufffd"))),
    }[split]
    with _serving(_serve(body), []) as port:
        args = _run(tmp_path, port, _SPECS)
        scope, target = tmp_path / "scope.yaml", tmp_path / "target.yaml"
        scope.write_text(scope.read_text().replace("env://NONE", "env://ILDOTTORE_SPLIT_KEY"))
        target.write_text(target.read_text() + 'auth_ref: "env://ILDOTTORE_SPLIT_KEY"\n')
        result = CliRunner().invoke(app, args)

    _ended(result, 0)
    report = (tmp_path / "r.json").read_text(encoding="utf-8")
    evidence = json.dumps(_evidence(tmp_path), ensure_ascii=False)
    stored = (tmp_path / "runs.sqlite").read_bytes().decode("latin-1")
    for kept in (report, evidence, stored, result.output):
        assert _KEY_HEAD not in kept and _KEY_TAIL not in kept
    assert "REDACTED:credential:" in report
