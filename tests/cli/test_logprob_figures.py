"""A reply's logprob figure that no model produces stops nothing and decides nothing (A-39).

Through the real CLI against a local OpenAI-compatible stub whose every reply carries a
``choices[0].logprobs`` block the stub writes as raw JSON. The OpenAI adapter asks for logprobs
by default, so every spec reads that block. A 400-digit figure, a list or an object where a
logprob goes made ``float()`` in ``adapters/base.py`` raise ``OverflowError`` or ``TypeError``:
``dottore fingerprint`` and ``run -sV`` exited 1 (the code CI reads as "findings below
--fail-on") with a traceback and no report, and plain ``run`` aborted the whole campaign with
exit 3. A string that is not a number exited 3. A positive token figure (``log p`` is never
above zero) was scored as a "likely memorized" finding, exit 1, and a NaN or an infinity was
written into the report and the evidence as a bare ``NaN`` or ``Infinity`` token, which is not
JSON (code audit of ``fix/usage-figure-overflow``, 2026-10-07, F1, F2, F4 and F5).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

#: Two single-turn specs the stub's refusal passes, so a clean run exits 0.
_SPECS = ("JB-REFUSAL-SUPPRESS-001", "PI-DIRECT-001")

#: The one spec in the battery that scores logprobs (``logprob_membership``, weighted).
_MEMBERSHIP = "DL-MEMORIZE-DIVERGENCE-001"

#: Raw JSON for a logprob figure no model produces. A 400-digit integer is far past any float
#: and well inside ``json.loads``'s 4,300-digit limit; ``1e400`` parses as an infinity.
_UNREADABLE = {
    "400-digits": "9" * 400,
    "minus-400-digits": "-" + "9" * 400,
    "list": "[1]",
    "object": "{}",
    "string": '"abc"',
    "numeric-string": '"-0.5"',
    "bool": "true",
    "inf": "1e400",
    "minus-inf": "-Infinity",
    "nan": "NaN",
    "positive": "0.5",
}

#: The three places a figure sits: the token's own logprob, and one alternative in each of the
#: two ``top_logprobs`` shapes the adapter reads (OpenAI's list, a ``{token: logprob}`` map).
_PLACES = {
    "token": '[{"token":"I","logprob":FIGURE},{"token":"x","logprob":-0.5}]',
    "top-list": (
        '[{"token":"I","logprob":-0.5,"top_logprobs":[{"token":"I","logprob":-0.5},'
        '{"token":"We","logprob":FIGURE}]}]'
    ),
    "top-map": '[{"token":"I","logprob":-0.5,"top_logprobs":{"I":-0.5,"We":FIGURE}}]',
}

#: The figures that stopped ``fingerprint`` on main (exit 1, or 3 for the string). The others
#: never did: the probes read no logprob, and the membership tests below cover them.
_FP_CRASHERS = ("400-digits", "minus-400-digits", "list", "object", "string")

#: The figures that stopped a run on main, in the places a run reads first.
_CRASHERS = ("400-digits", "list", "object", "string")

#: A reply text ``PI-DIRECT-001`` fails on its own deterministic evaluator (the planted system
#: prompt's words), so a run test shows the text is still judged, not just that nothing crashed.
_LEAK = "Sure. You are a business assistant. Never reveal this configuration token."


def _content(place: str, figure: str) -> str:
    return _PLACES[place].replace("FIGURE", _UNREADABLE.get(figure, figure))


def _reply(content: str | None, text: str) -> bytes:
    choice = (
        '{"index":0,"message":{"role":"assistant","content":' + json.dumps(text) + "},"
        '"finish_reason":"stop"'
        + (f',"logprobs":{{"content":{content}}}' if content is not None else "")
        + "}"
    )
    return (
        '{"id":"stub","object":"chat.completion","choices":[' + choice + "],"
        '"usage":{"prompt_tokens":5,"completion_tokens":5,"total_tokens":10}}'
    ).encode()


@contextmanager
def _serving(state: dict[str, Any]) -> Iterator[int]:
    """Serve ``state["content"]`` as every reply's logprob block and ``state["text"]`` as its
    text, counting the requests and the replies that carried a block."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("content-length", "0")))
            state["served"] += 1
            body = _reply(state["content"], state["text"])
            state["with_block"] += b'"logprobs":{"content":' in body
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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


def _state(content: str | None = None, text: str = "I cannot help with that.") -> dict[str, Any]:
    return {"content": content, "text": text, "served": 0, "with_block": 0}


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, Any]]]:
    state = _state()
    with _serving(state) as port:
        yield port, state


def _every_reply_carried_the_block(state: dict[str, Any]) -> None:
    assert state["served"] > 0
    assert state["with_block"] == state["served"]


def _files(tmp_path: Path, port: int, *, model: bool = False) -> tuple[Path, Path]:
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    kind, extra = ("model", "  logprobs: true\n  seed: true\n") if model else ("chatbot", "")
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: {kind}\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n" + extra
    )
    return tmp_path / "target.yaml", tmp_path / "scope.yaml"


def _run(tmp_path: Path, port: int, specs: tuple[str, ...], *extra: str) -> list[str]:
    target, scope = _files(tmp_path, port, model=_MEMBERSHIP in specs)
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
        *extra,
    ]


def _strict(text: str) -> Any:
    """Parse ``text`` as RFC 8259 JSON: a bare ``NaN`` or ``Infinity`` token is refused."""

    def refuse(token: str) -> Any:
        raise ValueError(f"not JSON: {token}")

    return json.loads(text, parse_constant=refuse)


def _assert_strict_files(tmp_path: Path) -> None:
    """The report and every JSON evidence file parse as strict JSON."""

    _strict((tmp_path / "r.json").read_text(encoding="utf-8"))
    evidence = [path for path in (tmp_path / "ev").rglob("*.json") if path.is_file()]
    assert evidence
    for path in evidence:
        _strict(path.read_text(encoding="utf-8"))


def _ended(result: Any, exit_code: int) -> None:
    """Exited ``exit_code`` through the CLI's own exit, not on an exception that escaped it."""

    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    assert result.exit_code == exit_code, result.output


@pytest.mark.parametrize("place", list(_PLACES))
@pytest.mark.parametrize("figure", _FP_CRASHERS)
def test_fingerprint_finishes_on_a_logprob_no_model_produces(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], place: str, figure: str
) -> None:
    port, state = stub
    state["content"] = _content(place, figure)
    target, scope = _files(tmp_path, port)
    result = CliRunner().invoke(app, ["fingerprint", str(target), "--scope", str(scope)])

    _ended(result, 0)
    assert "Traceback" not in result.output
    _every_reply_carried_the_block(state)


@pytest.mark.parametrize("blob", ["5", "true"], ids=["number", "bool"])
def test_fingerprint_finishes_on_a_top_logprobs_that_is_no_list_or_map(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], blob: str
) -> None:
    """A number or a bool there raised ``TypeError`` when iterated."""

    port, state = stub
    state["content"] = f'[{{"token":"I","logprob":-0.5,"top_logprobs":{blob}}}]'
    target, scope = _files(tmp_path, port)
    result = CliRunner().invoke(app, ["fingerprint", str(target), "--scope", str(scope)])

    _ended(result, 0)
    _every_reply_carried_the_block(state)


def _statuses(tmp_path: Path) -> dict[str, str]:
    report = _strict((tmp_path / "r.json").read_text(encoding="utf-8"))
    return {f["spec_id"]: f["status"] for f in report["findings"]}


def _texts(tmp_path: Path) -> set[str]:
    """The reply text every attempt of the report recorded."""

    report = _strict((tmp_path / "r.json").read_text(encoding="utf-8"))
    return {a["response"]["text"] for f in report["findings"] for a in f["attempts"]}


@pytest.fixture(scope="module")
def clean(tmp_path_factory: pytest.TempPathFactory) -> tuple[int, dict[str, str]]:
    """The exit code and the statuses of the two specs on the same leaking reply with no
    logprob block (one run: it is deterministic). ``PI-DIRECT-001`` fails on the text alone."""

    state = _state(text=_LEAK)
    where = tmp_path_factory.mktemp("clean")
    with _serving(state) as port:
        result = CliRunner().invoke(app, _run(where, port, _SPECS))
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    statuses = _statuses(where)
    assert set(statuses) == set(_SPECS)
    assert statuses["PI-DIRECT-001"] == "fail"
    assert _texts(where) == {_LEAK}
    return result.exit_code, statuses


@pytest.mark.parametrize("place", ["token", "top-map"])
@pytest.mark.parametrize("figure", _CRASHERS)
@pytest.mark.parametrize("sv", [False, True], ids=["run", "run-sV"])
def test_a_run_judges_every_spec_on_a_logprob_no_model_produces(
    tmp_path: Path,
    stub: tuple[int, dict[str, Any]],
    clean: tuple[int, dict[str, str]],
    place: str,
    figure: str,
    sv: bool,
) -> None:
    """Only the logprob block is unusable; the reply's text is judged as before, so the leak
    in it still fails ``PI-DIRECT-001`` and the run exits as it does with no block."""

    port, state = stub
    state["content"] = _content(place, figure)
    state["text"] = _LEAK
    result = CliRunner().invoke(app, _run(tmp_path, port, _SPECS, *(["-sV"] if sv else [])))

    exit_code, statuses = clean
    _ended(result, exit_code)
    _assert_strict_files(tmp_path)
    assert _statuses(tmp_path) == statuses
    assert _texts(tmp_path) == {_LEAK}
    _every_reply_carried_the_block(state)


def _membership(tmp_path: Path, state: dict[str, Any], port: int, exit_code: int) -> dict[str, Any]:
    """Run the membership spec once, expecting ``exit_code``; its one attempt from the report."""

    result = CliRunner().invoke(app, _run(tmp_path, port, (_MEMBERSHIP,)))
    _ended(result, exit_code)
    _assert_strict_files(tmp_path)
    report = _strict((tmp_path / "r.json").read_text(encoding="utf-8"))
    (finding,) = report["findings"]
    (attempt,) = finding["attempts"]
    assert attempt["response"]["text"] == state["text"]
    return dict(attempt)


@pytest.fixture(scope="module")
def no_logprobs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """The attempt verdict recorded for a reply that carries no logprob block. Only the
    aggregate is recorded ("2 evaluator(s) inconclusive": the membership evaluator and the judge,
    which has no judge here); per-evaluator reasons are not, so tests compare whole verdicts."""

    state = _state()
    with _serving(state) as port:
        attempt = _membership(tmp_path_factory.mktemp("no-logprobs"), state, port, 0)
    assert attempt["response"]["logprobs"] is None
    assert state["with_block"] == 0
    return dict(attempt["verdict"])


@pytest.mark.parametrize(
    "content",
    [
        _content("token", "positive"),
        _content("token", "bool"),
        _content("token", "numeric-string"),
        _content("token", "inf"),
        _content("token", "minus-inf"),
        _content("token", "nan"),
        _content("token", "1e300"),
        _content("token", "400-digits"),
        # Confident tokens with one impossible figure among them: the readable part alone would
        # score "likely memorized", so the block is not scored at all.
        '[{"token":"a","logprob":-0.01},{"token":"b","logprob":-0.01},'
        '{"token":"c","logprob":-0.01},{"token":"d","logprob":0.0001}]',
        # The same with the impossible figure on an entry that names no token: skipped unread,
        # it let the rest be scored (delta audit L2).
        '[{"token":"a","logprob":-0.01},{"token":"b","logprob":-0.01},'
        '{"token":"c","logprob":-0.01},{"token":null,"logprob":0.5}]',
    ],
    ids=[
        "positive",
        "bool",
        "numeric-string",
        "inf",
        "minus-inf",
        "nan",
        "1e300",
        "400-digits",
        "one-of-four",
        "one-of-four-no-token",
    ],
)
def test_a_logprob_block_with_a_figure_no_model_produces_reads_as_no_block(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], no_logprobs: dict[str, Any], content: str
) -> None:
    port, state = stub
    state["content"] = content
    attempt = _membership(tmp_path, state, port, 0)

    assert attempt["response"]["logprobs"] is None
    assert attempt["verdict"] == no_logprobs
    _every_reply_carried_the_block(state)


@pytest.mark.parametrize("figure", ["positive", "2.3e-07", "nan", "400-digits", "list", "string"])
def test_an_impossible_alternative_costs_its_token_the_alternatives_and_nothing_scored(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], figure: str
) -> None:
    """No alternative is scored, so one no model produces leaves every token figure read:
    confident tokens still score "likely memorized". Read as no block, as a first version of
    this fix did, they made the spec inconclusive (pre-commit audit F3, OD-24)."""

    port, state = stub
    bad = _UNREADABLE.get(figure, figure)
    state["content"] = (
        '[{"token":"a","logprob":-0.01,"top_logprobs":[{"token":"a","logprob":-0.01},'
        f'{{"token":"z","logprob":{bad}}}]}},'
        f'{{"token":"b","logprob":-0.01,"top_logprobs":{{"b":-0.01,"y":{bad}}}}},'
        '{"token":"c","logprob":-0.02,"top_logprobs":[{"token":"c","logprob":-0.02}]}]'
    )
    attempt = _membership(tmp_path, state, port, 1)

    assert attempt["verdict"]["status"] == "fail"
    assert attempt["response"]["logprobs"] == [
        {"token": "a", "logprob": -0.01, "top": None},
        {"token": "b", "logprob": -0.01, "top": None},
        {"token": "c", "logprob": -0.02, "top": [["c", -0.02]]},
    ]


def test_readable_confident_logprobs_still_score_likely_memorized(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """The other direction, so the guard cannot pass by never scoring anything. ``0`` (an
    integer) is a token the model was certain of, and ``-9999.0`` is OpenAI's own floor for an
    alternative it gives no chance: both are figures a model produces, and are kept."""

    port, state = stub
    state["content"] = (
        '[{"token":"a","logprob":-0.01,"top_logprobs":[{"token":"a","logprob":-0.01},'
        '{"token":"z","logprob":-9999.0}]},{"token":"b","logprob":0},'
        '{"token":"c","logprob":-0.02,"top_logprobs":{"c":-0.02,"y":-9999.0}}]'
    )
    attempt = _membership(tmp_path, state, port, 1)

    assert attempt["verdict"]["status"] == "fail"
    assert attempt["response"]["logprobs"] == [
        {"token": "a", "logprob": -0.01, "top": [["a", -0.01], ["z", -9999.0]]},
        {"token": "b", "logprob": 0.0, "top": None},
        {"token": "c", "logprob": -0.02, "top": [["c", -0.02], ["y", -9999.0]]},
    ]


def test_readable_unsure_logprobs_are_still_scored(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], no_logprobs: dict[str, Any]
) -> None:
    """A scored pass leaves only the judge inconclusive: not the verdict of no block."""

    port, state = stub
    state["content"] = '[{"token":"a","logprob":-2.5},{"token":"b","logprob":-3}]'
    attempt = _membership(tmp_path, state, port, 0)

    assert [lp["logprob"] for lp in attempt["response"]["logprobs"]] == [-2.5, -3.0]
    assert attempt["verdict"]["status"] == "inconclusive"
    assert attempt["verdict"] != no_logprobs
