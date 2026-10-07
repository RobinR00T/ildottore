"""A reply's usage figure that no float holds exactly stops nothing (2026-10-07).

Through the real CLI against a local OpenAI-compatible stub whose every reply reports a usage
figure the stub writes as raw JSON. A 400-digit token count was trued into the ledger and made
``dottore run`` exit 1 (the code CI reads as "findings below --fail-on") with ``OverflowError``
when the spend was persisted, and no report was written. A smaller one, past ``2**53``, halted
the campaign on the token ceiling after the first reply, so every other spec never ran. A
400-digit ``moderation_latency_ms`` made ``dottore fingerprint`` and ``run -sV`` exit 1 the same
way.
"""

from __future__ import annotations

import json
import sqlite3
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

#: Far past any float, well inside ``json.loads``'s 4,300-digit limit (a longer integer is
#: refused by the parser itself, a separate question left open on ``fix/target-deep-json``).
_HUGE = "9" * 400

#: The first whole number a float does not hold exactly, and the default token ceiling
#: (500,000) many times over: believed, it halted the campaign after one reply.
_PAST_EXACT = str(2**53 + 1)


def _reply(usage: str | None) -> bytes:
    body = (
        '{"id":"stub","object":"chat.completion","choices":[{"index":0,"message":'
        '{"role":"assistant","content":"I cannot help with that."},"finish_reason":"stop"}]'
    )
    return (body + (f',"usage":{usage}' if usage is not None else "") + "}").encode()


@contextmanager
def _serving(state: dict[str, Any]) -> Iterator[int]:
    """Serve ``state["usage"]`` in every reply on an ephemeral port, counting the requests."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("content-length", "0")))
            state["served"] += 1
            body = _reply(state["usage"])
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    # A short poll: `shutdown` waits out one, and the default half second was half this file.
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, Any]]]:
    state: dict[str, Any] = {"usage": None, "served": 0}
    with _serving(state) as port:
        yield port, state


def _files(tmp_path: Path, port: int) -> tuple[Path, Path]:
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    return tmp_path / "target.yaml", tmp_path / "scope.yaml"


def _run(tmp_path: Path, port: int, *extra: str) -> list[str]:
    target, scope = _files(tmp_path, port)
    return [
        "run",
        "-t",
        str(target),
        "--scope",
        str(scope),
        *(arg for spec in _SPECS for arg in ("--spec", spec)),
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


def _spent_tokens(tmp_path: Path) -> float:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        (row,) = conn.execute("SELECT spend_json FROM runs").fetchall()
    finally:
        conn.close()
    return float(json.loads(row[0])["tokens"])


@pytest.fixture(scope="module")
def baseline(tmp_path_factory: pytest.TempPathFactory) -> tuple[float, int]:
    """The tokens the two specs record when their replies report no usage (the reservation),
    and the requests that run sends. One run for the module: it is deterministic."""

    state: dict[str, Any] = {"usage": None, "served": 0}
    where = tmp_path_factory.mktemp("no-usage")
    with _serving(state) as port:
        result = CliRunner().invoke(app, _run(where, port))
    assert result.exit_code == 0, result.output
    return _spent_tokens(where), state["served"]


@pytest.mark.parametrize(
    "usage",
    [
        '{"total_tokens":FIGURE}',
        '{"tokens":FIGURE}',
        '{"prompt_tokens":FIGURE,"completion_tokens":5}',
        '{"prompt_tokens":5,"completion_tokens":FIGURE}',
        '{"input_tokens":FIGURE,"output_tokens":5}',
        '{"input_tokens":5,"output_tokens":FIGURE}',
        '{"input_tokens":5,"output_tokens":5,"cache_read_input_tokens":FIGURE}',
        '{"input_tokens":5,"output_tokens":5,"cache_creation_input_tokens":FIGURE}',
    ],
)
@pytest.mark.parametrize("figure", [_HUGE, _PAST_EXACT], ids=["400-digits", "2**53+1"])
def test_a_usage_figure_no_float_holds_leaves_the_reservation_and_the_run_finishes(
    tmp_path: Path,
    stub: tuple[int, dict[str, Any]],
    baseline: tuple[float, int],
    usage: str,
    figure: str,
) -> None:
    port, state = stub
    reserved, sends = baseline
    state["usage"] = usage.replace("FIGURE", figure)
    result = CliRunner().invoke(app, _run(tmp_path, port))

    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert {f["spec_id"] for f in report["findings"]} == set(_SPECS)
    assert state["served"] == sends
    # Read as no usage at all: each send keeps its reservation, the conservative figure.
    assert _spent_tokens(tmp_path) == reserved


def test_a_figure_a_float_holds_exactly_is_still_believed(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """The other direction, so the guard cannot pass by ignoring every figure: ``2**53`` itself
    is recorded for every reply (under a ceiling that leaves room for it)."""

    port, state = stub
    state["usage"] = f'{{"total_tokens":{2**53}}}'
    result = CliRunner().invoke(app, _run(tmp_path, port, "--budget-tokens", str(2**60)))

    assert result.exit_code == 0, result.output
    assert state["served"] > 1
    assert _spent_tokens(tmp_path) == state["served"] * 2**53


@pytest.mark.parametrize(
    "figure", [_HUGE, "-5", "1e400", "NaN"], ids=["400-digits", "negative", "inf", "nan"]
)
def test_a_latency_figure_no_float_holds_is_no_latency(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], figure: str
) -> None:
    """``1e400`` parses as an infinity. The printed guardrails showed an infinity and a NaN as
    ``null`` before too, but the evidence signal beside them carried ``Infinity`` and ``NaN``."""

    port, state = stub
    state["usage"] = '{"total_tokens":10,"moderation_latency_ms":FIGURE}'.replace("FIGURE", figure)
    target, scope = _files(tmp_path, port)
    result = CliRunner().invoke(app, ["fingerprint", str(target), "--scope", str(scope)])

    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    assert result.exit_code == 0, result.output
    assert '"moderation_latency_ms": null' in result.output
    assert "Infinity" not in result.output
    assert "NaN" not in result.output


def test_a_reported_latency_is_kept(tmp_path: Path, stub: tuple[int, dict[str, Any]]) -> None:
    port, state = stub
    state["usage"] = '{"total_tokens":10,"moderation_latency_ms":12.5}'
    target, scope = _files(tmp_path, port)
    result = CliRunner().invoke(app, ["fingerprint", str(target), "--scope", str(scope)])

    assert result.exit_code == 0, result.output
    assert '"moderation_latency_ms": 12.5' in result.output


def test_a_run_with_sv_finishes_on_a_latency_figure_no_float_holds(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    port, state = stub
    state["usage"] = '{"total_tokens":10,"moderation_latency_ms":FIGURE}'.replace("FIGURE", _HUGE)
    result = CliRunner().invoke(app, _run(tmp_path, port, "-sV"))

    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert {f["spec_id"] for f in report["findings"]} == set(_SPECS)
