"""A resumed run records what its ``-sV`` probe pass spent, however that pass stops (u12 A-46).

Through the real CLI against a local OpenAI-compatible stub that counts what it served. Only the
request ceiling used to record the probes a resumed pass had sent before it stopped: a probe
answered 503 three times (the meter retries it twice, then the adapter's environment error
stops the pass) left the stub at 23 requests and the run store at 20 (delta audit of PR #68,
2026-10-07, reproduced on main ``0501752``). A product error, Ctrl-C and SIGTERM lost the count
the same way, and so did anything that stopped the run between a pass that succeeded and the
runner's ledger opening. Every test here compares the store with the stub's own count.
"""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app
from ildottore.cli.run import fingerprint_probe_count
from ildottore.shared.nesting import MAX_DEPTH

_Reply = tuple[int, bytes]

_ANSWER = json.dumps(
    {
        "id": "stub",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "I cannot help with that."},
                "finish_reason": "stop",
            }
        ],
    }
).encode()

#: The ceiling of the halted run: every probe, then three attack requests before it stops.
_HALT_AT = 20


def _answer() -> _Reply:
    return 200, _ANSWER


def _unavailable() -> _Reply:
    return 503, b"down"


def _unauthorized() -> _Reply:
    return 401, b'{"error": "bad key"}'


def _not_json() -> _Reply:
    return 200, b"<html>not an API</html>"


def _too_deep() -> _Reply:
    """Brackets nested past ``MAX_DEPTH``: ``ResponseTooDeep``, refused and not retried (#65)."""

    deep = b"[" * (MAX_DEPTH + 1) + b"]" * (MAX_DEPTH + 1)
    return 200, _ANSWER[:-1] + b', "x": ' + deep + b"}"


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, Any]]]:
    """Serves ``script[n]`` for the n-th request (from 1), an answer otherwise.

    ``hang_at`` is a request number the stub never answers: on receiving it, it calls
    ``on_hang`` (which signals the CLI) and holds the connection until the test ends.
    """

    release = threading.Event()
    state: dict[str, Any] = {"script": {}, "served": 0, "hang_at": None, "on_hang": None}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("content-length", "0")))
            with lock:
                state["served"] += 1
                served = state["served"]
            if served == state["hang_at"]:
                state["on_hang"]()
                release.wait(60)
                return
            status, body = state["script"].get(served, _answer)()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], state
    finally:
        release.set()
        server.shutdown()
        server.server_close()


def _argv(tmp_path: Path, port: int, *extra: str) -> list[str]:
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    scope = tmp_path / "scope.yaml"
    target = tmp_path / "target.yaml"
    scope.write_text(
        f'version: "1.0"\ntargets:\n  - id: hostile\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    target.write_text(
        f'id: hostile\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    return [
        "run",
        "-t",
        str(target),
        "--scope",
        str(scope),
        "--spec",
        "JB-REFUSAL-SUPPRESS-001",
        "--spec",
        "PI-DIRECT-001",
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
        "-sV",
        *extra,
    ]


def _spend_json(tmp_path: Path, run_id: str) -> str | None:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        row = conn.execute("SELECT spend_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    finally:
        conn.close()
    return None if row[0] is None else str(row[0])


def _recorded(tmp_path: Path, run_id: str) -> int:
    spend = _spend_json(tmp_path, run_id)
    assert spend is not None, f"no spend recorded for {run_id}"
    return int(json.loads(spend)["requests"])


def _halted_run(tmp_path: Path, port: int, state: dict[str, Any]) -> str:
    """A -sV run stopped by its request ceiling after one spec: resumable, its spend recorded."""

    halted = CliRunner().invoke(app, _argv(tmp_path, port, "--budget-requests", str(_HALT_AT)))
    assert halted.exit_code == 3, halted.output
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        (run_id,) = conn.execute("SELECT run_id FROM runs").fetchone()
    finally:
        conn.close()
    assert state["served"] == _HALT_AT == _recorded(tmp_path, run_id), "precondition"
    return str(run_id)


@pytest.fixture
def no_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ildottore.core.execute.RetryPolicy.delay_for", lambda *_a: 0.0)


@pytest.mark.usefixtures("no_delay")
@pytest.mark.parametrize(
    ("reply", "sends", "cause"),
    [
        (_unavailable, 3, "HTTP 503"),
        (_unauthorized, 1, "HTTP 401"),
        (_not_json, 1, "not valid JSON"),
    ],
    ids=["no-answer-503", "product-401", "product-not-json"],
)
@pytest.mark.parametrize("probe", [1, 6])
def test_a_resumed_probe_pass_stopped_by_an_error_records_what_it_sent(
    tmp_path: Path,
    stub: tuple[int, dict[str, Any]],
    reply: Callable[[], _Reply],
    sends: int,
    cause: str,
    probe: int,
) -> None:
    port, state = stub
    run_id = _halted_run(tmp_path, port, state)
    first = _HALT_AT + probe
    state["script"] = dict.fromkeys(range(first, first + 10), reply)

    # Under -q too: the count is the one true figure for a pass whose error says "1 attempt".
    resumed = CliRunner().invoke(
        app, _argv(tmp_path, port, "--budget-requests", "200", "--resume", run_id, "-q")
    )

    assert resumed.exit_code == 3, resumed.output
    assert cause in resumed.stderr
    sent = probe - 1 + sends
    assert state["served"] == _HALT_AT + sent
    assert _recorded(tmp_path, run_id) == state["served"], (
        "the store has to record every request the stub served, the stopped pass included"
    )
    assert (
        f"resume: the -sV probe pass on 'hostile' stopped after {sent} request(s), retries "
        f"included; {run_id} now records {_HALT_AT + sent} request(s) spent"
    ) in resumed.stderr


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM], ids=["ctrl-c", "sigterm"])
def test_a_signal_during_a_resumed_probe_pass_records_what_it_sent(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], monkeypatch: pytest.MonkeyPatch, signum: int
) -> None:
    """The fifth probe of the resume is on the wire, unanswered, when the signal arrives."""

    port, state = stub
    monkeypatch.setattr("ildottore.core.execute.RetryPolicy.delay_for", lambda *_a: 0.0)
    run_id = _halted_run(tmp_path, port, state)
    process: dict[str, subprocess.Popen[bytes]] = {}
    state["hang_at"] = _HALT_AT + 5
    state["on_hang"] = lambda: os.kill(process["cli"].pid, signum)

    process["cli"] = subprocess.Popen(  # noqa: S603 - this interpreter running this CLI
        [
            sys.executable,
            "-c",
            # A shell that starts pytest with `&` passes SIGINT on ignored, and Python then
            # installs no Ctrl-C handler in the child (pre-merge audit: 5 of 5 failed so).
            "import signal, sys; signal.signal(signal.SIGINT, signal.default_int_handler); "
            "from ildottore.cli.main import main; sys.argv[0] = 'dottore'; main()",
            *_argv(tmp_path, port, "--budget-requests", "200", "--resume", run_id),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _, err = process["cli"].communicate(timeout=120)
    finally:
        if process["cli"].poll() is None:
            process["cli"].kill()
            process["cli"].wait()

    assert state["served"] == _HALT_AT + 5, err.decode(errors="replace")
    assert _recorded(tmp_path, run_id) == state["served"], err.decode(errors="replace")
    assert (
        f"stopped after 5 request(s), retries included; {run_id} now records "
        f"{_HALT_AT + 5} request(s) spent"
    ) in err.decode(errors="replace")


@pytest.mark.usefixtures("no_delay")
def test_a_stop_after_a_resumed_probe_pass_keeps_what_it_sent(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pass succeeded and the run stopped before the runner opened its ledger."""

    from ildottore.cli import run as run_mod

    port, state = stub
    run_id = _halted_run(tmp_path, port, state)

    def _interrupted(*_a: object, **_k: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(run_mod, "_persist_run_integrity", _interrupted)
    resumed = CliRunner().invoke(
        app, _argv(tmp_path, port, "--budget-requests", "200", "--resume", run_id)
    )

    assert resumed.exit_code != 0
    assert state["served"] == _HALT_AT + fingerprint_probe_count()
    assert _recorded(tmp_path, run_id) == state["served"]


@pytest.mark.usefixtures("no_delay")
def test_a_signal_on_the_write_after_a_successful_pass_still_records_it(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real SIGINT a few ms after the last probe lost all 17 in 2 of 16 tries (pre-commit
    audit): the write after a pass that succeeded sat outside the handlers. Here the signal
    lands at that write, before it commits; the handler has to write it again."""

    from ildottore.cli import run as run_mod

    port, state = stub
    run_id = _halted_run(tmp_path, port, state)
    charge = run_mod._charge_probe_pass
    calls: list[int] = []

    def _interrupted_once(*args: Any, **kwargs: Any) -> int | None:
        calls.append(state["served"])
        if len(calls) == 1:
            raise KeyboardInterrupt
        return charge(*args, **kwargs)

    monkeypatch.setattr(run_mod, "_charge_probe_pass", _interrupted_once)
    resumed = CliRunner().invoke(
        app, _argv(tmp_path, port, "--budget-requests", "200", "--resume", run_id)
    )

    probes = fingerprint_probe_count()
    assert resumed.exit_code != 0
    assert state["served"] == _HALT_AT + probes
    assert _recorded(tmp_path, run_id) == state["served"]
    assert calls == [_HALT_AT + probes] * 2, "interrupted after the pass, then written again"
    assert f"stopped after {probes} request(s), retries included" in resumed.stderr


@pytest.mark.usefixtures("no_delay")
def test_a_write_that_fails_is_said_and_keeps_the_error(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The count still reaches stderr when the store refuses it, and the 503 is still the error."""

    from ildottore.cli import run as run_mod

    port, state = stub
    run_id = _halted_run(tmp_path, port, state)
    state["script"] = dict.fromkeys(range(_HALT_AT + 1, _HALT_AT + 10), _unavailable)

    def _locked(*_a: object, **_k: object) -> int:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(run_mod, "_persist_spend", _locked)
    resumed = CliRunner().invoke(
        app, _argv(tmp_path, port, "--budget-requests", "200", "--resume", run_id)
    )

    assert resumed.exit_code == 3, resumed.output
    assert f"warning: the spend of {run_id} could not be recorded: database is locked" in (
        resumed.stderr
    )
    assert (
        "resume: the -sV probe pass on 'hostile' stopped after 3 request(s), retries included; "
        f"they could not be added to the spend of {run_id}"
    ) in resumed.stderr
    assert "HTTP 503" in resumed.stderr
    assert _recorded(tmp_path, run_id) == _HALT_AT, "the documented loss of a failed write"


@pytest.mark.usefixtures("no_delay")
def test_a_resume_whose_probe_pass_succeeds_counts_each_probe_once(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """The pass is now recorded when it ends, and again by the runner with the attack."""

    port, state = stub
    run_id = _halted_run(tmp_path, port, state)

    resumed = CliRunner().invoke(
        app, _argv(tmp_path, port, "--budget-requests", "200", "--resume", run_id)
    )

    assert resumed.exit_code in {0, 1, 2}, resumed.output
    assert "probe pass" not in resumed.stderr
    assert state["served"] > _HALT_AT + fingerprint_probe_count(), "the attack went out"
    assert _recorded(tmp_path, run_id) == state["served"]


@pytest.mark.usefixtures("no_delay")
def test_a_resumed_probe_pass_with_a_refused_reply_goes_on_and_records_it(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """A refused probe reply fails only that probe (u09 A-35), so the pass ends as one that
    succeeded and the send it cost is recorded with the others, each once (u12 A-46)."""

    port, state = stub
    run_id = _halted_run(tmp_path, port, state)
    state["script"] = {_HALT_AT + 1: _too_deep}

    resumed = CliRunner().invoke(
        app, _argv(tmp_path, port, "--budget-requests", "200", "--resume", run_id)
    )

    assert resumed.exit_code in {0, 1, 2}, resumed.output
    assert (
        f"1 of {fingerprint_probe_count()} probe(s) got no usable reply "
        "(metadata/self_id: ResponseTooDeep)"
    ) in resumed.stderr
    assert "resume: the -sV probe pass" not in resumed.stderr
    assert state["served"] > _HALT_AT + fingerprint_probe_count(), "the attack went out"
    assert _recorded(tmp_path, run_id) == state["served"]


@pytest.mark.usefixtures("no_delay")
def test_a_fresh_run_stopped_by_its_probe_pass_leaves_no_run_row(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """Nothing to resume: its run row is written after the pass, so none is made for it."""

    port, state = stub
    state["script"] = dict.fromkeys(range(1, 10), _unavailable)

    fresh = CliRunner().invoke(app, _argv(tmp_path, port))

    assert fresh.exit_code == 3, fresh.output
    assert state["served"] == 3
    assert "probe pass" not in fresh.stderr
    if (tmp_path / "runs.sqlite").exists():
        conn = sqlite3.connect(tmp_path / "runs.sqlite")
        try:
            assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
        finally:
            conn.close()


@pytest.mark.usefixtures("no_delay")
def test_a_resume_with_no_recorded_spend_does_not_record_the_probes_as_its_total(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """`--resume-unverified` said the ceiling covers this invocation alone; three probes stored
    as the campaign's spend would read as its total at the next resume."""

    port, state = stub
    run_id = _halted_run(tmp_path, port, state)
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        conn.execute("UPDATE runs SET spend_json = NULL WHERE run_id = ?", (run_id,))
        conn.commit()
    finally:
        conn.close()
    state["script"] = dict.fromkeys(range(_HALT_AT + 1, _HALT_AT + 10), _unavailable)

    resumed = CliRunner().invoke(
        app,
        _argv(
            tmp_path, port, "--budget-requests", "200", "--resume", run_id, "--resume-unverified"
        ),
    )

    assert resumed.exit_code == 3, resumed.output
    assert "no spend was recorded" in resumed.stderr
    assert state["served"] == _HALT_AT + 3
    assert "probe pass" not in resumed.stderr
    assert _spend_json(tmp_path, run_id) is None
