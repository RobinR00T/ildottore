"""One refused reply during the ``-sV`` probe pass fails that probe; the run goes on (OD-23).

Through the real CLI against a local OpenAI-compatible stub. Before, ``dottore run -sV`` exited 3
after one request on a first probe reply over 4 MiB ("exceeded 4194304 bytes") or in an encoding
it does not decode, before any attack; without ``-sV`` the same reply failed one attempt and
every spec ran (pre-commit audit of ``fix/target-deep-json``, 2026-10-07). ``dottore
fingerprint`` exited 3 on the same reply. A probe that gets no answer at all still stops the
pass with its cause, as before: the target is not answering.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.adapters.base import MAX_RESPONSE_BYTES
from ildottore.cli.app import app
from ildottore.cli.run import fingerprint_probe_count
from ildottore.fingerprint import PROBES_FAILED_FLAG, failed_probes
from ildottore.shared.models import ModelFingerprint
from ildottore.store.replay import replay_run

_Reply = tuple[int, dict[str, str], bytes]

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

_JSON = {"content-type": "application/json"}


def _answer() -> _Reply:
    return 200, _JSON, _ANSWER


def _too_large() -> _Reply:
    content = b"a" * (MAX_RESPONSE_BYTES + 1)
    return 200, _JSON, b'{"choices":[{"index":0,"message":{"content":"' + content + b'"}}]}'


def _undecodable() -> _Reply:
    return 200, {**_JSON, "content-encoding": "br"}, _ANSWER


def _unavailable() -> _Reply:
    return 503, {"content-type": "text/plain"}, b"down"


#: The refused reply and the class it fails with. Neither is retried: one send per probe.
_REFUSALS: dict[str, tuple[Callable[[], _Reply], str]] = {
    "too large": (_too_large, "ResponseTooLarge"),
    "undecodable": (_undecodable, "ResponseUndecodable"),
}

_SPECS = ("JB-REFUSAL-SUPPRESS-001", "PI-DIRECT-001")


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, Any]]]:
    """Serves ``script[n]`` for the n-th request (from 1), an ordinary answer otherwise."""

    state: dict[str, Any] = {"script": {}, "served": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("content-length", "0")))
            state["served"] += 1
            status, headers, body = state["script"].get(state["served"], _answer)()
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
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
        server.shutdown()
        server.server_close()


def _files(tmp_path: Path, port: int) -> tuple[Path, Path]:
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
    return scope, target


def _run_argv(tmp_path: Path, port: int, *extra: str) -> list[str]:
    scope, target = _files(tmp_path, port)
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


def _attempts(tmp_path: Path) -> tuple[str, list[dict[str, Any]]]:
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert {f["spec_id"] for f in report["findings"]} == set(_SPECS)
    return report["run"]["run_id"], [a for f in report["findings"] for a in f["attempts"]]


@pytest.mark.parametrize("refusal", sorted(_REFUSALS))
@pytest.mark.parametrize("flag", ["-sV", "-A"])
def test_a_refused_probe_reply_fails_that_probe_and_the_run_goes_on(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], refusal: str, flag: str
) -> None:
    port, state = stub
    reply, error = _REFUSALS[refusal]
    state["script"] = {1: reply}
    result = CliRunner().invoke(app, _run_argv(tmp_path, port, flag))

    assert result.exit_code == 0, result.output
    probes = fingerprint_probe_count()
    run_id, attempts = _attempts(tmp_path)
    warning = result.stderr
    assert f"1 of {probes} probe(s) got no usable reply (metadata/self_id: {error})" in warning
    # One line, the evidence path whole (rich wrapped it at 80 columns and cut the path).
    assert (
        "the fingerprint is built from the replies that came back. The exchanges are in "
        + str(tmp_path / "ev" / run_id / "probes")
        + "\n"
    ) in warning
    # Every attack attempt went out and was answered: the probe failure cost no attempt.
    assert attempts and all(a["response"] is not None and not a["error"] for a in attempts)
    assert state["served"] == probes + len(attempts)
    # The failed exchange is in the evidence, with its error and no reply.
    stored = replay_run(tmp_path / "ev", run_id).probes
    assert len(stored) == probes
    failed = [p for p in stored if p.response is None]
    assert len(failed) == 1
    assert error in (failed[0].error or "")


def test_a_pass_where_every_probe_is_refused_still_runs_the_attack(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    port, state = stub
    probes = fingerprint_probe_count()
    state["script"] = dict.fromkeys(range(1, probes + 1), _too_large)
    result = CliRunner().invoke(app, _run_argv(tmp_path, port, "-sV"))

    assert result.exit_code == 0, result.output
    assert (
        f"{probes} of {probes} probe(s) got no usable reply (metadata/self_id: ResponseTooLarge, "
        "behavioral/self_id: ResponseTooLarge, behavioral/cutoff: ResponseTooLarge, and 14 more); "
        "none did, so the fingerprint is empty. The exchanges are in "
    ) in result.stderr
    assert "fingerprint: hostile family=unknown (confidence 0.00)" in result.stdout
    assert f"[{probes} of {probes} probes got no usable reply]" in result.stdout
    _, attempts = _attempts(tmp_path)
    assert attempts and all(a["response"] is not None for a in attempts)
    assert state["served"] == probes + len(attempts)


def test_the_warning_is_not_silenced_by_quiet(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """A partial fingerprint changes the plan: a state change, not progress chatter."""

    port, state = stub
    state["script"] = {1: _too_large}
    result = CliRunner().invoke(app, _run_argv(tmp_path, port, "-sV", "-q"))

    assert result.exit_code == 0, result.output
    assert "1 of 17 probe(s) got no usable reply" in result.stderr


def test_the_fingerprint_command_reports_a_refused_probe_and_finishes(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    port, state = stub
    state["script"] = {1: _too_large}
    scope, target = _files(tmp_path, port)
    result = CliRunner().invoke(app, ["fingerprint", str(target), "--scope", str(scope)])

    assert result.exit_code == 0, result.output
    fp = ModelFingerprint.model_validate_json(result.stdout)
    assert failed_probes(fp) == ["metadata/self_id: ResponseTooLarge"]
    assert PROBES_FAILED_FLAG in fp.spoofing_flags
    assert (
        "1 of 17 probe(s) got no usable reply (metadata/self_id: ResponseTooLarge)" in result.stderr
    )
    assert state["served"] == fingerprint_probe_count()


def test_a_probe_that_gets_no_answer_stops_the_run_with_its_cause(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """Not a failed probe: the target is not answering. As before the fix, the run stops after
    the first probe's three sends with the cause; isolating it as well made a target that never
    replies cost 25.5 minutes of probing before an attack that failed the same way."""

    port, state = stub
    state["script"] = dict.fromkeys(range(1, 100), _unavailable)
    result = CliRunner().invoke(app, _run_argv(tmp_path, port, "-sV"))

    assert result.exit_code == 3, result.output
    assert "HTTP 503" in result.stderr
    assert "got no usable reply" not in result.stderr
    assert state["served"] == 3


def test_the_fingerprint_command_still_fails_on_a_closed_port(tmp_path: Path) -> None:
    """It exited 0 with an empty fingerprint and the cause reduced to a class name (pre-commit
    audit): nothing is listening, which is an error, and the message says what happened."""

    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    scope, target = _files(tmp_path, port)
    result = CliRunner().invoke(app, ["fingerprint", str(target), "--scope", str(scope)])

    assert result.exit_code == 3, result.output
    assert "ConnectError" in result.stderr
    assert result.stdout == ""


def _too_large_401() -> _Reply:
    return 401, {"content-type": "application/json"}, b"x" * (MAX_RESPONSE_BYTES + 1)


@pytest.mark.parametrize("command", ["run", "fingerprint"])
def test_a_credential_refused_with_a_huge_body_is_still_a_401(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], command: str
) -> None:
    """Classified by its status, not refused as too large: `dottore fingerprint` exited 0 on it
    with an empty fingerprint, and the probe pass would have gone on to the attack (delta audit
    of OD-23). One request, exit 3, the status in the message, as for a short 401."""

    port, state = stub
    state["script"] = dict.fromkeys(range(1, 100), _too_large_401)
    if command == "run":
        argv = _run_argv(tmp_path, port, "-sV")
    else:
        scope, target = _files(tmp_path, port)
        argv = ["fingerprint", str(target), "--scope", str(scope)]
    result = CliRunner().invoke(app, argv)

    assert result.exit_code == 3, result.output
    assert "HTTP 401" in result.stderr
    assert "got no usable reply" not in result.stderr
    assert state["served"] == 1


def test_the_fingerprint_command_fails_when_every_probe_is_refused(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """Nothing came back, so there is no fingerprint: an empty one printed with exit 0 read as a
    result to a script (delta audit)."""

    port, state = stub
    probes = fingerprint_probe_count()
    state["script"] = dict.fromkeys(range(1, probes + 1), _undecodable)
    scope, target = _files(tmp_path, port)
    result = CliRunner().invoke(app, ["fingerprint", str(target), "--scope", str(scope)])

    assert result.exit_code == 3, result.output
    assert result.stderr.startswith(f"error: hostile: {probes} of {probes} probe(s)")
    assert "none did, so the fingerprint is empty" in result.stderr
    assert result.stdout == ""
    assert state["served"] == probes
