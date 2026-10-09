"""An input filter that refuses the guardrail layer's benign request costs that probe (u09 A-67).

Azure OpenAI's prompt filter does not answer a request it blocks: it returns HTTP 400 with the
error code ``content_filter``. The adapters read every non-retryable 4xx as a product error, and
the probe pass let it through, so once A-67 added a benign request worded near a boundary ("How
do I kill a Python process ..."), ``dottore fingerprint`` and ``run -sV`` stopped with exit 3 on
such an endpoint after 8 requests, where ``main`` exited 0 (pre-merge audit of ``cd413c0``,
2026-10-09).

The benign request is read for the profile only, so a 4xx to it alone is a refusal of that
request: the probes before it went through with the same credential and route. It is now a
failed probe: ``benign_refused`` is unknown (``null``), ``probes_failed`` lists it, and the pass
and the run go on. The same 400 on any other probe still stops the pass, as on ``main``.

Through the real CLI against a local stub that blocks, as Azure does, every prompt with a word.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app
from ildottore.cli.run import fingerprint_probe_count
from ildottore.fingerprint import PROBES_FAILED_FLAG, failed_probes
from ildottore.shared.models import ModelFingerprint

#: The body Azure OpenAI returns, with status 400, for a prompt its content filter blocks.
_AZURE_PROMPT_FILTERED = json.dumps(
    {
        "error": {
            "message": (
                "The response was filtered due to the prompt triggering Azure OpenAI's content "
                "management policy. Please modify your prompt and retry."
            ),
            "type": None,
            "param": "prompt",
            "code": "content_filter",
            "status": 400,
            "innererror": {
                "code": "ResponsibleAIPolicyViolation",
                "content_filter_result": {
                    "violence": {"filtered": True, "severity": "medium"},
                },
            },
        }
    }
).encode()


def _completion(text: str) -> bytes:
    return json.dumps(
        {
            "id": "stub",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
        }
    ).encode()


@pytest.fixture
def azure() -> Iterator[tuple[int, dict[str, Any]]]:
    """Answers 400 ``content_filter`` to any prompt holding ``state["word"]``, else a reply."""

    state: dict[str, Any] = {"word": "kill", "served": 0, "blocked": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
            prompt = json.dumps(body.get("messages", [])).lower()
            state["served"] += 1
            if state["word"] in prompt:
                state["blocked"] += 1
                status, out = 400, _AZURE_PROMPT_FILTERED
            elif "refuse" in prompt:
                status, out = 200, _completion("I'm sorry, but I can't help with that.")
            else:
                status, out = 200, _completion("Hello, I am a helpful assistant.")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

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
        f'version: "1.0"\ntargets:\n  - id: azure\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    target.write_text(
        f'id: azure\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    return scope, target


def test_the_fingerprint_goes_on_past_an_input_filter_on_the_benign_request(
    tmp_path: Path, azure: tuple[int, dict[str, Any]]
) -> None:
    port, state = azure
    scope, target = _files(tmp_path, port)
    result = CliRunner().invoke(app, ["fingerprint", str(target), "--scope", str(scope)])

    assert result.exit_code == 0, result.output
    assert state["blocked"] == 1
    assert state["served"] == fingerprint_probe_count()
    fp = ModelFingerprint.model_validate_json(result.stdout)
    assert failed_probes(fp) == ["guardrail/guardrail_benign: AdapterStatusError"]
    assert PROBES_FAILED_FLAG in fp.spoofing_flags
    # Unknown, not "answered" and not "refused": the request never reached the model.
    assert fp.guardrails["benign_refused"] is None
    assert fp.guardrails["input_filter"] is None
    assert fp.guardrails["refusal_style"] == "polite-explain"
    assert result.stderr.startswith(
        f"warning: azure: 1 of {fingerprint_probe_count()} probe(s) got no usable reply "
        "(guardrail/guardrail_benign: AdapterStatusError)"
    )


def test_run_sv_goes_on_to_the_attack_past_an_input_filter_on_the_benign_request(
    tmp_path: Path, azure: tuple[int, dict[str, Any]]
) -> None:
    port, state = azure
    scope, target = _files(tmp_path, port)
    argv = [
        "run",
        "-t",
        str(target),
        "--scope",
        str(scope),
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
        "-oJ",
        str(tmp_path / "r.json"),
        "-sV",
    ]
    result = CliRunner().invoke(app, argv)

    assert result.exit_code != 3, result.output
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    attempts = [a for f in report["findings"] for a in f["attempts"]]
    assert attempts and all(a["response"] is not None for a in attempts)
    assert state["served"] == fingerprint_probe_count() + len(attempts)
    assert "(guardrail/guardrail_benign: AdapterStatusError)" in result.stderr


def test_the_same_refusal_of_any_other_probe_still_stops_the_pass(
    tmp_path: Path, azure: tuple[int, dict[str, Any]]
) -> None:
    """Only the profile-only probe is isolated: a 4xx to the request to refuse, which the pack
    attributes from, stops the pass as on ``main``."""

    port, state = azure
    state["word"] = "refuse"
    scope, target = _files(tmp_path, port)
    result = CliRunner().invoke(app, ["fingerprint", str(target), "--scope", str(scope)])

    assert result.exit_code == 3, result.output
    assert "non-retryable HTTP 400" in result.stderr
    assert result.stdout == ""
    assert state["blocked"] == 1
    assert state["served"] == 7  # the nudge is the seventh send; nothing after it went out


@pytest.mark.parametrize(
    ("status", "refused"),
    [(400, True), (403, True), (422, True), (499, True), (302, False), (501, False)],
)
def test_a_refused_request_is_a_4xx_status(status: int, refused: bool) -> None:
    """The predicate the composition root injects: a 4xx the endpoint answered one request with.
    A 3xx (redirects are not followed) or a 5xx the retries do not cover is not a refusal of
    the prompt; an error with no status (a reply that is not JSON) is not either."""

    from ildottore.adapters import AdapterProductError, AdapterStatusError
    from ildottore.adapters.base import ResponseTooLarge
    from ildottore.cli.wiring import refused_request

    error = AdapterStatusError(f"t: non-retryable HTTP {status}", status_code=status)
    assert isinstance(error, AdapterProductError)
    assert refused_request(error) is refused
    assert refused_request(AdapterProductError("t: success response was not valid JSON")) is False
    assert refused_request(ResponseTooLarge("t: too large")) is False
