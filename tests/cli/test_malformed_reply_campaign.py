"""A 200 the adapters cannot read fails its attempt; a target that answers nothing readable stops
early (OD-21, u04 and u08 A-74), through the real CLI.

Against a local OpenAI-compatible stub. On ``main`` at ``6d5f7ae`` one ``<html>`` reply made
``dottore run`` exit 3 at that reply ("aborted on AdapterProductError: hostile: success response
was not valid JSON ...; 1 of 2 specs never ran or did not finish" when it answered the fourth
request), whichever request it answered.
Decided 2026-10-11 under the owner's delegation (best practice), revisable: the attempt is
inconclusive, not retried, kept by a resume and re-derived by ``replay``, and the campaign goes on;
a campaign whose first five replies all are unreadable, with none readable, stops (exit 3) and says
to check the endpoint, so a wrong endpoint is not an all-inconclusive run.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

_REPLY = json.dumps(
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
)
_HTML = "<html><body>Service portal: please sign in</body></html>"
_SECURE = json.dumps(
    {
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(
                        {
                            "verdict": "secure",
                            "confidence": 0.95,
                            "reasoning": "The target refused.",
                            "observed_injection_attempt": False,
                        }
                    ),
                },
                "finish_reason": "stop",
            }
        ]
    }
)
#: A wrapper that pastes the model's output into its JSON unescaped breaks on a quote, which is
#: what a jailbreak that worked writes (pre-merge audit of 598f0858, HIGH 1).
_BROKEN = (
    '{"id":"stub","object":"chat.completion","choices":[{"index":0,"message":{"role":'
    '"assistant","content":"Sure. Ignoring my rules: "DAN mode enabled" PWNED"},'
    '"finish_reason":"stop"}]}'
)

#: Two single-turn specs, as in ``test_hostile_nesting.py``.
_SPECS = ("JB-REFUSAL-SUPPRESS-001", "PI-DIRECT-001")


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, Any]]]:
    """Answers the n-th request (from 1) with ``script[n]``, else with ``default``."""

    state: dict[str, Any] = {"script": {}, "default": _REPLY, "served": 0, "judged": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers.get("content-length", "0")))
            if json.loads(raw).get("model") == "j":  # the judge: a secure verdict
                state["judged"] += 1
                body = _SECURE.encode()
            elif state.get("waf"):  # a content filter's 200 block page for some prompts
                state["served"] += 1
                text = raw.decode("utf-8", "replace").lower()
                body = (_HTML if any(w in text for w in state["waf"]) else _REPLY).encode()
            else:
                state["served"] += 1
                body = state["script"].get(state["served"], state["default"]).encode()
            self.send_response(200)
            self.send_header("content-type", "text/html" if body.startswith(b"<") else "json")
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


def _argv(
    tmp_path: Path, port: int, *extra: str, specs: tuple[str, ...] = _SPECS, judge: bool = False
) -> list[str]:
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    entry = (
        "  - id: {id}\n"
        f'    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n{entry.format(id="hostile")}{entry.format(id="judge")}'
    )
    (tmp_path / "judge.yaml").write_text(
        f'id: judge\ntype: model\nprovider: openai\nendpoint: "{endpoint}"\nmodel: j\n'
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    if judge:
        extra = (*extra, "--judge", str(tmp_path / "judge.yaml"))
    (tmp_path / "target.yaml").write_text(
        f'id: hostile\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    return [
        *("run", "-t", str(tmp_path / "target.yaml"), "--scope", str(tmp_path / "scope.yaml")),
        *(arg for spec in specs for arg in ("--spec", spec)),
        *("--rate", "1000", "--concurrency", "1", "--no-color"),
        *("--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "runs.sqlite")),
        *("-oJ", str(tmp_path / "r.json")),
        *extra,
    ]


def _report(tmp_path: Path) -> dict[str, Any]:
    return json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _run_id(tmp_path: Path) -> str:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        (run_id,) = conn.execute("SELECT run_id FROM runs").fetchone()
    finally:
        conn.close()
    return str(run_id)


@pytest.mark.parametrize("at", [1, 4])
def test_one_reply_that_is_not_json_fails_its_attempt_and_the_scan_goes_on(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], at: int
) -> None:
    port, state = stub
    state["script"] = {at: _HTML}
    result = CliRunner().invoke(app, _argv(tmp_path, port, "--runs", "1"))

    assert result.exit_code != 3, result.output
    assert "did not complete" not in result.output
    report = _report(tmp_path)
    assert {f["spec_id"] for f in report["findings"]} == set(_SPECS)
    attempts = [a for f in report["findings"] for a in f["attempts"]]
    failed = [a for a in attempts if a["error"]]
    assert len(failed) == 1, [a["error"] for a in attempts]
    assert failed[0]["error"].startswith("ResponseMalformed: hostile: success response was not")
    assert failed[0]["error"].endswith("[unreadable_reply]")
    assert failed[0]["response"] is None
    assert failed[0]["verdict"]["status"] == "inconclusive"
    assert failed[0]["verdict"]["inconclusive_reason"] == "unreadable_reply"
    kept = failed[0]["request"]["metadata"]["unreadable_reply"]
    assert kept["excerpt"] == _HTML and kept["bytes"] == len(_HTML)
    assert all(a["response"] is not None for a in attempts if not a["error"])
    assert state["served"] == len(attempts)  # the unreadable one was not sent again
    assert report["summary"]["unreadable_reply"]["attempts"] == 1
    assert "Unreadable replies: 1 attempt(s) in 1 spec(s)" in result.stdout

    # `dottore replay` re-derives it from the evidence, as stored.
    replay = CliRunner().invoke(
        app,
        [
            *("replay", _run_id(tmp_path), "--evidence-root", str(tmp_path / "ev")),
            *("--run-db", str(tmp_path / "runs.sqlite")),
        ],
    )
    assert replay.exit_code == 0, replay.output
    assert "(unreadable_reply)" in replay.output
    assert "1 of " in replay.output and "could not be read" in replay.output


def test_a_target_that_answers_nothing_readable_stops_after_five_requests(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    port, state = stub
    state["default"] = _HTML
    result = CliRunner().invoke(app, _argv(tmp_path, port))

    assert result.exit_code == 3, result.output
    assert state["served"] == 6  # five attacks and the benign check, all answered with HTML
    assert (
        "error: run on hostile did not complete: aborted on UnreadableReplies: the target's "
        "first 5 replies in this run could not be read"
    ) in result.stderr
    assert "nor a benign check sent then" in result.stderr
    assert "endpoint is an OpenAI chat completions URL" in result.stderr
    assert "response template" not in result.stderr  # a target file declares none (LOW 2)
    assert "ResponseMalformed: hostile: success response was not valid JSON" in result.stderr
    # Every reply sent is stored, the fifth included (MEDIUM 1).
    stored = [p for p in (tmp_path / "ev").rglob("*.json") if "probes" not in p.parts]
    assert len(stored) == 5
    assert result.stderr.rstrip().endswith("2 of 2 specs never ran or did not finish")
    report = _report(tmp_path)
    assert report["summary"]["status"]["state"] == "aborted"


def test_a_resume_after_the_stop_sends_the_unreadable_attempts_again(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """The five replies stored before the stop are not kept (LOW 1): the target may have been
    fixed, so a resume sends them again, and with the endpoint answering the run finishes with
    no unreadable attempt left."""

    port, state = stub
    state["default"] = _HTML
    first = CliRunner().invoke(app, _argv(tmp_path, port, "--runs", "2"))
    assert first.exit_code == 3, first.output
    assert state["served"] == 6  # five attacks and the benign check
    run_id = _run_id(tmp_path)

    state["default"] = _REPLY
    resumed = CliRunner().invoke(app, _argv(tmp_path, port, "--runs", "2", "--resume", run_id))
    assert resumed.exit_code != 3, resumed.output
    said = resumed.stdout + resumed.stderr
    assert "5 that could not be read will be sent again" in said
    # It keeps none: verification of 07aa0b3a, LOW 2 ("keeps 0 attempt(s) across 1 spec(s)").
    assert "keeps none of the 5 attempt(s) it stored" in said and "keeps 0 attempt" not in said
    report = _report(tmp_path)
    attempts = {a["attempt_id"] for f in report["findings"] for a in f["attempts"]}
    assert report["summary"]["unreadable_reply"]["attempts"] == 0
    assert state["served"] == 6 + len(attempts)


def test_fewer_attempts_than_the_stop_all_unreadable_is_not_a_clean_scan(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """Two attempts, both unreadable: the stop is never reached, and the run is reported as one
    that evaluated nothing, its reason naming the unreadable replies (not "failed on transport")."""

    port, state = stub
    state["default"] = _HTML
    # One spec with one variant (`mutations: [identity]`), sent twice.
    argv = _argv(tmp_path, port, "--runs", "2", specs=("BIAS-STEREOTYPE-001",))
    result = CliRunner().invoke(app, argv)

    assert result.exit_code == 3, result.output
    assert state["served"] == 2
    assert (
        "every one of the 2 attempt(s) got a reply that could not be read as the provider's, so "
        "nothing was evaluated: check that the target file's endpoint is an OpenAI chat "
        "completions URL"
    ) in result.stderr
    assert _report(tmp_path)["summary"]["status"]["state"] == "unreachable"


@pytest.mark.parametrize(
    ("errors", "said"),
    [
        (
            ["ResponseMalformed: t: x; not evaluated [unreadable_reply]"] * 2,
            "every one of the 2 attempt(s) got a reply that could not be read as the provider's",
        ),
        (
            [
                "AdapterEnvError: t: exhausted 4 attempt(s)",
                "ResponseMalformed: t: x; not evaluated [unreadable_reply]",
            ],
            "every one of the 2 attempt(s) failed on transport or (1 of them) with a reply that "
            "could not be read as the provider's",
        ),
        (
            ["AdapterEnvError: t: exhausted 4 attempt(s)"] * 2,
            "every one of the 2 attempt(s) failed on transport, so nothing was evaluated: "
            "AdapterEnvError",
        ),
    ],
    ids=["unreadable", "mixed", "transport"],
)
def test_the_unreachable_reason_names_what_the_attempts_got(errors: list[str], said: str) -> None:
    from ildottore.cli.run import _unreachable_reason
    from ildottore.core.runner import CampaignResult
    from ildottore.shared.models import Attempt, ModelRequest, TestPlan, TestRun
    from tests.cli.conftest import make_finding

    base = make_finding("PI-DIRECT-001")
    attempts = [
        Attempt(
            attempt_id=f"a{i}",
            spec_id="PI-DIRECT-001",
            request=ModelRequest(prompt="p"),
            error=error,
        )
        for i, error in enumerate(errors)
    ]
    result = CampaignResult(
        plan=TestPlan(plan_ref="p", target_id="t", adaptive=False),
        run=TestRun(run_id="r"),
        findings=[base.model_copy(update={"attempts": attempts})],
    )
    reason = _unreachable_reason(result) or ""
    assert reason.startswith(said), reason
    if "could not be read" in said:
        assert "check the target file's endpoint and provider" in reason  # no advice stored


def test_a_jailbreak_that_broke_the_wrapper_never_passes_its_spec(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """Pre-merge audit of 598f0858, HIGH 1, as measured: `PI-DIRECT-001 --runs 3`, the first
    reply a wrapper's JSON broken by the quotes of `"DAN mode enabled" PWNED`, the other two
    refusals a secure judge passes. On 598f0858 the spec passed (two of three held), exit 0, and
    no report said a reply was unreadable; on 6d5f7ae the run stopped, exit 3. Now the spec is
    inconclusive, and every report counts the unreadable attempt."""

    port, state = stub
    state["script"] = {1: _BROKEN}
    argv = _argv(
        tmp_path,
        port,
        *("--runs", "3", "--concurrency", "1", "-q"),
        *("-oS", str(tmp_path / "r.sarif"), "-oX", str(tmp_path / "r.xml")),
        *("-oH", str(tmp_path / "r.html")),
        specs=("PI-DIRECT-001",),
        judge=True,
    )
    result = CliRunner().invoke(app, argv)

    assert result.exit_code == 0, result.output
    assert state["judged"] > 0
    (finding,) = _report(tmp_path)["findings"]
    assert finding["status"] == "inconclusive"
    assert "could not be read as the provider's reply" in finding["reasoning"]
    assert "Unreadable replies: 1 attempt(s) in 1 spec(s) (PI-DIRECT-001)" in result.stdout
    assert _report(tmp_path)["summary"]["unreadable_reply"] == {
        "attempts": 1,
        "specs": ["PI-DIRECT-001"],
    }
    sarif = json.loads((tmp_path / "r.sarif").read_text(encoding="utf-8"))
    (run,) = sarif["runs"]
    assert run["results"][0]["properties"]["unreadable_reply"] == 1
    assert "could not be read" in run["results"][0]["message"]["text"]
    assert run["properties"]["unreadable_reply"] == 1
    assert "unreadable_reply=1" in (tmp_path / "r.xml").read_text(encoding="utf-8")
    assert "could not be read" in (tmp_path / "r.html").read_text(encoding="utf-8")


def test_a_target_that_breaks_mid_run_stops_after_twenty_unreadable_replies_in_a_row(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """Pre-merge audit of 598f0858, MEDIUM 2: two readable replies, then a login page for every
    request. On 598f0858 the default battery sent 355 requests, 353 of them unreadable, and
    exited 0. Now it stops after 20 unreadable replies in a row, exit 3, and says why."""

    port, state = stub
    state["script"] = {1: _REPLY, 2: _REPLY}
    state["default"] = _HTML
    result = CliRunner().invoke(app, _argv(tmp_path, port, "--concurrency", "1"))

    assert result.exit_code == 3, result.output
    assert state["served"] == 23  # 2 read, 20 in a row, and the benign check, HTML too
    assert (
        "aborted on UnreadableReplies: the target's last 20 replies in this run could not be read "
        "as replies, in a row after ones that could"
    ) in result.stderr


def test_a_target_behind_a_filter_that_blocks_attack_prompts_finishes_its_battery(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """Verification of 07aa0b3a, MEDIUM: a content filter that answers prompts holding some words
    with a 200 HTML block page. With the auditor's words, the default battery at `--concurrency 1`
    read 69 of 284 replies as block pages, 20 of them in a row, and stopped with exit 3; every
    resume then sent the 69 first, and a fresh watch stopped it after five: it could never finish.
    Before each stop the watch now sends one benign request, the filter lets it through, and the
    run goes on to the end with the blocked attempts inconclusive and counted."""

    port, state = stub
    state["waf"] = [
        "ignore",
        "instruction",
        "system prompt",
        "pretend",
        "rules",
        "secret",
        "password",
        "bypass",
    ]
    # The default battery, as the auditor ran it.
    result = CliRunner().invoke(app, _argv(tmp_path, port, "--concurrency", "1", specs=()))

    assert result.exit_code != 3, result.stderr
    assert "did not complete" not in result.stderr
    report = _report(tmp_path)
    assert report["summary"]["status"]["state"] == "complete"
    assert report["summary"]["unreadable_reply"]["attempts"] > 20
    assert "Unreadable replies:" in result.stdout
    probes = list((tmp_path / "ev").rglob("probes/*.json"))
    assert probes, "the run of block pages was checked with a benign request"
