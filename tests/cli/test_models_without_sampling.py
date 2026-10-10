"""A model that takes no temperature or top_p can be scanned (u12 A-68).

Anthropic's API reference (read in the reference bundled with the claude-api skill, cached
2026-09-25; not tested against the live API) says Claude Opus 4.7 and later, the Fable and Mythos
5 families answer a ``temperature`` or a ``top_p`` with HTTP 400, and Sonnet 5 and Sonnet 5.5 any
value but the default. The scanner pins temperature 0 on every spec, probe and judge request, so
every ``provider: anthropic`` campaign against those models stopped at its first request with
``non-retryable HTTP 400``, and nothing said why.

Now a target file's ``capabilities.sampling`` says whether the target takes them. Left out, a
documented list (``adapters.anthropic.MODELS_WITHOUT_SAMPLING``) decides for ``provider:
anthropic``; ``false`` sends neither to any model, through the OpenAI adapter too, and ``true``
sends them to a listed one. What goes out is what is recorded, and the record, the run's notice,
``--dry-run``, ``-sn``, the ``-sV`` line, ``dottore fingerprint`` and ``dottore replay`` say that
such replies are not temperature-0 deterministic. A 400 that names a sampling parameter the
request sent is refused, not retried, in words that name the capability.

Through the real CLI against a loopback stub whose ``/v1/messages`` endpoint refuses any
``temperature`` or ``top_p``, as the reference says those models do (the error text is the stub's
own: the reference names none).
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

from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.cli.run import fingerprint_probe_count
from ildottore.shared.digest import target_digest
from ildottore.shared.models import Capabilities, Sampling, Target

_SPEC = "JB-REFUSAL-SUPPRESS-001"  # its own sampling: temperature 0, seed 42, max_tokens 600
_LISTED = "claude-opus-5-5"
_SAMPLING_KEYS = ("temperature", "top_p", "top_k")

_JUDGE_SAYS_SECURE = json.dumps(
    {
        "verdict": "secure",
        "confidence": 0.95,
        "reasoning": "the reply refused",
        "observed_injection_attempt": False,
    }
)
_REFUSED = {
    "type": "error",
    "error": {"type": "invalid_request_error", "message": "temperature is not supported"},
}


def _anthropic(text: str) -> dict[str, Any]:
    return {
        "id": "stub",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
    }


def _openai(text: str) -> dict[str, Any]:
    return {
        "id": "stub",
        "object": "chat.completion",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}
        ],
    }


@pytest.fixture
def stub() -> Iterator[tuple[int, list[tuple[str, dict[str, Any]]]]]:
    """Strict Anthropic endpoints (target and judge) and a recording OpenAI one."""

    seen: list[tuple[str, dict[str, Any]]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
            seen.append((self.path, body))
            status = 200
            if self.path.endswith("/messages") and any(k in body for k in _SAMPLING_KEYS):
                status, reply = 400, _REFUSED
            elif self.path.startswith("/judge/"):
                reply = _anthropic(_JUDGE_SAYS_SECURE)
            elif self.path.endswith("/messages"):
                reply = _anthropic("I cannot help with that.")
            else:
                reply = _openai("I cannot help with that.")
            raw = json.dumps(reply).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield server.server_address[1], seen
    finally:
        server.shutdown()
        server.server_close()


def _files(
    tmp_path: Path,
    port: int,
    *,
    model: str = _LISTED,
    provider: str = "anthropic",
    sampling: bool | None = None,
    judge_model: str = "claude-fable-5-1",
    block: str = "",
) -> None:
    path = "/v1/messages" if provider == "anthropic" else "/v1/chat/completions"
    endpoint = f"http://127.0.0.1:{port}{path}"
    judge_endpoint = f"http://127.0.0.1:{port}/judge/v1/messages"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n        path_prefixes: ["{path}"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
        f'  - id: judge\n    base_url: "{judge_endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/judge/v1/messages"]\n'
        '    identities:\n      - name: judge\n        auth_ref: "env://NONE"\n'
    )
    declared = "" if sampling is None else f"  sampling: {str(sampling).lower()}\n"
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: chatbot\nprovider: {provider}\nendpoint: "{endpoint}"\n'
        f'model: "{model}"\ncapabilities:\n  tools: false\n  rag: false\n'
        + declared
        + (f"sampling_defaults: {block}\n" if block else "")
    )
    (tmp_path / "judge.yaml").write_text(
        f'id: judge\ntype: model\nprovider: anthropic\nendpoint: "{judge_endpoint}"\n'
        f'model: "{judge_model}"\n'
    )


def _run(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "run",
        "-t",
        str(tmp_path / "target.yaml"),
        "--scope",
        str(tmp_path / "scope.yaml"),
        "--spec",
        _SPEC,
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
        *extra,
    ]


def _sampled(seen: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    return [{k: body[k] for k in (*_SAMPLING_KEYS, "seed") if k in body} for _, body in seen]


def _run_id(tmp_path: Path) -> str:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        (row,) = conn.execute("SELECT run_id FROM runs").fetchall()
    finally:
        conn.close()
    return str(row[0])


def _stored(tmp_path: Path, kind: str) -> list[dict[str, Any]]:
    folder = tmp_path / "ev" / _run_id(tmp_path) / kind
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))]


# --- the battery ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "provider", "sampling"),
    [
        (_LISTED, "anthropic", None),  # the list decides
        ("claude-sonnet-5", "anthropic", None),
        ("m", "anthropic", False),  # the capability decides, for a model the list does not know
        ("o-reasoner", "openai", False),  # and through the OpenAI adapter too
    ],
    ids=["listed", "listed-sonnet-5", "declared-anthropic", "declared-openai"],
)
def test_a_target_that_takes_no_sampling_is_sent_none_and_the_record_says_so(
    tmp_path: Path,
    stub: tuple[int, list[tuple[str, dict[str, Any]]]],
    model: str,
    provider: str,
    sampling: bool | None,
) -> None:
    """f12ba83, 8d1bc59 and 00b2fca sent temperature 0: the strict endpoint refused the first
    request and the run stopped (exit 3); against OpenAI it went out."""

    port, seen = stub
    _files(tmp_path, port, model=model, provider=provider, sampling=sampling)
    result = CliRunner().invoke(app, _run(tmp_path))
    assert result.exit_code == 0, result.output
    expected = {} if provider == "anthropic" else {"seed": 42}
    assert seen and all(s == expected for s in _sampled(seen)), seen
    assert "is sent no temperature or top_p" in result.stderr, result.stderr
    assert "not temperature-0 deterministic" in result.stderr
    attempts = _stored(tmp_path, "attempts")
    assert attempts
    for attempt in attempts:
        recorded = {k: v for k, v in (attempt["request"]["sampling"] or {}).items() if v}
        assert "temperature" not in recorded and "top_p" not in recorded, attempt
        assert attempt["sampling"] == attempt["request"]["sampling"]
        unsent = attempt["request"]["metadata"]["sampling_not_sent"]
        assert "temperature" in unsent, attempt
        assert ("seed" in unsent) is (provider == "anthropic")


def test_the_record_lists_what_the_block_asked_for_and_did_not_go_out(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """The block's top_p and seed never go out to a listed model, and the record says so: it was
    counted from the block as the adapter keeps it, which had already lost them (pre-merge audit
    of A-68). The probes' record lists them too."""

    port, seen = stub
    _files(tmp_path, port, block="{ top_p: 0.9, seed: 7, max_tokens: 33 }")
    result = CliRunner().invoke(app, _run(tmp_path, "-sV"))
    assert result.exit_code == 0, result.output
    assert all(s == {} for s in _sampled(seen)), seen
    for attempt in _stored(tmp_path, "attempts"):
        unsent = attempt["request"]["metadata"]["sampling_not_sent"]
        assert {"temperature", "top_p", "seed"} <= set(unsent), attempt
        assert attempt["request"]["sampling"]["max_tokens"] == 600, "the spec's own wins"
    for probe in _stored(tmp_path, "probes"):
        unsent = probe["request"]["metadata"]["sampling_not_sent"]
        assert {"temperature", "top_p", "seed"} <= set(unsent), probe


def test_a_listed_model_declared_sampling_true_is_sent_it_and_the_refusal_names_the_fix(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """The capability overrides the list. The strict endpoint then refuses the first request,
    and the run says what to set, after one request (a 400 is not retried)."""

    port, seen = stub
    _files(tmp_path, port, sampling=True)
    result = CliRunner().invoke(app, _run(tmp_path))
    assert result.exit_code == 3, result.output
    assert len(seen) == 1 and _sampled(seen) == [{"temperature": 0.0}], seen
    flat = " ".join(result.output.split())
    assert "the target refused the request's temperature" in flat, flat
    assert "`sampling: false` under capabilities in the target file of stub" in flat, flat


def test_a_model_the_list_does_not_know_is_refused_in_words_that_name_the_capability(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """Before: `non-retryable HTTP 400 from /v1/messages`, and nothing said why."""

    port, seen = stub
    _files(tmp_path, port, model="claude-opus-9")
    result = CliRunner().invoke(app, _run(tmp_path))
    assert result.exit_code == 3, result.output
    assert len(seen) == 1, seen
    flat = " ".join(result.output.split())
    assert "the target refused the request's temperature" in flat, flat
    assert "`sampling: false` under capabilities in the target file of stub" in flat, flat


# --- the probes, the judge and the plan -------------------------------------------------------


def test_the_probes_go_out_with_no_temperature_and_the_fingerprint_says_so(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    port, seen = stub
    _files(tmp_path, port)
    fingerprint = CliRunner().invoke(
        app, ["fingerprint", str(tmp_path / "target.yaml"), "--scope", str(tmp_path / "scope.yaml")]
    )
    assert fingerprint.exit_code == 0, fingerprint.output
    assert len(seen) == fingerprint_probe_count()
    assert all(s == {} for s in _sampled(seen)), seen
    assert "the fingerprint is not temperature-0 repeatable" in fingerprint.stderr

    seen.clear()
    result = CliRunner().invoke(app, _run(tmp_path, "-sV"))
    assert result.exit_code == 0, result.output
    assert all(s == {} for s in _sampled(seen)), seen
    assert "[probes sent with no temperature: not temperature-0 repeatable]" in result.output
    probes = _stored(tmp_path, "probes")
    assert len(probes) == fingerprint_probe_count()
    for probe in probes:
        assert (probe["request"]["sampling"] or {}).get("temperature") is None, probe
        assert "temperature" in probe["request"]["metadata"]["sampling_not_sent"], probe


def test_a_judge_that_refuses_sampling_stops_the_run_and_names_the_fix(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """The judge read every SamplingRefused as an outage: each judged spec came back
    inconclusive, the run exited 0, and nothing named `sampling: false` (29 refused judge
    requests in the pre-merge audit). It stops at the first refusal now, as a target does."""

    port, seen = stub
    _files(tmp_path, port, model="claude-sonnet-4-6", provider="openai", judge_model="claude-x-9")
    result = CliRunner().invoke(app, _run(tmp_path, "--judge", str(tmp_path / "judge.yaml")))
    assert result.exit_code == 3, result.output
    judged = [body for path, body in seen if path.startswith("/judge/")]
    assert len(judged) == 1, "the first refusal stops it: no retry, no second pass"
    flat = " ".join(result.output.split())
    assert "SamplingRefused" in flat, flat
    assert "`sampling: false` under capabilities in the target file of judge" in flat, flat


def test_a_judge_that_takes_no_sampling_is_sent_none(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """The judge pins temperature 0 and 0.5 and top_p 1.0; a Fable judge refused all of it."""

    port, seen = stub
    _files(tmp_path, port)
    result = CliRunner().invoke(app, _run(tmp_path, "--judge", str(tmp_path / "judge.yaml")))
    assert result.exit_code == 0, result.output
    judged = [body for path, body in seen if path.startswith("/judge/")]
    assert judged and all(not any(k in b for k in _SAMPLING_KEYS) for b in judged), judged
    assert "the --judge model judge is sent no temperature or top_p" in result.stderr


def test_the_dry_run_and_discovery_say_it_and_send_nothing(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    port, seen = stub
    _files(tmp_path, port)
    dry = CliRunner().invoke(
        app, _run(tmp_path, "--dry-run", "--judge", str(tmp_path / "judge.yaml"))
    )
    assert dry.exit_code == 0, dry.output
    flat = " ".join(dry.stdout.split())
    assert (
        f"sampling: stub is sent no temperature or top_p (model {_LISTED} takes none, per "
        "adapters.anthropic.MODELS_WITHOUT_SAMPLING; set capabilities.sampling: true to send "
        "them): it samples at its own default, so its replies are not temperature-0 deterministic"
    ) in flat, flat
    assert "judge sampling: judge is sent no temperature or top_p" in flat, flat
    assert "two samples at that default" in flat
    assert "judge gets no top_p" not in flat, "the no-sampling line says it all"
    discovery = CliRunner().invoke(app, _run(tmp_path, "-sn"))
    assert discovery.exit_code == 0, discovery.output
    assert "sampling:  stub is sent no temperature or top_p" in discovery.stdout, discovery.stdout
    assert seen == []


def test_replay_says_the_attempts_went_out_with_no_temperature(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    port, _seen = stub
    _files(tmp_path, port)
    assert CliRunner().invoke(app, _run(tmp_path)).exit_code == 0
    run_id = _run_id(tmp_path)
    replayed = CliRunner().invoke(
        app,
        [
            "replay",
            run_id,
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
        ],
    )
    assert replayed.exit_code == 0, replayed.output
    flat = " ".join(replayed.output.split())
    assert "3 of 3 attempt artifact(s) went out with no temperature" in flat, flat
    assert "not temperature-0 deterministic" in flat


# --- the pieces -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "listed"),
    [
        ("claude-opus-5-5", True),
        ("claude-opus-5", True),
        ("CLAUDE-OPUS-4-8", True),
        ("claude-opus-4-7@20260416", True),
        ("claude-fable-5-1", True),
        ("claude-mythos-5-1", True),
        ("claude-sonnet-5", True),
        ("claude-sonnet-5-5", True),
        ("anthropic.claude-opus-5-5", True),  # Bedrock
        ("us.anthropic.claude-sonnet-5-5", True),  # a Bedrock inference profile
        ("anthropic.claude-opus-4-7-v1:0", True),
        ("arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-4-7-v1:0", True),
        (
            "arn:aws:bedrock:us-east-1:123456789012:inference-profile/"
            "us.anthropic.claude-sonnet-5-5-v1:0",
            True,
        ),
        ("anthropic/claude-opus-4.7", True),  # a gateway's slash-and-dot form
        ("openrouter/anthropic/claude-fable-5.1", True),
        ("claude-opus-5.5", True),
        ("claude-opus-4-7[1m]", True),  # a context-window tag
        ("projects/p/locations/global/publishers/anthropic/models/claude-opus-4-8@20260601", True),
        ("anthropic/claude-sonnet-4.6", False),
        ("claude-opus-4.70", False),
        ("claude-opus-50[1m]", False),
        ("claude-opus-4-6[1m]", False),
        ("anthropic.claude-haiku-4-5-v1:0", False),
        ("arn:aws:bedrock:us-east-1:123456789012:provisioned-model/abc123", False),
        ("foo.claude-opus-5", False),  # a prefix that is not a gateway's
        ("claude-3-7-sonnet", False),
        ("claude-opus-4-6", False),
        ("claude-sonnet-4-6", False),
        ("claude-haiku-4-5", False),
        ("claude-opus-50", False),  # a family matches whole, never a longer number
        ("claude-sonnet-50-1", False),
        ("not-claude-opus-5", False),
        ("", False),
        (None, False),
    ],
)
def test_the_list_matches_a_family_whole(model: str | None, listed: bool) -> None:
    from ildottore.adapters.anthropic import takes_no_sampling

    assert takes_no_sampling(model) is listed


@pytest.mark.parametrize(
    ("provider", "model", "declared", "takes"),
    [
        ("anthropic", _LISTED, None, False),
        ("anthropic", _LISTED, True, True),  # the capability overrides the list
        ("anthropic", "claude-sonnet-4-6", None, True),
        ("anthropic", "claude-sonnet-4-6", False, False),
        ("openai", _LISTED, None, True),  # the list is the Messages API's: a gateway declares it
        ("openai", "m", False, False),
    ],
)
def test_takes_sampling_follows_the_capability_then_the_list(
    provider: str, model: str, declared: bool | None, takes: bool
) -> None:
    target = Target(
        id="t",
        type="chatbot",  # type: ignore[arg-type]
        provider=provider,
        model=model,
        capabilities=Capabilities(sampling=declared),
    )
    assert wiring.takes_sampling(target)[0] is takes


@pytest.mark.parametrize("enabled", [True, False])
def test_the_anthropic_rule_without_sampling_drops_temperature_and_top_p(enabled: bool) -> None:
    from ildottore.adapters.anthropic import sent_sampling

    asked = Sampling(temperature=0.0, top_p=1.0, seed=42, max_tokens=9)
    sent = sent_sampling(asked, sampling_enabled=enabled)
    assert sent == (Sampling(temperature=0.0, max_tokens=9) if enabled else Sampling(max_tokens=9))


def test_a_target_that_does_not_declare_the_capability_keeps_its_digest() -> None:
    """A run stored before the capability existed still resumes: the digest of a target that
    does not declare it is the one 00b2fca computed (measured there)."""

    target = Target(
        id="stub",
        type="chatbot",  # type: ignore[arg-type]
        provider="anthropic",
        endpoint="http://127.0.0.1:9/v1/messages",
        model=_LISTED,
        capabilities=Capabilities(tools=False, rag=False),
        sampling_defaults=Sampling(temperature=0.0),
    )
    assert target_digest(target) == (
        "sha256:v2:ae260794a6c973935c624dfd37b94b5067f944552d90e59add9c2ca8cee1fb7e"
    )
    assert target_digest(target, mock_scenario="bare") == (
        "sha256:v2:598054dd8bdb86fd0e848217da835fbe500282ef38bd79192da4c45f533bfd42"
    )
    declared = target.model_copy(
        update={"capabilities": Capabilities(tools=False, rag=False, sampling=False)}
    )
    assert target_digest(declared) != target_digest(target), "declared, it is part of what answers"


@pytest.mark.parametrize("value", ["maybe", "[]", "{}"])
def test_a_sampling_capability_that_is_not_a_boolean_is_refused(tmp_path: Path, value: str) -> None:
    from tests.cli.conftest import write_scope

    write_scope(tmp_path)
    (tmp_path / "target.yaml").write_text(
        f"id: mock-target\ntype: chatbot\ncapabilities:\n  sampling: {value}\n"
    )
    result = CliRunner().invoke(app, _run(tmp_path, "--dry-run"))
    assert result.exit_code == 3, result.output
    assert "'capabilities' failed validation: sampling" in " ".join(result.output.split())


# --- a resume ---------------------------------------------------------------------------------


def _context(tmp_path: Path) -> dict[str, Any]:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        (raw,) = conn.execute("SELECT context_json FROM runs").fetchone()
    finally:
        conn.close()
    return dict(json.loads(raw))


def _write_context(tmp_path: Path, context: dict[str, Any]) -> None:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        with conn:
            conn.execute("UPDATE runs SET context_json = ?", (json.dumps(context),))
    finally:
        conn.close()


def _halt(tmp_path: Path) -> str:
    halted = CliRunner().invoke(app, _run(tmp_path, "--budget-requests", "1"))
    assert halted.exit_code == 3, halted.output
    assert "budget ceiling reached" in halted.output, halted.output
    return _run_id(tmp_path)


def test_the_run_records_whether_its_target_and_judge_were_sent_sampling(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    port, seen = stub
    _files(tmp_path, port, judge_model="claude-sonnet-4-6")
    run_id = _halt_with_judge(tmp_path)
    context = _context(tmp_path)
    assert context["takes_sampling"] is False and context["judge_takes_sampling"] is True
    seen.clear()
    resumed = CliRunner().invoke(
        app, _run(tmp_path, "--resume", run_id, "--judge", str(tmp_path / "judge.yaml"))
    )
    assert resumed.exit_code in (0, 3), resumed.output
    assert "when it started" not in resumed.stderr, "nothing changed, nothing said"
    target = [body for path, body in seen if not path.startswith("/judge/")]
    assert target and all(not any(k in b for k in _SAMPLING_KEYS) for b in target), target


def _halt_with_judge(tmp_path: Path) -> str:
    command = _run(tmp_path, "--budget-requests", "1", "--judge", str(tmp_path / "judge.yaml"))
    halted = CliRunner().invoke(app, command)
    assert halted.exit_code == 3, halted.output
    return _run_id(tmp_path)


@pytest.mark.parametrize("recorded", [True, None], ids=["recorded", "started-before-the-record"])
def test_a_resume_with_attempts_kept_continues_as_its_run_started(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]], recorded: bool | None
) -> None:
    """A run recorded as sent a temperature (or one started before the record: every version
    sent one) is not continued without it, half pinned and half unpinned, scored as one."""

    port, seen = stub
    _files(tmp_path, port, model="o-reasoner", provider="openai", sampling=False)
    run_id = _halt(tmp_path)
    context = _context(tmp_path)
    assert context["takes_sampling"] is False
    if recorded is None:
        context.pop("takes_sampling")
    else:
        context["takes_sampling"] = recorded
    _write_context(tmp_path, context)
    seen.clear()
    resumed = CliRunner().invoke(app, _run(tmp_path, "--resume", run_id))
    assert resumed.exit_code == 0, resumed.output
    said = " ".join(resumed.stderr.split())
    assert (
        f"resume: {run_id} sent stub a temperature and a top_p when it started and keeps 1 "
        "attempt(s) sent so, so it continues as it started; this version would send no "
        "temperature or top_p (a fresh run does)"
    ) in said, said
    assert "is sent no temperature or top_p" not in said, "the run is pinned as it started"
    assert seen and all(body.get("temperature") == 0.0 for _, body in seen), seen
    assert _context(tmp_path)["takes_sampling"] is True, "recorded as it went out"


def test_a_resume_that_keeps_no_attempt_is_sent_as_this_version_decides(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from ildottore.cli.run import _continued_takes

    listed = Target(id="stub", type="chatbot", provider="anthropic", model=_LISTED)  # type: ignore[arg-type]
    assert _continued_takes("run-a", "stub", True, listed, kept=0) is None
    assert "keeps no attempt, so it is sent no temperature or top_p" in capsys.readouterr().err
    assert _continued_takes("run-a", "stub", False, listed, kept=3) is None, "no change"
    assert capsys.readouterr().err == ""
    continued = _continued_takes("run-a", "stub", True, listed, kept=3)
    assert continued is not None and wiring.takes_sampling(continued)[0] is True


@pytest.mark.parametrize("key", ["takes_sampling", "judge_takes_sampling"])
def test_a_takes_sampling_record_that_is_not_a_boolean_is_refused(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]], key: str
) -> None:
    port, seen = stub
    _files(tmp_path, port, model="o-reasoner", provider="openai", sampling=False)
    run_id = _halt(tmp_path)
    context = _context(tmp_path)
    context[key] = "no"
    _write_context(tmp_path, context)
    seen.clear()
    resumed = CliRunner().invoke(app, _run(tmp_path, "--resume", run_id))
    assert resumed.exit_code == 3, resumed.output
    assert "takes_sampling or judge_takes_sampling value that is not true or false" in " ".join(
        resumed.output.split()
    )
    assert seen == []
