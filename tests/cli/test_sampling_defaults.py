"""A target file's ``sampling_defaults`` is a fallback, field by field (OD-39, u12 A-66).

The block was parsed, validated (A-45, A-50) and kept in the target's digest, and nothing sent
it: every request went out with the spec's own sampling (temperature 0 when a spec declares
none), the ``-sV`` probes with ``PROBE_SAMPLING`` and the judge with its own, so
``sampling_defaults: { top_p: 0.25 }`` reached no request and the manual said so. The owner
decided on 2026-10-09 that it applies as a fallback: each field the spec, the probe or the judge
leaves unset is taken from the block of the file the request goes to (the judge's own file for
the judge), and what is still unset is the provider's default.

Through the real CLI against a loopback stub that keeps every body it is sent: an OpenAI target,
an Anthropic one (which has no ``seed``, so the block's is neither sent nor recorded), a REST
template (which carries no sampling field, by design), the ``--judge`` model, the ``-sV`` probes,
``--estimate`` (which prices the ``max_tokens`` the block adds) and ``--resume`` of a run started
before the block was applied (it continues as it started, and says so). The attempt and the
probe evidence record what went out.
"""

from __future__ import annotations

import json
import re
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
from ildottore.core.runner import fill_sampling, spec_sampling
from ildottore.shared.models import Sampling, Target
from tests.cli.conftest import write_scope

_REPO = Path(__file__).resolve().parents[2]
_SPEC = "JB-REFUSAL-SUPPRESS-001"
_SPEC_FILE = _REPO / "specs" / "attacks" / f"{_SPEC}.yaml"
#: The spec's own block: the stub's refusal passes it, and it leaves `top_p` unset.
_OWN = {"temperature": 0.0, "seed": 42, "max_tokens": 600}

_JUDGE_SAYS_SECURE = json.dumps(
    {
        "verdict": "secure",
        "confidence": 0.95,
        "reasoning": "the reply refused",
        "observed_injection_attempt": False,
    }
)
_SAMPLING_KEYS = ("temperature", "top_p", "max_tokens", "seed")


def _openai(content: str) -> dict[str, Any]:
    return {
        "id": "stub",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }


@pytest.fixture
def stub() -> Iterator[tuple[int, list[tuple[str, dict[str, Any]]]]]:
    """An OpenAI target, an Anthropic one, a REST one and a judge; every body kept in order."""

    seen: list[tuple[str, dict[str, Any]]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
            seen.append((self.path, body))
            if self.path.startswith("/judge/"):
                reply: dict[str, Any] = _openai(_JUDGE_SAYS_SECURE)
            elif self.path == "/v1/messages":
                reply = {
                    "id": "stub",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": "I cannot help with that."}],
                    "stop_reason": "end_turn",
                }
            elif self.path == "/rest":
                reply = {"text": "I cannot help with that."}
            else:
                reply = _openai("I cannot help with that.")
            raw = json.dumps(reply).encode()
            self.send_response(200)
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


def _flow(block: dict[str, Any] | None) -> str:
    return "" if block is None else f"sampling_defaults: {json.dumps(block)}\n"


def _files(
    tmp_path: Path,
    port: int,
    *,
    provider: str = "openai",
    block: dict[str, Any] | None = None,
    judge_block: dict[str, Any] | None = None,
) -> None:
    path = {"openai": "/v1/chat/completions", "anthropic": "/v1/messages", "rest": "/rest"}
    endpoint = f"http://127.0.0.1:{port}{path[provider]}"
    judge_endpoint = f"http://127.0.0.1:{port}/judge/v1/chat/completions"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        f'        path_prefixes: ["{path[provider]}"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
        f'  - id: judge\n    base_url: "{judge_endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/judge/v1/chat/completions"]\n'
        '    identities:\n      - name: judge\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: chatbot\nprovider: {provider}\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n" + _flow(block)
    )
    (tmp_path / "judge.yaml").write_text(
        f'id: judge\ntype: model\nprovider: openai\nendpoint: "{judge_endpoint}"\nmodel: j\n'
        + _flow(judge_block)
    )


def _undeclared_spec_dir(tmp_path: Path) -> Path:
    """The same spec with its `sampling:` line taken out: a pack spec that declares none."""

    out = tmp_path / "specs"
    out.mkdir()
    text = _SPEC_FILE.read_text(encoding="utf-8")
    kept = [line for line in text.splitlines() if not line.startswith("sampling:")]
    assert len(kept) == len(text.splitlines()) - 1, "the spec declares one sampling line"
    (out / _SPEC_FILE.name).write_text("\n".join(kept) + "\n", encoding="utf-8")
    return out


def _run(tmp_path: Path, *extra: str, spec_dir: Path | None = None) -> list[str]:
    return [
        "run",
        "-t",
        str(tmp_path / "target.yaml"),
        "--scope",
        str(tmp_path / "scope.yaml"),
        "--spec",
        _SPEC,
        *(("--spec-path", str(spec_dir)) if spec_dir is not None else ()),
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


def _sampled(body: dict[str, Any]) -> dict[str, Any]:
    return {key: body[key] for key in _SAMPLING_KEYS if key in body}


def _run_id(tmp_path: Path) -> str:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        rows = conn.execute("SELECT run_id FROM runs").fetchall()
    finally:
        conn.close()
    assert len(rows) == 1, rows
    return str(rows[0][0])


def _context(tmp_path: Path, run_id: str) -> dict[str, Any]:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        (raw,) = conn.execute(
            "SELECT context_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    finally:
        conn.close()
    return dict(json.loads(raw))


def _write_context(tmp_path: Path, run_id: str, context: dict[str, Any]) -> None:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        with conn:
            conn.execute(
                "UPDATE runs SET context_json = ? WHERE run_id = ?", (json.dumps(context), run_id)
            )
    finally:
        conn.close()


def _stored(tmp_path: Path, kind: str) -> list[dict[str, Any]]:
    """The attempts (`attempts`) or probes (`probes`) of the one run, as stored."""

    folder = tmp_path / "ev" / _run_id(tmp_path) / kind
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))]


def _recorded(artifact: dict[str, Any]) -> dict[str, Any]:
    """The sampling an artifact records, its request's and its own, which must agree."""

    request = dict(artifact["request"]["sampling"] or {})
    own = artifact.get("sampling")
    if own is not None:
        assert dict(own) == request, artifact
    return {key: value for key, value in request.items() if value is not None}


# --- the battery ------------------------------------------------------------------------------


def test_the_block_fills_what_the_spec_leaves_unset(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """The spec pins temperature, seed and max_tokens; only top_p comes from the block."""

    port, seen = stub
    block = {"temperature": 0.9, "top_p": 0.25, "seed": 7, "max_tokens": 33}
    _files(tmp_path, port, block=block)
    result = CliRunner().invoke(app, _run(tmp_path))
    assert result.exit_code == 0, result.output
    assert seen, "the stub was sent the battery"
    expected = {**_OWN, "top_p": 0.25}
    assert all(_sampled(body) == expected for _, body in seen), seen
    attempts = _stored(tmp_path, "attempts")
    assert attempts and all(_recorded(a) == expected for a in attempts)


def test_without_a_block_a_request_goes_out_as_before(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """The control: the spec's own block and nothing else, as on main."""

    port, seen = stub
    _files(tmp_path, port)
    result = CliRunner().invoke(app, _run(tmp_path))
    assert result.exit_code == 0, result.output
    assert seen and all(_sampled(body) == _OWN for _, body in seen), seen
    assert all(_recorded(a) == _OWN for a in _stored(tmp_path, "attempts"))


@pytest.mark.parametrize(
    ("block", "expected"),
    [
        # The block's temperature wins over the scanner's temperature 0: that pin is the
        # scanner's for a spec that declares nothing, not the spec's own.
        ({"temperature": 0.9, "max_tokens": 33}, {"temperature": 0.9, "max_tokens": 33}),
        # A block without a temperature leaves the scanner's pin in place.
        ({"top_p": 0.25}, {"temperature": 0.0, "top_p": 0.25}),
        (None, {"temperature": 0.0}),
    ],
    ids=["block-temperature", "block-without-temperature", "no-block"],
)
def test_a_spec_that_declares_no_sampling_takes_the_block_then_temperature_0(
    tmp_path: Path,
    stub: tuple[int, list[tuple[str, dict[str, Any]]]],
    block: dict[str, Any] | None,
    expected: dict[str, Any],
) -> None:
    port, seen = stub
    _files(tmp_path, port, block=block)
    result = CliRunner().invoke(app, _run(tmp_path, spec_dir=_undeclared_spec_dir(tmp_path)))
    assert result.exit_code == 0, result.output
    assert seen and all(_sampled(body) == expected for _, body in seen), seen
    assert all(_recorded(a) == expected for a in _stored(tmp_path, "attempts"))


def test_anthropic_sends_no_seed_from_the_block_and_records_none(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """The Messages API has no seed: the block's is dropped, so no attempt records one; its
    max_tokens replaces the adapter's own 1024."""

    port, seen = stub
    _files(tmp_path, port, provider="anthropic", block={"top_p": 0.25, "seed": 7, "max_tokens": 33})
    result = CliRunner().invoke(app, _run(tmp_path, spec_dir=_undeclared_spec_dir(tmp_path)))
    assert result.exit_code == 0, result.output
    expected = {"temperature": 0.0, "top_p": 0.25, "max_tokens": 33}
    assert seen and all(_sampled(body) == expected for _, body in seen), seen
    assert all(_recorded(a) == expected for a in _stored(tmp_path, "attempts"))


def test_a_rest_target_sends_no_sampling_and_records_none_of_the_block(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """By design: a REST template has no sampling field, so the block reaches nothing and the
    attempt keeps the spec's own sampling only (which it recorded before, unsent)."""

    port, seen = stub
    _files(tmp_path, port, provider="rest", block={"top_p": 0.25, "max_tokens": 33})
    result = CliRunner().invoke(app, _run(tmp_path))
    assert result.exit_code == 0, result.output
    assert seen and all(_sampled(body) == {} for _, body in seen), seen
    assert all(_recorded(a) == _OWN for a in _stored(tmp_path, "attempts"))


def test_the_offline_mock_records_none_of_the_block(tmp_path: Path) -> None:
    write_scope(tmp_path)
    (tmp_path / "target.yaml").write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: hardened\n"
        'sampling_defaults: {"top_p": 0.25}\n'
    )
    result = CliRunner().invoke(app, _run(tmp_path))
    assert result.exit_code == 0, result.output
    attempts = _stored(tmp_path, "attempts")
    assert attempts and all(_recorded(a) == _OWN for a in attempts)


# --- the judge and the probes -----------------------------------------------------------------


def test_the_judge_takes_its_own_files_block_not_the_targets(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """The judge sets temperature (0, then 0.5) and top_p 1.0; its own file adds max_tokens and
    seed. The scanned target's block reaches the target's requests only."""

    port, seen = stub
    _files(
        tmp_path,
        port,
        block={"top_p": 0.25, "max_tokens": 33, "seed": 7},
        judge_block={"temperature": 0.9, "top_p": 0.75, "max_tokens": 99, "seed": 5},
    )
    result = CliRunner().invoke(app, _run(tmp_path, "--judge", str(tmp_path / "judge.yaml")))
    assert result.exit_code == 0, result.output
    judged = [_sampled(body) for path, body in seen if path.startswith("/judge/")]
    attacked = [_sampled(body) for path, body in seen if not path.startswith("/judge/")]
    assert judged and attacked
    assert {json.dumps(s, sort_keys=True) for s in judged} == {
        json.dumps({"temperature": t, "top_p": 1.0, "max_tokens": 99, "seed": 5}, sort_keys=True)
        for t in (0.0, 0.5)
    }, judged
    assert all(s == {**_OWN, "top_p": 0.25} for s in attacked), attacked


def test_the_probes_keep_their_own_sampling_and_take_the_rest(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """``PROBE_SAMPLING`` (temperature 0, 512 tokens) wins; the block adds top_p and seed, on the
    wire and in `probes/`, through `run -sV` and `dottore fingerprint` alike."""

    port, seen = stub
    _files(tmp_path, port, block={"temperature": 0.9, "top_p": 0.25, "seed": 7, "max_tokens": 33})
    expected = {"temperature": 0.0, "max_tokens": 512, "top_p": 0.25, "seed": 7}

    fingerprint = CliRunner().invoke(
        app,
        [
            "fingerprint",
            str(tmp_path / "target.yaml"),
            "--scope",
            str(tmp_path / "scope.yaml"),
        ],
    )
    assert fingerprint.exit_code == 0, fingerprint.output
    assert len(seen) == fingerprint_probe_count()
    assert all(_sampled(body) == expected for _, body in seen), seen

    seen.clear()
    result = CliRunner().invoke(app, _run(tmp_path, "-sV"))
    assert result.exit_code == 0, result.output
    probes = [_sampled(body) for _, body in seen[: fingerprint_probe_count()]]
    assert probes and all(p == expected for p in probes), probes
    stored = _stored(tmp_path, "probes")
    assert len(stored) == fingerprint_probe_count()
    assert all(_recorded(p) == expected for p in stored)


# --- what the plan says -----------------------------------------------------------------------


def _tokens_out(output: str) -> int:
    found = re.search(r"~tokens: \d+ in \+ (\d+) out", output)
    assert found, output
    return int(found.group(1))


def _requests(output: str) -> int:
    found = re.search(r"^estimate: (\d+) requests", output, re.M)
    assert found, output
    return int(found.group(1))


def test_the_estimate_prices_the_max_tokens_the_block_adds(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """A spec with no max_tokens is priced at the block's, the cap the ledger reserves."""

    port, seen = stub
    spec_dir = _undeclared_spec_dir(tmp_path)
    _files(tmp_path, port, block={"max_tokens": 2000})
    result = CliRunner().invoke(app, _run(tmp_path, "--estimate", spec_dir=spec_dir))
    assert result.exit_code == 0, result.output
    assert seen == [], "an estimate sends nothing"
    assert _tokens_out(result.output) == _requests(result.output) * 2000


def test_the_dry_run_says_what_the_block_fills_and_where_it_is_not_sent(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    port, _seen = stub
    _files(tmp_path, port, block={"top_p": 0.25, "seed": 7})
    sent = CliRunner().invoke(app, _run(tmp_path, "--dry-run"))
    assert sent.exit_code == 0, sent.output
    # The spec sets its own seed, so the block's reaches none of it.
    assert (
        "sampling: stub's sampling_defaults fills top_p 0.25 on 1 of 1, seed 7 on 0 of 1 specs "
        "(a spec's own value wins)" in sent.output
    ), sent.output
    _files(tmp_path, port, provider="rest", block={"top_p": 0.25})
    unsent = CliRunner().invoke(app, _run(tmp_path, "--dry-run"))
    assert unsent.exit_code == 0, unsent.output
    assert "sampling: stub's sampling_defaults is not sent" in unsent.output, unsent.output


# --- a resume ---------------------------------------------------------------------------------


def _halt(tmp_path: Path) -> str:
    halted = CliRunner().invoke(app, _run(tmp_path, "--budget-requests", "1"))
    assert halted.exit_code == 3, halted.output
    assert "budget ceiling reached" in halted.output, halted.output
    return _run_id(tmp_path)


def test_a_run_started_now_resumes_with_the_block(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    port, seen = stub
    _files(tmp_path, port, block={"top_p": 0.25})
    run_id = _halt(tmp_path)
    assert _context(tmp_path, run_id)["sampling_defaults_applied"] is True
    seen.clear()
    resumed = CliRunner().invoke(app, _run(tmp_path, "--resume", run_id))
    assert resumed.exit_code == 0, resumed.output
    assert "started before sampling_defaults was applied" not in resumed.stderr
    assert seen and all(_sampled(body) == {**_OWN, "top_p": 0.25} for _, body in seen), seen


def test_a_run_started_before_the_block_was_applied_resumes_as_it_started(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    """Its first half went out without the block; so does the rest, said on stderr, and every
    later resume agrees (the record now says false)."""

    port, seen = stub
    _files(tmp_path, port, block={"top_p": 0.25})
    run_id = _halt(tmp_path)
    context = _context(tmp_path, run_id)
    del context["sampling_defaults_applied"]  # as an older version wrote it
    _write_context(tmp_path, run_id, context)
    seen.clear()
    resumed = CliRunner().invoke(app, _run(tmp_path, "--resume", run_id))
    assert resumed.exit_code == 0, resumed.output
    assert (
        f"resume: {run_id} started before sampling_defaults was applied, so it continues as it "
        "started, without the target file's sampling_defaults; a fresh run sends them"
    ) in resumed.stderr, resumed.stderr
    assert seen and all(_sampled(body) == _OWN for _, body in seen), seen
    assert _context(tmp_path, run_id)["sampling_defaults_applied"] is False


def test_an_old_run_without_a_block_resumes_without_a_word(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    port, _seen = stub
    _files(tmp_path, port)
    run_id = _halt(tmp_path)
    context = _context(tmp_path, run_id)
    del context["sampling_defaults_applied"]
    _write_context(tmp_path, run_id, context)
    resumed = CliRunner().invoke(app, _run(tmp_path, "--resume", run_id))
    assert resumed.exit_code == 0, resumed.output
    assert "sampling_defaults" not in resumed.stderr, resumed.stderr


def test_a_record_that_is_not_true_or_false_is_refused(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]]
) -> None:
    port, seen = stub
    _files(tmp_path, port, block={"top_p": 0.25})
    run_id = _halt(tmp_path)
    context = _context(tmp_path, run_id)
    context["sampling_defaults_applied"] = "yes"
    _write_context(tmp_path, run_id, context)
    seen.clear()
    resumed = CliRunner().invoke(app, _run(tmp_path, "--resume", run_id))
    assert resumed.exit_code == 3, resumed.output
    assert "sampling_defaults_applied value that is not true or false" in resumed.output
    assert seen == []


# --- the pieces -------------------------------------------------------------------------------


def test_fill_sampling_fills_only_what_is_unset() -> None:
    own = Sampling(temperature=0.0, seed=42)
    fallback = Sampling(temperature=0.9, top_p=0.25, seed=7, max_tokens=33)
    assert fill_sampling(own, fallback) == Sampling(
        temperature=0.0, top_p=0.25, seed=42, max_tokens=33
    )
    assert fill_sampling(own, None) is own
    assert fill_sampling(own, Sampling(temperature=0.5)) is own, "nothing to fill: the same object"


def test_spec_sampling_without_a_block_is_what_the_runner_always_sent() -> None:
    (spec,) = wiring.build_registry([_SPEC_FILE]).list()
    assert spec_sampling(spec) is spec.sampling
    undeclared = spec.model_copy(update={"sampling": None})
    assert spec_sampling(undeclared) == Sampling(temperature=0.0)
    assert spec_sampling(undeclared, Sampling(temperature=0.7)) == Sampling(temperature=0.7)


@pytest.mark.parametrize(
    ("provider", "expected"),
    [
        ("openai", Sampling(temperature=0.9, top_p=0.25, seed=7, max_tokens=33)),
        ("OpenAI ", Sampling(temperature=0.9, top_p=0.25, seed=7, max_tokens=33)),
        ("anthropic", Sampling(temperature=0.9, top_p=0.25, max_tokens=33)),
        ("rest", None),
        ("mcp", None),
        ("websocket", None),
        (None, None),
    ],
)
def test_sampling_fallback_keeps_what_the_adapter_sends(
    provider: str | None, expected: Sampling | None
) -> None:
    block = Sampling(temperature=0.9, top_p=0.25, seed=7, max_tokens=33)
    target = Target(id="t", type="chatbot", provider=provider, sampling_defaults=block)  # type: ignore[arg-type]
    assert wiring.sampling_fallback(target) == expected
    seed_only = target.model_copy(
        update={"provider": "anthropic", "sampling_defaults": Sampling(seed=7)}
    )
    assert wiring.sampling_fallback(seed_only) is None, "nothing it sends is left"


@pytest.mark.parametrize(
    ("target", "scope", "extra"),
    [
        ("target.local.yaml", "scope.local.yaml", ("--quick",)),
        (
            "target.app.yaml",
            "scope.app.yaml",
            ("-vv", "--spec", "PI-INDIRECT-*", "--spec", "AG-TOOL-*"),
        ),
    ],
    ids=["scenario-B", "scenario-G"],
)
def test_the_worked_examples_print_the_sampling_line_the_readme_shows(
    target: str, scope: str, extra: tuple[str, ...]
) -> None:
    """examples/README.md quotes these dry runs as real output, the `sampling:` line included."""

    examples = _REPO / "examples"
    result = CliRunner().invoke(
        app,
        [
            "run",
            "--dry-run",
            *extra,
            "-t",
            str(examples / target),
            "--scope",
            str(examples / scope),
        ],
    )
    assert result.exit_code == 0, result.output
    (line,) = [ln for ln in result.stdout.splitlines() if ln.startswith("  sampling: ")]
    assert line in (examples / "README.md").read_text(encoding="utf-8").splitlines(), line


@pytest.mark.parametrize("spec_id", ["JB-CRESCENDO-001", "DL-XTENANT-001"])
def test_every_turn_and_the_identity_sweep_take_the_block(
    tmp_path: Path, stub: tuple[int, list[tuple[str, dict[str, Any]]]], spec_id: str
) -> None:
    """A multi-turn conversation sends the block with each turn, and the identity sweep with
    each identity: the runner fills every request it builds, not only the single-turn send."""

    port, seen = stub
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        "    identities:\n"
        '      - name: tenant-a\n        auth_ref: "env://NONE"\n'
        '        canary: "CANARY_A_{{run_id}}"\n'
        '      - name: tenant-b\n        auth_ref: "env://NONE"\n'
        '        canary: "CANARY_B_{{run_id}}"\n'
    )
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n  multi_identity: true\n"
        'sampling_defaults: {"top_p": 0.25}\n'
    )
    command = _run(tmp_path)
    command[command.index(_SPEC)] = spec_id
    result = CliRunner().invoke(app, command)
    assert result.exit_code in (0, 1), result.output
    (spec,) = [
        s for s in wiring.build_registry([_REPO / "specs" / "attacks"]).list() if s.id == spec_id
    ]
    assert spec.sampling is not None and spec.sampling.top_p is None
    expected = {**spec.sampling.model_dump(exclude_none=True), "top_p": 0.25}
    assert len(seen) >= 2, seen
    assert all(_sampled(body) == expected for _, body in seen), seen
