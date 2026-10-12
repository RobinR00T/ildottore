"""A credential variable is a variable's name, and a live run refuses one that is not set
(u12 A-82; CLI audit of 2026-10-11, M4 and M8).

M4: ``auth_ref: env://TYPO`` with ``TYPO`` unset read as "no credential". ``--dry-run`` said
nothing, every request went out without a credential, and the run stopped on ``non-retryable
HTTP 401`` naming nothing. A live run (``run``, ``fingerprint``) now refuses it before anything is
sent, naming the variable and never a value; a mode that sends nothing (``--dry-run``,
``--estimate``, ``-sn``) says it on stderr and goes on. ``env://NONE`` is the one reference that
says "no credential": its variable is never read.

M8: nothing checked that an ``env://`` reference named a variable. ``api_key_env: "sk-ant-..."``
in a fleet file was written as ``auth_ref: env://sk-ant-...`` into ``scope.yaml`` and the target
file, exit 0, and a password in a fleet endpoint's user info was copied into both. A name is now
``[A-Za-z_][A-Za-z0-9_]*`` in a target file, a scope and a fleet file, refused without being
quoted, and a fleet endpoint with user info is refused before anything is written.
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

from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.shared.credential_refs import unset_variable

runner = CliRunner()

KEY = "sk-ant-api03-Q7xZ2mV9pL4kR8tN1wB6yH3jF5dS0aC-QwErTyUiOpAsDfGh"
PASSWORD = "Hunter2Secret9f8e7d"
_FRAGMENTS = [KEY[i : i + 10] for i in range(0, len(KEY) - 10, 5)] + [PASSWORD[:10]]
_REPLY = {
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


@pytest.fixture
def stub() -> Iterator[tuple[int, list[dict[str, str]]]]:
    """An OpenAI-compatible loopback endpoint that records each request's headers."""

    seen: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("content-length", "0")))
            seen.append({k.lower(): v for k, v in self.headers.items()})
            raw = json.dumps(_REPLY).encode()
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


def _files(
    tmp_path: Path,
    port: int,
    *,
    target_ref: str | None = "env://DOTTORE_TEST_KEY",
    identities: tuple[tuple[str, str], ...] = (("default", "env://DOTTORE_TEST_KEY"),),
    judge_ref: str | None = None,
    multi_identity: bool = False,
) -> None:
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    entries = "".join(
        f'      - name: {name}\n        auth_ref: "{ref}"\n' for name, ref in identities
    )
    scope = (
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions", "/judge/v1/chat/completions"]\n'
        f"    identities:\n{entries}"
    )
    target = f'id: stub\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
    if target_ref is not None:
        target += f'auth_ref: "{target_ref}"\n'
    if multi_identity:
        target += "capabilities:\n  multi_identity: true\n"
    if judge_ref is not None:
        judge_endpoint = f"http://127.0.0.1:{port}/judge/v1/chat/completions"
        scope += (
            f'  - id: judge\n    base_url: "{judge_endpoint}"\n'
            f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
            '        path_prefixes: ["/judge/v1/chat/completions"]\n'
            f'    identities:\n      - name: judge\n        auth_ref: "{judge_ref}"\n'
        )
        (tmp_path / "judge.yaml").write_text(
            f'id: judge\ntype: model\nprovider: openai\nendpoint: "{judge_endpoint}"\n'
            f'model: j\nauth_ref: "{judge_ref}"\n'
        )
    (tmp_path / "scope.yaml").write_text(scope)
    (tmp_path / "target.yaml").write_text(target)


def _run(tmp_path: Path, *extra: str, spec: str = "PI-DIRECT-001") -> Any:
    return runner.invoke(
        app,
        [
            "run",
            "-t",
            str(tmp_path / "target.yaml"),
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--spec",
            spec,
            "--runs",
            "1",
            "--rate",
            "1000",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            "-q",
            *extra,
        ],
    )


def _no_leak(text: str) -> None:
    for fragment in _FRAGMENTS:
        assert fragment not in text, text


# --- M4: an unset variable on a live target -------------------------------------------------


@pytest.mark.parametrize(("value", "state"), [(None, "not set"), ("  ", "set but empty")])
def test_a_live_run_refuses_an_unset_variable_before_sending_anything(
    tmp_path: Path,
    stub: tuple[int, list[dict[str, str]]],
    monkeypatch: pytest.MonkeyPatch,
    value: str | None,
    state: str,
) -> None:
    port, seen = stub
    if value is None:
        monkeypatch.delenv("DOTTORE_TEST_KEY", raising=False)
    else:
        monkeypatch.setenv("DOTTORE_TEST_KEY", value)
    _files(tmp_path, port)
    result = _run(tmp_path)
    assert result.exit_code == 3, result.output
    assert (
        "error: target 'stub' auth_ref 'env://DOTTORE_TEST_KEY' names the environment variable "
        f"DOTTORE_TEST_KEY, which is {state}, so every request would go out without a "
        "credential; nothing was sent"
    ) in result.output
    assert "leaves auth_ref out" in result.output and "env://NONE" in result.output
    assert seen == []
    # Nothing written for a run that never started.
    assert not (tmp_path / "ev").exists()


@pytest.mark.parametrize("mode", [["--dry-run"], ["--estimate"], ["-sn"]])
def test_a_mode_that_sends_nothing_warns_and_goes_on(
    tmp_path: Path,
    stub: tuple[int, list[dict[str, str]]],
    monkeypatch: pytest.MonkeyPatch,
    mode: list[str],
) -> None:
    port, seen = stub
    monkeypatch.delenv("DOTTORE_TEST_KEY", raising=False)
    _files(tmp_path, port)
    result = _run(tmp_path, *mode)
    assert result.exit_code == 0, result.output
    assert (
        "warning: target 'stub' auth_ref 'env://DOTTORE_TEST_KEY' names the environment variable "
        "DOTTORE_TEST_KEY, which is not set: a live run refuses this before sending anything"
    ) in result.output
    assert seen == []


def test_a_set_variable_is_sent_and_says_nothing(
    tmp_path: Path, stub: tuple[int, list[dict[str, str]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, seen = stub
    monkeypatch.setenv("DOTTORE_TEST_KEY", "k-live-value")
    _files(tmp_path, port)
    result = _run(tmp_path)
    assert result.exit_code in (0, 1, 2), result.output
    assert "names the environment variable" not in result.output
    assert seen and all(h.get("authorization") == "Bearer k-live-value" for h in seen)


def test_no_auth_ref_and_env_none_send_no_credential_and_are_not_refused(
    tmp_path: Path, stub: tuple[int, list[dict[str, str]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The two documented ways to say "no credential"; ``NONE`` is never read, even when set."""

    port, seen = stub
    monkeypatch.setenv("NONE", "a-value-nobody-meant-to-send")
    for target_ref in (None, "env://NONE"):
        seen.clear()
        _files(tmp_path, port, target_ref=target_ref, identities=(("default", "env://NONE"),))
        result = _run(tmp_path)
        assert result.exit_code in (0, 1, 2), result.output
        assert "names the environment variable" not in result.output
        assert seen and all("authorization" not in h for h in seen), seen


def test_the_judge_variable_is_checked_too(
    tmp_path: Path, stub: tuple[int, list[dict[str, str]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, seen = stub
    monkeypatch.setenv("DOTTORE_TEST_KEY", "k")
    monkeypatch.delenv("DOTTORE_TEST_JUDGE_KEY", raising=False)
    _files(tmp_path, port, judge_ref="env://DOTTORE_TEST_JUDGE_KEY")
    result = _run(tmp_path, "--judge", str(tmp_path / "judge.yaml"))
    assert result.exit_code == 3, result.output
    assert (
        "the --judge model 'judge' auth_ref 'env://DOTTORE_TEST_JUDGE_KEY' names the environment "
        "variable DOTTORE_TEST_JUDGE_KEY, which is not set"
    ) in result.output
    assert seen == []


def test_the_identity_sweep_variables_are_checked_when_a_spec_sweeps(
    tmp_path: Path, stub: tuple[int, list[dict[str, str]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, seen = stub
    monkeypatch.delenv("DOTTORE_TENANT_B", raising=False)
    identities = (("tenant-a", "env://NONE"), ("tenant-b", "env://DOTTORE_TENANT_B"))
    _files(tmp_path, port, target_ref=None, identities=identities, multi_identity=True)
    result = _run(tmp_path, spec="DL-XTENANT-001")
    assert result.exit_code == 3, result.output
    assert (
        "target 'stub' identity 'tenant-b' (the scope's, sent by the identity sweep) auth_ref "
        "'env://DOTTORE_TENANT_B' names the environment variable DOTTORE_TENANT_B, which is not set"
    ) in result.output
    assert seen == []
    # A battery that sweeps no identity does not read them.
    result = _run(tmp_path)
    assert result.exit_code in (0, 1, 2), result.output
    assert "DOTTORE_TENANT_B" not in result.output


def test_fingerprint_refuses_an_unset_variable(
    tmp_path: Path, stub: tuple[int, list[dict[str, str]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, seen = stub
    monkeypatch.delenv("DOTTORE_TEST_KEY", raising=False)
    _files(tmp_path, port)
    result = runner.invoke(
        app,
        ["fingerprint", str(tmp_path / "target.yaml"), "--scope", str(tmp_path / "scope.yaml")],
    )
    assert result.exit_code == 3, result.output
    assert "names the environment variable DOTTORE_TEST_KEY, which is not set" in result.output
    assert "every probe would go out without a credential" in result.output
    assert seen == []


def test_unset_variable_reads_only_a_named_variable() -> None:
    env = {"SET": "v", "EMPTY": "", "BLANK": " \t"}
    assert unset_variable("env://SET", env) is None
    assert unset_variable("env://MISSING", env) == ("MISSING", "not set")
    assert unset_variable("env://EMPTY", env) == ("EMPTY", "set but empty")
    assert unset_variable("env://BLANK", env) == ("BLANK", "set but empty")
    for not_this_question in (None, "env://NONE", "vault://kv/x", "a-literal", "env://9X"):
        assert unset_variable(not_this_question, env) is None


def test_env_none_is_never_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NONE", "should-not-be-sent")
    assert wiring.resolve_auth_ref("env://NONE") is None


# --- M8: a reference names a variable -------------------------------------------------------


@pytest.mark.parametrize(
    "ref",
    [f"env://{KEY}", "env://OPENAI_API_KEY ", "env:// OPENAI_API_KEY", "env://", "env://9LIVES"],
    ids=["key", "trailing-space", "leading-space", "empty", "digit-first"],
)
def test_a_target_file_reference_that_names_no_variable_is_refused_unquoted(
    tmp_path: Path, ref: str
) -> None:
    _files(tmp_path, 9, target_ref=ref, identities=(("default", "env://NONE"),))
    result = _run(tmp_path, "--dry-run")
    assert result.exit_code == 3, result.output
    assert (
        f"target file {tmp_path / 'target.yaml'} 'auth_ref' names no environment variable after "
        "env:// (a name is letters, digits and _, not starting with a digit, not shown here)"
    ) in result.output.replace("\n", "")
    _no_leak(result.output)


def test_a_scope_identity_that_names_no_variable_is_refused_unquoted(tmp_path: Path) -> None:
    _files(tmp_path, 9, target_ref=None, identities=(("default", f"env://{KEY}"),))
    result = _run(tmp_path, "--dry-run")
    assert result.exit_code == 3, result.output
    assert (
        "target 'stub' identity 'default': auth_ref names no environment variable after env://"
    ) in result.output.replace("\n", "")
    _no_leak(result.output)


def test_a_reference_built_in_code_is_refused_by_the_resolver() -> None:
    with pytest.raises(ValueError, match="names no environment variable") as info:
        wiring.resolve_auth_ref(f"env://{KEY}")
    assert KEY[:10] not in str(info.value)


def _fleet(tmp_path: Path, body: str) -> Any:
    (tmp_path / "fleet.yaml").write_text(body)
    return runner.invoke(app, ["fleet", str(tmp_path / "fleet.yaml"), "--out", str(tmp_path / "o")])


@pytest.mark.parametrize(
    ("body", "where"),
    [
        (
            'version: "1"\ntargets:\n  - id: a\n    endpoint: http://127.0.0.1:9/v1/chat/completions\n'
            f'    api_key_env: "{KEY}"\n',
            "targets.0.api_key_env",
        ),
        (
            'version: "1"\ntargets:\n  - id: a\n    endpoint: http://127.0.0.1:9/v1/chat/completions\n'
            "judge:\n  id: j\n  endpoint: http://127.0.0.1:9/v1/chat/completions\n"
            '  api_key_env: "OPENAI KEY"\n',
            "judge.api_key_env",
        ),
    ],
    ids=["target", "judge"],
)
def test_fleet_refuses_a_key_where_a_variable_name_belongs(
    tmp_path: Path, body: str, where: str
) -> None:
    result = _fleet(tmp_path, body)
    assert result.exit_code == 3, result.output
    assert f"{where}: Value error, is not an environment variable's name" in result.output
    _no_leak(result.output)
    assert not (tmp_path / "o").exists()


@pytest.mark.parametrize(
    "endpoint",
    [
        f"https://ops:{PASSWORD}@api.example.com/v1/chat/completions",
        "https://ops@api.example.com/v1/chat/completions",
    ],
    ids=["user-and-password", "user-only"],
)
def test_fleet_refuses_user_info_in_an_endpoint(tmp_path: Path, endpoint: str) -> None:
    for body, where in (
        (f'version: "1"\ntargets:\n  - id: a\n    endpoint: "{endpoint}"\n', "targets.0.endpoint"),
        (
            'version: "1"\ntargets:\n  - id: a\n    endpoint: https://api.example.com/v1\n'
            f'judge:\n  id: j\n  endpoint: "{endpoint}"\n',
            "judge.endpoint",
        ),
    ):
        result = _fleet(tmp_path, body)
        assert result.exit_code == 3, result.output
        assert f"{where}: Value error, carries a user name or password" in result.output
        _no_leak(result.output)
        assert not (tmp_path / "o").exists()


def test_fleet_still_writes_a_variable_name_and_the_no_credential_reference(
    tmp_path: Path,
) -> None:
    result = _fleet(
        tmp_path,
        'version: "1"\ntargets:\n'
        "  - id: hosted\n    endpoint: https://api.openai.com/v1/chat/completions\n"
        "    api_key_env: OPENAI_API_KEY\n"
        "  - id: local\n    endpoint: http://localhost:11434/v1/chat/completions\n",
    )
    assert result.exit_code == 0, result.output
    scope = (tmp_path / "o" / "scope.yaml").read_text()
    assert "auth_ref: env://OPENAI_API_KEY" in scope and "auth_ref: env://NONE" in scope
    assert "auth_ref: env://OPENAI_API_KEY" in (tmp_path / "o" / "target-hosted.yaml").read_text()
    assert "auth_ref" not in (tmp_path / "o" / "target-local.yaml").read_text()


@pytest.mark.parametrize(
    ("endpoint", "said"),
    [
        (f"https://api.example.com/v1?api_key={KEY}", "query string (the parameter 'api_key')"),
        (f"https://api.example.com/v1?access_token={PASSWORD}", "the parameter 'access_token'"),
        (f"https://api.example.com/v1?q={KEY}", "query string (a value shaped like a key)"),
        (f"https://api.example.com/v1?{KEY}", "query string (a value shaped like a key)"),
        (f"https://api.example.com/v1#token={PASSWORD}", "fragment (the parameter 'token')"),
        (f"https:/ops:{KEY}@api.example.com/v1", "has no host after its scheme"),
        (f"https:\\\\ops:{KEY}@api.example.com/v1", "has no host after its scheme"),
        ("https://:443/v1", "has no host after its scheme"),
    ],
    ids=[
        "api_key",
        "access_token",
        "key-value",
        "bare-key",
        "fragment",
        "slash",
        "backslash",
        "no-host",
    ],
)
def test_fleet_refuses_a_credential_anywhere_in_an_endpoint(
    tmp_path: Path, endpoint: str, said: str
) -> None:
    """Pre-merge audit of A-82, MEDIUM 3: a query string and a URL urlsplit reads with no host
    carried a key into scope.yaml and the target file, exit 0."""

    for body, where in (
        (f'version: "1"\ntargets:\n  - id: a\n    endpoint: "{endpoint}"\n', "targets.0.endpoint"),
        (
            'version: "1"\ntargets:\n  - id: a\n    endpoint: https://api.example.com/v1\n'
            f'judge:\n  id: j\n  endpoint: "{endpoint}"\n',
            "judge.endpoint",
        ),
    ):
        result = _fleet(tmp_path, body)
        assert result.exit_code == 3, result.output
        assert f"{where}: Value error, " in result.output and said in result.output
        _no_leak(result.output)
        assert not (tmp_path / "o").exists()


def test_fleet_keeps_a_query_that_carries_no_credential(tmp_path: Path) -> None:
    """Azure OpenAI's endpoint carries its API version in the query."""

    endpoint = (
        "https://x.openai.azure.com/openai/deployments/d/chat/completions?api-version=2024-02-01"
    )
    result = _fleet(
        tmp_path,
        f'version: "1"\ntargets:\n  - id: a\n    endpoint: "{endpoint}"\n    api_key_env: AZ\n',
    )
    assert result.exit_code == 0, result.output
    assert "api-version=2024-02-01" in (tmp_path / "o" / "target-a.yaml").read_text()
