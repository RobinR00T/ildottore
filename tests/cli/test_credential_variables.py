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
#: A key of no documented format: what only the entropy rule reads as one. `KEY` is Anthropic's
#: format, which the redactor masks whatever its entropy since main's u01 A-78.
TOKEN = "Q7xZ2mV9pL4kR8tN1wB6yH3jF5dS0aCQwErTyUiOpAsDfGh"
_FRAGMENTS = (
    [KEY[i : i + 10] for i in range(0, len(KEY) - 10, 5)]
    + [TOKEN[i : i + 10] for i in range(0, len(TOKEN) - 10, 5)]
    + [PASSWORD[:10]]
)
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
    # Eight characters at least: a shorter one is refused as one the redactor cannot mask by
    # value (main's u04 A-78), before this check is reached.
    monkeypatch.setenv("DOTTORE_TEST_KEY", "k-live-value")
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
        (
            f"https://api.example.com/v1?q={KEY}",
            "query string (the parameter 'q', whose value is a credential format)",
        ),
        (
            f"https://api.example.com/v1?{KEY}",
            "query string (a component shaped like a key (a credential format))",
        ),
        (
            f"https://api.example.com/v1?q={TOKEN}",
            "query string (the parameter 'q', whose value is a high-entropy token)",
        ),
        (
            f"https://api.example.com/v1?{TOKEN}",
            "query string (a component shaped like a key (a high-entropy token))",
        ),
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
        "key-value-entropy",
        "bare-entropy",
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


# --- round-2 audit of A-82: what a fleet endpoint may and may not carry -------------------------

_LOW = "s3cr3tpassw0rd"  # a credential of low entropy, caught by its parameter's name
_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)


@pytest.mark.parametrize(
    "endpoint",
    [
        f"https://a.example.com/key/{KEY}/v1/chat/completions",
        f"https://a.example.com/v1/chat/completions;token={KEY}",
        f"https://a.example.com/v1/chat/completions?accessToken={_LOW}",
        f"https://a.example.com/v1/chat/completions?bearer={_LOW}",
        f"https://a.example.com/v1/chat/completions?jwt={_JWT}",
        f"https://a.example.com/v1/chat/completions?code={_LOW}",
        f"https://a.example.com/v1/chat/completions?sessionid={_LOW}",
        f"https://a.example.com/v1/chat/completions?k={_LOW}",
        f"https://a.example.com/v1/chat/completions?api_key[]={_LOW}",
        f"https://a.example.com/v1/chat/completions?api_key%20={_LOW}",
        f"https://a.example.com/v1/chat/completions?%2561pi_key={_LOW}",
        f"https://a.example.com/v1/chat/completions?apiKey={_LOW}",
        f"https://a.example.com/v1/chat/completions?client_secret={_LOW}",
        f"https://a.example.com/v1/chat/completions?sv=2022-11-02&sig={_LOW}",
        "https://s3.amazonaws.com/b/o?X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20261012",
    ],
)
def test_fleet_refuses_a_credential_in_a_path_or_under_any_name(
    tmp_path: Path, endpoint: str
) -> None:
    result = _fleet(tmp_path, f'version: "1"\ntargets:\n  - id: a\n    endpoint: "{endpoint}"\n')
    assert result.exit_code == 3, result.output
    assert "carries a credential" in result.output
    for secret in (KEY[15:35], _LOW, _JWT[40:60]):
        assert secret not in result.output
    assert not (tmp_path / "o").exists()


@pytest.mark.parametrize(
    "query",
    [
        "tenant=3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "project=proj_8f7e6d5c4b3a2918",
        "trace_id=4bf92f3577b34da6a3ce929d0e0e4736",
        "request_id=req_8f7e6d5c4b3a29187a6b",
        "user=alice%40example.com",
        "sort_key=created",
        "session=interactive",
        "max_token=100",
        "use_auth=true",
        "signature_version=4",
        "tokenizer=cl100k",
        "api-version=2024-02-15-preview",
        "api-key-header=x-api-key",
        "primary_key_id=1",
    ],
)
def test_fleet_keeps_what_a_legitimate_endpoint_carries(tmp_path: Path, query: str) -> None:
    """The whole redactor (its PII and identifier rules) and a name's last word refused these
    (round-2 audit of A-82, LOW 3)."""

    endpoint = f"https://llm.internal.example/v1/chat/completions?{query}"
    result = _fleet(tmp_path, f'version: "1"\ntargets:\n  - id: a\n    endpoint: "{endpoint}"\n')
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    "path",
    [
        "/v1/projects/my-proj-123456/locations/us-central1/publishers/google/models/"
        "gemini-1.5-pro:generateContent",
        "/v1/0123456789abcdef0123456789abcdef/my-gw/openai/chat/completions",
        "/model/anthropic.claude-3-5-sonnet-20240620-v1:0/invoke",
    ],
)
def test_fleet_keeps_a_legitimate_path(tmp_path: Path, path: str) -> None:
    result = _fleet(
        tmp_path, f'version: "1"\ntargets:\n  - id: a\n    endpoint: "https://h.example{path}"\n'
    )
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    ("query", "name"),
    [
        ("X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20261012", "'X-Amz-Credential'"),
        (f"%2561pi_key={_LOW}", "'%2561pi_key'"),
    ],
)
def test_a_parameter_name_is_printed_as_written(tmp_path: Path, query: str, name: str) -> None:
    """A name is not a secret (round-2 audit of A-82, LOW 5): it printed `a parameter`, or the
    CLI masked it as high entropy."""

    endpoint = f"https://h.example/v1?{query}"
    result = _fleet(tmp_path, f'version: "1"\ntargets:\n  - id: a\n    endpoint: "{endpoint}"\n')
    assert result.exit_code == 3, result.output
    assert f"(the parameter {name})" in result.output.replace("\n", "")


def test_key_shape_reads_key_formats_and_entropy_and_no_pii() -> None:
    from ildottore.cli.key_shape import key_shape, normalised_name

    assert key_shape(KEY) == "a credential format"
    assert key_shape(TOKEN) == "a high-entropy token"
    assert key_shape("AKIAIOSFODNN7EXAMPLE") == "a credential format"
    assert key_shape(_JWT) == "a credential format"
    for not_a_key in (
        "alice@example.com",
        "CVE-2021-44228",
        "+1 415 555 0100",
        "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "4bf92f3577b34da6a3ce929d0e0e4736",
        "req_8f7e6d5c4b3a29187a6b",
        "",
    ):
        assert key_shape(not_a_key) is None, not_a_key
    assert normalised_name(" accessToken[] ") == "access_token"
    assert normalised_name("%2561pi_key") == "api_key"
    assert normalised_name("X-Amz-Credential") == "x_amz_credential"


@pytest.mark.parametrize(
    "endpoint",
    [
        f"https://a.example.com/v1/chat/completions?{KEY}=1",
        f"https://a.example.com/v1/chat/completions#{KEY}=x",
        f"https://a.example.com/v1/chat/completions;{KEY}=x",
    ],
    ids=["query-name", "fragment-name", "path-parameter-name"],
)
def test_fleet_refuses_a_key_written_as_a_parameter_name(tmp_path: Path, endpoint: str) -> None:
    """Refused on e1824e99, accepted by the round-2 rework, written to disk (round-3 audit)."""

    result = _fleet(tmp_path, f'version: "1"\ntargets:\n  - id: a\n    endpoint: "{endpoint}"\n')
    assert result.exit_code == 3, result.output
    assert "a parameter name shaped like a key" in result.output
    _no_leak(result.output)
    assert not (tmp_path / "o").exists()


@pytest.mark.parametrize(
    "name",
    [
        "application_key",
        "app_key",
        "api_secret",
        "oauth_token",
        "oauth_signature",
        "private_token",
        "personal_access_token",
        "sas_token",
        "x_goog_api_key",
        "X-Goog-Signature",
        "X-Goog-Credential",
        "xapikey",
        "XApiKey",
        "accesskey",
        "secretkey",
        "auth_key",
        "authkey",
        "hapikey",
        "token_secret",
        "passcode",
    ],
)
def test_fleet_refuses_the_credential_names_the_round_3_audit_added(
    tmp_path: Path, name: str
) -> None:
    endpoint = f"https://a.example.com/v1/chat/completions?{name}={_LOW}"
    result = _fleet(tmp_path, f'version: "1"\ntargets:\n  - id: a\n    endpoint: "{endpoint}"\n')
    assert result.exit_code == 3, result.output
    assert _LOW not in result.output
    assert not (tmp_path / "o").exists()
