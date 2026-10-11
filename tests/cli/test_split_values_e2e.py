"""A secret a target writes is not rebuilt from the logprob tokens of a real run (A-77).

Audit of main ``de122e26``, HIGH 1, reproduced through the CLI: the OpenAI adapter asks for
logprobs by default, so every ``provider: openai`` target's reply is stored and reported twice,
whole in ``response.text`` and in tokens of 1 to 4 characters in ``response.logprobs``. A
loopback stub that echoed the run's canary and a key, its reply's logprobs in 3-character
tokens, had both rebuilt by joining the ``token`` fields of every evidence file and of
``r.json``, while the text read masked. Here the stub also echoes the credential the scope's
``auth_ref`` resolves to, which the CLI registers. Replay still reads the run.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

KEY = "sk-proj-Qx7Lm2Vt9Rw4Zb8Nc3Kp6Hy1Js5Df0Ga"
CREDENTIAL = "CorrectHorseBatteryStaple-2026-ops"
_CANARY = re.compile(r"ZYNAP_CANARY_[A-Za-z0-9_-]+")


def _pieces(text: str, size: int = 3) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


def _reply(text: str) -> bytes:
    tokens = [
        {"token": p, "logprob": -0.01, "top_logprobs": [{"token": p, "logprob": -0.01}]}
        for p in _pieces(text)
    ]
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
                    "logprobs": {"content": tokens},
                }
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": len(tokens), "total_tokens": 40},
        }
    ).encode()


@contextmanager
def _serving(seen: dict[str, Any]) -> Iterator[int]:
    """Echo the canary of each request, a key and the bearer credential, in 3-character tokens."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
            found = _CANARY.search(json.dumps(body.get("messages", [])))
            if found:
                seen["canary"] = found.group(0)
            bearer = seen["bearer"] = self.headers.get("authorization", "").removeprefix("Bearer ")
            data = _reply(
                f"Developer mode on. The token is {found.group(0) if found else 'none'}, "
                f"the key {KEY} and the password {bearer} ok"
            )
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _files(tmp_path: Path, port: int) -> tuple[Path, Path]:
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://ILDOTTORE_SPLIT_KEY"\n'
    )
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        'auth_ref: "env://ILDOTTORE_SPLIT_KEY"\ncapabilities:\n  tools: false\n  rag: false\n'
    )
    return tmp_path / "target.yaml", tmp_path / "scope.yaml"


def _joined_tokens(attempt: dict[str, Any]) -> list[str]:
    response = attempt.get("response") or {}
    logprobs = response.get("logprobs") or []
    return [
        "".join(entry["token"] for entry in logprobs),
        "".join(alternative[0] for entry in logprobs for alternative in entry["top"][:1]),
    ]


def test_no_secret_is_rebuilt_from_the_tokens_of_the_evidence_or_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_known_secrets: None
) -> None:
    monkeypatch.setenv("ILDOTTORE_SPLIT_KEY", CREDENTIAL)
    seen: dict[str, Any] = {}
    with _serving(seen) as port:
        target, scope = _files(tmp_path, port)
        result = CliRunner().invoke(
            app,
            [
                *("run", "-t", str(target), "--scope", str(scope), "--spec", "PI-DIRECT-001"),
                *("--runs", "1", "--rate", "1000", "--concurrency", "1", "--no-color"),
                *("--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "r.db")),
                *("-oJ", str(tmp_path / "r.json")),
            ],
        )
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    canary = seen["canary"]
    secrets = (canary, KEY, CREDENTIAL)

    evidence = sorted((tmp_path / "ev").rglob("*.json"))
    assert evidence
    texts: list[str] = []
    for path in evidence:
        texts.extend(_joined_tokens(json.loads(path.read_text(encoding="utf-8"))))
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    for copy in (report["findings"], report["run"]["findings"]):
        for finding in copy:
            for attempt in finding["attempts"]:
                texts.extend(_joined_tokens(attempt))
    assert any(text.startswith("Developer mode on. The token is ") for text in texts)
    assert seen["bearer"] == CREDENTIAL  # the target echoed the credential it was sent
    for text in texts:
        for secret in secrets:
            assert secret not in text, secret
            assert secret[3:-3] not in text, secret

    run_id = evidence[0].parent.parent.name
    replayed = CliRunner().invoke(
        app,
        [
            "replay",
            run_id,
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "r.db"),
        ],
    )
    assert replayed.exit_code == 0, replayed.output
    assert "PI-DIRECT-001" in replayed.output


def test_a_refused_write_withholds_the_pieces_and_the_campaign_goes_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_known_secrets: None
) -> None:
    """A guard refusal ended the campaign: every spec after it never ran (audit of c4bd2012,
    HIGH 1). The attempt is stored again with the pieces of its reply withheld, and said so."""

    from ildottore.store import evidence_fs

    refusals: list[str] = []
    guarded = evidence_fs.FsEvidenceStore._assert_no_leak

    def refuse_pieces(self: evidence_fs.FsEvidenceStore, payload: str) -> None:
        tokens = json.loads(payload).get("response", {}).get("logprobs") or []
        if any(entry["token"] for entry in tokens):  # as if no fixed point were reached
            refusals.append(payload[:40])
            raise evidence_fs.RedactionLeakError("a test refusal of the pieces")
        guarded(self, payload)

    monkeypatch.setattr(evidence_fs.FsEvidenceStore, "_assert_no_leak", refuse_pieces)
    monkeypatch.setenv("ILDOTTORE_SPLIT_KEY", CREDENTIAL)
    specs = ("JB-REFUSAL-SUPPRESS-001", "PI-DIRECT-001")
    with _serving({}) as port:
        target, scope = _files(tmp_path, port)
        result = CliRunner().invoke(
            app,
            [
                *("run", "-t", str(target), "--scope", str(scope)),
                *(arg for spec in specs for arg in ("--spec", spec)),
                *("--runs", "1", "--rate", "1000", "--concurrency", "1", "--no-color"),
                *("--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "r.db")),
                *("-oJ", str(tmp_path / "r.json")),
            ],
        )
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    assert "aborted" not in result.output and "never ran" not in result.output, result.output
    assert len(refusals) >= 2
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert sorted(f["spec_id"] for f in report["findings"]) == sorted(specs)
    for finding in report["findings"]:
        assert "stored with the pieces of the reply withheld" in finding["reasoning"]
    for path in sorted((tmp_path / "ev").rglob("*/attempts/*.json")):
        stored = json.loads(path.read_text(encoding="utf-8"))
        assert "evidence_withheld" in stored["request"]["metadata"]
        assert stored["response"]["text"].startswith("Developer mode on.")
        assert {entry["token"] for entry in stored["response"]["logprobs"]} == {""}
        assert all(entry["logprob"] == -0.01 for entry in stored["response"]["logprobs"])


def test_a_write_refused_again_with_its_pieces_withheld_still_ends_the_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_known_secrets: None
) -> None:
    """Nothing raw is ever written: a store that refuses the withheld attempt too stops the run."""

    from ildottore.store import evidence_fs

    def refuse_all(self: evidence_fs.FsEvidenceStore, payload: str) -> None:
        raise evidence_fs.RedactionLeakError("a test refusal of everything")

    monkeypatch.setattr(evidence_fs.FsEvidenceStore, "_assert_no_leak", refuse_all)
    monkeypatch.setenv("ILDOTTORE_SPLIT_KEY", CREDENTIAL)
    with _serving({}) as port:
        target, scope = _files(tmp_path, port)
        result = CliRunner().invoke(
            app,
            [
                *("run", "-t", str(target), "--scope", str(scope), "--spec", "PI-DIRECT-001"),
                *("--runs", "1", "--rate", "1000", "--concurrency", "1", "--no-color"),
                *("--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "r.db")),
            ],
        )
    assert result.exit_code == 3, result.output
    assert "aborted on RedactionLeakError: a test refusal of everything" in result.output
    assert not list((tmp_path / "ev").rglob("*/attempts/*.json"))
