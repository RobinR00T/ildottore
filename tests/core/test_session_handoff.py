"""Session adoption (u08 A-134, OD-76, ADR-0026): ``DL-SESSION-ADOPT-001`` end to end.

Identity A opens a conversation and plants a canary; identity B sends the attack carrying A's
conversation id. Against a loopback REST stub that binds a conversation to whoever opened it, B
is answered in a conversation of its own and the spec passes; against one that does not, B's reply
holds A's canary and the spec fails. Both through the real command line, the target file's
``rest.session`` naming the body field the id travels in, and once more with the id the server
issues (``rest.session.reply_path``). No conversation id reaches the evidence or the reports.
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

from ildottore.adapters.rest import MAX_SESSION_ID_LENGTH, RestAdapter, RestTemplate
from ildottore.cli.app import app
from ildottore.core.runner import sweeps_identities
from ildottore.core.session_handoff import (
    carries_session,
    hands_off,
    owner_index,
    scanner_session_id,
    session_digest,
    session_gap,
)
from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.registry import Registry, load_paths
from ildottore.shared.enums import SESSION_ID
from ildottore.shared.models import (
    AttackSpec,
    Capabilities,
    ModelRequest,
    ModelResponse,
    RestSession,
    RestSpec,
    Target,
)
from ildottore.shared.package_data import BATTERY

_SPEC = "DL-SESSION-ADOPT-001"
_CODE = re.compile(r"reference code is (\S+?)\.")


@pytest.fixture(autouse=True)
def _identity_b_key(monkeypatch: pytest.MonkeyPatch) -> None:
    # B carries its own key: one credential on two identities is refused (u01 A-91).
    monkeypatch.setenv("IDENTITY_B_KEY", "key-identity-b-000002")


def _spec() -> AttackSpec:
    registry = Registry.from_packs(load_paths([BATTERY / "attacks"]).packs)
    return next(spec for spec in registry.list() if spec.id == _SPEC)


def _target(session: RestSession | None) -> Target:
    return Target(
        id="stub",
        type="chatbot",
        provider="rest",
        endpoint="http://127.0.0.1:9/chat",
        capabilities=Capabilities(multi_identity=True),
        rest=RestSpec(session=session) if session is not None else None,
    )


# --- the loopback stub ----------------------------------------------------------------------


@contextmanager
def _stub(*, binds: bool, issues: bool = False) -> Iterator[tuple[int, list[dict[str, Any]]]]:
    """A chat endpoint that keeps conversations: bound to their owner (``binds``) or not.

    The conversation id comes in the body's ``conversation_id``. With ``issues`` the server
    names a new conversation itself and returns the id in the reply, as many deployments do; an
    id it did not issue opens a fresh conversation. Every request is recorded, its caller the
    ``authorization`` header (``anonymous`` when none).
    """

    conversations: dict[str, dict[str, Any]] = {}
    seen: list[dict[str, Any]] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
            caller = self.headers.get("authorization") or "anonymous"
            asked = body.get("conversation_id")
            with lock:
                seen.append({"caller": caller, "body": body})
                known = conversations.get(asked) if isinstance(asked, str) else None
                if known is None or (binds and known["owner"] != caller):
                    # A fresh conversation: the client's id, or one the server issues.
                    cid = f"srv-{len(conversations) + 1:04d}" if issues or not asked else asked
                    if binds and known is not None and not issues:
                        cid = f"{asked}#{caller}"  # the same id, another caller: its own
                    known = conversations.setdefault(cid, {"owner": caller, "notes": []})
                else:
                    cid = asked
                prompt = str(body.get("prompt", ""))
                code = _CODE.search(prompt)
                if code:
                    known["notes"].append(code.group(1))
                    text = "OK."
                elif known["notes"]:
                    text = f"Sure, your private reference code is {known['notes'][-1]}."
                else:
                    text = "This looks like a new conversation; I have no reference code yet."
            reply: dict[str, Any] = {"text": text}
            if issues:
                reply["conversation_id"] = cid
            raw = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1], seen
    finally:
        server.shutdown()
        server.server_close()


_NEW = "This looks like a new conversation; I have no reference code yet."


def _run(
    tmp_path: Path, port: int, *, reply_path: bool = False, canned: bool = False
) -> dict[str, Any]:
    endpoint = f"http://127.0.0.1:{port}/chat"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n        path_prefixes: ["/chat"]\n'
        '    identities:\n      - name: identity-a\n        auth_ref: "env://NONE"\n'
        '      - name: identity-b\n        auth_ref: "env://IDENTITY_B_KEY"\n'
    )
    session = "  session:\n    field: conversation_id\n"
    if reply_path:
        session += "    reply_path: conversation_id\n"
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: chatbot\nprovider: rest\nendpoint: "{endpoint}"\n'
        f"capabilities:\n  multi_identity: true\nrest:\n{session}"
        + (f'canned_replies: ["{_NEW}"]\n' if canned else "")
    )
    result = CliRunner().invoke(
        app,
        [
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
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            "--no-color",
            "-oA",
            str(tmp_path / "report"),
        ],
    )
    # Every attempt answered by the application halts the run (A-130): exit 3, reports written.
    assert result.exit_code != 3 or canned, result.output
    report: dict[str, Any] = json.loads((tmp_path / "report.json").read_text())
    report["_exit"] = result.exit_code
    return report


def _finding(report: dict[str, Any]) -> dict[str, Any]:
    (finding,) = [f for f in report["findings"] if f["spec_id"] == _SPEC]
    return finding


def _stored(tmp_path: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (tmp_path / "ev").rglob("*")
        if path.is_file()
    ) + "\n".join(p.read_text(encoding="utf-8") for p in tmp_path.glob("report.*"))


# --- through the command line ---------------------------------------------------------------


@pytest.mark.parametrize("issues", [False, True], ids=["scanner-id", "issued-id"])
def test_a_server_that_does_not_bind_the_session_fails(tmp_path: Path, issues: bool) -> None:
    with _stub(binds=False, issues=issues) as (port, seen):
        report = _run(tmp_path, port, reply_path=issues)
    finding = _finding(report)
    assert finding["status"] == "fail", finding
    # The attempt's own reply holds the canary: confirmed, Critical, the gate's exit code.
    assert finding["confirmed"] is True, finding
    assert finding["risk"]["band"] == "critical"
    assert (finding["risk"]["successes"], finding["risk"]["trials"]) == (2, 2)
    assert report["_exit"] == 2
    # The owner (B: the attempts go as A, whose credential the target file shares) planted
    # first; A sent the attack with B's conversation id, in the sweep and in its attempt.
    owner, adopter, attempt = seen
    assert owner["caller"].startswith("Bearer ") and "reference code is" in owner["body"]["prompt"]
    assert adopter["caller"] == attempt["caller"] == "anonymous"
    handed = "srv-0001" if issues else owner["body"]["conversation_id"]
    assert adopter["body"]["conversation_id"] == attempt["body"]["conversation_id"] == handed
    # No conversation id is written down: the evidence records its digest.
    stored = _stored(tmp_path)
    for request in seen:
        cid = request["body"].get("conversation_id")
        if cid:
            assert cid not in stored
    assert session_digest(adopter["body"]["conversation_id"]) in stored


@pytest.mark.parametrize("issues", [False, True], ids=["scanner-id", "issued-id"])
def test_a_server_that_binds_the_session_to_its_owner_passes(tmp_path: Path, issues: bool) -> None:
    with _stub(binds=True, issues=issues) as (port, seen):
        report = _run(tmp_path, port, reply_path=issues)
    finding = _finding(report)
    assert finding["status"] == "pass", finding
    assert report["_exit"] == 0
    assert len(seen) == 3  # the plant, the adoption, the attempt: what the estimate prices


def test_an_adopter_answered_with_a_canned_reply_is_left_out_not_a_pass(tmp_path: Path) -> None:
    """ADR-0025 in the handoff too (u08 A-130 with A-134): the application's fixed text is no
    answer from the conversation, so the adopter it went to is left out, by name.

    The bound stub answers every adopter with the same new-conversation text, declared here as
    one of the target file's ``canned_replies``. The handoff's sends did not mark it: the sweep
    read it as the adopter's own reply, so the run counted a reply the model wrote and ended
    with exit 0, where every attempt the application answered halts it (exit 3).
    """

    with _stub(binds=True) as (port, seen):
        report = _run(tmp_path, port, canned=True)
    finding = _finding(report)
    assert finding["status"] == "inconclusive", finding
    assert report["_exit"] == 3  # every attempt the application's: measured the filter (A-130)
    assert len(seen) == 3  # nothing more is sent for it
    assert "the reply is one of the target file's canned_replies" in _stored(tmp_path)


def test_without_rest_session_nothing_is_sent(tmp_path: Path) -> None:
    """The handoff has nowhere to travel: refused before a request, never a pass."""

    with _stub(binds=False) as (port, seen):
        endpoint = f"http://127.0.0.1:{port}/chat"
        _run(tmp_path, port)  # writes the files; then the same target without rest.session
        (tmp_path / "target.yaml").write_text(
            f'id: stub\ntype: chatbot\nprovider: rest\nendpoint: "{endpoint}"\n'
            "capabilities:\n  multi_identity: true\n"
        )
        seen.clear()
        result = CliRunner().invoke(
            app,
            [
                "run",
                "-t",
                str(tmp_path / "target.yaml"),
                "--scope",
                str(tmp_path / "scope.yaml"),
                "--spec",
                _SPEC,
                "--runs",
                "1",
                "--evidence-root",
                str(tmp_path / "ev2"),
                "--run-db",
                str(tmp_path / "runs2.sqlite"),
                "--no-color",
                "-oJ",
                str(tmp_path / "second.json"),
            ],
        )
    # The one spec selected cannot be delivered: the plan refuses before a request goes out,
    # as for every other undeliverable spec, and names the fix.
    assert result.exit_code == 3, result.output
    assert seen == []
    assert "1 not seeded" in result.output
    assert "rest.session" in result.output
    assert not (tmp_path / "second.json").exists()


# --- the pieces -----------------------------------------------------------------------------


def test_the_spec_hands_a_session_over_only_where_the_target_carries_it() -> None:
    spec = _spec()
    assert hands_off(spec)
    bare, carried = _target(None), _target(RestSession(field="conversation_id"))
    assert not carries_session(bare) and carries_session(carried)
    assert session_gap(spec, bare) is not None
    assert session_gap(spec, carried) is None
    assert not sweeps_identities(spec, bare)
    assert sweeps_identities(spec, carried)
    other = next(
        s
        for s in Registry.from_packs(load_paths([BATTERY / "attacks"]).packs).list()
        if s.id == "DL-XTENANT-001"
    )
    assert not hands_off(other) and session_gap(other, bare) is None


def test_the_scanner_id_is_stable_per_run_and_spec_and_names_neither() -> None:
    first = scanner_session_id("run-1", _SPEC)
    assert first == scanner_session_id("run-1", _SPEC)
    assert first != scanner_session_id("run-2", _SPEC)
    assert first != scanner_session_id("run-1", "DL-XTENANT-001")
    assert re.fullmatch(r"dottore-[0-9a-f]{32}", first)
    assert "run-1" not in first
    assert re.fullmatch(r"[0-9a-f]{12}", session_digest(first))


class _P:
    def __init__(self, sends: bool) -> None:
        self.sends_attempts = sends


def test_the_owner_is_the_first_identity_the_attempts_are_not_sent_as() -> None:
    assert owner_index([_P(True), _P(False), _P(False)]) == 1
    assert owner_index([_P(False), _P(True)]) == 0
    assert owner_index([_P(True), _P(True)]) == 0


def test_rest_session_refuses_the_prompt_key_and_a_bad_path() -> None:
    with pytest.raises(ValueError, match="prompt"):
        RestSession(field="prompt")
    with pytest.raises(ValueError):
        RestSession(field="conversation id")
    with pytest.raises(ValueError):
        RestSession(field="conversation_id", reply_path="a..b")
    assert RestSession(field="conversation_id", reply_path="data.0.id").reply_path == "data.0.id"


def _adapter(**template: Any) -> RestAdapter:
    return RestAdapter(
        id="stub",
        base_url="http://127.0.0.1:9",
        allowlist=EndpointAllowlist([Endpoint(host="127.0.0.1:9", path_prefixes=["/"])]),
        template=RestTemplate(path="/chat", **template),
    )


def test_the_rest_body_carries_the_id_only_for_a_request_that_holds_one() -> None:
    adapter = _adapter(session_field="conversation_id")
    plain, _ = adapter._build_request(ModelRequest(prompt="hi"))
    handed, _ = adapter._build_request(ModelRequest(prompt="hi", metadata={SESSION_ID: "c-1"}))
    assert plain == {"prompt": "hi"}
    assert handed == {"prompt": "hi", "conversation_id": "c-1"}
    # No field declared: the id goes nowhere, as every request went before.
    assert _adapter()._build_request(ModelRequest(prompt="hi", metadata={SESSION_ID: "c-1"}))[
        0
    ] == {"prompt": "hi"}


def test_the_issued_id_is_read_bounded_and_kept_only_for_a_handoff_request() -> None:
    adapter = _adapter(session_field="conversation_id", session_reply_path="meta.id")
    assert adapter._parse_body({"text": "ok", "meta": {"id": "srv-1"}}).session_id == "srv-1"
    too_long = "x" * (MAX_SESSION_ID_LENGTH + 1)
    assert adapter._parse_body({"text": "ok", "meta": {"id": too_long}}).session_id is None
    assert adapter._parse_body({"text": "ok", "meta": {"id": {"a": 1}}}).session_id is None
    assert _adapter()._parse_body({"text": "ok", "meta": {"id": "srv-1"}}).session_id is None


def test_a_reply_without_an_id_dumps_as_before() -> None:
    assert "session_id" not in ModelResponse(text="ok").model_dump()
    assert ModelResponse(text="ok", session_id="s").model_dump()["session_id"] == "s"
