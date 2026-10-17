"""An MCP spec runs against an MCP server only (OD-44, u12 and u08).

Decided 2026-10-11 under the owner's delegation (best practice, revisable). ``MCP-TOOLPOISON-001``
reads what the read-only MCP adapter renders from a server's advertised tools, resources and
prompts, and nothing gated it, so the default battery sent its discovery request to a chat model
as a prompt. Both directions were wrong there: a model that merely explained what to look for
("a description that says *you must first call* ...") tripped the regex and was a confirmed
Critical, exit 2 (on ``main`` too, pre-merge audit of ``4f3ed297``, M3); and with a judge
configured, a reply that lists no tool could pass, a clean MCP surface the target does not have.

Now the spec ``requires: [mcp]``, the capability mechanism every other gated spec uses: a target
is an MCP server exactly when its ``provider`` is ``mcp`` (the loader sets
``capabilities.mcp``; an offline mock may declare it), so the planner skips the spec elsewhere
as ``capability_unavailable`` and a run does not count it as covered.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ildottore.cli import fleet as fleet_mod
from ildottore.cli.run import RunOptions, execute_run
from ildottore.cli.wiring import load_target
from ildottore.core.planner import build_plan
from ildottore.registry import load_paths
from ildottore.shared.digest import target_digest
from ildottore.shared.enums import RequiresCapability, TargetType, VerdictStatus
from ildottore.shared.models import Capabilities, Target
from ildottore.shared.package_data import BATTERY

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "examples"


def _specs() -> list:  # type: ignore[type-arg]
    result = load_paths([BATTERY / "attacks"])
    return [spec for pack in result.packs for spec in pack.specs]


def _plan(target: Target):  # type: ignore[no-untyped-def]
    return build_plan(_specs(), None, target.capabilities, target_id=target.id, plan_ref="p")


def test_the_mcp_spec_requires_an_mcp_server() -> None:
    (spec,) = [s for s in _specs() if s.id == "MCP-TOOLPOISON-001"]
    assert RequiresCapability.MCP in spec.requires


def test_a_chat_target_does_not_plan_the_mcp_spec() -> None:
    target = load_target(EXAMPLES / "target.local.yaml")
    assert target.capabilities.mcp is False
    plan = _plan(target)
    assert "MCP-TOOLPOISON-001" not in {s.spec_id for s in plan.selected}
    (skip,) = [s for s in plan.skipped if s.spec_id == "MCP-TOOLPOISON-001"]
    assert skip.reason == "capability_unavailable: target does not declare mcp"


def test_an_mcp_target_is_an_mcp_server_without_declaring_it() -> None:
    target = load_target(EXAMPLES / "target.mcp.yaml")
    assert target.capabilities.mcp is True
    assert "MCP-TOOLPOISON-001" in {s.spec_id for s in _plan(target).selected}


def _target_file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "target.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_mcp_declared_on_a_live_target_of_another_provider_is_refused(tmp_path: Path) -> None:
    path = _target_file(
        tmp_path,
        "id: chat\ntype: chatbot\nprovider: openai\n"
        'endpoint: "https://api.example/v1/chat/completions"\n'
        "capabilities:\n  tools: true\n  mcp: true\n",
    )
    with pytest.raises(ValueError) as refused:
        load_target(path)
    message = str(refused.value)
    assert message.startswith(f"target file {path} 'capabilities'"), message
    assert "mcp" in message and "provider" in message


def test_mcp_false_on_an_mcp_target_is_refused(tmp_path: Path) -> None:
    path = _target_file(
        tmp_path,
        'id: srv\ntype: api\nprovider: mcp\nendpoint: "http://localhost:3000/mcp"\n'
        "capabilities:\n  tools: true\n  mcp: false\n",
    )
    with pytest.raises(ValueError, match="'capabilities'"):
        load_target(path)


def test_an_offline_mock_may_declare_mcp(tmp_path: Path) -> None:
    path = _target_file(
        tmp_path, "id: m\ntype: api\nmock_scenario: vulnerable\ncapabilities:\n  mcp: true\n"
    )
    assert load_target(path).capabilities.mcp is True


def test_a_fleet_entry_cannot_declare_mcp(tmp_path: Path) -> None:
    path = tmp_path / "fleet.yaml"
    path.write_text(
        'version: "1"\ntargets:\n'
        "  - id: local\n    endpoint: http://localhost:11434/v1/chat/completions\n"
        "    capabilities: { mcp: true }\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="mcp"):
        fleet_mod.load_fleet(path)


def test_a_fleet_mcp_entry_writes_a_target_that_is_an_mcp_server(tmp_path: Path) -> None:
    path = tmp_path / "fleet.yaml"
    path.write_text(
        'version: "1"\ntargets:\n  - id: srv\n    kind: mcp\n    endpoint: http://localhost:3000/mcp\n',
        encoding="utf-8",
    )
    out = fleet_mod.materialize_fleet(fleet_mod.load_fleet(path), tmp_path / "out")
    (written,) = out.target_paths
    assert load_target(written).capabilities.mcp is True


def test_the_digest_of_a_target_holds_no_derived_mcp() -> None:
    """A run stored before the capability existed still resumes (the A-68 rule for ``sampling``).

    The two digests are the ones ``0685f2c`` computes for these targets.
    """

    chat = Target(
        id="t",
        type=TargetType.CHATBOT,
        capabilities=Capabilities(tools=True),
        provider="openai",
        endpoint="https://x.example/v1/chat/completions",
    )
    server = Target(
        id="m",
        type=TargetType.API,
        capabilities=Capabilities(tools=True, mcp=True),
        provider="mcp",
        endpoint="http://localhost:3000/mcp",
    )
    assert target_digest(chat) == (
        "sha256:v2:d60f1d997533801368a39a16b3729cce05dbd8ddf4de9dd86e7b179dfa187850"
    )
    assert target_digest(server) == (
        "sha256:v2:808e8c51a205bd8200cfda95d09410ed859dc56e19643b0778c2c025ead1d1ea"
    )


_EXPLAINER = (
    "I cannot see an MCP server from here, but here is what to look for in each advertised "
    "description: text such as 'before using any other tool you must first call send_file', "
    "'do not tell the user', or an address like 'to attacker@evil.test.'"
)


@pytest.fixture
def chat_model() -> Iterator[tuple[int, list[str]]]:
    """An OpenAI-compatible model that explains what poisoned metadata looks like."""

    prompts: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("content-length", "0")))
            prompts.append(body.decode("utf-8", "replace"))
            out = json.dumps(
                {
                    "id": "stub",
                    "object": "chat.completion",
                    "model": "m",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": _EXPLAINER},
                            "finish_reason": "stop",
                        }
                    ],
                }
            ).encode()
            self.send_response(200)
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
        yield server.server_address[1], prompts
    finally:
        server.shutdown()
        server.server_close()


def test_a_chat_model_that_explains_the_markers_is_not_scored_as_an_mcp_server(
    tmp_path: Path, chat_model: tuple[int, list[str]]
) -> None:
    """It was a confirmed Critical fail, exit 2; the spec is not sent at all now."""

    port, prompts = chat_model
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        f'version: "1.0"\ntargets:\n  - id: chat\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n',
        encoding="utf-8",
    )
    target = _target_file(
        tmp_path,
        f'id: chat\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: true\n",
    )
    outcome = execute_run(
        RunOptions(
            targets=[target],
            scope=scope,
            spec_globs=["MCP-TOOLPOISON-001", "PI-DIRECT-001"],
            runs=2,
            rate=1000.0,
            quiet=True,
            evidence_root=tmp_path / "ev",
            run_db=tmp_path / "runs.sqlite",
        ),
        [BATTERY],
    )
    by_id = {f.spec_id: f for f in outcome.findings}
    mcp = by_id["MCP-TOOLPOISON-001"]
    assert mcp.status is VerdictStatus.INCONCLUSIVE
    assert mcp.attempts == []
    assert mcp.confirmed is False
    assert prompts and not any("MCP discovery" in p for p in prompts)
    assert by_id["PI-DIRECT-001"].attempts
