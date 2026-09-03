"""u03 :class:`MockTarget` tests - determinism, purity, sequences, capabilities.

Covers contract §7 acceptance:
* determinism (Hypothesis, 100 repeated ``send`` byte-identical),
* no-network (AST import check + socket-guard),
* capability honesty (declared from the fixture),
* sequence cycling for N-run repros.
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.shared.models import Capabilities, FixtureCase, ModelRequest, TokenLogprob
from ildottore.shared.protocols import TargetAdapter

_FORBIDDEN_IMPORTS = {"httpx", "socket", "requests", "urllib", "time", "random"}
_MOCK_PY = Path(__file__).resolve().parents[2] / "src" / "ildottore" / "adapters" / "mock.py"


def test_mock_target_satisfies_protocol() -> None:
    target = MockTarget(MockScenario(response="hi"))
    assert isinstance(target, TargetAdapter)
    assert target.id == "mock"


async def test_send_returns_canned_response() -> None:
    scenario = MockScenario(
        response="canned answer",
        tool_calls=[{"name": "shell", "args": {"cmd": "ls"}}],
        finish_reason="stop",
    )
    target = MockTarget(scenario, id="mock:x")
    resp = await target.send(ModelRequest(prompt="anything"))
    assert resp.text == "canned answer"
    assert resp.tool_calls == [{"name": "shell", "args": {"cmd": "ls"}}]
    assert resp.finish_reason == "stop"
    assert resp.logprobs is None


async def test_send_ignores_the_prompt() -> None:
    """The mock replays the fixture verbatim - it never interprets the attack."""

    target = MockTarget(MockScenario(response="fixed"))
    a = await target.send(ModelRequest(prompt="attack A"))
    target.reset()
    b = await target.send(ModelRequest(prompt="totally different attack B"))
    assert a.text == b.text == "fixed"


async def test_logprobs_replayed_when_declared() -> None:
    lp = [TokenLogprob(token="yes", logprob=-0.1, top=[("yes", -0.1), ("no", -2.3)])]
    target = MockTarget(MockScenario(response="r", logprobs=lp))
    resp = await target.send(ModelRequest())
    assert resp.logprobs is not None
    assert resp.logprobs[0].token == "yes"
    assert resp.logprobs[0].top == [("yes", -0.1), ("no", -2.3)]


async def test_capabilities_from_scenario() -> None:
    caps = Capabilities(tools=True, logprobs=True)
    target = MockTarget(MockScenario(response="r", capabilities=caps))
    assert target.capabilities() == caps
    # Default scenario declares no capabilities.
    assert MockTarget(MockScenario(response="r")).capabilities() == Capabilities()


async def test_returned_tool_calls_are_copies() -> None:
    """Mutating a returned response must not poison a later replay (determinism)."""

    target = MockTarget(MockScenario(response="r", tool_calls=[{"name": "t"}]))
    first = await target.send(ModelRequest(metadata={"mock_attempt": 0}))
    first.tool_calls[0]["name"] = "MUTATED"
    second = await target.send(ModelRequest(metadata={"mock_attempt": 0}))
    assert second.tool_calls == [{"name": "t"}]


async def test_sequence_cycles_by_attempt_index() -> None:
    target = MockTarget(MockScenario(response=["r0", "r1", "r2"]))
    texts = [(await target.send(ModelRequest(metadata={"mock_attempt": i}))).text for i in range(5)]
    assert texts == ["r0", "r1", "r2", "r0", "r1"]


async def test_cursor_advances_without_explicit_index() -> None:
    target = MockTarget(MockScenario(response=["a", "b"]))
    assert (await target.send(ModelRequest())).text == "a"
    assert (await target.send(ModelRequest())).text == "b"
    assert (await target.send(ModelRequest())).text == "a"
    target.reset()
    assert (await target.send(ModelRequest())).text == "a"


async def test_negative_attempt_index_rejected() -> None:
    target = MockTarget(MockScenario(response="r"))
    with pytest.raises(ValueError, match="non-negative"):
        await target.send(ModelRequest(metadata={"mock_attempt": -1}))


def test_empty_sequence_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        MockScenario(response=[])


def test_from_fixture_copies_verbatim() -> None:
    case = FixtureCase(response="declared", tool_calls=[{"name": "t"}], expect_verdict="fail")
    scenario = MockScenario.from_fixture(case)
    assert scenario.response == "declared"
    assert scenario.tool_calls == [{"name": "t"}]
    assert scenario.capabilities == Capabilities()
    assert scenario.logprobs is None


def test_from_fixture_supplies_out_of_band_extras() -> None:
    case = FixtureCase(response="r", expect_verdict="pass")
    caps = Capabilities(logprobs=True)
    lp = [TokenLogprob(token="t", logprob=-0.5)]
    scenario = MockScenario.from_fixture(case, capabilities=caps, logprobs=lp, finish_reason="stop")
    assert scenario.capabilities == caps
    assert scenario.logprobs == lp
    assert scenario.finish_reason == "stop"


# --- determinism (contract §7 hard) ------------------------------------------------


@settings(max_examples=100, deadline=None)
@given(text=st.text(max_size=200), n=st.integers(min_value=2, max_value=25))
def test_send_is_byte_identical_across_repeats(text: str, n: int) -> None:
    """100 repeated ``send`` on the same fixture return byte-identical responses."""

    import asyncio

    scenario = MockScenario(response=text, tool_calls=[{"k": "v"}])

    async def one() -> str:
        target = MockTarget(scenario)
        # Pin the index so every call is a pure function of (scenario, 0).
        resp = await target.send(ModelRequest(metadata={"mock_attempt": 0}))
        return resp.model_dump_json()

    baseline = asyncio.run(one())
    for _ in range(n):
        assert asyncio.run(one()) == baseline


# --- no-network (contract §7 hard) -------------------------------------------------


def test_mock_module_imports_nothing_networky() -> None:
    """AST-scan ``mock.py``: it must import none of the forbidden modules."""

    tree = ast.parse(_MOCK_PY.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module.split(".")[0])
    offenders = imported & _FORBIDDEN_IMPORTS
    assert offenders == set(), f"mock.py imports forbidden modules: {offenders}"


async def test_send_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """A socket-guard proves ``send`` opens no network connection."""

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("MockTarget.send attempted to open a socket")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)

    target = MockTarget(MockScenario(response="offline"))
    resp = await target.send(ModelRequest(prompt="p"))
    assert resp.text == "offline"
