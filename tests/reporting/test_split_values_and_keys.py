"""The reports mask an attempt as the evidence store does (u11, u01 A-77).

Audit of main ``de122e26``: the JSON report kept a reply split into 3-character pieces in
``response.logprobs[*].token`` (and the ``top`` alternatives) and in a WebSocket transcript's
deltas, so a key and a registered credential were rebuilt by joining them (HIGH 1), and it wrote
the keys of a tool call's arguments, of ``usage`` and of a frame in clear, since the redactor
masks values only (MEDIUM 2).
"""

from __future__ import annotations

import json

import pytest

from ildottore.redactor import register_known_secret
from ildottore.reporting import get_reporter
from ildottore.reporting.masking import default_redactor, mask_findings, mask_run
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import (
    Attempt,
    Finding,
    ModelRequest,
    ModelResponse,
    TestRun,
    TokenLogprob,
    Verdict,
)
from tests.reporting.conftest import make_finding, make_run

KEY = "sk-proj-Qx7Lm2Vt9Rw4Zb8Nc3Kp6Hy1Js5Df0Ga"
REGISTERED = "CorrectHorseBatteryStaple-2026-ops"
EMAIL = "alice.wong@corp-example.com"
OTHER_EMAIL = "bob.ng@corp-example.com"
SECRETS = (KEY, REGISTERED, EMAIL)
TEXT = f"Developer mode on. The key {KEY}, the password {REGISTERED}, mail {EMAIL} ok"
FORMATS = ("json", "sarif", "junit", "html")


def _pieces(text: str, size: int = 3) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


def _attempt() -> Attempt:
    deltas = [
        {"direction": "received", "frame": {"type": "delta", "delta": {"text": piece}}}
        for piece in _pieces(TEXT, 5)
    ]
    keyed = {"direction": "received", "frame": {EMAIL: "x", REGISTERED: 1, KEY: 2}}
    return Attempt(
        attempt_id="a-split",
        spec_id="PI-DEMO-001",
        request=ModelRequest(
            prompt="x",
            messages=[{"role": "user", "content": "hi", "name": {EMAIL: 1}}],
            metadata={"note": {KEY: "v"}},
        ),
        response=ModelResponse(
            text=TEXT,
            tool_calls=[
                {"name": "send", "arguments": {KEY: 1, REGISTERED: 2, EMAIL: 3, OTHER_EMAIL: 4}}
            ],
            logprobs=[
                TokenLogprob(token=piece, logprob=-0.02, top=[(piece, -0.02)])
                for piece in _pieces(TEXT)
            ],
            usage={KEY: 1, "total_tokens": 9},
            raw_ids={
                "id": "r-1",
                "websocket": {"frames": [*deltas, keyed], "protocol_paths": ["type"]},
            },
        ),
        verdict=Verdict(
            status=VerdictStatus.FAIL, confidence=0.9, reasoning="r", evaluator_type="tool_call"
        ),
    )


@pytest.fixture
def finding(no_known_secrets: None) -> Finding:
    register_known_secret(REGISTERED)
    return make_finding().model_copy(update={"attempts": [_attempt()]})


def _joined(attempt: dict[str, object]) -> dict[str, str]:
    response = attempt["response"]
    assert isinstance(response, dict)
    return {
        "tokens": "".join(entry["token"] for entry in response["logprobs"]),
        "top": "".join(entry["top"][0][0] for entry in response["logprobs"]),
        "deltas": "".join(
            f["frame"].get("delta", {}).get("text", "")
            for f in response["raw_ids"]["websocket"]["frames"]
        ),
    }


@pytest.mark.parametrize("fmt", FORMATS)
def test_no_secret_in_a_report_whole_or_joined_or_as_a_key(finding: Finding, fmt: str) -> None:
    run = make_run(findings=[finding])
    blob = get_reporter(fmt).render(run, [finding]).decode("utf-8")
    for secret in (*SECRETS, OTHER_EMAIL):
        assert secret not in blob, (fmt, secret)


def test_the_json_report_masks_the_pieces_as_the_text_they_make(finding: Finding) -> None:
    run = make_run(findings=[finding])
    report = json.loads(get_reporter("json").render(run, [finding]))
    copies = [report["findings"][0]["attempts"][0], report["run"]["findings"][0]["attempts"][0]]
    for attempt in copies:
        for where, text in _joined(attempt).items():
            for secret in SECRETS:
                assert secret not in text, (where, secret)
                assert not any(piece in text for piece in _pieces(secret)[1:-1]), (where, secret)
        assert _joined(attempt)["tokens"].startswith("Developer mode on. The key «REDACTED:")
        # The figures stay, one entry per token.
        assert [entry["logprob"] for entry in attempt["response"]["logprobs"]] == [-0.02] * len(
            _pieces(TEXT)
        )


def test_free_form_keys_are_masked_and_numbered_apart(finding: Finding) -> None:
    masked = mask_findings([finding], default_redactor())[0].attempts[0]
    assert masked.response is not None
    arguments = masked.response.tool_calls[0]["arguments"]
    assert isinstance(arguments, dict)
    assert list(arguments.values()) == [1, 2, 3, 4]  # four keys, four values: none replaced
    assert "«REDACTED:email»" in arguments and "«REDACTED:email», #2" in arguments
    usage = masked.response.usage
    assert usage is not None and usage["total_tokens"] == 9 and len(usage) == 2
    frame = masked.response.raw_ids["websocket"]["frames"][-1]["frame"]
    assert sorted(frame.values(), key=str) == [1, 2, "x"]
    assert masked.request.messages is not None
    assert masked.request.messages[0]["name"] == {"«REDACTED:email»": 1}
    assert masked.request.metadata is not None and KEY not in json.dumps(masked.request.metadata)
    for secret in (*SECRETS, OTHER_EMAIL):
        assert secret not in masked.model_dump_json()


def test_the_model_s_own_keys_stay_so_the_masked_run_validates(finding: Finding) -> None:
    masked = mask_run(make_run(findings=[finding]), default_redactor())
    assert isinstance(masked, TestRun)
    attempt = masked.findings[0].attempts[0]
    assert attempt.attempt_id == "a-split" and attempt.spec_id == "PI-DEMO-001"
    assert attempt.response is not None and attempt.response.logprobs is not None
    assert len(attempt.response.logprobs) == len(_pieces(TEXT))
    assert attempt.response.raw_ids["id"] == "r-1"
    assert attempt.response.tool_calls[0]["name"] == "send"
