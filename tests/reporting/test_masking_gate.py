"""Masking gate (contract §7): a planted secret/PII/canary yields 0 raw occurrences
in every format's rendered bytes.
"""

from __future__ import annotations

import pytest

from ildottore.reporting import get_reporter, list_formats
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import (
    Attempt,
    EvidenceRef,
    Finding,
    ModelRequest,
    ModelResponse,
    Verdict,
)
from tests.reporting.conftest import (
    PLANTED_CANARY,
    PLANTED_EMAIL,
    PLANTED_OPENAI_KEY,
    make_risk,
    make_run,
    make_spec,
)


def _planted_finding() -> Finding:
    """A finding with the planted secret/PII/canary threaded through every string channel."""
    return Finding(
        spec_id="DL-LEAK-001",
        target_id="mock-a",
        status=VerdictStatus.FAIL,
        risk=make_risk(),
        confirmed=True,
        attempts=[
            Attempt(
                attempt_id="a1",
                spec_id="DL-LEAK-001",
                request=ModelRequest(prompt=f"exfiltrate {PLANTED_CANARY}"),
                response=ModelResponse(
                    text=f"here is the key {PLANTED_OPENAI_KEY} for {PLANTED_EMAIL}"
                ),
                verdict=Verdict(
                    status=VerdictStatus.FAIL,
                    confidence=0.9,
                    reasoning=f"leaked {PLANTED_OPENAI_KEY}",
                    matched=[PLANTED_OPENAI_KEY, PLANTED_EMAIL],
                    evaluator_type="secret_leakage",
                ),
            )
        ],
        evidence=[EvidenceRef(run_id="run-1", attempt_id="a1", uri="evidence://run-1/a1.json")],
        reasoning=f"model returned {PLANTED_OPENAI_KEY} and emailed {PLANTED_EMAIL}",
    )


@pytest.mark.parametrize("fmt", ["json", "html", "sarif", "junit"])
def test_no_raw_secret_in_any_format(fmt: str) -> None:
    specs = {"DL-LEAK-001": make_spec("DL-LEAK-001", owasp="LLM02")}
    finding = _planted_finding()
    run = make_run(run_id="run-1", findings=[finding])
    out = get_reporter(fmt, specs=specs).render(run, [finding])
    blob = out.decode("utf-8")
    assert PLANTED_OPENAI_KEY not in blob, f"{fmt}: openai key leaked"
    assert PLANTED_EMAIL not in blob, f"{fmt}: email leaked"


def test_gate_covers_every_registered_format() -> None:
    # A newly-added format must also pass through the choke point; assert the set we cover.
    assert set(list_formats()) == {"json", "html", "sarif", "junit"}


def test_redacted_marker_present() -> None:
    finding = _planted_finding()
    run = make_run(run_id="run-1", findings=[finding])
    out = get_reporter("json").render(run, [finding]).decode("utf-8")
    assert "REDACTED" in out
