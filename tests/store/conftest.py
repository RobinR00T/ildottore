"""Shared builders + fixtures for the u10 store tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.shared.enums import ScanBand, VerdictStatus
from ildottore.shared.models import (
    Attempt,
    Finding,
    ModelRequest,
    ModelResponse,
    RiskScore,
    Target,
    TestRun,
    Verdict,
)


def make_attempt(
    *,
    attempt_id: str = "a-1",
    spec_id: str = "PI-DIRECT-001",
    prompt: str = "hello",
    response_text: str = "world",
    status: VerdictStatus = VerdictStatus.FAIL,
    mutation: str = "identity",
) -> Attempt:
    """A minimal, fully-populated :class:`Attempt` for persistence tests."""

    return Attempt(
        attempt_id=attempt_id,
        spec_id=spec_id,
        mutation=mutation,
        request=ModelRequest(prompt=prompt),
        response=ModelResponse(text=response_text),
        verdict=Verdict(
            status=status,
            confidence=0.9,
            reasoning="test",
            evaluator_type="regex_absence",
        ),
    )


def make_finding(
    *,
    spec_id: str = "PI-DIRECT-001",
    target_id: str = "tgt-1",
    status: VerdictStatus = VerdictStatus.FAIL,
    repro: float = 0.6,
    confidence: float = 0.9,
) -> Finding:
    """A minimal scored :class:`Finding`."""

    return Finding(
        spec_id=spec_id,
        target_id=target_id,
        status=status,
        confirmed=True,
        risk=RiskScore(
            impact=3,
            exploitability=3,
            reproducibility=repro,
            risk=9.0,
            band=ScanBand.HIGH,
            confidence=confidence,
        ),
    )


def make_run(
    *,
    run_id: str = "run-1",
    suite_ref: str = "suites/core",
    target_id: str = "tgt-1",
    findings: list[Finding] | None = None,
) -> TestRun:
    """A :class:`TestRun` with one target and optional findings."""

    return TestRun(
        run_id=run_id,
        suite_ref=suite_ref,
        targets=[Target(id=target_id, type="chatbot")],
        findings=findings if findings is not None else [make_finding(target_id=target_id)],
        started_at="2026-07-07T00:00:00Z",
        finished_at="2026-07-07T00:01:00Z",
    )


@pytest.fixture
def store_root(tmp_path: Path) -> Path:
    """A store root under a path with a space (paths-with-spaces safety)."""

    root = tmp_path / "evidence store"
    root.mkdir()
    return root
