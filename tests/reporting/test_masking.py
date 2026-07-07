"""Masking pre-pass (contract §4 KEEP, §6, §7 masking gate)."""

from __future__ import annotations

from ildottore.reporting.masking import (
    MaskingContext,
    Redactor,
    default_redactor,
    mask_findings,
    mask_run,
    mask_text,
)
from ildottore.shared.models import Finding, TestRun
from tests.reporting.conftest import (
    PLANTED_EMAIL,
    PLANTED_OPENAI_KEY,
    make_finding,
    make_run,
)


def test_default_redactor_satisfies_protocol() -> None:
    assert isinstance(default_redactor(), Redactor)


def test_mask_text_masks_secret() -> None:
    masked = mask_text(f"key is {PLANTED_OPENAI_KEY}", default_redactor())
    assert PLANTED_OPENAI_KEY not in masked
    assert "REDACTED" in masked


def test_mask_run_returns_testrun_and_masks_strings() -> None:
    run = make_run(findings=[make_finding(reasoning=f"leaked {PLANTED_OPENAI_KEY}")])
    masked = mask_run(run, default_redactor())
    assert isinstance(masked, TestRun)
    assert PLANTED_OPENAI_KEY not in masked.model_dump_json()


def test_mask_findings_preserves_order_and_masks() -> None:
    findings = [
        make_finding("A-1", reasoning=f"contact {PLANTED_EMAIL}"),
        make_finding("B-2", reasoning="clean"),
    ]
    masked = mask_findings(findings, default_redactor())
    assert [f.spec_id for f in masked] == ["A-1", "B-2"]
    assert all(isinstance(f, Finding) for f in masked)
    assert PLANTED_EMAIL not in masked[0].model_dump_json()


def test_masking_context_masks_both() -> None:
    run = make_run(findings=[make_finding(reasoning=f"{PLANTED_OPENAI_KEY} to {PLANTED_EMAIL}")])
    ctx = MaskingContext(run, list(run.findings), default_redactor())
    blob = ctx.run.model_dump_json() + "".join(f.model_dump_json() for f in ctx.findings)
    assert PLANTED_OPENAI_KEY not in blob
    assert PLANTED_EMAIL not in blob


def test_masking_is_idempotent() -> None:
    redactor = default_redactor()
    run = make_run(findings=[make_finding(reasoning=f"leaked {PLANTED_OPENAI_KEY}")])
    once = mask_run(run, redactor)
    twice = mask_run(once, redactor)
    assert once.model_dump_json() == twice.model_dump_json()
