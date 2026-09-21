"""Masking pre-pass (contract §4 KEEP, §6, §7 masking gate)."""

from __future__ import annotations

from pathlib import Path

from ildottore.registry import Registry, load_paths
from ildottore.reporting.masking import (
    MaskingContext,
    Redactor,
    default_redactor,
    mask_findings,
    mask_run,
    mask_text,
)
from ildottore.shared.enums import TargetType
from ildottore.shared.models import Finding, Target, TestRun
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


# --- regression: a spec id is a join key, masking must never rewrite it ---------------


def test_shipped_spec_ids_survive_mask_findings(specs_dir: Path) -> None:
    """Every id in the shipped battery comes back byte-identical from the pre-pass.

    ``spec_id`` is the join key for ``dottore diff`` (baseline vs current) and the SARIF
    rule id, so a rewritten id silently breaks regression tracking. 15 of the 72 shipped
    ids used to come out as ``«REDACTED:high_entropy:...»``: a hyphenated uppercase id
    scores 3.72-3.94 bits/char, just over the entropy fallback's 3.7 threshold.
    """

    ids = sorted(spec.id for spec in Registry.from_packs(load_paths([specs_dir]).packs).list())
    assert ids, "the shipped specs/ tree loaded no specs"

    masked = mask_findings([make_finding(spec_id=spec_id) for spec_id in ids], default_redactor())

    assert [f.spec_id for f in masked] == ids
    # The id also travels on each attempt; the SARIF/JSON writers read both.
    assert [attempt.spec_id for f in masked for attempt in f.attempts] == ids


# --- regression: a dated model name is not a phone number -----------------------------


def test_dated_model_name_survives_mask_run() -> None:
    """The report must be able to name the model it just tested.

    The ``phone`` detector read a dated suffix as a number, so ``Target.model`` /
    ``Target.name`` rendered as ``claude-opus-«REDACTED:phone»`` and the run's date fields
    as ``«REDACTED:phone»``, in every format. The detector now exempts a date stamp by
    shape, so the identifier comes back byte-identical.
    """

    model = "claude-opus-4-1-20250805"
    run = make_run(
        targets=[
            Target(id="live-a", type=TargetType.MODEL, name=model, model=model),
            Target(id="live-b", type=TargetType.MODEL, name="gpt-4o-mini-2024-07-18"),
        ],
        findings=[make_finding(reasoning="target complied on 2026-09-20")],
    )

    masked = mask_run(run, default_redactor())

    assert masked.targets[0].name == model
    assert masked.targets[0].model == model
    assert masked.targets[1].name == "gpt-4o-mini-2024-07-18"
    assert masked.started_at == run.started_at
    assert masked.findings[0].reasoning == "target complied on 2026-09-20"
