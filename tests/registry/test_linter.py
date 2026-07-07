"""Lint rule engine + fixtures-prove-detection tests (contract §7)."""

from __future__ import annotations

from pathlib import Path

from ildottore.registry import (
    LintCode,
    Severity,
    evaluate_fixture,
    lint,
    lint_packs,
    load_path,
)
from ildottore.registry.fixtures_engine import DEFAULT_STUB_TABLE
from ildottore.shared import EvaluatorType, VerdictStatus


def test_good_pack_lints_clean(packs_root: Path) -> None:
    report = lint([packs_root / "good"])
    assert report.ok, report.errors
    assert report.errors == []
    assert report.counts.specs == 2
    assert report.counts.suites == 1
    assert report.counts.packs == 1


def test_bad_pack_flags_no_detect_and_missing_test_only(packs_root: Path) -> None:
    report = lint([packs_root / "bad"])
    assert not report.ok
    codes = {e.code for e in report.errors}
    assert LintCode.FIXTURE_NO_DETECT in codes
    assert LintCode.MISSING_TEST_ONLY in codes


def test_collision_lints_exactly_one_id_collision(packs_root: Path) -> None:
    report = lint([packs_root / "collision"])
    collision_errs = [e for e in report.errors if e.code is LintCode.ID_COLLISION]
    assert len(collision_errs) == 1
    assert not report.ok


def test_suite_unknown_ref_is_error(packs_root: Path, tmp_path: Path) -> None:
    # Build a pack whose suite references a missing spec id.
    pack = tmp_path / "reffy"
    (pack / "attacks").mkdir(parents=True)
    (pack / "suites").mkdir(parents=True)
    (pack / "pack.yaml").write_text(
        "id: reffy\npack_version: '1.0'\nname: reffy\n", encoding="utf-8"
    )
    (pack / "suites" / "s.yaml").write_text(
        "id: s\nsuite_version: '1.0'\nname: s\nspecs:\n  - spec_id: GHOST-999\n",
        encoding="utf-8",
    )
    report = lint([pack])
    codes = {e.code for e in report.errors}
    assert LintCode.UNKNOWN_SPEC_REF in codes


def test_missing_framework_map_is_error(packs_root: Path, tmp_path: Path) -> None:
    # A schema-valid spec with a blank nist mapping (schema allows empty string).
    pack = tmp_path / "fw"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: fw\npack_version: '1.0'\nname: fw\n", encoding="utf-8")
    (pack / "attacks" / "a.yaml").write_text(
        (packs_root / "good" / "attacks" / "JB-REFUSAL-001.yaml")
        .read_text(encoding="utf-8")
        .replace('nist_ai_rmf: "MEASURE 2.7"', 'nist_ai_rmf: ""')
        .replace("id: JB-REFUSAL-001", "id: FW-BLANK-001"),
        encoding="utf-8",
    )
    report = lint([pack])
    codes = {e.code for e in report.errors}
    assert LintCode.MISSING_FRAMEWORK_MAP in codes


def test_load_errors_carried_into_report(invalid_specs_dir: Path) -> None:
    report = lint([invalid_specs_dir])
    assert not report.ok
    assert any(e.code is LintCode.SCHEMA for e in report.errors)


def test_unprovable_evaluator_yields_warning_not_error(packs_root: Path, tmp_path: Path) -> None:
    # A spec whose only evaluator has no W1 stub → warning, still ok().
    pack = tmp_path / "unprov"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text(
        "id: unprov\npack_version: '1.0'\nname: unprov\n", encoding="utf-8"
    )
    src = (packs_root / "good" / "attacks" / "DL-CANARY-001.yaml").read_text(encoding="utf-8")
    src = src.replace("id: DL-CANARY-001", "id: DL-PII-001")
    src = src.replace(
        '  - type: secret_leakage\n    canary_ref: "ZYNAP_CANARY_ABC123"',
        "  - type: pii_detector",
    )
    (pack / "attacks" / "a.yaml").write_text(src, encoding="utf-8")
    report = lint([pack])
    assert report.ok, report.errors  # only a warning
    assert any(
        w.code is LintCode.FIXTURE_NO_DETECT and w.severity is Severity.WARNING
        for w in report.warnings
    )


def test_lint_packs_accepts_custom_stub_table(packs_root: Path) -> None:
    result = load_path(packs_root / "good")

    def _always_pass(_spec: object, _ev: object) -> VerdictStatus:
        return VerdictStatus.PASS

    table = {EvaluatorType.REFUSAL: _always_pass, EvaluatorType.SECRET_LEAKAGE: _always_pass}
    report = lint_packs(result.packs, result.errors, stub_table=table)  # type: ignore[arg-type]
    # With an always-pass table, vulnerable fixtures no longer detect → FIXTURE_NO_DETECT.
    assert any(e.code is LintCode.FIXTURE_NO_DETECT for e in report.errors)


def test_evaluate_fixture_reports_missing_stub(packs_root: Path) -> None:
    reg = load_path(packs_root / "good")
    spec = next(s for p in reg.packs for s in p.specs if s.id == "DL-CANARY-001")
    verdict, missing = evaluate_fixture(spec, spec.fixtures.vulnerable, DEFAULT_STUB_TABLE)
    assert verdict is VerdictStatus.FAIL
    assert missing == []
