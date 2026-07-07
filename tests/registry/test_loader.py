"""Loader / discovery tests (contract §5.2, §7)."""

from __future__ import annotations

from pathlib import Path

from ildottore.registry import LintCode, load_path
from ildottore.registry.loader import load_paths


def test_load_good_pack(packs_root: Path) -> None:
    result = load_path(packs_root / "good")
    assert not result.errors
    assert len(result.packs) == 1
    pack = result.packs[0]
    assert pack.id == "good-pack"
    assert pack.version == "1.0"
    assert {s.id for s in pack.specs} == {"JB-REFUSAL-001", "DL-CANARY-001"}
    assert [s.id for s in pack.suites] == ["good-baseline"]


def test_load_loose_specs_synthetic_pack(valid_specs_dir: Path) -> None:
    result = load_path(valid_specs_dir)
    assert not result.errors
    assert len(result.packs) == 1
    assert result.packs[0].id == "loose-specs"
    assert len(result.packs[0].specs) == 3


def test_load_invalid_loose_specs_report_errors(invalid_specs_dir: Path) -> None:
    result = load_path(invalid_specs_dir)
    # Every invalid fixture yields at least one SCHEMA/PARSE finding; none construct.
    assert result.errors
    codes = {e.code for e in result.errors}
    assert codes <= {LintCode.SCHEMA, LintCode.PARSE_ERROR}


def test_load_single_spec_file(valid_specs_dir: Path) -> None:
    one = valid_specs_dir / "JB-MULTITURN-001.yaml"
    result = load_path(one)
    assert not result.errors
    assert len(result.packs) == 1
    assert result.packs[0].specs[0].id == "JB-MULTITURN-001"


def test_load_missing_path() -> None:
    result = load_path(Path("/nonexistent/does/not/exist"))
    assert result.errors
    assert result.errors[0].code is LintCode.PARSE_ERROR


def test_load_collision_dirs_two_packs(packs_root: Path) -> None:
    result = load_path(packs_root / "collision")
    assert {p.id for p in result.packs} == {"pack-a", "pack-b"}


def test_load_paths_concatenates(packs_root: Path, valid_specs_dir: Path) -> None:
    result = load_paths([packs_root / "good", valid_specs_dir])
    ids = {p.id for p in result.packs}
    assert "good-pack" in ids
    assert "loose-specs" in ids


def test_non_mapping_spec_root_is_parse_error(tmp_path: Path) -> None:
    f = tmp_path / "list.yaml"
    f.write_text("- just\n- a\n- list\n", encoding="utf-8")
    result = load_path(f)
    assert result.errors and result.errors[0].code is LintCode.PARSE_ERROR


def test_bad_pack_manifest_root_is_parse_error(tmp_path: Path) -> None:
    pack = tmp_path / "p"
    pack.mkdir()
    (pack / "pack.yaml").write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    result = load_path(pack)
    assert result.errors and result.errors[0].code is LintCode.PARSE_ERROR
    assert result.packs == []


def test_bad_suite_root_is_parse_error(tmp_path: Path) -> None:
    pack = tmp_path / "p"
    (pack / "suites").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: p\npack_version: '1.0'\nname: p\n", encoding="utf-8")
    (pack / "suites" / "s.yaml").write_text("- list\n", encoding="utf-8")
    result = load_path(pack)
    assert any(e.code is LintCode.PARSE_ERROR for e in result.errors)


def test_invalid_pack_manifest_is_schema_error(tmp_path: Path) -> None:
    pack = tmp_path / "p"
    pack.mkdir()
    # Missing required pack_version → Pydantic validation error surfaced as SCHEMA.
    (pack / "pack.yaml").write_text("id: p\nname: p\n", encoding="utf-8")
    result = load_path(pack)
    assert any(e.code is LintCode.SCHEMA for e in result.errors)
    assert result.packs == []


def test_invalid_suite_is_schema_error(tmp_path: Path) -> None:
    pack = tmp_path / "p"
    (pack / "suites").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: p\npack_version: '1.0'\nname: p\n", encoding="utf-8")
    # Missing required suite_version.
    (pack / "suites" / "s.yaml").write_text("id: s\nname: s\n", encoding="utf-8")
    result = load_path(pack)
    assert any(e.code is LintCode.SCHEMA for e in result.errors)


def test_malformed_yaml_spec_is_parse_error(tmp_path: Path) -> None:
    f = tmp_path / "broken.yaml"
    f.write_text("a: [1, 2\n  b: broken", encoding="utf-8")
    result = load_path(f)
    assert result.errors and result.errors[0].code is LintCode.PARSE_ERROR
