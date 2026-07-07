"""Signature-pack + corpus loader tests (u09 contract §4 KEEP, §5 step 1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ildottore.fingerprint.attribution import _FIELD_SEP, _KV_SEP  # type: ignore[attr-defined]
from ildottore.fingerprint.signatures import (
    SignaturePack,
    SignaturePackError,
    load_corpus,
    load_pack,
)


def test_pack_loads_and_validates(pack: SignaturePack) -> None:
    assert pack.pack_version == 1
    assert pack.entries
    # every entry declares a statistical centroid of the expected dimension
    from ildottore.fingerprint.layers.statistical import FEATURES_PER_PROBE
    from ildottore.fingerprint.probes import STATISTICAL_BATTERY

    expected = FEATURES_PER_PROBE * len(STATISTICAL_BATTERY)
    for entry in pack.entries:
        assert entry.stat is not None
        assert len(entry.stat.centroid) == expected


def test_pack_families_are_stable_and_deduped(pack: SignaturePack) -> None:
    families = pack.families()
    assert families == list(dict.fromkeys(families))  # order-preserving, no dupes
    assert "anthropic-claude" in families


def test_family_and_version_names_are_separator_safe(pack: SignaturePack) -> None:
    # attribution encoding reserves these separators; pack names must avoid them
    for entry in pack.entries:
        for token in (entry.family, entry.version or ""):
            assert _FIELD_SEP not in token
            assert _KV_SEP not in token


def test_unsupported_pack_version_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "pack.yaml"
    bad.write_text("pack_version: 999\nname: x\nentries: []\n", encoding="utf-8")
    with pytest.raises(SignaturePackError, match="unsupported pack_version"):
        load_pack(bad)


def test_non_mapping_pack_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "pack.yaml"
    bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(SignaturePackError, match="must be a mapping"):
        load_pack(bad)


def test_invalid_yaml_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "pack.yaml"
    bad.write_text("pack_version: 1\nname: x\n entries: [\n", encoding="utf-8")
    with pytest.raises(SignaturePackError, match="invalid YAML"):
        load_pack(bad)


def test_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(SignaturePackError, match="cannot read"):
        load_pack(tmp_path / "nope.yaml")


def test_schema_violation_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "pack.yaml"
    # pack_version ok but an entry missing 'family' (schema violation)
    bad.write_text(
        "pack_version: 1\nname: x\nentries:\n  - version: v1\n",
        encoding="utf-8",
    )
    with pytest.raises(SignaturePackError, match="schema validation"):
        load_pack(bad)


def test_corpus_loads(tmp_path: Path) -> None:
    cases = load_corpus()
    assert cases
    assert all(c.family for c in cases)


def test_corpus_requires_cases_key(tmp_path: Path) -> None:
    bad = tmp_path / "corpus.yaml"
    bad.write_text("not_cases: []\n", encoding="utf-8")
    with pytest.raises(SignaturePackError, match="'cases' list"):
        load_corpus(bad)


def test_corpus_schema_violation_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "corpus.yaml"
    bad.write_text("cases:\n  - {}\n", encoding="utf-8")  # missing case_id/family
    with pytest.raises(SignaturePackError, match="schema validation"):
        load_corpus(bad)
