"""Linter rule for multimodal media: renderability + capability gating (multimodal audit)."""

from __future__ import annotations

import base64

from ildottore.registry.errors import LintCode
from ildottore.registry.linter import _check_media
from ildottore.shared import AttackSpec


def _spec(media: list[dict[str, object]], requires: list[str]) -> AttackSpec:
    return AttackSpec.model_validate(
        {
            "id": "MM-LINT-001",
            "spec_version": "1.0",
            "name": "media lint test spec",
            "category": "prompt_injection",
            "owasp": "LLM01",
            "mitre_atlas": {"tactic": "Initial Access"},
            "nist_ai_rmf": "MEASURE 2.7",
            "severity": "high",
            "target_type": "model",
            "requires": requires,
            "description": "test",
            "attack": {"user_prompt": "hi", "media": media},
            "expected_secure_behavior": ["refuses"],
            "evaluators": [{"type": "regex_absence", "patterns": ["x"]}],
            "scoring": {"impact": 3, "exploitability": 3, "confidence_threshold": 0.8},
            "fixtures": {
                "vulnerable": {"response": "x", "expect_verdict": "fail"},
                "hardened": {"response": "y", "expect_verdict": "pass"},
            },
        }
    )


def test_unrenderable_media_part_is_lint_error() -> None:
    # A schema-valid part with no payload must be caught at lint, not crash a run.
    errs = _check_media(_spec([{"kind": "image", "format": "png"}], ["multimodal"]))
    assert any(e.code == LintCode.ASSET_ERROR for e in errs)


def test_image_media_without_multimodal_requires_is_lint_error() -> None:
    errs = _check_media(_spec([{"kind": "image", "format": "png", "render_text": "x"}], []))
    assert any(e.code == LintCode.SCHEMA and "multimodal" in e.message for e in errs)


def test_audio_media_requires_audio_capability() -> None:
    b64 = base64.b64encode(b"RIFFfake").decode()
    # Declaring only 'multimodal' is not enough for an audio part; it needs 'audio'.
    errs = _check_media(
        _spec([{"kind": "audio", "format": "wav", "data_b64": b64}], ["multimodal"])
    )
    assert any("audio" in e.message for e in errs)


def test_valid_multimodal_spec_has_no_media_errors() -> None:
    assert (
        _check_media(
            _spec([{"kind": "image", "format": "png", "render_text": "x"}], ["multimodal"])
        )
        == []
    )


def test_no_media_is_noop() -> None:
    spec = _spec([{"kind": "image", "format": "png", "render_text": "x"}], ["multimodal"])
    spec = spec.model_copy(update={"attack": spec.attack.model_copy(update={"media": None})})
    assert _check_media(spec) == []
