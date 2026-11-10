"""CCN-STIC-2011 (ESP-IA) on a spec: the pinned table, the matrix, the lint, the card (u02 A-116).

``esp_ia`` names the Functional Security Requirements a FAIL of the spec is evidence against.
Falsification only, as with AISVS: a PASS never says a requirement is met. The battery's mapping
is pinned here, requirement by requirement, so a change to it is a reviewed diff.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml

from ildottore.cli.describe import render_describe
from ildottore.registry import LintCode, LintError
from ildottore.reporting.summary import build_battery_coverage
from ildottore.shared.digest import spec_digest
from ildottore.shared.esp_ia import (
    ESP_IA_CODE_RE,
    ESP_IA_NOT_TESTED_BY_DESIGN,
    ESP_IA_OUT_OF_REACH,
    ESP_IA_QUESTIONS,
    ESP_IA_REQUIREMENTS,
    ESP_IA_RULES,
    applicable_rules,
    unknown_esp_ia_codes,
)
from ildottore.shared.frameworks import framework_editions
from ildottore.shared.models import AttackSpec
from tests.registry.test_linter import _lint_with_iopc

_BATTERY = Path(__file__).resolve().parents[2] / "src" / "ildottore" / "battery" / "attacks"

#: The battery's mapping, as reviewed on 2026-11-02 (ADR-0023). Left out on purpose: content
#: safety and bias (ESP-IA has no content threat), insecure generated code (OUT-*: the weakness
#: is in what the code does), SUPPLY-SLOPSQUAT-001 and the two MCP catalogue specs.
_MAPPING = {
    "RFS-AGE-01": {
        "AG-AUTONOMY-DRIFT-001",
        "AG-AUTONOMY-SELFCORRECT-001",
        "AG-CONFIRM-BYPASS-001",
        "AG-CRED-SWEEP-001",
        "AG-DESTRUCTIVE-DBDROP-001",
        "AG-EXTORT-CHAIN-001",
        "AG-INTERAGENT-COMPROMISE-001",
        "AG-LOG-EVASION-001",
        "AG-PERSIST-BEACON-001",
        "AG-RECURSIVE-HIJACK-001",
    },
    "RFS-AGE-02": {
        "AC-SSRF-001",
        "AC-SSRF-SCHEME-001",
        "AG-CODEEXEC-UNEXPECTED-001",
        "AG-EXTORT-CHAIN-001",
        "AG-TOOL-UNAUTH-001",
        "AG-TOOLCHAIN-EXFIL-001",
        "AG-TOOLMETA-POISON-001",
        "FUNCALL-ARGSMUGGLE-001",
        "FUNCALL-PRICE-TAMPER-001",
        "FUNCALL-SQLI-ARG-001",
        "MM-IMG-TOOL-EXFIL-001",
        "PI-DELAYED-TRIGGER-001",
    },
    "RFS-AGE-03": {
        "AC-BFLA-001",
        "AC-BOLA-001",
        "AC-RBAC-001",
        "AG-IDENTITY-ABUSE-001",
    },
    "RFS-AGE-04": {"AC-BFLA-001"},
    "RFS-AGE-05": {"AC-BOLA-001"},
    "RFS-DIS-01": {
        "AC-DEBUG-001",
        "AG-GOAL-THEFT-001",
        "DL-PII-ELICIT-001",
        "DL-SECRET-CANARY-001",
        "EMB-INVERSION-PROBE-001",
        "EMB-NEIGHBOR-LEAK-001",
        "PI-DIRECT-001",
        "PI-INDIRECT-RAG-001",
        "PI-INDIRECT-TOOL-001",
        "RECON-MODEL-IDENTITY-001",
        "RECON-SYSTEM-001",
        "SP-LEAK-001",
    },
    "RFS-DIS-02": {
        "AC-BOLA-001",
        "DL-SESSION-ADOPT-001",
        "DL-XSESSION-001",
        "DL-XTENANT-001",
        "EMB-XTENANT-RETRIEVAL-001",
    },
    "RFS-DIS-03": {"DL-SESSION-ADOPT-001", "DL-XSESSION-001"},
    "RFS-DIS-04": {"AG-EXFIL-EGRESS-001"},
    "RFS-DIS-05": {
        "AG-CRED-SWEEP-001",
        "AG-EXFIL-EGRESS-001",
        "AG-TOOLCHAIN-EXFIL-001",
        "MM-IMG-TOOL-EXFIL-001",
    },
    "RFS-EVA-01": {"GUARD-INPUT-EVASION-001", "GUARD-UNICODE-EVASION-001"},
    "RFS-EXH-01": {"DOS-RESOURCE-HIJACK-001", "DOS-TOKEN-AMP-001"},
    "RFS-INJ-01": {
        "AG-IDENTITY-ABUSE-001",
        "GUARD-INPUT-EVASION-001",
        "GUARD-OUTPUT-ENCODE-001",
        "GUARD-UNICODE-EVASION-001",
        "JB-CRESCENDO-001",
        "JB-ENCODING-001",
        "JB-LIKERT-001",
        "JB-LINEAR-001",
        "JB-MULTILINGUAL-001",
        "JB-OFFENSIVE-RANSOM-CODEGEN-001",
        "JB-REFUSAL-SUPPRESS-001",
        "JB-ROLEPLAY-001",
        "JB-SEQUENTIAL-001",
        "JB-TREE-001",
        "PI-DIRECT-001",
    },
    "RFS-INJ-02": {
        "AG-CODEEXEC-UNEXPECTED-001",
        "AG-EXTORT-CHAIN-001",
        "AG-INTERAGENT-COMPROMISE-001",
        "AG-TOOLMETA-POISON-001",
        "AG-WORM-PROPAGATE-001",
        "MEM-POISON-001",
        "MM-AUD-PROMPTINJECT-001",
        "MM-IMG-DOC-INJECT-001",
        "MM-IMG-FILENAME-INJECT-001",
        "MM-IMG-PROMPTINJECT-001",
        "MM-IMG-SPLIT-PAYLOAD-001",
        "MM-IMG-TOOL-EXFIL-001",
        "PI-DELAYED-TRIGGER-001",
        "PI-INDIRECT-RAG-001",
        "PI-INDIRECT-TOOL-001",
    },
    "RFS-INV-01": {"DL-MEMORIZE-DIVERGENCE-001"},
    "RFS-MEM-01": {"DL-MEMORIZE-DIVERGENCE-001"},
    "RFS-OVS-01": {
        "AG-CONFIRM-BYPASS-001",
        "AG-DESTRUCTIVE-DBDROP-001",
        "AG-TRUST-APPROVAL-001",
    },
    "RFS-POI-01": {"AG-RECURSIVE-HIJACK-001", "MEM-POISON-001"},
    "RFS-TRA-03": {"AG-LOG-EVASION-001"},
}


def _battery() -> dict[str, AttackSpec]:
    specs = (
        AttackSpec.model_validate(yaml.safe_load(p.read_text())) for p in _BATTERY.glob("*.yaml")
    )
    return {s.id: s for s in specs}


# --- the pinned table and the matrix -------------------------------------------------------


def test_the_table_has_27_requirements_from_9_threats_and_2_policies() -> None:
    assert len(ESP_IA_REQUIREMENTS) == 27
    assert all(ESP_IA_CODE_RE.match(code) for code in ESP_IA_REQUIREMENTS)
    sources = set(ESP_IA_REQUIREMENTS.values())
    assert len({s for s in sources if s.startswith("T.")}) == 9
    assert {s for s in sources if s.startswith("P.")} == {"P.OVERSIGHT", "P.TRACEABILITY"}
    assert sum(1 for s in ESP_IA_REQUIREMENTS.values() if s.startswith("P.")) == 5


def test_the_matrix_names_every_requirement_once_and_only_known_questions() -> None:
    named = [code for rule in ESP_IA_RULES for code in rule.requirements]
    assert sorted(named) == sorted(ESP_IA_REQUIREMENTS)
    assert len(ESP_IA_RULES) == 24
    for rule in ESP_IA_RULES:
        assert set(rule.all_of) | set(rule.any_of) <= set(ESP_IA_QUESTIONS)
        assert all(ESP_IA_REQUIREMENTS[c] == rule.threat for c in rule.requirements)
    assert len(ESP_IA_QUESTIONS) == 22


def test_the_classification_is_disjoint_and_inside_the_table() -> None:
    assert set(ESP_IA_OUT_OF_REACH) <= set(ESP_IA_REQUIREMENTS)
    assert set(ESP_IA_NOT_TESTED_BY_DESIGN) <= set(ESP_IA_REQUIREMENTS)
    assert not set(ESP_IA_OUT_OF_REACH) & set(ESP_IA_NOT_TESTED_BY_DESIGN)


@pytest.mark.parametrize(
    ("yes", "rules"),
    [
        (set(), []),
        ({"C01", "C03"}, ["R02"]),
        ({"C02"}, ["RP02"]),
        ({"C16"}, ["R16", "RP02"]),
        ({"C16", "C16a", "C15", "C17"}, ["R16", "R17", "R18", "R19", "R20", "RP01", "RP02"]),
        ({"C12", "C15", "C18"}, ["R11", "R14", "R15"]),
    ],
)
def test_the_matrix_reads_the_answers(yes: set[str], rules: list[str]) -> None:
    answers = {q: q in yes for q in ESP_IA_QUESTIONS}
    assert [r.code for r in applicable_rules(answers)] == rules


def test_unknown_codes_are_listed_once() -> None:
    assert unknown_esp_ia_codes(["RFS-INJ-01", "RFS-ZZZ-01", "RFS-ZZZ-01"]) == ["RFS-ZZZ-01"]


# --- the battery ---------------------------------------------------------------------------


def test_the_battery_mapping_is_the_reviewed_one() -> None:
    found: dict[str, set[str]] = {}
    for spec in _battery().values():
        for code in spec.esp_ia or []:
            found.setdefault(code, set()).add(spec.id)
    assert found == _MAPPING
    assert not unknown_esp_ia_codes(found)
    assert not set(found) & (set(ESP_IA_OUT_OF_REACH) | set(ESP_IA_NOT_TESTED_BY_DESIGN))


def test_coverage_counts_19_of_27_and_says_why_for_the_rest() -> None:
    (axis,) = [a for a in build_battery_coverage(_battery().values()).axes if a.key == "esp_ia"]
    assert (axis.exercised, axis.total) == (19, 27)
    assert [c for c, _ in axis.missing] == ["RFS-EXT-01"]
    assert len(axis.out_of_reach) == 6
    assert [c for c, _, _ in axis.by_design] == ["RFS-EXH-02"]


# --- the lint ------------------------------------------------------------------------------


def test_an_unknown_requirement_is_refused(tmp_path: Path) -> None:
    errors = cast(list[LintError], _lint_with_iopc(tmp_path, "esp_ia: [RFS-ZZZ-01]\n", "espbad"))
    (refused,) = [e for e in errors if e.code is LintCode.UNKNOWN_FRAMEWORK_CODE]
    assert "'RFS-ZZZ-01' is not in the pinned CCN-STIC-2011 ESP-IA 1.0 table" in refused.message


def test_a_requirement_out_of_reach_is_refused(tmp_path: Path) -> None:
    errors = cast(
        list[LintError],
        _lint_with_iopc(tmp_path, "esp_ia: [RFS-TRA-01, RFS-EXH-02]\n", "espreach"),
    )
    refused = [e for e in errors if e.code is LintCode.FRAMEWORK_CLAIM_CONTRADICTED]
    assert [e.message.split("'")[1] for e in refused] == ["RFS-TRA-01", "RFS-EXH-02"]
    assert "out of reach" in refused[0].message
    assert "deliberately not tested" in refused[1].message


@pytest.mark.parametrize("bad", ["RFS-INJ-1", "rfs-inj-01", "RFS-INJ-10", "INJ-01"])
def test_a_malformed_requirement_is_refused_by_the_schema(tmp_path: Path, bad: str) -> None:
    errors = cast(list[LintError], _lint_with_iopc(tmp_path, f"esp_ia: ['{bad}']\n", "espshape"))
    assert any(e.code in (LintCode.SCHEMA, LintCode.PARSE_ERROR) for e in errors), errors


# --- where it shows, and where it does not -------------------------------------------------


def test_the_card_and_editions_carry_it() -> None:
    spec = _battery()["AC-BOLA-001"]
    assert (
        "esp_ia:      RFS-AGE-03 (T.AGENCY), RFS-AGE-05 (T.AGENCY), RFS-DIS-02 (T.DISCLOSURE)"
        in render_describe(spec)
    )
    assert framework_editions()["ccn_esp_ia"] == "1.0"
    assert "esp_ia:" not in render_describe(_battery()["SAFETY-HARMFUL-001"])


def test_a_requirement_is_no_part_of_the_spec_digest() -> None:
    spec = _battery()["PI-DIRECT-001"]
    assert spec_digest(spec) == spec_digest(spec.model_copy(update={"esp_ia": None}))
