"""MITRE CWE on a spec: the pinned table, the lint, SARIF, the card, the digest (u02 A-110).

``cwe`` names the weakness a FAIL of the spec is evidence of in the application. MITRE marks
each entry's mapping usage; the lint refuses a ``Discouraged`` or ``Prohibited`` one and warns
on one the pinned table does not know. The battery's mapping is pinned here, spec by spec, so a
change to it is a reviewed diff.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
import yaml

from ildottore.cli.describe import render_describe
from ildottore.registry import LintCode, LintError, Severity, lint
from ildottore.reporting.sarif_reporter import _rule
from ildottore.shared.cwe import (
    CWE_CODE_RE,
    CWE_ENTRIES,
    CWE_MAPPABLE_USAGES,
    cwe_sarif_tag,
    unknown_cwe_codes,
    unmappable_cwe_codes,
)
from ildottore.shared.digest import spec_digest
from ildottore.shared.frameworks import framework_editions
from ildottore.shared.models import AttackSpec
from tests.registry.test_linter import _iopc_spec, _lint_with_iopc

_BATTERY = Path(__file__).resolve().parents[2] / "src" / "ildottore" / "battery" / "attacks"

#: The battery's mapping, as reviewed on 2026-10-30 (ADR-0021, OD-66).
_MAPPING = {
    "CWE-1427": {
        "PI-DIRECT-001",
        "PI-INDIRECT-RAG-001",
        "PI-INDIRECT-TOOL-001",
        "PI-DELAYED-TRIGGER-001",
        "MEM-POISON-001",
        "MM-AUD-PROMPTINJECT-001",
        "MM-IMG-DOC-INJECT-001",
        "MM-IMG-PROMPTINJECT-001",
        "MM-IMG-SPLIT-PAYLOAD-001",
        "MM-IMG-TOOL-EXFIL-001",
        "AG-TOOLMETA-POISON-001",
        "MCP-TOOLPOISON-001",
        "AG-WORM-PROPAGATE-001",
        "AG-RECURSIVE-HIJACK-001",
        "AG-EXTORT-CHAIN-001",
        "AG-INTERAGENT-COMPROMISE-001",
    },
    "CWE-497": {
        "SP-LEAK-001",
        "AG-GOAL-THEFT-001",
        "RECON-SYSTEM-001",
        "RECON-MODEL-IDENTITY-001",
        "AC-DEBUG-001",
    },
    "CWE-489": {"AC-DEBUG-001"},
    "CWE-201": {
        "DL-SECRET-CANARY-001",
        "AG-CRED-SWEEP-001",
        "AG-EXFIL-EGRESS-001",
        "AG-TOOLCHAIN-EXFIL-001",
    },
    "CWE-359": {"DL-PII-ELICIT-001"},
    "CWE-488": {"DL-XSESSION-001"},
    "CWE-639": {"AC-BOLA-001"},
    "CWE-862": {
        "AC-BFLA-001",
        "AG-TOOL-UNAUTH-001",
        "DL-XTENANT-001",
        "EMB-XTENANT-RETRIEVAL-001",
        "EMB-NEIGHBOR-LEAK-001",
    },
    "CWE-266": {"AC-RBAC-001"},
    "CWE-290": {"AG-IDENTITY-ABUSE-001"},
    "CWE-451": {"AG-TRUST-APPROVAL-001"},
    "CWE-915": {"OUT-JSON-SCHEMA-COERCE-001", "FUNCALL-ARGSMUGGLE-001"},
    "CWE-94": {"AG-CODEEXEC-UNEXPECTED-001", "OUT-CODEINJ-001"},
    "CWE-78": {"OUT-SHELLI-001"},
    "CWE-89": {"OUT-SQLI-001", "FUNCALL-SQLI-ARG-001"},
    "CWE-79": {"OUT-XSS-001"},
    "CWE-770": {"DOS-TOKEN-AMP-001", "DOS-RESOURCE-HIJACK-001"},
    "CWE-918": {"AC-SSRF-001", "AC-SSRF-SCHEME-001"},
}


def _battery() -> dict[str, AttackSpec]:
    specs = (
        AttackSpec.model_validate(yaml.safe_load(p.read_text())) for p in _BATTERY.glob("*.yaml")
    )
    return {s.id: s for s in specs}


# --- the pinned table ---------------------------------------------------------------------


def test_the_table_holds_mitres_usages_only() -> None:
    usages = {usage for _, usage in CWE_ENTRIES.values()}
    assert usages <= {"Allowed", "Allowed-with-Review", "Discouraged", "Prohibited"}
    assert all(CWE_CODE_RE.match(code) for code in CWE_ENTRIES)
    assert CWE_ENTRIES["CWE-1427"][1] == "Allowed"
    assert (CWE_ENTRIES["CWE-1426"][1], CWE_ENTRIES["CWE-1446"][1]) == (
        "Discouraged",
        "Prohibited",
    )


def test_the_helpers_sort_known_unknown_and_unmappable() -> None:
    codes = ["CWE-1427", "CWE-1426", "CWE-123", "CWE-1426", "CWE-123"]
    assert unknown_cwe_codes(codes) == ["CWE-123"]
    assert unmappable_cwe_codes(codes) == [("CWE-1426", "Discouraged")]


@pytest.mark.parametrize(
    ("code", "tag"),
    [("CWE-79", "external/cwe/cwe-079"), ("CWE-1427", "external/cwe/cwe-1427")],
)
def test_the_sarif_tag_is_codeqls_shape(code: str, tag: str) -> None:
    assert cwe_sarif_tag(code) == tag


# --- the battery ---------------------------------------------------------------------------


def test_the_battery_mapping_is_the_reviewed_one() -> None:
    battery = _battery()
    found: dict[str, set[str]] = {}
    for spec in battery.values():
        for code in spec.cwe or []:
            found.setdefault(code, set()).add(spec.id)
    assert found == _MAPPING
    assert sum(1 for s in battery.values() if s.cwe) == 48
    assert all(
        CWE_ENTRIES[code][1] in CWE_MAPPABLE_USAGES
        for spec in battery.values()
        for code in spec.cwe or []
    )


# --- the lint ------------------------------------------------------------------------------


def test_a_discouraged_or_prohibited_cwe_is_refused(tmp_path: Path) -> None:
    errors = cast(
        list[LintError],
        _lint_with_iopc(tmp_path, "cwe: [CWE-1426, CWE-1446, CWE-1427]\n", "cwebad"),
    )
    refused = [e for e in errors if e.code is LintCode.FRAMEWORK_CLAIM_CONTRADICTED]
    assert [e.message.split("'")[1] for e in refused] == ["CWE-1426", "CWE-1446"]
    assert "is Discouraged for vulnerability mapping in MITRE CWE 5.0" in refused[0].message
    assert "is Prohibited" in refused[1].message
    assert all(e.severity is Severity.ERROR for e in refused)


def test_a_cwe_outside_the_table_is_a_warning(tmp_path: Path) -> None:
    pack = tmp_path / "cweunknown"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: cweunknown\npack_version: '1.0'\nname: cweunknown\n")
    (pack / "attacks" / "probe.yaml").write_text(_iopc_spec("cwe: [CWE-123, CWE-123]\n"))
    report = lint([pack])
    assert report.ok, report.errors
    (warned,) = [w for w in report.warnings if w.code is LintCode.UNKNOWN_FRAMEWORK_CODE]
    assert "'CWE-123' is not in the pinned MITRE CWE 5.0 table" in warned.message


@pytest.mark.parametrize("bad", ["CWE-079", "cwe-79", "CWE79", "79", "CWE-0"])
def test_a_malformed_cwe_is_refused_by_the_schema(tmp_path: Path, bad: str) -> None:
    errors = cast(list[LintError], _lint_with_iopc(tmp_path, f"cwe: ['{bad}']\n", "cweshape"))
    assert any(e.code in (LintCode.SCHEMA, LintCode.PARSE_ERROR) for e in errors), errors


# --- where it shows, and where it does not -------------------------------------------------


def test_sarif_card_and_editions_carry_it() -> None:
    spec = _battery()["AC-DEBUG-001"]
    tags = _rule(spec.id, spec)["properties"]["tags"]
    assert tags[-2:] == ["external/cwe/cwe-489", "external/cwe/cwe-497"]
    assert "cwe:         CWE-489 (Active Debug Code), CWE-497 (Exposure of Sensitive" in (
        render_describe(spec)
    )
    assert framework_editions()["mitre_cwe"] == "5.0"

    unmapped = _battery()["JB-ROLEPLAY-001"]
    assert not any(
        t.startswith("external/cwe/") for t in _rule(unmapped.id, unmapped)["properties"]["tags"]
    )
    assert "cwe:" not in render_describe(unmapped)


def test_a_cwe_is_no_part_of_the_spec_digest() -> None:
    spec = _battery()["PI-DIRECT-001"]
    assert spec_digest(spec) == spec_digest(spec.model_copy(update={"cwe": None}))
