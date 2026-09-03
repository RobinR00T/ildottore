"""Acceptance for the OWASP LLM08 "Vector & Embedding Weaknesses" spec family.

Declarative-only extension (docs/03, docs/08 §4, docs/11): three new attack specs -
``EMB-XTENANT-RETRIEVAL-001`` (cross-tenant vector-store retrieval leak), ``EMB-INVERSION-
PROBE-001`` (embedding-inversion / verbatim source reconstruction) and ``EMB-NEIGHBOR-LEAK-
001`` (neighbor-document / corpus-index enumeration) - plus the ``embeddings`` suite that
references them. No new evaluator type: all three reuse ``secret_leakage`` (planted canary),
``authz_leak`` and ``semantic_judge`` exactly as ``docs/04`` defines them.

This mirrors ``tests/battery/test_battery.py``'s method (real registry loader, real u06
evaluators, u03 golden harness) but scopes assertions to the three new ids specifically, so a
regression here points straight at this family rather than the whole shipped battery.
"""

from __future__ import annotations

import yaml

from ildottore.shared.enums import (
    Category,
    RequiresCapability,
    TargetType,
    VerdictStatus,
)
from ildottore.shared.models import AttackSpec
from ildottore.testing.golden import assert_flags_vulnerable, assert_passes_hardened

from .conftest import SUITES_DIR, PrimaryEvaluatorDispatcher

EMB_LLM08_IDS: tuple[str, ...] = (
    "EMB-XTENANT-RETRIEVAL-001",
    "EMB-INVERSION-PROBE-001",
    "EMB-NEIGHBOR-LEAK-001",
)


# --- shape: category / owasp / target_type / requires per the brief -----------------


def test_emb_ids_are_present(specs_by_id: dict[str, AttackSpec]) -> None:
    for spec_id in EMB_LLM08_IDS:
        assert spec_id in specs_by_id, f"{spec_id} not found in the loaded registry"


def test_emb_specs_are_owasp_llm08_rag(specs_by_id: dict[str, AttackSpec]) -> None:
    """Every EMB-* spec targets LLM08 over a RAG target with the `rag` capability declared."""

    for spec_id in EMB_LLM08_IDS:
        spec = specs_by_id[spec_id]
        assert spec.owasp == "LLM08", f"{spec_id}: expected owasp LLM08, got {spec.owasp!r}"
        assert spec.category in (Category.RAG_SECURITY, Category.DATA_LEAKAGE), (
            f"{spec_id}: expected rag_security or data_leakage, got {spec.category.value!r}"
        )
        assert spec.target_type is TargetType.RAG, f"{spec_id}: expected target_type rag"
        assert RequiresCapability.RAG in spec.requires, f"{spec_id}: must require 'rag'"


def test_emb_specs_use_only_existing_evaluator_types(specs_by_id: dict[str, AttackSpec]) -> None:
    """No new evaluator type: only secret_leakage / authz_leak / semantic_judge appear."""

    allowed = {"secret_leakage", "authz_leak", "semantic_judge"}
    for spec_id in EMB_LLM08_IDS:
        spec = specs_by_id[spec_id]
        used = {cfg.type.value for cfg in spec.evaluators}
        assert used <= allowed, f"{spec_id}: unexpected evaluator type(s) {used - allowed}"
        # Primary evaluator is the deterministic canary check - offline-provable and
        # capability-independent (the u03 harness only drives evaluators[0]).
        assert spec.evaluators[0].type.value == "secret_leakage", (
            f"{spec_id}: primary evaluator must be secret_leakage for the golden gate"
        )


def test_emb_specs_are_safe_by_design(specs_by_id: dict[str, AttackSpec]) -> None:
    """Planted canary + synthetic setup only - no real data (docs/11 DL1/DL2)."""

    for spec_id in EMB_LLM08_IDS:
        spec = specs_by_id[spec_id]
        assert spec.setup is not None and spec.setup.canaries, f"{spec_id}: needs a canary"
        assert spec.setup.canaries == ["ZYNAP_CANARY_{{run_id}}"], (
            f"{spec_id}: must use the standard planted-canary convention"
        )


# --- golden gate: fail on vulnerable, pass on hardened (real evaluators) ------------


def test_emb_flags_vulnerable_and_passes_hardened(
    specs_by_id: dict[str, AttackSpec], dispatcher: PrimaryEvaluatorDispatcher
) -> None:
    for spec_id in EMB_LLM08_IDS:
        spec = specs_by_id[spec_id]
        vuln = assert_flags_vulnerable(spec, dispatcher)
        assert vuln.status is VerdictStatus.FAIL
        hard = assert_passes_hardened(spec, dispatcher)
        assert hard.status is VerdictStatus.PASS


def test_emb_hardened_fixture_never_contains_the_canary(specs_by_id: dict[str, AttackSpec]) -> None:
    for spec_id in EMB_LLM08_IDS:
        spec = specs_by_id[spec_id]
        assert "ZYNAP_CANARY" not in spec.fixtures.hardened.response, (
            f"{spec_id}: hardened fixture must not contain the canary"
        )
        assert "ZYNAP_CANARY_{{run_id}}" in spec.fixtures.vulnerable.response, (
            f"{spec_id}: vulnerable fixture must embed the planted canary token"
        )


# --- suite wiring --------------------------------------------------------------------


def test_embeddings_suite_references_the_three_ids() -> None:
    suite = yaml.safe_load((SUITES_DIR / "embeddings.yaml").read_text())
    referenced = {entry["spec_id"] for entry in suite["specs"]}
    assert referenced == set(EMB_LLM08_IDS)


def test_embeddings_suite_specs_all_resolve(specs_by_id: dict[str, AttackSpec]) -> None:
    suite = yaml.safe_load((SUITES_DIR / "embeddings.yaml").read_text())
    for entry in suite["specs"]:
        assert entry["spec_id"] in specs_by_id, f"embeddings.yaml -> unknown {entry['spec_id']!r}"


def test_owasp_and_quick_suites_untouched_by_the_new_family() -> None:
    """The frozen T0 suites (docs/08 §3) must not silently absorb the new LLM08 ids."""

    for suite_name in ("owasp-llm-top10.yaml", "quick.yaml"):
        suite = yaml.safe_load((SUITES_DIR / suite_name).read_text())
        referenced = {entry["spec_id"] for entry in suite["specs"]}
        overlap = referenced & set(EMB_LLM08_IDS)
        assert not overlap, f"{suite_name} must not reference EMB-* ids: {overlap}"
