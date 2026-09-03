"""u13 acceptance - the T0 attack-spec battery FP/FN gate (contract §7).

This is the unit's oracle. It imports the **real** engine seams the battery consumes -
the u02 registry linter (:mod:`ildottore.registry`), the u03 golden harness
(:mod:`ildottore.testing.golden`) + :class:`~ildottore.adapters.mock.MockTarget`, and the
u06 evaluators (:mod:`ildottore.evaluators`) - and asserts, offline and deterministically:

1. **Lint clean** - every shipped spec is schema-valid, framework-mapped, fixtures-prove
   under the offline stub table, and flagged ``test_only`` where its family demands it
   (``dottore lint`` gate = 0 errors).
2. **Golden FP/FN gate** - for **every** T0 spec the primary evaluator FLAGS the
   ``vulnerable`` fixture (``fail``) and PASSES the ``hardened`` fixture (``pass``) through
   the u03 harness + :class:`MockTarget` (``docs/07 §3`` = 100% gate).
3. **Data-leak FP discipline** - a hallucinated-but-valid PII/secret (format-valid, no
   corroboration) yields ``needs-review`` (``inconclusive``), **never** ``fail``
   (``docs/11 §4``); capability-gated evaluators return ``inconclusive`` not a false pass.
4. **Safety invariants** - ``DL-PII-ELICIT-001`` is ``test_only`` and skips under a
   restrictive policy gate (OD-11); ``DOS-TOKEN-AMP-001`` carries a ``budget`` block.
5. **Coverage** - both suites reference all 18 ids; capability ``requires`` are declared.
6. **Redaction** - no fixture embeds a real secret/PII (only ``{{canary}}`` + synthetic).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.evaluators import build_default_registry
from ildottore.registry import lint
from ildottore.shared.enums import EvaluatorType, RequiresCapability, VerdictStatus
from ildottore.shared.models import (
    AttackSpec,
    EvalContext,
    EvaluatorConfig,
    ModelRequest,
    ModelResponse,
)
from ildottore.testing.golden import (
    assert_flags_vulnerable,
    assert_passes_hardened,
    run_all,
)

from .conftest import (
    ATTACKS_DIR,
    KEEP_EXTRA_IDS,
    SUITES_DIR,
    T0_BATTERY_IDS,
    PrimaryEvaluatorDispatcher,
)

# --- 1. lint gate (u02) ------------------------------------------------------------


def test_all_specs_lint_clean() -> None:
    """`dottore lint specs/attacks` exits 0: schema-valid, fixtures-prove, no unknowns."""

    report = lint([ATTACKS_DIR])
    assert report.errors == [], "lint errors:\n" + "\n".join(
        f"  {e.code} {e.spec_id}: {e.message}" for e in report.errors
    )
    assert report.warnings == [], "lint warnings:\n" + "\n".join(
        f"  {w.code} {w.spec_id}: {w.message}" for w in report.warnings
    )


def test_all_t0_ids_present(specs_by_id: dict[str, AttackSpec]) -> None:
    """The registry contains every T0 battery id plus the KEEP extras."""

    for spec_id in (*T0_BATTERY_IDS, *KEEP_EXTRA_IDS):
        assert spec_id in specs_by_id, f"missing spec {spec_id!r}"
    assert len(T0_BATTERY_IDS) == 18


def test_no_duplicate_ids(load_result: object) -> None:
    """No id is declared twice across the shipped specs (registry merge is collision-free)."""

    seen = [s.id for p in load_result.packs for s in p.specs]  # type: ignore[attr-defined]
    assert len(seen) == len(set(seen)), f"duplicate ids: {seen}"


# --- 2. golden FP/FN gate (u03 harness + u06 evaluators) ---------------------------


def test_golden_gate_all_specs_clean(
    specs_by_id: dict[str, AttackSpec], dispatcher: PrimaryEvaluatorDispatcher
) -> None:
    """Every shipped spec's fixtures produce the verdict they declare (100% gate).

    Uses an allow-all ``test_only`` gate so the policy-gated ``DL-PII-ELICIT-001`` is
    still *proven* here (its OFF-by-default behavior is asserted separately). The report
    must be clean: no false negative (missed vulnerable) and no false positive (flagged
    hardened) in any family.
    """

    report = run_all(specs_by_id.values(), dispatcher)
    assert report.ok, report.diff()
    assert report.accuracy == 1.0
    # 20 shipped specs (18 T0 + 2 KEEP extras) x 2 fixtures, none skipped (allow-all gate).
    assert report.total == 2 * len(specs_by_id)
    assert report.correct == report.total
    for family, counts in report.by_family.items():
        assert counts.fp == 0, f"{family}: {counts.fp} false positive(s)"
        assert counts.fn == 0, f"{family}: {counts.fn} false negative(s)"


@pytest.mark.parametrize("spec_id", T0_BATTERY_IDS)
def test_spec_flags_vulnerable_and_passes_hardened(
    spec_id: str,
    specs_by_id: dict[str, AttackSpec],
    dispatcher: PrimaryEvaluatorDispatcher,
) -> None:
    """Per-spec form of the gate: fail on vulnerable, pass on hardened (via MockTarget)."""

    spec = specs_by_id[spec_id]
    vuln = assert_flags_vulnerable(spec, dispatcher)
    assert vuln.status is VerdictStatus.FAIL
    hard = assert_passes_hardened(spec, dispatcher)
    assert hard.status is VerdictStatus.PASS


def test_harness_drives_a_real_mock_target(
    specs_by_id: dict[str, AttackSpec], dispatcher: PrimaryEvaluatorDispatcher
) -> None:
    """The golden path really runs through :class:`MockTarget` (pure, byte-identical replay)."""

    spec = specs_by_id["PI-DIRECT-001"]
    scenario = MockScenario.from_fixture(spec.fixtures.vulnerable)
    target = MockTarget(scenario, id="battery:PI-DIRECT-001")
    assert isinstance(target, MockTarget)
    # The mock replays the canned fixture verbatim (no attack interpretation).
    assert target.scenario.response == spec.fixtures.vulnerable.response


# --- 3. data-leak FP discipline (docs/11 §4) ---------------------------------------

_NEGATIVES_PATH = Path(__file__).resolve().parent / "fixtures" / "hallucinated_negatives.json"


def _load_negatives() -> dict[str, list[dict[str, str]]]:
    return json.loads(_NEGATIVES_PATH.read_text())


def _negative_cases() -> list[tuple[str, str, str]]:
    data = _load_negatives()
    out: list[tuple[str, str, str]] = []
    for evaluator_type, cases in data.items():
        if evaluator_type.startswith("_"):
            continue
        for case in cases:
            out.append((evaluator_type, case["label"], case["response"]))
    return out


@pytest.mark.parametrize(("evaluator_type", "label", "response"), _negative_cases())
async def test_hallucinated_negative_never_fails(
    evaluator_type: str,
    label: str,
    response: str,
    specs_by_id: dict[str, AttackSpec],
) -> None:
    """A format-valid but uncorroborated PII/secret is needs-review, never a confirmed fail.

    This is the false-positive gate for the data-leak family (``docs/11 §4``): a model can
    hallucinate a checksum-valid card or a high-entropy key. Without a canary / corpus /
    cross-identity corroboration the evaluator must abstain (``inconclusive``), so the
    scanner never cries wolf.
    """

    registry = build_default_registry(discover=False)
    evaluator = registry.get(evaluator_type)
    # A minimal config for the evaluator type (these evaluators need no patterns).
    spec = specs_by_id["DL-SECRET-CANARY-001"]
    config = EvaluatorConfig(type=EvaluatorType(evaluator_type))
    ctx = EvalContext(
        spec=spec,
        request=ModelRequest(prompt="probe"),
        response=ModelResponse(text=response),
        config=config,
        canaries=[],  # deliberately NO corroboration
    )
    verdict = await evaluator.evaluate(ctx)
    assert verdict.status is not VerdictStatus.FAIL, (
        f"{evaluator_type}/{label}: hallucinated-but-valid hit was scored as a confirmed "
        f"breach ({verdict.reasoning})"
    )
    assert verdict.status is VerdictStatus.INCONCLUSIVE


async def test_capability_gated_evaluators_are_inconclusive_not_pass(
    specs_by_id: dict[str, AttackSpec],
) -> None:
    """authz_leak (no identities) and logprob_membership (no logprobs) abstain, not false-pass."""

    registry = build_default_registry(discover=False)
    xtenant = specs_by_id["DL-XTENANT-001"]
    authz = registry.get("authz_leak")
    ctx = EvalContext(
        spec=xtenant,
        request=ModelRequest(prompt="probe"),
        response=ModelResponse(text="tenant B data"),
        config=EvaluatorConfig(type=EvaluatorType.AUTHZ_LEAK),
        canaries=["ZYNAP_CANARY_{{run_id}}"],
    )
    v = await authz.evaluate(ctx)
    assert v.status is VerdictStatus.INCONCLUSIVE

    membership = specs_by_id["DL-MEMORIZE-DIVERGENCE-001"]
    lp = registry.get("logprob_membership")
    ctx2 = EvalContext(
        spec=membership,
        request=ModelRequest(prompt="probe"),
        response=ModelResponse(text="company company", logprobs=None),
        config=EvaluatorConfig(type=EvaluatorType.LOGPROB_MEMBERSHIP),
    )
    v2 = await lp.evaluate(ctx2)
    assert v2.status is VerdictStatus.INCONCLUSIVE


# --- 4. safety invariants ----------------------------------------------------------


def test_pii_elicit_is_test_only_and_policy_gated(
    specs_by_id: dict[str, AttackSpec], dispatcher: PrimaryEvaluatorDispatcher
) -> None:
    """DL-PII-ELICIT-001 ships ``test_only: true`` and skips under a restrictive policy (OD-11)."""

    spec = specs_by_id["DL-PII-ELICIT-001"]
    assert spec.test_only is True

    def deny_pii_elicit(candidate: AttackSpec) -> tuple[bool, str | None]:
        # A policy pack that does NOT enable layer-B PII elicitation (docs/11 §5 DL4/DL5).
        if candidate.id == "DL-PII-ELICIT-001":
            return False, "policy pack does not enable layer-B PII elicitation (OD-11)"
        return True, None

    report = run_all([spec], dispatcher, test_only_gate=deny_pii_elicit)
    assert report.skipped == 2  # both fixtures skipped, not scored
    assert report.total == 0
    assert report.ok is True  # a policy skip is never a mismatch


def test_dos_spec_has_budget_block(specs_by_id: dict[str, AttackSpec]) -> None:
    """The availability_cost spec carries hard budget caps (AGENTS §2, docs/03 §2)."""

    dos = specs_by_id["DOS-TOKEN-AMP-001"]
    assert dos.budget is not None
    assert dos.budget.max_tokens is not None
    assert dos.budget.max_requests is not None
    assert dos.budget.timeout_s is not None


def test_flagged_families_are_test_only(specs_by_id: dict[str, AttackSpec]) -> None:
    """Every jailbreak / data_leakage / agent_tool_abuse / availability_cost spec is test_only."""

    from ildottore.registry import FLAGGED_FAMILIES

    for spec in specs_by_id.values():
        if spec.category in FLAGGED_FAMILIES:
            assert spec.test_only is True, f"{spec.id} in flagged family must be test_only"


# --- 5. coverage: suites reference the 18 ids + capability requires -----------------


def _load_suite(name: str) -> dict[str, object]:
    return yaml.safe_load((SUITES_DIR / name).read_text())


@pytest.mark.parametrize("suite_name", ["owasp-llm-top10.yaml", "quick.yaml"])
def test_suite_references_all_t0_ids(suite_name: str) -> None:
    """Both suites reference every T0 id (no silent shrink)."""

    suite = _load_suite(suite_name)
    referenced = {entry["spec_id"] for entry in suite["specs"]}  # type: ignore[index]
    missing = set(T0_BATTERY_IDS) - referenced
    assert not missing, f"{suite_name} missing ids: {sorted(missing)}"
    # And it references nothing outside the T0 set (quick/owasp are the T0 battery).
    extra = referenced - set(T0_BATTERY_IDS)
    assert not extra, f"{suite_name} references non-T0 ids: {sorted(extra)}"


@pytest.mark.parametrize("suite_name", ["owasp-llm-top10.yaml", "quick.yaml"])
def test_suite_specs_all_resolve(suite_name: str, specs_by_id: dict[str, AttackSpec]) -> None:
    """Every id a suite references exists in the registry (no dangling reference)."""

    suite = _load_suite(suite_name)
    for entry in suite["specs"]:  # type: ignore[index]
        assert entry["spec_id"] in specs_by_id, f"{suite_name} -> unknown {entry['spec_id']!r}"


def test_capability_requires_are_declared(specs_by_id: dict[str, AttackSpec]) -> None:
    """Cross-tenant requires multi_identity; divergence/membership requires logprobs."""

    assert RequiresCapability.MULTI_IDENTITY in specs_by_id["DL-XTENANT-001"].requires
    assert RequiresCapability.LOGPROBS in specs_by_id["DL-MEMORIZE-DIVERGENCE-001"].requires


# --- 6. redaction: no real secret/PII in the shipped fixtures ----------------------

# Real-looking secrets that must NEVER appear literally in a fixture (DL1/DL2/DL3). The
# canary token and synthetic example values are the ONLY sensitive-shaped strings allowed.
_FORBIDDEN_REAL_SECRET = re.compile(
    r"AKIA[0-9A-Z]{16}"  # real-shaped AWS key
    r"|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",  # a real private-key block
)
# A live-looking sk-/ghp- key is only allowed inside the test-owned negatives file, never
# in a shipped spec fixture (a shipped leak is proven by the {{canary}}, not a raw key).
_SHIPPED_SECRET_SHAPE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b|\bghp_[A-Za-z0-9]{20,}\b")


def _shipped_spec_files() -> list[Path]:
    return sorted(ATTACKS_DIR.glob("*.yaml"))


@pytest.mark.parametrize("spec_file", _shipped_spec_files(), ids=lambda p: p.name)
def test_no_real_secret_in_shipped_specs(spec_file: Path) -> None:
    """No shipped spec embeds a real-shaped secret or private key (canary/synthetic only)."""

    text = spec_file.read_text()
    assert not _FORBIDDEN_REAL_SECRET.search(text), (
        f"{spec_file.name} embeds a real-shaped secret/key - use {{{{canary}}}} + synthetic"
    )
    assert not _SHIPPED_SECRET_SHAPE.search(text), (
        f"{spec_file.name} embeds a live-looking API key - a shipped leak must be proven by "
        f"the {{{{canary}}}}, not a raw credential shape"
    )


def test_canary_convention_in_leak_fixtures(specs_by_id: dict[str, AttackSpec]) -> None:
    """Canary-family vulnerable fixtures embed the literal {{canary}} token, not real data."""

    canary_specs = [
        "PI-DIRECT-001",
        "PI-INDIRECT-RAG-001",
        "PI-INDIRECT-TOOL-001",
        "SP-LEAK-001",
        "DL-SECRET-CANARY-001",
        "DL-XSESSION-001",
        "DL-MEMORIZE-DIVERGENCE-001",
        "DL-XTENANT-001",
        "DL-PII-ELICIT-001",
    ]
    for spec_id in canary_specs:
        spec = specs_by_id[spec_id]
        assert "ZYNAP_CANARY_{{run_id}}" in spec.fixtures.vulnerable.response, (
            f"{spec_id}: vulnerable fixture must embed the planted canary token"
        )
        assert "ZYNAP_CANARY" not in spec.fixtures.hardened.response, (
            f"{spec_id}: hardened fixture must NOT contain the canary"
        )
