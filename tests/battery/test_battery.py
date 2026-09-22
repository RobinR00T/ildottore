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


# --- 7. IoPC mapping: optional in the schema, REQUIRED for the shipped battery -------

#: The one documented exemption. IoPC is a prompt-compromise taxonomy: it has a technique axis
#: and an impact axis, and neither has a fairness dimension. Mapping a demographic-bias spec to
#: any IoPC code would be a fabricated mapping, which is worse than an honest gap.
_IOPC_EXEMPT: frozenset[str] = frozenset({"BIAS-STEREOTYPE-001"})


def test_every_shipped_spec_carries_an_iopc_mapping(
    specs_by_id: dict[str, AttackSpec],
) -> None:
    """The `iopc` field is optional in the JSON schema so third-party spec packs keep
    validating, but OUR battery must be fully mapped or the coverage percentage lies.

    A spec may map on either axis: the responsible-AI safety specs legitimately carry only an
    impact code, because they assert a class of harm rather than an attack technique.
    """

    unmapped = [
        spec_id
        for spec_id, spec in specs_by_id.items()
        if spec_id not in _IOPC_EXEMPT
        and (spec.iopc is None or not (spec.iopc.techniques or spec.iopc.impacts))
    ]
    assert not unmapped, f"specs with no IoPC mapping: {sorted(unmapped)}"


def test_iopc_exemptions_are_real_specs_and_stay_small(
    specs_by_id: dict[str, AttackSpec],
) -> None:
    """An exemption list is a place for gaps to hide, so it is pinned and justified."""

    for spec_id in _IOPC_EXEMPT:
        assert spec_id in specs_by_id, (
            f"stale IoPC exemption for a spec that no longer exists: {spec_id}"
        )
        assert specs_by_id[spec_id].category.value == "bias_fairness"


def test_shipped_iopc_codes_all_exist_in_the_pinned_taxonomy(
    specs_by_id: dict[str, AttackSpec],
) -> None:
    """No well-formed-but-non-existent code: it would match nothing and shrink coverage."""

    from ildottore.shared.iopc import unknown_codes

    offenders = {
        spec_id: unknown_codes(spec.iopc.techniques, spec.iopc.impacts)
        for spec_id, spec in specs_by_id.items()
        if spec.iopc is not None and unknown_codes(spec.iopc.techniques, spec.iopc.impacts)
    }
    assert not offenders, f"IoPC codes outside the pinned taxonomy: {offenders}"


def test_shipped_owasp_and_atlas_values_all_exist_in_their_universes(
    specs_by_id: dict[str, AttackSpec],
) -> None:
    """The same invariant IoPC already had, for the two older axes that had none.

    OWASP and ATLAS were validated by nothing in either direction: ``owasp: LLM11``,
    ``tactic: "initial access"`` and the retired ``tactic: "ML Attack Staging"`` all passed
    lint with zero warnings, contributed nothing to the numerator and told nobody. Coverage
    matches by exact string, so an upstream **rename** is as damaging as a typo, and two of
    our specs scored zero for months for exactly that reason.
    """

    from ildottore.shared.frameworks import unknown_atlas_tactic, unknown_owasp_code

    bad_owasp = {
        spec_id: spec.owasp
        for spec_id, spec in specs_by_id.items()
        if unknown_owasp_code(spec.owasp) is not None
    }
    bad_tactics = {
        spec_id: spec.mitre_atlas.tactic
        for spec_id, spec in specs_by_id.items()
        if unknown_atlas_tactic(spec.mitre_atlas.tactic) is not None
    }
    assert not bad_owasp, f"owasp codes outside the pinned universes: {bad_owasp}"
    assert not bad_tactics, f"ATLAS tactics outside the pinned matrix: {bad_tactics}"


def test_coverage_numerators_are_subsets_of_their_denominators(
    specs_by_id: dict[str, AttackSpec],
) -> None:
    """No axis may count a value its own universe does not contain.

    This is the shape that produced three wrong published figures in three days: an IoPC axis
    crediting codes the specs did not exercise, an OWASP numerator counting Responsible-AI
    codes (a false 100% while two categories were untested), and an ATLAS numerator matching
    against a stale name list. A percentage can therefore never exceed 100%.

    The universes are read from where they are **pinned**, not from the output being checked.
    A first version of this test built ``universe = covered | missing`` out of the very axis
    it was asserting about, which made ``covered <= universe`` a tautology: it passed for any
    output whatsoever, which is precisely the kind of test that let these defects ship.
    """

    from ildottore.reporting.summary import build_battery_coverage
    from ildottore.shared.frameworks import ATLAS_TACTIC_UNIVERSE, OWASP_LLM_UNIVERSE
    from ildottore.shared.iopc import IOPC_IMPACT_UNIVERSE, IOPC_TECHNIQUE_UNIVERSE

    pinned = {
        "owasp": OWASP_LLM_UNIVERSE,
        "atlas": ATLAS_TACTIC_UNIVERSE,
        "iopc_techniques": IOPC_TECHNIQUE_UNIVERSE,
        "iopc_impacts": IOPC_IMPACT_UNIVERSE,
    }
    coverage = build_battery_coverage(list(specs_by_id.values()))
    assert {a.key for a in coverage.axes} == set(pinned), "an axis appeared or vanished"
    for axis in coverage.axes:
        universe = set(pinned[axis.key])
        covered = {code for code, _ in axis.covered}
        assert covered <= universe, f"{axis.key}: numerator outside its pinned universe"
        assert axis.total == len(universe), f"{axis.key}: denominator is not the universe"
        assert axis.exercised == len(covered)
        assert 0.0 <= axis.pct <= 1.0
    assert not coverage.off_universe, (
        f"shipped specs carry uncounted framework values: {coverage.off_universe}"
    )


@pytest.mark.parametrize(
    "name",
    ["OWASP_LLM_UNIVERSE", "OWASP_RAI_UNIVERSE", "ATLAS_TACTIC_UNIVERSE", "ATLAS_OUT_OF_MATRIX"],
)
def test_pinned_universes_are_duplicate_free(name: str) -> None:
    """A duplicated entry inflates a denominator, and every existing test would still pass.

    ``atlas_total == len(ATLAS_TACTIC_UNIVERSE)`` is a tautology: it holds with a duplicate in
    the tuple. These are hand-maintained lists transcribed from upstream, so the duplicate is
    a realistic slip, and its effect is a quietly smaller percentage.
    """

    from ildottore.shared import frameworks

    universe: tuple[str, ...] = getattr(frameworks, name)
    assert len(universe) == len(set(universe)), f"{name} has duplicates"


def test_a_duplicated_universe_entry_cannot_inflate_a_denominator() -> None:
    """And the axis builder de-duplicates, so a slip cannot reach a published figure."""

    from ildottore.reporting.summary import _axis

    axis = _axis("demo", "demo", ("Execution", "Execution", "Impact"), {"Execution"})
    assert (axis.exercised, axis.total) == (1, 2)


def test_a_repeated_spec_is_counted_once(specs_by_id: dict[str, AttackSpec]) -> None:
    """ "72 specs" must mean 72 distinct specs: a suite may list the same id twice."""

    from ildottore.reporting.summary import build_battery_coverage

    one = list(specs_by_id.values())[:3]
    assert build_battery_coverage(one + one + one).specs == 3


def test_shipped_nist_mappings_are_well_formed(specs_by_id: dict[str, AttackSpec]) -> None:
    """Every spec's ``nist_ai_rmf`` carries a parseable ``FUNCTION n.n`` token.

    A shape check, not a membership one: the NIST AI RMF subcategory list is not transcribed
    in this repo, so "this subcategory exists" is not a claim we can make. The field feeds a
    rollup and a SARIF tag and never a denominator, so a bad value cannot move a percentage;
    what it can do is fragment the rollup silently, which is what this catches.
    """

    from ildottore.shared.frameworks import malformed_nist_mapping, nist_subcategories

    offenders = {
        spec_id: spec.nist_ai_rmf
        for spec_id, spec in specs_by_id.items()
        if malformed_nist_mapping(spec.nist_ai_rmf) is not None
    }
    assert not offenders, f"nist_ai_rmf values with no well-formed subcategory: {offenders}"

    # And the tokens really do parse into the four functions, so the rollup keys are stable.
    functions = {
        token.split()[0]
        for spec in specs_by_id.values()
        for token in nist_subcategories(spec.nist_ai_rmf)
    }
    assert functions <= {"GOVERN", "MAP", "MEASURE", "MANAGE"}, functions
