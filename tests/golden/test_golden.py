"""u03 golden-harness runner tests - fixtures, verdicts, accuracy gate, policy.

Covers contract §7 acceptance for :mod:`ildottore.testing.golden`:
* ``load_fixtures`` resolves inline fixtures into replayable scenarios,
* ``run_spec`` drives the mock target through the injected (stub) evaluator,
* the assertion helpers flag/pass the right scenarios,
* ``run_all`` returns accuracy ``1.0`` on matches and **exits non-zero**
  (``GoldenReport.ok is False`` with a populated ``mismatches`` diff) on an
  injected wrong verdict (``docs/07 §3`` = 100% gate),
* capability honesty yields ``inconclusive: capability_unavailable`` - never a
  fabricated ``pass``,
* the ``test_only`` policy gate skips (and records the reason) rather than dropping.

The evaluator is the in-test :class:`~tests.golden.conftest.StubEvaluator` (the real
pipeline is u06, injected via the ``Evaluator`` protocol - contract §3/§8).
"""

from __future__ import annotations

import pytest

from ildottore.adapters.mock import MockScenario
from ildottore.shared.enums import Category, InconclusiveReason, VerdictStatus
from ildottore.testing.golden import (
    FixturePair,
    GoldenReport,
    Mismatch,
    ScenarioResult,
    assert_flags_vulnerable,
    assert_passes_hardened,
    load_fixtures,
    run_all,
    run_spec,
)

from .conftest import LEAK_MARKER, SpecFactory, StubEvaluator

# --- fixture resolution ------------------------------------------------------------


def test_load_fixtures_resolves_both_scenarios(make_spec: SpecFactory) -> None:
    spec = make_spec()
    pair = load_fixtures(spec)
    assert isinstance(pair, FixturePair)
    assert LEAK_MARKER in pair.vulnerable.response
    assert LEAK_MARKER not in pair.hardened.response


def test_load_fixtures_maps_requires_to_capabilities(make_spec: SpecFactory) -> None:
    """A spec's ``requires`` become the mock's declared capabilities."""

    spec = make_spec(requires=["tools", "rag"])
    pair = load_fixtures(spec)
    assert pair.vulnerable.capabilities.tools is True
    assert pair.vulnerable.capabilities.rag is True
    assert pair.vulnerable.capabilities.logprobs is False


# --- run_spec ----------------------------------------------------------------------


async def test_run_spec_flags_vulnerable(make_spec: SpecFactory) -> None:
    spec = make_spec()
    verdict = await run_spec(spec, "vulnerable", StubEvaluator())
    assert verdict.status is VerdictStatus.FAIL


async def test_run_spec_passes_hardened(make_spec: SpecFactory) -> None:
    spec = make_spec()
    verdict = await run_spec(spec, "hardened", StubEvaluator())
    assert verdict.status is VerdictStatus.PASS


async def test_run_spec_accepts_prebuilt_fixtures(make_spec: SpecFactory) -> None:
    """Passing ``fixtures`` bypasses re-resolution (used for capability tests)."""

    spec = make_spec()
    pair = FixturePair(
        vulnerable=MockScenario(response=f"leaked {LEAK_MARKER}"),
        hardened=MockScenario(response="refused"),
    )
    verdict = await run_spec(spec, "vulnerable", StubEvaluator(), fixtures=pair)
    assert verdict.status is VerdictStatus.FAIL


async def test_run_spec_builds_request_from_turns(make_spec: SpecFactory) -> None:
    """A multi-turn attack still drives cleanly (request carries messages)."""

    from ildottore.shared.models import Attack

    spec = make_spec()
    spec = spec.model_copy(update={"attack": Attack(turns=["hi", f"now {LEAK_MARKER}"])})
    verdict = await run_spec(spec, "vulnerable", StubEvaluator())
    assert verdict.status is VerdictStatus.FAIL


# --- capability honesty (contract §3/§7) -------------------------------------------


async def test_capability_unavailable_never_fabricates_pass(make_spec: SpecFactory) -> None:
    """A spec requiring an absent capability yields inconclusive, not pass."""

    spec = make_spec(requires=["logprobs"])
    # Hand-build fixtures whose scenarios do NOT declare the required capability.
    pair = FixturePair(
        vulnerable=MockScenario(response=f"x {LEAK_MARKER}"),
        hardened=MockScenario(response="safe"),
    )
    verdict = await run_spec(spec, "hardened", StubEvaluator(), fixtures=pair)
    assert verdict.status is VerdictStatus.INCONCLUSIVE
    assert verdict.inconclusive_reason is InconclusiveReason.CAPABILITY_UNAVAILABLE
    assert "logprobs" in verdict.reasoning


# --- assertion helpers -------------------------------------------------------------


def test_assert_flags_vulnerable_ok(make_spec: SpecFactory) -> None:
    verdict = assert_flags_vulnerable(make_spec(), StubEvaluator())
    assert verdict.status is VerdictStatus.FAIL


def test_assert_passes_hardened_ok(make_spec: SpecFactory) -> None:
    verdict = assert_passes_hardened(make_spec(), StubEvaluator())
    assert verdict.status is VerdictStatus.PASS


def test_assert_flags_vulnerable_raises_on_wrong_verdict(
    make_spec: SpecFactory, inverted_evaluator: object
) -> None:
    with pytest.raises(AssertionError, match="expected 'fail'"):
        assert_flags_vulnerable(make_spec(), inverted_evaluator)  # type: ignore[arg-type]


def test_assert_passes_hardened_raises_on_wrong_verdict(
    make_spec: SpecFactory, inverted_evaluator: object
) -> None:
    with pytest.raises(AssertionError, match="expected 'pass'"):
        assert_passes_hardened(make_spec(), inverted_evaluator)  # type: ignore[arg-type]


# --- run_all: the 100% accuracy gate -----------------------------------------------


def test_run_all_clean_is_accuracy_one(make_spec: SpecFactory) -> None:
    specs = [make_spec(spec_id="JB-A-001"), make_spec(spec_id="JB-A-002")]
    report = run_all(specs, StubEvaluator())
    assert isinstance(report, GoldenReport)
    assert report.total == 4  # 2 specs x 2 fixtures
    assert report.correct == 4
    assert report.accuracy == 1.0
    assert report.ok is True
    assert report.mismatches == []
    assert report.diff() == ""


def test_run_all_empty_specs_is_ok() -> None:
    report = run_all([], StubEvaluator())
    assert report.total == 0
    assert report.accuracy == 1.0  # vacuously clean
    assert report.ok is True


def test_run_all_wrong_verdict_fails_gate(
    make_spec: SpecFactory, inverted_evaluator: object
) -> None:
    """Injected wrong verdicts → ok False, populated mismatches, non-empty diff."""

    specs = [make_spec(spec_id="JB-B-001")]
    report = run_all(specs, inverted_evaluator)  # type: ignore[arg-type]
    assert report.ok is False
    assert report.accuracy == 0.0
    assert len(report.mismatches) == 2  # both scenarios flip
    diff = report.diff()
    assert "JB-B-001" in diff
    assert "mismatch" in diff


def test_run_all_classifies_fp_and_fn(make_spec: SpecFactory, inverted_evaluator: object) -> None:
    """Hardened→fail is a false positive; vulnerable→pass is a false negative."""

    spec = make_spec(spec_id="JB-C-001", category=Category.JAILBREAK)
    report = run_all([spec], inverted_evaluator)  # type: ignore[arg-type]
    family = report.by_family[Category.JAILBREAK.value]
    assert family.n == 2
    assert family.fp == 1
    assert family.fn == 1


def test_run_all_per_family_tally(make_spec: SpecFactory) -> None:
    specs = [
        make_spec(spec_id="JB-D-001", category=Category.JAILBREAK),
        make_spec(spec_id="PI-D-001", category=Category.PROMPT_INJECTION),
    ]
    report = run_all(specs, StubEvaluator())
    assert report.by_family[Category.JAILBREAK.value].n == 2
    assert report.by_family[Category.PROMPT_INJECTION.value].n == 2
    assert report.by_family[Category.JAILBREAK.value].fp == 0
    assert report.by_family[Category.JAILBREAK.value].fn == 0


# --- test_only policy gate (contract §5 step 4) ------------------------------------


def test_test_only_spec_skipped_when_gate_denies(make_spec: SpecFactory) -> None:
    spec = make_spec(spec_id="JB-E-001", test_only=True)

    def deny(_spec: object) -> tuple[bool, str | None]:
        return False, "pack does not enable test_only specs"

    report = run_all([spec], StubEvaluator(), test_only_gate=deny)
    assert report.skipped == 2  # both scenarios skipped
    assert report.total == 0  # excluded from the accuracy denominator
    assert report.ok is True  # skips are not mismatches


def test_test_only_spec_runs_when_gate_allows(make_spec: SpecFactory) -> None:
    spec = make_spec(spec_id="JB-F-001", test_only=True)

    def allow(_spec: object) -> tuple[bool, str | None]:
        return True, None

    report = run_all([spec], StubEvaluator(), test_only_gate=allow)
    assert report.skipped == 0
    assert report.total == 2
    assert report.ok is True


def test_test_only_default_gate_allows(make_spec: SpecFactory) -> None:
    """With no gate injected, a test_only spec runs (allow-all default)."""

    spec = make_spec(spec_id="JB-G-001", test_only=True)
    report = run_all([spec], StubEvaluator())
    assert report.skipped == 0
    assert report.total == 2


# --- report model surface ----------------------------------------------------------


def test_scenario_result_matched_property(make_spec: SpecFactory) -> None:
    from ildottore.shared.models import Verdict

    spec = make_spec()
    passing = ScenarioResult(
        spec_id=spec.id,
        category=spec.category,
        scenario="hardened",
        expected=VerdictStatus.PASS,
        verdict=Verdict(
            status=VerdictStatus.PASS,
            confidence=1.0,
            reasoning="ok",
            evaluator_type="stub",
        ),
    )
    assert passing.matched is True


def test_mismatch_model_fields() -> None:
    miss = Mismatch(
        spec_id="X-Y-001",
        scenario="vulnerable",
        expected=VerdictStatus.FAIL,
        got=VerdictStatus.PASS,
        reasoning="missed",
    )
    assert miss.spec_id == "X-Y-001"
    assert miss.expected is VerdictStatus.FAIL
    assert miss.got is VerdictStatus.PASS
