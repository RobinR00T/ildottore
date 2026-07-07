"""Lint rule engine (contract §5.4, §7).

Runs over a loaded pack set + the merged registry and emits a :class:`LintReport`. Rules:

* **SCHEMA / PARSE_ERROR** — surfaced by the loader (invalid YAML / schema breach).
* **ID_COLLISION** — a later pack re-declares an existing id (from the registry merge).
* **MISSING_TEST_ONLY** — a spec in a flagged family lacks ``test_only: true``.
* **UNKNOWN_EVALUATOR_TYPE** — a declared evaluator type the engine can't satisfy.
* **MISSING_FRAMEWORK_MAP** — an owasp/mitre/nist mapping is blank.
* **FIXTURE_NO_DETECT** — ``fixtures.vulnerable`` does not yield a fail.
* **FIXTURE_HARDENED_FAIL** — ``fixtures.hardened`` does not all-pass.
* **UNKNOWN_SPEC_REF** — a suite references a spec id absent from the registry.

The linter runs **no code and opens no socket**: it consumes already-parsed models and the
offline stub evaluator table.
"""

from __future__ import annotations

from pathlib import Path

from ildottore.shared import AttackSpec, EvaluatorType, VerdictStatus

from .errors import LintCode, LintCounts, LintError, LintReport, Severity
from .fixtures_engine import DEFAULT_STUB_TABLE, StubEvaluator, evaluate_fixture
from .loader import load_paths
from .pack import FLAGGED_FAMILIES, LoadedPack
from .registry import Registry

# Evaluator types with no offline stub in W1. A spec relying solely on these can't be
# fixtures-proved yet, so the linter warns (not errors) rather than false-flagging it.
_UNPROVABLE_IN_W1: frozenset[EvaluatorType] = frozenset(
    {
        EvaluatorType.EXACT_MATCH,
        EvaluatorType.PII_DETECTOR,
        EvaluatorType.SECRET_SHAPE,
        EvaluatorType.VERBATIM_OVERLAP,
        EvaluatorType.LOGPROB_MEMBERSHIP,
        EvaluatorType.AUTHZ_LEAK,
    }
)


def _check_test_only(spec: AttackSpec) -> list[LintError]:
    if spec.category in FLAGGED_FAMILIES and not spec.test_only:
        return [
            LintError(
                code=LintCode.MISSING_TEST_ONLY,
                message=(
                    f"spec in flagged family {spec.category.value!r} must set "
                    f"test_only: true (docs/02 S5)"
                ),
                spec_id=spec.id,
            )
        ]
    return []


def _check_framework_map(spec: AttackSpec) -> list[LintError]:
    errors: list[LintError] = []
    if not spec.owasp.strip():
        errors.append(_fw_err(spec, "owasp"))
    if not spec.mitre_atlas.tactic.strip():
        errors.append(_fw_err(spec, "mitre_atlas.tactic"))
    if not spec.nist_ai_rmf.strip():
        errors.append(_fw_err(spec, "nist_ai_rmf"))
    return errors


def _fw_err(spec: AttackSpec, field: str) -> LintError:
    return LintError(
        code=LintCode.MISSING_FRAMEWORK_MAP,
        message=f"missing/blank framework mapping: {field}",
        spec_id=spec.id,
    )


def _check_fixtures(spec: AttackSpec, table: dict[EvaluatorType, StubEvaluator]) -> list[LintError]:
    """Prove the spec detects on ``vulnerable`` and passes on ``hardened``."""
    errors: list[LintError] = []

    declared = {cfg.type for cfg in spec.evaluators}
    provable = declared - _UNPROVABLE_IN_W1
    if not provable:
        # Nothing to prove offline yet; a warning keeps the honest signal without failing.
        errors.append(
            LintError(
                code=LintCode.FIXTURE_NO_DETECT,
                severity=Severity.WARNING,
                message=(
                    "no W1-provable evaluator (all declared types need u06); "
                    "fixtures-prove deferred"
                ),
                spec_id=spec.id,
            )
        )
        return errors

    vuln_verdict, _ = evaluate_fixture(spec, spec.fixtures.vulnerable, table)
    if vuln_verdict is not VerdictStatus.FAIL:
        errors.append(
            LintError(
                code=LintCode.FIXTURE_NO_DETECT,
                message=(
                    "fixtures.vulnerable did not yield a fail under declared evaluators "
                    f"(got {vuln_verdict.value!r}); the spec does not prove detection"
                ),
                spec_id=spec.id,
            )
        )

    hard_verdict, _ = evaluate_fixture(spec, spec.fixtures.hardened, table)
    if hard_verdict is not VerdictStatus.PASS:
        errors.append(
            LintError(
                code=LintCode.FIXTURE_HARDENED_FAIL,
                message=(
                    "fixtures.hardened did not all-pass under declared evaluators "
                    f"(got {hard_verdict.value!r}); false-positive risk"
                ),
                spec_id=spec.id,
            )
        )
    return errors


def _check_suite_refs(pack: LoadedPack, registry: Registry) -> list[LintError]:
    errors: list[LintError] = []
    for suite in pack.suites:
        for entry in suite.specs:
            try:
                registry.get(entry.spec_id)
            except KeyError:
                errors.append(
                    LintError(
                        code=LintCode.UNKNOWN_SPEC_REF,
                        message=(
                            f"suite {suite.id!r} references unknown spec id {entry.spec_id!r}"
                        ),
                        spec_id=entry.spec_id,
                        path=str(pack.root),
                    )
                )
    return errors


def lint_packs(
    packs: list[LoadedPack],
    load_errors: list[LintError] | None = None,
    *,
    stub_table: dict[EvaluatorType, StubEvaluator] | None = None,
) -> LintReport:
    """Lint an already-loaded pack set + carry forward any load-time findings."""
    table = stub_table if stub_table is not None else DEFAULT_STUB_TABLE
    registry = Registry.from_packs(packs)

    findings: list[LintError] = list(load_errors or [])
    findings.extend(registry.collisions)

    for spec in _unique_specs(packs):
        findings.extend(_check_test_only(spec))
        findings.extend(_check_framework_map(spec))
        findings.extend(_check_fixtures(spec, table))

    for pack in packs:
        findings.extend(_check_suite_refs(pack, registry))

    errors = [f for f in findings if f.severity is Severity.ERROR]
    warnings = [f for f in findings if f.severity is Severity.WARNING]
    counts = LintCounts(
        specs=len({s.id for s in _unique_specs(packs)}),
        suites=sum(len(p.suites) for p in packs),
        packs=len(packs),
    )
    return LintReport(errors=errors, warnings=warnings, counts=counts)


def _unique_specs(packs: list[LoadedPack]) -> list[AttackSpec]:
    """First-wins de-dup of specs across packs (matches the registry merge)."""
    seen: set[str] = set()
    out: list[AttackSpec] = []
    for pack in packs:
        for spec in pack.specs:
            if spec.id in seen:
                continue
            seen.add(spec.id)
            out.append(spec)
    return out


def lint(
    paths: list[Path],
    *,
    stub_table: dict[EvaluatorType, StubEvaluator] | None = None,
) -> LintReport:
    """Load every search path (no exec/no network) and lint the merged result."""
    loaded = load_paths(paths)
    return lint_packs(loaded.packs, loaded.errors, stub_table=stub_table)
