"""ATT&CK Navigator layers (``reporting.navigator``) and the ``-oN`` reporter.

What a layer must get right: the format fields the Navigator reads, one cell per tactic the
technique is drawn under (narrowed by a spec's restriction), observed and capability-only told
apart, a run's verdicts coloured worst-first, not-exercised specs absent, and nothing from a
target's reply in the bytes.
"""

from __future__ import annotations

import json

from ildottore.reporting import get_reporter
from ildottore.reporting.navigator import (
    COLOR_CAPABILITY_ONLY,
    COLOR_EXPLOITED,
    COLOR_INCONCLUSIVE,
    COLOR_NOT_EXPLOITED,
    COLOR_OBSERVED,
    battery_layer,
    fold_states,
    layer_entries,
    run_layer,
)
from ildottore.shared.attack import ATTACK_VERSION
from ildottore.shared.enums import AttackOccurrence, ScanBand, VerdictStatus
from ildottore.shared.models import AttackSpec, AttackTechniqueMapping, MitreAttack
from tests.reporting.conftest import make_finding, make_run, make_spec


def _spec(spec_id: str, *entries: tuple[str, str] | tuple[str, str, list[str]]) -> AttackSpec:
    techniques = [
        AttackTechniqueMapping(
            id=e[0],
            occurrence=AttackOccurrence(e[1]),
            tactics=list(e[2]) if len(e) == 3 else None,
        )
        for e in entries
    ]
    return make_spec(spec_id, name=f"spec {spec_id}").model_copy(
        update={"mitre_attack": MitreAttack(techniques=techniques)}
    )


def _cells(layer: dict[str, object]) -> dict[tuple[str, str], dict[str, object]]:
    techniques = layer["techniques"]
    assert isinstance(techniques, list)
    return {(c["techniqueID"], c["tactic"]): c for c in techniques}


def test_layer_entries_fold_specs_per_technique_observed_winning() -> None:
    specs = [
        _spec("A-1", ("T1698", "capability-only")),
        _spec("B-1", ("T1698", "observed"), ("T1053.003", "observed", ["persistence"])),
        _spec("C-1", ("T1562", "observed")),  # retired: skipped, the linter's job
    ]
    entries = {e.technique_id: e for e in layer_entries(specs)}
    assert set(entries) == {"T1698", "T1053.003"}
    assert entries["T1698"].occurrence == "observed"
    assert entries["T1698"].specs == (("A-1", "spec A-1"), ("B-1", "spec B-1"))
    assert entries["T1053.003"].tactics == ("persistence",), "the restriction narrows the cells"
    assert entries["T1698"].name == "Indirect Prompt Injection"


def test_battery_layer_has_the_navigator_fields_and_tells_the_occurrences_apart() -> None:
    layer = battery_layer(
        [
            _spec("PI-1", ("T1699", "observed")),
            _spec("JB-1", ("T1699", "observed"), ("T1587.001", "capability-only")),
        ]
    )
    assert layer["versions"] == {"attack": "20", "navigator": "5.3.2", "layer": "4.5"}
    assert layer["domain"] == "enterprise-attack"
    assert ATTACK_VERSION in str(layer["name"])
    cells = _cells(layer)
    assert set(cells) == {("T1699", "execution"), ("T1587.001", "resource-development")}
    observed = cells[("T1699", "execution")]
    assert (observed["color"], observed["score"]) == (COLOR_OBSERVED, 1)
    assert "JB-1 (spec JB-1)" in str(observed["comment"])
    assert "PI-1 (spec PI-1)" in str(observed["comment"])
    listed = cells[("T1587.001", "resource-development")]
    assert (listed["color"], listed["score"]) == (COLOR_CAPABILITY_ONLY, 0)
    assert "not counted" in str(listed["comment"])
    assert "1 observed" in str(layer["description"])
    assert "1 capability-only" in str(layer["description"])
    assert next(item["label"] for item in layer["legendItems"]).startswith("observed")


def test_run_layer_colours_by_the_worst_verdict_and_leaves_unexercised_specs_out() -> None:
    specs = [
        _spec("PI-1", ("T1699", "observed")),
        _spec("PI-2", ("T1699", "observed")),
        _spec("AG-1", ("T1700", "observed")),
        _spec("AG-2", ("T1485", "observed")),
        _spec("JB-1", ("T1587.001", "capability-only")),
    ]
    state_of = {"PI-1": "pass", "PI-2": "fail", "AG-1": "inconclusive", "JB-1": "fail"}
    layer = run_layer(specs, state_of, run_id="run-9", started_at="2026-01-01", targets=["t"])
    cells = _cells(layer)
    assert ("T1485", "impact") not in cells, "AG-2 sent nothing scorable"
    assert cells[("T1699", "execution")]["color"] == COLOR_EXPLOITED, "one exploit colours it"
    assert cells[("T1700", "exfiltration")]["color"] == COLOR_INCONCLUSIVE
    assert cells[("T1587.001", "resource-development")]["color"] == COLOR_CAPABILITY_ONLY, (
        "no verdict can turn an artefact into an action"
    )
    assert "1 technique(s) exploited, 0 not exploited, 1 inconclusive" in str(layer["description"])
    all_pass = run_layer(specs[:1], {"PI-1": "pass"}, run_id="r", started_at="d", targets=[])
    assert _cells(all_pass)[("T1699", "execution")]["color"] == COLOR_NOT_EXPLOITED


def test_navigator_reporter_is_registered_deterministic_and_carries_no_reply() -> None:
    specs = {
        "PI-1": _spec("PI-1", ("T1699", "observed")),
        "DL-1": make_spec("DL-1", owasp="LLM02"),  # no mapping: absent from the layer
    }
    leak = "sk-live-SHOULD-NEVER-APPEAR-9f8e7d6c"
    findings = [
        make_finding("PI-1", status=VerdictStatus.FAIL, band=ScanBand.HIGH, reasoning=leak),
        make_finding("DL-1", status=VerdictStatus.PASS, band=ScanBand.LOW, reasoning=leak),
    ]
    run = make_run(run_id="run-nav", findings=findings)
    reporter = get_reporter("navigator", specs=specs)
    first = reporter.render(run, findings)
    assert first == reporter.render(run, findings)
    layer = json.loads(first)
    assert layer["versions"]["layer"] == "4.5"
    assert [c["techniqueID"] for c in layer["techniques"]] == ["T1699"]
    assert layer["techniques"][0]["color"] == COLOR_EXPLOITED
    assert "run-nav" in layer["name"]
    assert leak not in first.decode("utf-8"), "the layer is built from specs, never a reply"


def test_contradicted_restriction_draws_nothing_as_coverage_counts_nothing() -> None:
    """A ``tactics`` restriction naming no tactic of the technique keeps nothing: the entry has
    no cell, the same zero the coverage fold applies (``shared.attack.restrict_tactics``)."""

    contradicted = _spec("AG-1", ("T1053.003", "observed", ["impact"]))
    assert layer_entries([contradicted]) == ()
    narrowed = _spec("AG-2", ("T1053.003", "observed", ["persistence", "impact"]))
    (entry,) = layer_entries([narrowed])
    assert entry.tactics == ("persistence",), "the kept tactic only, the rejected one dropped"


def test_fold_states_takes_the_worst_state_per_spec_whatever_the_order() -> None:
    """A run against several targets yields one finding per spec and target."""

    assert fold_states([("X", "pass"), ("X", "fail")]) == {"X": "fail"}
    assert fold_states([("X", "fail"), ("X", "pass")]) == {"X": "fail"}
    assert fold_states([("X", "pass"), ("X", "inconclusive")]) == {"X": "inconclusive"}
    assert fold_states([("X", "weird"), ("X", "pass")]) == {"X": "weird"}, (
        "an unknown state ranks as inconclusive, below pass"
    )


def test_reporter_folds_several_findings_per_spec_to_the_worst() -> None:
    specs = {"PI-1": _spec("PI-1", ("T1699", "observed"))}
    findings = [
        make_finding("PI-1", status=VerdictStatus.FAIL, band=ScanBand.HIGH),
        make_finding("PI-1", status=VerdictStatus.PASS, band=ScanBand.LOW),
    ]
    run = make_run(run_id="run-two-targets", findings=findings)
    layer = json.loads(get_reporter("navigator", specs=specs).render(run, findings))
    assert layer["techniques"][0]["color"] == COLOR_EXPLOITED, "exploited on one target"
    reversed_layer = json.loads(
        get_reporter("navigator", specs=specs).render(run, list(reversed(findings)))
    )
    assert reversed_layer["techniques"][0]["color"] == COLOR_EXPLOITED, "order must not matter"


def test_battery_layer_records_the_files_that_failed_to_load() -> None:
    layer = battery_layer([_spec("PI-1", ("T1699", "observed"))], unloaded=2)
    assert {"name": "specs_unloaded", "value": "2"} in layer["metadata"]
    assert "2 spec file(s) failed to load and are absent" in str(layer["description"])
    clean = battery_layer([_spec("PI-1", ("T1699", "observed"))])
    assert {"name": "specs_unloaded", "value": "0"} in clean["metadata"]
    assert "failed to load" not in str(clean["description"])
