"""`dottore coverage`: what the battery TESTS, computed without running anything."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ildottore.cli.coverage import (
    FRAMEWORK_KEYS,
    battery_coverage,
    render_coverage,
    render_coverage_json,
)
from ildottore.reporting.summary import build_battery_coverage
from ildottore.shared.iopc import IOPC_IMPACT_UNIVERSE, IOPC_TECHNIQUE_UNIVERSE

REPO = Path(__file__).resolve().parents[2]
#: The whole specs tree, as the CLI uses: suites live beside attacks, so a registry
#: built from attacks/ alone cannot resolve --suite.
SPECS = REPO / "specs"


def _coverage():
    return battery_coverage([SPECS])


def test_reports_every_axis_over_the_whole_battery() -> None:
    cov = _coverage()
    assert cov.specs == 75
    keys = [a.key for a in cov.axes]
    assert keys == [
        "owasp",
        "atlas",
        "iopc_techniques",
        "iopc_impacts",
        "aisvs_l1",
        "aisvs_l2",
        "aisvs_l3",
    ]
    for axis in cov.axes:
        assert 0.0 <= axis.pct <= 1.0, axis.label
        assert (
            axis.exercised + len(axis.missing) + len(axis.out_of_reach) + len(axis.by_design)
            == axis.total
        )


def test_responsible_ai_codes_never_inflate_the_owasp_axis() -> None:
    """RAI0x is a different framework; counting it read as a perfect 10/10.

    The battery carries 8 OWASP LLM codes plus RAI01 and RAI02. Summed blindly that is ten
    distinct values over a denominator of ten, which reported 100% OWASP coverage while LLM03
    and LLM04 are untested. This pins the filter.
    """

    owasp = next(a for a in _coverage().axes if a.key == "owasp")
    assert owasp.exercised == 8
    assert owasp.total == 10
    assert all(code.startswith("LLM") for code, _ in owasp.covered)
    # Both OWASP gaps are out of reach for a black-box runtime scanner, so neither sits in
    # `missing`, which since 2026-09-22 means "not covered yet" and nothing else.
    assert owasp.missing == ()
    assert {code for code, _, _ in owasp.out_of_reach} == {"LLM03", "LLM04"}


def test_iopc_axes_use_the_pinned_universe_as_denominator() -> None:
    cov = _coverage()
    tech = next(a for a in cov.axes if a.key == "iopc_techniques")
    impact = next(a for a in cov.axes if a.key == "iopc_impacts")
    assert tech.total == len(IOPC_TECHNIQUE_UNIVERSE)
    assert impact.total == len(IOPC_IMPACT_UNIVERSE)
    # titles, not bare codes: the impact axis is meant to be readable
    assert any(title != code for code, title in tech.covered)


def test_gaps_are_named_not_just_counted() -> None:
    """A percentage with no list of what is missing invites a flattering reading."""

    cov = _coverage()
    out = render_coverage(cov, framework="iopc")
    for axis in cov.axes:
        if not axis.key.startswith("iopc"):
            continue
        for code, _title in axis.missing:
            assert code in out, f"{code} is a pending gap and must be named"
        for code, _title, _reason in axis.out_of_reach:
            assert code in out, f"{code} is out of reach and must still be named"
    assert "IOPC-T2.003" in out and "Training & Fine-tuning Data Poisoning" in out


def test_no_gaps_flag_suppresses_the_listing() -> None:
    out = render_coverage(_coverage(), framework="iopc", show_gaps=False)
    assert "Not covered" not in out
    assert "Out of reach" not in out
    assert "Deliberately not tested" not in out
    assert "IOPC-T2.003" not in out
    assert "IoPC techniques" in out


def test_framework_filter_selects_axes() -> None:
    cov = _coverage()
    assert "OWASP" in render_coverage(cov, framework="owasp", show_gaps=False)
    assert "IoPC" not in render_coverage(cov, framework="owasp", show_gaps=False)
    iopc = render_coverage(cov, framework="iopc", show_gaps=False)
    assert "IoPC techniques" in iopc and "IoPC impacts" in iopc
    assert "OWASP" not in iopc
    aisvs = render_coverage(cov, framework="aisvs", show_gaps=False)
    assert [line.split(",")[1].split()[:2] for line in aisvs.splitlines() if "AISVS" in line] == [
        ["level", "1"],
        ["level", "2"],
        ["level", "3"],
    ]
    assert "IoPC" not in aisvs and "ATLAS" not in aisvs
    assert "OWASP AISVS" not in render_coverage(cov, framework="owasp", show_gaps=False)
    assert "all" in FRAMEWORK_KEYS


def test_suite_scoping_measures_only_that_suite() -> None:
    whole = battery_coverage([SPECS])
    scoped = battery_coverage([SPECS], suite="nova-iopc")
    assert scoped.specs == 13
    assert scoped.specs < whole.specs
    whole_t = next(a for a in whole.axes if a.key == "iopc_techniques")
    scoped_t = next(a for a in scoped.axes if a.key == "iopc_techniques")
    assert scoped_t.exercised < whole_t.exercised
    assert scoped_t.total == whole_t.total  # same denominator, smaller numerator


def test_unknown_suite_is_refused_not_reported_as_zero_coverage() -> None:
    """A suite that does not exist is a typo, and 0% is a wrong answer to a typo.

    This test used to assert the opposite (``cov.specs == 0`` and every axis at 0%), which
    pinned the defect rather than the behaviour: "this battery covers nothing" and "you named
    a suite I do not have" are different statements, and the first one reads as a measurement.
    The refusal names the registered suites so the fix needs no guessing.
    """

    with pytest.raises(ValueError) as err:
        battery_coverage([SPECS], suite="does-not-exist")
    assert "not registered" in str(err.value)
    assert "quick" in str(err.value)  # the message lists what IS registered


def test_json_output_honours_no_gaps() -> None:
    """``--json --no-gaps`` drops ``missing`` too: one flag, one meaning per output mode."""

    doc = json.loads(render_coverage_json(_coverage(), framework="owasp", show_gaps=False))
    assert "covered" in doc["axes"][0]
    assert "missing" not in doc["axes"][0]


def test_json_output_is_machine_readable_and_complete() -> None:
    doc = json.loads(render_coverage_json(_coverage(), framework="iopc"))
    assert doc["specs"] == 75
    assert [a["key"] for a in doc["axes"]] == ["iopc_techniques", "iopc_impacts"]
    tech = doc["axes"][0]
    assert len(tech["covered"]) == tech["exercised"]
    assert (
        len(tech["covered"])
        + len(tech["missing"])
        + len(tech["out_of_reach"])
        + len(tech["not_tested_by_design"])
        == tech["total"]
    )
    assert {"code", "title", "reason"} == set(tech["out_of_reach"][0])


def test_empty_spec_set_is_zero_not_a_crash() -> None:
    cov = build_battery_coverage([])
    assert cov.specs == 0
    assert all(a.exercised == 0 and a.pct == 0.0 and a.total > 0 for a in cov.axes)


# --- honest gaps: roadmap vs out of reach (added 2026-09-22) ------------------------


def test_every_classification_is_pinned_per_axis() -> None:
    """A reclassification has to be argued in a diff, not landed quietly.

    Nothing checked WHICH codes sat in which bucket, so an audit moved a plainly testable gap
    into "out of reach" with a fabricated reason and the whole suite stayed green. A reason
    string can be asserted non-empty; it cannot be asserted true. The defence is that the
    membership is written down here, so moving a code shows up as a test change next to the
    argument for it.
    """

    from ildottore.cli.coverage import battery_coverage

    by_key = {a.key: a for a in battery_coverage([SPECS]).axes}

    assert {c for c, _ in by_key["owasp"].missing} == set()
    assert {c for c, _, _ in by_key["owasp"].out_of_reach} == {"LLM03", "LLM04"}
    assert by_key["owasp"].by_design == ()

    # "Command and Control" is roadmap, NOT out of reach: this repository ships fixtures in
    # which an agent writes a cron entry calling a C2-shaped address, so the behaviour is
    # observable in a target's own tool calls. It was briefly classified unreachable.
    assert {c for c, _ in by_key["atlas"].missing} == {"Command and Control"}
    assert {c for c, _, _ in by_key["atlas"].by_design} == {"AI Attack Adaptation"}
    assert {c for c, _, _ in by_key["atlas"].out_of_reach} == {"AI Model Access"}

    assert {c for c, _ in by_key["iopc_techniques"].missing} == set()
    assert {c for c, _, _ in by_key["iopc_techniques"].out_of_reach} == {
        "IOPC-T2.003",
        "IOPC-T8.003",
    }
    assert {c for c, _, _ in by_key["iopc_techniques"].by_design} == {"IOPC-T8.004"}

    assert by_key["iopc_impacts"].missing == ()
    assert by_key["iopc_impacts"].out_of_reach == ()


def test_a_classified_code_is_one_that_is_actually_uncovered() -> None:
    """The other two directions a reclassification can go, both of which were unguarded.

    `_axis` only consults the two dicts for codes the battery does NOT cover, so an entry for a
    COVERED code is invisible to every other assertion here while still changing real output:
    an audit put `LLM01` into the out-of-reach dict and five suite-scoped reports began printing
    that prompt injection is out of reach for a black-box scanner, with the whole suite green.
    An entry for a code in no universe at all is inert, which is its own kind of rot.
    """

    from ildottore.reporting.summary import build_battery_coverage
    from ildottore.shared.frameworks import NOT_TESTED_BY_DESIGN, OUT_OF_REACH

    coverage = battery_coverage([SPECS])
    covered = {code for axis in coverage.axes for code, _ in axis.covered}
    universe = {code for axis in coverage.axes for code, _ in (*axis.covered, *axis.missing)} | {
        code for axis in coverage.axes for code, _, _ in (*axis.out_of_reach, *axis.by_design)
    }

    classified = set(OUT_OF_REACH) | set(NOT_TESTED_BY_DESIGN)
    assert not (classified & covered), (
        "a code the battery covers is classified as unreachable or untested: "
        f"{sorted(classified & covered)}. It reads as inert on the full battery and changes "
        "what a suite-scoped report says."
    )
    assert classified <= universe, (
        f"classified codes outside every pinned universe: {sorted(classified - universe)}"
    )
    assert build_battery_coverage([]).axes, "the empty battery still resolves its axes"


def test_a_gap_is_either_roadmap_or_out_of_reach_with_a_reason() -> None:
    """ "8 of 10" invites the reader to assume the other two are coming. Some never are."""

    from ildottore.cli.coverage import battery_coverage

    coverage = battery_coverage([SPECS])
    for axis in coverage.axes:
        assert (
            axis.exercised + len(axis.missing) + len(axis.out_of_reach) + len(axis.by_design)
            == axis.total
        ), f"{axis.key}: every code is covered, pending, out of reach or deliberately untested"
        for _code, _title, reason in (*axis.out_of_reach, *axis.by_design):
            assert reason.strip(), "a classified gap without a reason is just a gap hidden"


def test_out_of_reach_codes_stay_in_the_denominator() -> None:
    """Removing them would raise every percentage by redefining the universe (clause A-12).

    This is the same move the reporting layer refuses everywhere else: a denominator measured
    on the survivors. Stating a gap is not a licence to stop counting it.
    """

    from ildottore.cli.coverage import battery_coverage
    from ildottore.shared.frameworks import OWASP_LLM_UNIVERSE

    coverage = battery_coverage([SPECS])
    owasp = next(a for a in coverage.axes if a.key == "owasp")

    assert owasp.out_of_reach, "the OWASP axis has out-of-reach codes to speak about"
    assert owasp.total == len(OWASP_LLM_UNIVERSE)
    assert owasp.pct < 1.0


def test_the_two_groups_are_rendered_apart_and_the_denominator_is_explained() -> None:
    from ildottore.cli.coverage import battery_coverage, render_coverage

    rendered = render_coverage(battery_coverage([SPECS]))

    assert "Out of reach for a black-box runtime scanner" in rendered
    assert "Deliberately not tested, and why" in rendered
    assert "stay in the denominator" in rendered
    # The reason travels with the code, in the human output as well as the JSON.
    assert "training and fine-tuning stages need pipeline access" in rendered


def test_the_json_keeps_the_two_lists_apart() -> None:
    import json

    from ildottore.cli.coverage import battery_coverage, render_coverage_json

    payload = json.loads(render_coverage_json(battery_coverage([SPECS])))
    owasp = next(a for a in payload["axes"] if a["key"] == "owasp")

    assert owasp["missing"] == [], "both OWASP gaps are out of reach, neither is pending"
    assert {entry["code"] for entry in owasp["out_of_reach"]} == {"LLM03", "LLM04"}
    assert all(entry["reason"] for entry in owasp["out_of_reach"])


# --- AISVS: a control framework, pinned bucket by bucket (added 2026-10-03) -----------


def _aisvs(patterns: str) -> set[str]:
    """Expand space-separated chapter / section / requirement patterns (``C4 C3.1 C9.2.3``)
    over the pinned table, written here independently of ``shared.aisvs``'s own grouping so a
    change there has to be repeated here, next to its argument."""

    from ildottore.shared.aisvs import AISVS_REQUIREMENTS

    out: set[str] = set()
    for pattern in patterns.split():
        prefix = f"v1.0-{pattern}"
        hits = (
            {prefix}
            if pattern.count(".") == 2
            else {c for c in AISVS_REQUIREMENTS if c.startswith(prefix + ".")}
        )
        assert hits <= set(AISVS_REQUIREMENTS) and hits, pattern
        out |= hits
    return out


def test_every_aisvs_requirement_is_pinned_to_its_bucket() -> None:
    """The four AISVS buckets, written down (clause A-26, A-28).

    The first classification counted 37 requirements as covered. An independent audit the same
    morning (2026-10-03) read every spec behind them and kept 17: some specs only show the model
    PROPOSING a tool call where the control is the runtime blocking it, some test the tester's
    own schema or allowlist instead of the operator's, four send a placeholder instead of a
    concrete request, and the multilingual spec sends English. The 20 it dropped are in the
    roadmap below, not deleted, because a better spec could cover them.
    """

    from ildottore.cli.coverage import battery_coverage

    axes = [a for a in battery_coverage([SPECS]).axes if a.key.startswith("aisvs")]
    covered = {c for a in axes for c, _ in a.covered}
    missing = {c for a in axes for c, _ in a.missing}
    out_of_reach = {c for a in axes for c, _, _ in a.out_of_reach}
    by_design = {c for a in axes for c, _, _ in a.by_design}

    assert covered == _aisvs(
        "C2.1.2 C2.1.3 C2.1.6 C2.2.3 C5.2.2 C5.2.4 C7.3.1 C7.3.2 C8.1.3 C9.3.5 C9.3.6 "
        "C9.5.2 C9.5.3 C9.5.4 C10.4.2 C11.1.1 C11.1.4"
    )
    # Roadmap: partial evidence today (W) plus observable-but-unbuilt (G). Not out of reach.
    assert missing == _aisvs(
        "C2.1.1 C2.1.4 C2.1.5 C2.1.7 C2.1.8 C2.2.1 C2.2.2 C2.2.4 C5.2.1 C5.3.1 C7.1.1 C7.1.2 "
        "C7.2.2 C7.3.3 C7.3.4 C7.4.1 C7.4.2 C7.4.3 C8.1.1 C8.2.1 C8.2.3 C8.2.4 C8.3 C9.1.2 "
        "C9.2.1 C9.2.2 C9.2.4 C9.2.5 C9.2.7 C9.2.10 C9.3.2 C9.3.4 C9.3.7 C9.5.1 C9.5.5 C9.5.6 "
        "C10.4.1 C11.2.1 C11.2.3 C11.2.5 C11.3.2 C11.3.4 C11.4.1 C11.4.2"
    )
    # Includes the operator-side processes this tool can be the instrument for (C3.2, C6.1.4,
    # C11.1.2/3/5, C1.3.3, the logging and alerting rows of C12): a reply cannot show they ran.
    assert out_of_reach == _aisvs(
        "C1 C3 C4 C5.1 C5.2.3 C5.2.5 C5.2.6 C5.2.7 C5.3.2 C6 C7.2.1 C7.2.3 C8.1.2 C8.2.2 "
        "C8.2.5 C9.1.1 C9.1.3 C9.2.3 C9.2.6 C9.2.8 C9.2.9 C9.3.1 C9.3.3 C9.3.8 C9.4 C9.6 "
        "C11.1.2 C11.1.3 C11.1.5 C11.2.4 C11.3.1 C11.3.3 C11.4.3 C12"
    )
    assert by_design == _aisvs(
        "C7.4.4 C10.1 C10.2 C10.3 C10.4.3 C10.4.4 C10.4.5 C10.4.6 C10.4.7 C10.4.8 C11.2.2"
    )
    assert (len(covered), len(missing), len(out_of_reach), len(by_design)) == (17, 46, 105, 23)
    assert [a.exercised for a in axes] == [5, 12, 0]


def test_each_aisvs_claim_is_carried_by_the_specs_the_audit_kept() -> None:
    """Which spec carries which control, pinned, because the covered SET above would not move if
    a spec were added to a row it does not test.

    That was most of what the 2026-10-03 audit removed: ten jailbreak specs on the instruction
    hierarchy row although none of them sends a system message, a canary spec on the "secrets
    are not in the model's context" row although the canary is one the tester planted, an MCP
    server check on the client-screening row. Adding a spec to a row is a claim about its
    oracle, so it shows up here as a diff.
    """

    from collections import defaultdict

    from ildottore.cli import wiring

    carried: dict[str, set[str]] = defaultdict(set)
    for spec in wiring.build_registry([SPECS]).list():
        for code in spec.aisvs or []:
            carried[code].add(spec.id)

    assert dict(carried) == {
        "v1.0-C2.1.2": {"JB-ENCODING-001"},
        "v1.0-C2.1.3": {
            "MM-AUD-PROMPTINJECT-001",
            "MM-IMG-DOC-INJECT-001",
            "MM-IMG-PROMPTINJECT-001",
            "MM-IMG-SPLIT-PAYLOAD-001",
            "MM-IMG-TOOL-EXFIL-001",
            "PI-DIRECT-001",
            "PI-INDIRECT-RAG-001",
            "PI-INDIRECT-TOOL-001",
        },
        "v1.0-C2.1.6": {"PI-DIRECT-001", "SP-LEAK-001"},
        "v1.0-C2.2.3": {
            "MM-AUD-PROMPTINJECT-001",
            "MM-IMG-DOC-INJECT-001",
            "MM-IMG-PROMPTINJECT-001",
            "MM-IMG-SPLIT-PAYLOAD-001",
            "MM-IMG-TOOL-EXFIL-001",
        },
        "v1.0-C5.2.2": {"DL-XTENANT-001", "EMB-XTENANT-RETRIEVAL-001"},
        "v1.0-C5.2.4": {"AC-BOLA-001", "DL-XSESSION-001", "DL-XTENANT-001"},
        "v1.0-C7.3.1": {
            "JB-ENCODING-001",
            "JB-LIKERT-001",
            "JB-MULTILINGUAL-001",
            "JB-OFFENSIVE-RANSOM-CODEGEN-001",
            "JB-REFUSAL-SUPPRESS-001",
            "JB-SEQUENTIAL-001",
            "JB-TREE-001",
            "SAFETY-DISINFO-001",
            "SAFETY-PHISH-BEC-001",
        },
        "v1.0-C7.3.2": {
            "AG-GOAL-THEFT-001",
            "PI-DIRECT-001",
            "RECON-MODEL-IDENTITY-001",
            "RECON-SYSTEM-001",
            "SP-LEAK-001",
        },
        "v1.0-C8.1.3": {"EMB-NEIGHBOR-LEAK-001", "EMB-XTENANT-RETRIEVAL-001"},
        "v1.0-C9.3.5": {
            "AG-CODEEXEC-UNEXPECTED-001",
            "AG-EXTORT-CHAIN-001",
            "MM-IMG-TOOL-EXFIL-001",
        },
        "v1.0-C9.3.6": {"PI-INDIRECT-TOOL-001"},
        "v1.0-C9.5.2": {"AC-BOLA-001", "DL-XTENANT-001"},
        "v1.0-C9.5.3": {"AC-BOLA-001", "DL-XTENANT-001"},
        "v1.0-C9.5.4": {"AG-CRED-SWEEP-001"},
        "v1.0-C10.4.2": {"AG-TOOLMETA-POISON-001", "PI-INDIRECT-TOOL-001"},
        "v1.0-C11.1.1": {"SAFETY-DISINFO-001", "SAFETY-PHISH-BEC-001"},
        "v1.0-C11.1.4": {
            "JB-ENCODING-001",
            "JB-LIKERT-001",
            "JB-OFFENSIVE-RANSOM-CODEGEN-001",
            "JB-REFUSAL-SUPPRESS-001",
            "JB-SEQUENTIAL-001",
            "JB-TREE-001",
        },
    }


def test_codes_are_listed_in_the_order_a_reader_counts_them() -> None:
    """String order printed every AISVS chapter from 10 up ahead of chapter 2."""

    from ildottore.cli.coverage import battery_coverage

    by_key = {a.key: a for a in battery_coverage([SPECS]).axes}
    l1 = [c for c, _ in by_key["aisvs_l1"].missing]
    assert l1[0] == "v1.0-C2.1.1"
    assert l1.index("v1.0-C9.3.2") < l1.index("v1.0-C10.4.1") < l1.index("v1.0-C11.2.1")
    # The zero-padded axes keep the order they always had.
    assert [c for c, _ in by_key["owasp"].covered] == sorted(c for c, _ in by_key["owasp"].covered)
