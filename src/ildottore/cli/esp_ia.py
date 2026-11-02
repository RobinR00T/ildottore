"""CCN-STIC-2011 (ESP-IA) for one target: what applies (u12 A-117) and the evidence (u12 A-118).

Two read-only views over :mod:`ildottore.shared.esp_ia`, neither of which sends anything:

* ``dottore coverage --framework esp_ia --target FILE`` runs the guide's applicability matrix
  over the vendor's answers in the target file, and says, for each requirement that applies,
  which specs of the battery would run against that target and which would not, and why.
* ``dottore replay RUN_ID --esp-ia FILE.md`` writes a Markdown draft shaped like the guide's
  Annex B (the Evaluation Technical Report): results by requirement and one test case per spec,
  from the hash-verified evidence of a run.

Both keep the falsification reading the whole mapping rests on. A spec's FAIL is evidence
against a requirement; a PASS means the probes did not falsify it, never that the requirement
is met. Only an accredited laboratory, against the CCN's own test guides, writes PASS (*PASA*),
so no line written here does.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ildottore.cli.run import delivery_gap
from ildottore.core.planner import build_plan
from ildottore.redactor import visible_controls
from ildottore.shared.digest import spec_digest, target_digest
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.esp_ia import (
    ESP_IA_NOT_TESTED_BY_DESIGN,
    ESP_IA_OUT_OF_REACH,
    ESP_IA_QUESTIONS,
    ESP_IA_REQUIREMENTS,
    ESP_IA_VERSION,
    EspIaRule,
    applicable_rules,
)
from ildottore.shared.models import AttackSpec, Target
from ildottore.store import ReplayResult, SqliteRunStore

__all__ = [
    "Applicability",
    "EspIaError",
    "RequirementRow",
    "applicability",
    "evidence_document",
    "render_applicability",
    "render_applicability_json",
]

#: What every view prints under its figures: the line between this tool and a laboratory.
FALSIFICATION_NOTE = (
    "A spec that FAILS is evidence against the requirement. One that passes did not falsify it, "
    "which is not the same as meeting it: only an accredited laboratory, applying the CCN's test "
    "guides, says PASS."
)

#: Every rule but ``RP02`` carries a condition between the declared architecture elements.
CONDITION_NOTE = (
    "The guide also attaches a condition between declared architecture elements to every rule "
    "but RP02. With one target this reads it as met whenever the answers are: check each rule "
    "against the architecture in the Security Declaration."
)


class EspIaError(ValueError):
    """The ESP-IA view cannot be built as asked (no answers, another target, no run record)."""


@dataclass(frozen=True)
class RequirementRow:
    """One applicable requirement, and what the battery can say about it on this target."""

    code: str
    source: str
    #: The rules that made it apply, in the guide's order.
    rules: tuple[str, ...]
    #: Spec ids that declare it and would be sent to this target.
    runs: tuple[str, ...] = ()
    #: ``(spec_id, why)`` for the ones that declare it and would not.
    blocked: tuple[tuple[str, str], ...] = ()
    out_of_reach: str | None = None
    by_design: str | None = None


@dataclass(frozen=True)
class Applicability:
    target_id: str
    answers: Mapping[str, bool]
    rules: tuple[EspIaRule, ...]
    rows: tuple[RequirementRow, ...]
    specs: int


def _answers(target: Target) -> Mapping[str, bool]:
    if target.esp_ia is None:
        raise EspIaError(
            f"target {target.id!r} has no 'esp_ia: answers:' block; the matrix needs the vendor's "
            f"yes or no to each of {ESP_IA_QUESTIONS[0]} to {ESP_IA_QUESTIONS[-1]}"
        )
    return target.esp_ia.answers


def _applicable(answers: Mapping[str, bool]) -> tuple[tuple[EspIaRule, ...], dict[str, list[str]]]:
    """The rules met, and each requirement they make applicable with the rules behind it."""

    rules = applicable_rules(answers)
    by_code: dict[str, list[str]] = {}
    for rule in rules:
        for code in rule.requirements:
            by_code.setdefault(code, []).append(rule.code)
    # The guide's requirement order, not the order the rules happened to name them in.
    return rules, {c: by_code[c] for c in ESP_IA_REQUIREMENTS if c in by_code}


def applicability(target: Target, specs: Iterable[AttackSpec], *, uses_mock: bool) -> Applicability:
    """The matrix over ``target``'s answers, and what ``specs`` can do about each requirement.

    A spec is blocked for the reasons the plan of ``dottore run`` would give: a capability the
    target does not declare, then, for a live target, a scene it does not hold (``delivery_gap``).
    An offline mock replays its fixtures, which hold the scene, as the plan reads it.
    """

    answers = _answers(target)
    rules, applicable = _applicable(answers)
    spec_list = list({spec.id: spec for spec in specs}.values())
    plan = build_plan(
        spec_list, None, target.capabilities, target_id=target.id, plan_ref="esp-ia-applicability"
    )
    why: dict[str, str] = {skip.spec_id: skip.reason for skip in plan.skipped}
    if not uses_mock:
        for spec in spec_list:
            if spec.id not in why and (gap := delivery_gap(spec, target)) is not None:
                why[spec.id] = gap
    rows = []
    for code, rule_codes in applicable.items():
        declaring = [s.id for s in spec_list if code in (s.esp_ia or [])]
        rows.append(
            RequirementRow(
                code=code,
                source=ESP_IA_REQUIREMENTS[code],
                rules=tuple(rule_codes),
                runs=tuple(s for s in declaring if s not in why),
                blocked=tuple((s, why[s]) for s in declaring if s in why),
                out_of_reach=ESP_IA_OUT_OF_REACH.get(code),
                by_design=ESP_IA_NOT_TESTED_BY_DESIGN.get(code),
            )
        )
    return Applicability(
        target_id=target.id,
        answers=answers,
        rules=rules,
        rows=tuple(rows),
        specs=len(spec_list),
    )


def _sources(rows: Iterable[RequirementRow]) -> list[str]:
    return list(dict.fromkeys(row.source for row in rows))


def _row_status(row: RequirementRow) -> str:
    if row.out_of_reach is not None:
        return f"out of reach: {row.out_of_reach}"
    if row.by_design is not None:
        return f"deliberately not tested: {row.by_design}"
    if row.runs:
        return f"{len(row.runs)} spec(s) would run"
    if row.blocked:
        return "every spec that tests it is blocked on this target"
    return "no spec tests it yet (roadmap)"


def _reason_code(why: str) -> str:
    """``setup_not_seeded`` of ``setup_not_seeded: this spec needs ...``; a missing capability
    keeps its names (``capability_unavailable (memory)``), which say it all."""

    code, _, rest = why.partition(":")
    if code == "capability_unavailable":
        return f"{code} ({rest.rsplit('declare', 1)[-1].strip()})"
    return code


def render_applicability(result: Applicability) -> str:
    """Human-readable matrix result for one target, no scan performed.

    A blocked spec prints its reason's code; each reason in full is printed once, at the end.
    """

    yes = [q for q, answer in result.answers.items() if answer]
    lines = [
        f"ESP-IA applicability for target {visible_controls(result.target_id)} "
        f"(CCN-STIC-2011 ESP-IA {ESP_IA_VERSION}; {result.specs} specs read, no scan performed)",
        "",
        f"  Answered yes: {len(yes)} of {len(result.answers)} ({', '.join(yes) or 'none'})",
        f"  Rules met:    {' '.join(r.code for r in result.rules) or 'none'}",
        f"  Threats and policies: {', '.join(_sources(result.rows)) or 'none'}",
        f"  Requirements that apply: {len(result.rows)} of {len(ESP_IA_REQUIREMENTS)}",
    ]
    reasons: dict[str, str] = {}
    for row in result.rows:
        lines += ["", f"  {row.code}  {row.source}  (rule {', '.join(row.rules)})"]
        lines.append(f"    {_row_status(row)}")
        if row.runs:
            lines.append(f"    runs: {', '.join(row.runs)}")
        grouped: dict[str, list[str]] = {}
        for spec_id, why in row.blocked:
            grouped.setdefault(_reason_code(why), []).append(spec_id)
            if not why.startswith("capability_unavailable"):
                reasons.setdefault(_reason_code(why), why)
        for code, spec_ids in grouped.items():
            lines.append(f"    blocked, {code}: {', '.join(spec_ids)}")
    if reasons:
        lines += ["", "  Why a spec is blocked (what `dottore run` would say):"]
        lines += [f"    {visible_controls(why)}" for why in reasons.values()]
    lines += ["", f"  {CONDITION_NOTE}", f"  {FALSIFICATION_NOTE}"]
    return "\n".join(lines)


def render_applicability_json(result: Applicability) -> str:
    """Machine-readable form of :func:`render_applicability`."""

    payload = {
        "framework": "ccn_esp_ia",
        "edition": ESP_IA_VERSION,
        "target_id": result.target_id,
        "specs": result.specs,
        "answers": dict(result.answers),
        "rules": [r.code for r in result.rules],
        "sources": _sources(result.rows),
        "requirements": [
            {
                "code": row.code,
                "source": row.source,
                "rules": list(row.rules),
                "runs": list(row.runs),
                "blocked": [{"spec_id": s, "reason": why} for s, why in row.blocked],
                "out_of_reach": row.out_of_reach,
                "not_tested_by_design": row.by_design,
            }
            for row in result.rows
        ],
        "notes": [CONDITION_NOTE, FALSIFICATION_NOTE],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


# --- the Annex B-shaped evidence draft (u12 A-118) -----------------------------------------


def _target_checked(target: Target, context: Mapping[str, Any], run_id: str) -> None:
    """Refuse the answers of a target file that is not the one the run scanned."""

    stored = context.get("target_digest")
    route = context.get("route")
    mock_scenario = route if isinstance(route, str) and route != "live" else None
    if stored is None:
        raise EspIaError(f"run {run_id!r} recorded no target digest; its target cannot be matched")
    if target_digest(target, mock_scenario=mock_scenario) != stored:
        raise EspIaError(
            f"the target file is not the one run {run_id!r} scanned (its digest differs): the "
            "answers of another target would label this run's evidence"
        )


def _result(findings: Sequence[Mapping[str, Any]]) -> str:
    statuses = {f["status"] for f in findings}
    if not findings:
        return "no test in this run"
    if VerdictStatus.FAIL.value in statuses:
        return "**FAIL evidence**"
    if statuses == {VerdictStatus.PASS.value}:
        return "not falsified"
    return "inconclusive"


def _cell(text: str) -> str:
    """Table-safe text: control characters written out, pipes escaped, one line."""

    return visible_controls(text).replace("|", "\\|").replace("\n", " ")


def evidence_document(
    result: ReplayResult,
    store: SqliteRunStore,
    specs: Mapping[str, AttackSpec],
    *,
    target: Target | None = None,
) -> str:
    """The Markdown draft for ``result``'s run, shaped like Annex B of CCN-STIC-2011.

    ``specs`` is the battery read now: a spec whose digest still matches the one the run
    recorded lends its ``esp_ia`` list and its text; any other is named as changed and counts
    for no requirement. ``target`` is the target file with the vendor's answers; without it,
    every requirement is listed and sections 2.4 and 2.5 say how to fill them.
    """

    run_id = result.run_id
    if not store.knows_run(run_id):
        raise EspIaError(f"the run store has no record of run {run_id!r}: the draft needs it")
    run_row = store.get_run(run_id) or {}
    context = store.get_run_context(run_id) or {}
    recorded = store.get_run_spec_digests(run_id) or {}
    findings = store.list_findings(run_id)
    answers: Mapping[str, bool] | None = None
    if target is not None:
        _target_checked(target, context, run_id)
        answers = _answers(target)

    current: dict[str, AttackSpec] = {}
    changed: list[str] = []
    for spec_id in sorted({f["spec_id"] for f in findings}):
        spec = specs.get(spec_id)
        if spec is not None and recorded.get(spec_id) == spec_digest(spec):
            current[spec_id] = spec
        else:
            changed.append(spec_id)
    by_requirement: dict[str, list[Mapping[str, Any]]] = {}
    for finding in findings:
        spec = current.get(finding["spec_id"])
        for code in (spec.esp_ia or []) if spec is not None else []:
            by_requirement.setdefault(code, []).append(finding)

    if answers is not None:
        rules, applicable = _applicable(answers)
        codes = list(applicable)
    else:
        rules, applicable = (), {}
        codes = list(ESP_IA_REQUIREMENTS)

    lines = _introduction(run_id, run_row, context, target)
    lines += _description(rules, applicable, answers)
    lines += _results(codes, by_requirement)
    lines += _test_cases(findings, current, changed, str(run_row.get("target_id")))
    lines += _left_to_the_laboratory()
    return "\n".join(lines) + "\n"


def _introduction(
    run_id: str,
    run_row: Mapping[str, Any],
    context: Mapping[str, Any],
    target: Target | None,
) -> list[str]:
    return [
        f"# ESP-IA evidence draft: run `{run_id}`",
        "",
        f"> Shaped like Annex B of CCN-STIC-2011 ESP-IA {ESP_IA_VERSION} (the Evaluation Technical "
        "Report), and **not one**: a laboratory's ETR is written by its evaluators against the "
        "CCN's test guides. This draft records what one Il Dottore run falsified, from its "
        f"hash-verified evidence. {FALSIFICATION_NOTE}",
        "",
        "## 1. Introduction",
        "",
        "Numbered as Annex B is. Sections 3, 5 and 6 (executive summary, analysis of the "
        "Security Declaration, test environment) are the laboratory's and are left out.",
        "",
        f"* **Run:** `{run_id}`, started {run_row.get('started_at')}, finished "
        f"{run_row.get('finished_at')}, {run_row.get('n_runs')} repetition(s) per attempt",
        f"* **Tool:** Il Dottore {context.get('tool_version')}, judging rules "
        f"{context.get('judging_rules')} (digest `{context.get('judging_digest')}`)",
        f"* **Target:** `{visible_controls(str(run_row.get('target_id')))}`, digest "
        f"`{context.get('target_digest')}`"
        + ("" if target is None else ", matched against the target file given"),
        f"* **Framework:** CCN-STIC-2011 ESP-IA {ESP_IA_VERSION}; requirement codes only, the "
        "guide's text is not reproduced",
        "",
    ]


def _description(
    rules: tuple[EspIaRule, ...],
    applicable: Mapping[str, list[str]],
    answers: Mapping[str, bool] | None,
) -> list[str]:
    lines = ["## 2. Target of evaluation", ""]
    lines += [
        "Sections 2.1 to 2.3 (functional description, architecture, security problem) come from "
        "the vendor's Security Declaration (Annex A) and are not something a run can write.",
        "",
        "### 2.4 Applicable requirements",
        "",
    ]
    if answers is None:
        lines += [
            "Not computed: pass `--target FILE` with the vendor's `esp_ia: answers:` to apply "
            "the matrix. Section 4 lists all 27 requirements meanwhile.",
            "",
            "### 2.5 Applicable threats and policies",
            "",
            "Not computed, for the same reason.",
            "",
        ]
        return lines
    yes = [q for q, answer in answers.items() if answer]
    lines += [
        f"Answered yes: {', '.join(yes) or 'none'}. Rules met: "
        f"{' '.join(r.code for r in rules) or 'none'}. {CONDITION_NOTE}",
        "",
        "| Requirement | Threat or policy | Rules |",
        "|---|---|---|",
    ]
    lines += [
        f"| {code} | {ESP_IA_REQUIREMENTS[code]} | {', '.join(rule_codes)} |"
        for code, rule_codes in applicable.items()
    ]
    sources = list(dict.fromkeys(ESP_IA_REQUIREMENTS[c] for c in applicable))
    lines += [
        "",
        "### 2.5 Applicable threats and policies",
        "",
        ", ".join(sources) or "None.",
        "",
    ]
    return lines


def _results(codes: list[str], by_requirement: Mapping[str, list[Mapping[str, Any]]]) -> list[str]:
    lines = [
        "## 4. Results by requirement",
        "",
        "| Requirement | Tests | Result in this run |",
        "|---|---|---|",
    ]
    for code in codes:
        found = by_requirement.get(code, [])
        tests = ", ".join(f"PR_{f['spec_id']}" for f in found) or "none"
        if code in ESP_IA_OUT_OF_REACH:
            outcome = f"out of reach for a black-box scanner: {ESP_IA_OUT_OF_REACH[code]}"
        elif code in ESP_IA_NOT_TESTED_BY_DESIGN:
            outcome = f"deliberately not tested: {ESP_IA_NOT_TESTED_BY_DESIGN[code]}"
        else:
            outcome = _result(found)
        lines.append(f"| {code} | {tests} | {_cell(outcome)} |")
    lines += [
        "",
        "**Verdict of the evaluation:** not given by this tool. The guide's verdict needs every "
        "applicable requirement to pass against the CCN's criteria, no non-conformity, and no AI "
        "vulnerability from the additional penetration testing that compromises the product.",
        "",
    ]
    return lines


def _test_cases(
    findings: Sequence[Mapping[str, Any]],
    current: Mapping[str, AttackSpec],
    changed: list[str],
    target_id: str,
) -> list[str]:
    lines = ["## 7. Requirement verification: one test case per spec", ""]
    if changed:
        lines += [
            f"Changed since the run (digest differs) or not in the specs read now, so counted "
            f"for no requirement: {', '.join(changed)}.",
            "",
        ]
    for finding in findings:
        spec = current.get(finding["spec_id"])
        if spec is None or not spec.esp_ia:
            continue
        refs = json.loads(finding["evidence_refs_json"])
        hashes = sorted({ref["sha256"] for ref in refs})
        shown = ", ".join(f"`{h[:12]}`" for h in hashes[:5])
        more = f" and {len(hashes) - 5} more" if len(hashes) > 5 else ""
        expected = "; ".join(spec.expected_secure_behavior)
        lines += [
            f"### PR_{spec.id}",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Test code | PR_{spec.id} |",
            f"| Requirements verified | {', '.join(spec.esp_ia)} |",
            "| CCN test guide applied | none: the spec is the oracle; name the CCN guide here |",
            "| Evaluator | to be filled in by the laboratory |",
            "| Affected elements | to be filled in: the I-, M-, D- and S- elements the "
            "Security Declaration names |",
            f"| Objective | {_cell(spec.name)} |",
            f"| Scenario | target `{_cell(target_id)}`; the spec is written for a "
            f"{spec.target_type.value} (OWASP {spec.owasp}) |",
            f"| Procedure | {_cell(' '.join(spec.description.split()))} |",
            f"| Expected results | {_cell(expected)} |",
            f"| Obtained results | {finding['status']}, severity {finding['severity']}, "
            f"reproducibility {finding['repro']}; evidence {shown}{more} |",
            f"| Conclusion | {_conclusion(finding['status'])} |",
            "",
        ]
    return lines


def _conclusion(status: str) -> str:
    if status == VerdictStatus.FAIL.value:
        return "evidence against the requirements above (`dottore replay --pack` reproduces it)"
    if status == VerdictStatus.PASS.value:
        return "not falsified by these probes; not a PASS"
    return "inconclusive: neither evidence against nor a clean result"


def _left_to_the_laboratory() -> list[str]:
    return [
        "## 8. Additional penetration testing",
        "",
        "Not part of this run. The guide asks the laboratory for at least three person-days, "
        "with the OWASP AI Testing Guide as the minimum reference.",
        "",
        "## 9. Observation reports and non-conformities",
        "",
        "To be filled in by the laboratory.",
    ]
