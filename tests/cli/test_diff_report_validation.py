"""A report finding that fails validation is refused on one line naming the report, not the value.

``diff.load_findings`` handed each finding of a JSON run report to ``Finding.model_validate``
without catching its ``ValidationError``. Because that error is a ``ValueError``, ``dottore
diff`` and ``dottore calibrate`` caught it and printed pydantic's own text: several lines
(``error: 1 validation error for Finding``, the field, ``input_value='maybe-later'`` and a docs
URL) that quoted the report's value and did not say which of the files it was (pre-commit audit
of ``fix/target-file-validation``, A-45, 2026-10-07). The scope, fleet, policy-pack and target
loaders already wrapped it through ``shared/config_errors.validation_problems``. Clause A-49
(u12).
"""

from __future__ import annotations

import contextlib
import json
import tracemalloc
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner, Result

from ildottore.cli import diff as diff_mod
from ildottore.cli.app import _masked
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app

from .conftest import make_finding

runner = CliRunner()

#: Shaped like a key pasted in the wrong place: pydantic quoted it in full when it was short
#: and kept its start and its tail when it truncated it in the middle.
PASTED = "797c48a81f494d0f3e8d13bd49459b6f" * 2


def good(spec_id: str = "PI-A") -> dict[str, Any]:
    """One finding as ``JsonReporter`` writes it."""

    return make_finding(spec_id).model_dump(mode="json")


def with_field(field: str, value: object) -> list[object]:
    return [{**good(), field: value}]


def with_confidence(value: object) -> list[object]:
    finding = good()
    return [{**finding, "risk": {**finding["risk"], "confidence": value}}]


#: (findings written with the value, the value, what the line must say about it). Each value is
#: one the CLI's redactor leaves readable, so its absence from the output is the loader's doing.
BAD_FINDINGS: dict[str, tuple[Callable[[Any], list[object]], Any, str]] = {
    "status not a verdict": (
        lambda value: with_field("status", value),
        "maybe-later",
        "failed validation: findings.0.status: Input should be 'pass', 'fail' or 'inconclusive'",
    ),
    "pasted key as a boolean": (
        lambda value: with_field("confirmed", value),
        PASTED,
        "failed validation: findings.0.confirmed: Input should be a valid boolean",
    ),
    "confidence past 1": (
        with_confidence,
        7.25,
        "failed validation: findings.0.risk.confidence: Input should be less than or equal to 1",
    ),
    "unknown key": (
        lambda value: with_field("statsu", value),
        "maybe-later",
        "failed validation: findings.0.statsu: Extra inputs are not permitted",
    ),
    "finding not an object": (
        lambda value: [value],
        "maybe-later",
        "failed validation: findings.0: Input should be a valid dictionary or instance of Finding",
    ),
    "second finding": (
        lambda value: [good("PI-B"), *with_field("status", value)],
        "maybe-later",
        "failed validation: findings.1.status: Input should be 'pass', 'fail' or 'inconclusive'",
    ),
}


def write_report(path: Path, findings: list[object], *, bare: bool = False) -> Path:
    document: object = findings if bare else {"schema_version": "1.0", "findings": findings}
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def write_bad(tmp_path: Path, case: str, name: str = "bad.json") -> tuple[Path, str, str]:
    build, value, where = BAD_FINDINGS[case]
    return write_report(tmp_path / name, build(value)), str(value), where


def pieces(value: str) -> list[str]:
    """Every 8-character run of ``value`` (the whole of a shorter one), as in A-45's tests."""

    return [value[start : start + 8] for start in range(max(1, len(value) - 7))]


def refusal(result: Result, path: Path, value: str) -> str:
    """The command's one ``error:`` line, which names ``path`` and quotes no piece of ``value``,
    nor a mask the redactor put in its place."""

    assert result.exit_code == ExitCode.ERROR, (result.exception, result.output)
    lines = result.stderr.splitlines()
    assert len(lines) == 1, result.stderr
    line = lines[0]
    assert line.startswith(f"error: the report {path.absolute()} failed validation: "), line
    for leaked in ("input_value", "input_type", "errors.pydantic.dev", "validation error for"):
        assert leaked not in result.output
    for piece in pieces(value):
        assert piece not in result.output, piece
    assert "REDACTED" not in result.output
    return line


@pytest.mark.parametrize("case", sorted(BAD_FINDINGS))
def test_diff_refuses_a_bad_baseline_finding_naming_the_report(tmp_path: Path, case: str) -> None:
    bad, value, where = write_bad(tmp_path, case)
    current = write_report(tmp_path / "current.json", [good()])

    result = runner.invoke(app, ["diff", str(bad), str(current)])

    assert where in refusal(result, bad, value)


def test_diff_refuses_a_bad_current_finding_naming_the_report(tmp_path: Path) -> None:
    baseline = write_report(tmp_path / "baseline.json", [])
    bad, value, where = write_bad(tmp_path, "status not a verdict")

    result = runner.invoke(app, ["diff", str(baseline), str(bad)])

    assert where in refusal(result, bad, value)


@pytest.mark.parametrize("case", sorted(BAD_FINDINGS))
def test_calibrate_refuses_a_bad_finding_naming_the_report(tmp_path: Path, case: str) -> None:
    bad, value, where = write_bad(tmp_path, case)
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-A: pass\n", encoding="utf-8")

    result = runner.invoke(app, ["calibrate", str(bad), str(labels)])

    assert where in refusal(result, bad, value)


def test_a_bare_list_of_findings_is_refused_the_same_way(tmp_path: Path) -> None:
    build, value, where = BAD_FINDINGS["status not a verdict"]
    bad = write_report(tmp_path / "bare.json", build(value), bare=True)
    current = write_report(tmp_path / "current.json", [good()])

    result = runner.invoke(app, ["diff", str(bad), str(current)])

    assert where in refusal(result, bad, value)


def test_the_first_bad_finding_is_named_with_its_problems_in_field_order(tmp_path: Path) -> None:
    """The line is about the first finding that fails, as pydantic's was, and gives its index; its
    problems come in the model's field order whatever order the report wrote them in (`confirmed`
    first here), and a key it does not have would come after them. A later bad finding is not
    listed."""

    finding = good("PI-C")
    worse = {
        "confirmed": PASTED,
        **{key: value for key, value in finding.items() if key != "confirmed"},
        "status": "maybe-later",
        "risk": {**finding["risk"], "confidence": 7.25},
    }
    assert next(iter(worse)) == "confirmed"
    later = {**good("PI-D"), "status": "maybe-later"}
    bad = write_report(tmp_path / "bad.json", [good(), worse, later])
    current = write_report(tmp_path / "current.json", [good()])

    result = runner.invoke(app, ["diff", str(bad), str(current)])

    line = refusal(result, bad, "maybe-later")
    for piece in pieces(PASTED):
        assert piece not in result.output, piece
    reasons = [
        "failed validation: findings.1.status: Input should be",
        "; findings.1.risk.confidence: Input should be less than or equal to 1",
        "; findings.1.confirmed: Input should be a valid boolean",
    ]
    positions = [line.find(reason) for reason in reasons]
    assert -1 not in positions, (reasons, line)
    assert positions == sorted(positions), line
    assert "findings.0" not in line
    assert "findings.2" not in line


def test_validation_stops_at_the_first_bad_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validating every finding together built every error of every finding to list 20: 1,116
    MiB against 135 MiB on a 12 MB report (pre-commit audit). One at a time, nothing after the first
    bad finding is validated."""

    seen: list[object] = []
    validate = diff_mod._LocatedFinding.model_validate

    def counting(data: Any, **kwargs: Any) -> Any:
        seen.append(data)
        return validate(data, **kwargs)

    monkeypatch.setattr(diff_mod._LocatedFinding, "model_validate", counting)
    findings = [good("PI-A"), {**good("PI-B"), "status": "maybe-later"}]
    findings += [{**good(f"PI-{n}"), "status": "maybe-later"} for n in range(50)]
    bad = write_report(tmp_path / "bad.json", findings)

    with pytest.raises(ValueError, match=r"findings\.1\.status"):
        diff_mod.load_findings(bad)

    assert len(seen) == 2


def traced_peak(call: Callable[[], object]) -> int:
    """The Python memory ``call`` adds at its peak, refused or not."""

    tracemalloc.start()
    try:
        start, _ = tracemalloc.get_traced_memory()
        with contextlib.suppress(ValueError):
            call()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak - start


def test_loading_costs_no_more_than_reading_however_many_findings_fail(tmp_path: Path) -> None:
    """2,000 findings with 100 keys they do not have: loading peaks where reading the JSON does.

    The test above counts the helper's validations, and a check of every finding by another route
    before it (a `TypeAdapter` over the list, or `Finding.model_validate` keeping the errors) got
    past it and built every error again (delta audit). Both peak at about 8 times the reading here.
    A check by another route that keeps pydantic's exceptions without listing their errors is seen
    by neither test: 457 and 375 MiB against 135 MiB on a 12 MB report (pre-merge audit). That gap
    is written in clause A-49, not pinned here.
    """

    unknown = {f"unknown{n:03d}": n for n in range(100)}
    findings = [{**good(f"PI-{n}"), **unknown} for n in range(2000)]
    bad = write_report(tmp_path / "bad.json", findings)

    reading = traced_peak(lambda: diff_mod._read_report(bad))
    loading = traced_peak(lambda: diff_mod.load_findings(bad))

    assert loading < 2 * reading, (loading, reading)


def test_the_listing_stops_at_twenty_problems_and_counts_the_rest(tmp_path: Path) -> None:
    """A finding with 30 keys it does not have: the line lists 20, the spec loader's figure."""

    finding = good()
    for n in range(30):
        finding[f"extra{n:02d}"] = "maybe-later"
    bad = write_report(tmp_path / "bad.json", [finding])
    current = write_report(tmp_path / "current.json", [good()])

    result = runner.invoke(app, ["diff", str(bad), str(current)])

    line = refusal(result, bad, "maybe-later")
    assert "findings.0.extra19: Extra inputs are not permitted" in line
    assert "extra20" not in line
    assert line.endswith("; and 10 more"), line


def test_a_relative_report_path_is_named_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Named as typed, a report called after a commit SHA was masked as a high-entropy value;
    the absolute path of an existing file is kept readable (pre-commit audit)."""

    monkeypatch.chdir(tmp_path)
    name = "4f0c2a9be81d07c6f53a2e9d4b18c07f6a5e3d21.json"
    build, value, where = BAD_FINDINGS["status not a verdict"]
    write_report(tmp_path / name, build(value))
    write_report(tmp_path / "current.json", [good()])

    result = runner.invoke(app, ["diff", name, "current.json"])

    assert where in refusal(result, Path(name), value)


@pytest.mark.parametrize("case", sorted(BAD_FINDINGS))
def test_the_cli_redactor_leaves_each_value_readable(case: str) -> None:
    """Otherwise the CLI tests above could pass on a value the redactor masked, not omitted."""

    value = str(BAD_FINDINGS[case][1])
    assert value in _masked(ValueError(f"got {value} here"))


@pytest.mark.parametrize("case", sorted(BAD_FINDINGS))
def test_load_findings_raises_a_plain_value_error_not_pydantics(tmp_path: Path, case: str) -> None:
    """``diff`` and ``calibrate`` read the file through ``incomplete_reason`` first, so this is
    the reader on its own; the type check keeps pydantic's text out of a caller that prints
    ``str(exc)`` without the CLI's handler."""

    bad, value, where = write_bad(tmp_path, case)

    with pytest.raises(ValueError) as refused:
        diff_mod.load_findings(bad)

    assert type(refused.value) is ValueError
    message = str(refused.value)
    assert message.startswith(f"the report {bad.absolute()} failed validation: ")
    assert where in message
    assert "\n" not in message
    for piece in pieces(value):
        assert piece not in message, piece
