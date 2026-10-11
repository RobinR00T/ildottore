"""Versions are read, a report is recognised, and the report schema says what a report holds
(u11 and u12 A-82; CLI audit of 2026-10-11, L4, L5 and L7).

* L4: ``dottore diff`` compared reports declaring ``schema_version`` ``2.0``, ``9.0`` or none, and a
  SARIF log passed by mistake gave ``error: 'findings'``. A JSON run report is read when its
  ``schema_version`` is ``1`` or ``1.<minor>`` (report-1.0 grows additively); one without it, one
  of another major version, a SARIF log and a document with no ``findings`` list are each refused
  on a line that says which it is. A bare list of findings is still read, as documented.
* L5: ``report-1.0.schema.json`` constrained only ``summary``; ``run`` and each item of
  ``findings`` were bare objects, and ``dottore schema export`` could not print it. They now
  name their required keys and the types and ranges of what a finding's verdict rests on, with
  ``additionalProperties`` left open (the version note: report-1.0 grows additively, so an older
  report validates against this copy), and ``schema export --name report`` prints it.
* L7: a scope's and a fleet file's ``version`` took any text. Both are ``1`` or ``1.<minor>``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app
from ildottore.reporting import report_schema

from .conftest import write_scope, write_target

runner = CliRunner()
_REPO = Path(__file__).resolve().parents[2]
#: Reports two earlier builds wrote, kept as they were written: ``f12ba833`` (#95) and
#: ``6d5f7ae3`` (#104), a live judged run of 40 attempts each, from the CLI audit of 2026-10-11.
_OLD_REPORTS = sorted((_REPO / "tests" / "fixtures" / "reports").glob("report-*.json"))
#: A directory of further reports to check (the audit's 88, written by ``f12ba833``,
#: ``6d5f7ae3`` and ``de122e26``): set to run the corpus test, which skips without it.
_CORPUS = "DOTTORE_REPORT_CORPUS"


def _report(tmp_path: Path, name: str, *extra: str, scenario: str = "vulnerable") -> Path:
    out = tmp_path / f"{name}.json"
    result = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(write_target(tmp_path, mock_scenario=scenario)),
            "--scope",
            str(write_scope(tmp_path)),
            "--spec",
            "PI-DIRECT-001",
            "--spec",
            "DL-SYSPROMPT-001",
            "--runs",
            "1",
            "-q",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "r.db"),
            "-oJ",
            str(out),
            *extra,
        ],
    )
    assert result.exit_code in (0, 1, 2), result.output
    return out


def _diff(a: Path, b: Path) -> Any:
    return runner.invoke(app, ["diff", str(a), str(b)])


def _rewrite(path: Path, change: Any, name: str) -> Path:
    data = json.loads(path.read_text())
    change(data)
    out = path.with_name(name)
    out.write_text(json.dumps(data))
    return out


# --- L4: diff reads report schema 1 -------------------------------------------------------


@pytest.mark.parametrize("version", ["2.0", "9.0", "0.9", "1.0.1.x", 1.0, None])
def test_diff_refuses_a_report_of_another_version(tmp_path: Path, version: object) -> None:
    good = _report(tmp_path, "good")

    def set_version(data: dict[str, Any]) -> None:
        if version is None:
            del data["schema_version"]
        else:
            data["schema_version"] = version

    other = _rewrite(good, set_version, "other.json")
    for a, b in ((good, other), (other, good)):
        result = _diff(a, b)
        assert result.exit_code == 3, result.output
        said = result.output.replace("\n", "")
        if version is None:
            assert "has no schema_version, so it is not a JSON run report" in said
        else:
            assert "this build reads report schema 1 (1.0, or 1.<minor>)" in said


@pytest.mark.parametrize("version", ["1", "1.0", "1.7"])
def test_diff_reads_every_minor_version_of_one(tmp_path: Path, version: str) -> None:
    good = _report(tmp_path, "good")
    minor = _rewrite(good, lambda d: d.__setitem__("schema_version", version), "minor.json")
    assert _diff(good, minor).exit_code == 0


def test_diff_recognises_a_sarif_log(tmp_path: Path) -> None:
    good = _report(tmp_path, "good", "-oS", str(tmp_path / "good.sarif"))
    result = _diff(good, tmp_path / "good.sarif")
    assert result.exit_code == 3, result.output
    assert "is a SARIF log (-oS), not the JSON run report (-oJ) that dottore diff compares" in (
        result.output.replace("\n", "")
    )
    assert "'findings'" not in result.output


def test_diff_recognises_a_document_with_no_findings(tmp_path: Path) -> None:
    good = _report(tmp_path, "good")
    bare = _rewrite(good, lambda d: d.pop("findings"), "bare.json")
    result = _diff(good, bare)
    assert result.exit_code == 3, result.output
    assert "has no findings list" in result.output.replace("\n", "")


def test_a_bare_list_of_findings_is_still_read(tmp_path: Path) -> None:
    good = _report(tmp_path, "good")
    listed = tmp_path / "list.json"
    listed.write_text(json.dumps(json.loads(good.read_text())["findings"]))
    assert _diff(good, listed).exit_code == 0


def test_calibrate_refuses_another_version_too(tmp_path: Path) -> None:
    good = _report(tmp_path, "good")
    other = _rewrite(good, lambda d: d.__setitem__("schema_version", "2.0"), "other.json")
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-DIRECT-001: fail\n")
    result = runner.invoke(app, ["calibrate", str(other), str(labels)])
    assert result.exit_code == 3, result.output
    assert "this build reads report schema 1" in result.output.replace("\n", "")


# --- L5: the report schema says what a report holds ---------------------------------------


def test_schema_export_prints_the_report_schema() -> None:
    result = runner.invoke(app, ["schema", "export", "--name", "report"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == report_schema()
    everything = json.loads(runner.invoke(app, ["schema", "export"]).output)
    assert everything["report"] == report_schema()


def test_the_report_schema_constrains_run_and_findings() -> None:
    schema = report_schema()
    run = schema["properties"]["run"]
    assert set(run["required"]) >= {"run_id", "targets", "findings", "summary"}
    finding = schema["definitions"]["finding"]
    assert set(finding["required"]) == {"spec_id", "target_id", "status", "risk", "confirmed"}
    assert schema["properties"]["findings"]["items"] == {"$ref": "#/definitions/finding"}
    # Open, by the version note: report-1.0 grows additively.
    assert run["additionalProperties"] is True and finding["additionalProperties"] is True
    assert "grows additively" in schema["description"]


@pytest.mark.parametrize(
    ("change", "where"),
    [
        (lambda d: d["findings"][0].__setitem__("status", "maybe"), "status"),
        (lambda d: d["findings"][0]["risk"].__setitem__("risk", 99), "risk"),
        (lambda d: d["findings"][0]["risk"].__setitem__("band", "severe"), "band"),
        (lambda d: d["findings"][0].pop("spec_id"), "spec_id"),
        (lambda d: d["findings"][0].__setitem__("confirmed", "yes"), "confirmed"),
        (lambda d: d["run"].pop("run_id"), "run_id"),
        (lambda d: d["run"].__setitem__("targets", {}), "targets"),
        (lambda d: d["run"]["findings"][0].__setitem__("status", "maybe"), "status"),
        (lambda d: d["run"].__setitem__("scope_sha256", 5), "scope_sha256"),
    ],
)
def test_a_report_that_breaks_them_fails_the_schema(
    tmp_path: Path, change: Any, where: str
) -> None:
    doc = json.loads(_report(tmp_path, "good").read_text())
    jsonschema.validate(doc, report_schema())
    change(doc)
    with pytest.raises(jsonschema.ValidationError) as info:
        jsonschema.validate(doc, report_schema())
    assert where in str(info.value)


@pytest.mark.parametrize("scenario", ["vulnerable", "hardened", "bare"])
def test_every_report_this_build_writes_still_validates(tmp_path: Path, scenario: str) -> None:
    doc = json.loads(_report(tmp_path, scenario, scenario=scenario).read_text())
    jsonschema.validate(doc, report_schema())


@pytest.mark.parametrize("path", _OLD_REPORTS, ids=[p.stem for p in _OLD_REPORTS])
def test_a_report_an_earlier_build_wrote_still_validates(path: Path) -> None:
    jsonschema.validate(json.loads(path.read_text(encoding="utf-8")), report_schema())


def _corpus() -> list[Path]:
    root = os.environ.get(_CORPUS)
    if not root:
        return []
    found = []
    for path in sorted(Path(root).rglob("*.json")):
        if {"attempts", "probes"} & set(path.parts) or "/diff-" in path.as_posix():
            continue  # evidence, and the audit's hand-broken inputs of its diff cases
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if isinstance(data, dict) and "schema_version" in data and "run" in data:
            found.append(path)
    return found


@pytest.mark.skipif(not os.environ.get(_CORPUS), reason=f"{_CORPUS} is not set")
def test_every_report_of_a_corpus_still_validates() -> None:
    reports = _corpus()
    assert reports
    schema = report_schema()
    for path in reports:
        jsonschema.validate(json.loads(path.read_text(encoding="utf-8")), schema)


# --- L7: a scope's and a fleet file's version ---------------------------------------------


def _scope_with(tmp_path: Path, version: str) -> Path:
    path = write_scope(tmp_path)
    path.write_text(path.read_text().replace('version: "1.0"', f"version: {version}", 1))
    return path


@pytest.mark.parametrize("version", ['"2.0"', '"0.1"', '"v1"', '"latest"', '""', '"1.0.0"'])
def test_a_scope_of_another_version_is_refused(tmp_path: Path, version: str) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(write_target(tmp_path, mock_scenario="vulnerable")),
            "--scope",
            str(_scope_with(tmp_path, version)),
            "--dry-run",
        ],
    )
    assert result.exit_code == 3, result.output
    assert "this build reads scope version 1 (1.0, or 1 or 1.<minor>: write" in (
        result.output.replace("\n", "")
    )


@pytest.mark.parametrize("version", ['"1"', '"1.0"', '"1.3"'])
def test_a_scope_of_version_one_loads(tmp_path: Path, version: str) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(write_target(tmp_path, mock_scenario="vulnerable")),
            "--scope",
            str(_scope_with(tmp_path, version)),
            "--dry-run",
            "-q",
        ],
    )
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(("version", "ok"), [('"1"', True), ('"1.2"', True), ('"2"', False)])
def test_a_fleet_file_version_is_one(tmp_path: Path, version: str, ok: bool) -> None:
    (tmp_path / "fleet.yaml").write_text(
        f"version: {version}\ntargets:\n  - id: a\n    endpoint: mock://a/chat\n"
    )
    result = runner.invoke(
        app, ["fleet", str(tmp_path / "fleet.yaml"), "--out", str(tmp_path / "o")]
    )
    if ok:
        assert result.exit_code == 0, result.output
    else:
        assert result.exit_code == 3, result.output
        assert "version: Value error, this build reads fleet version 1" in result.output
        assert not (tmp_path / "o").exists()


def test_every_shipped_scope_and_fleet_still_loads() -> None:
    from ildottore.cli.fleet import load_fleet
    from ildottore.policy import load_scope

    for path in [*_REPO.glob("examples/scope*.yaml"), _REPO / "specs" / "scope.example.yaml"]:
        load_scope(path)
    for path in (_REPO / "examples" / "fleet.yaml", _REPO / "specs" / "fleet.example.yaml"):
        load_fleet(path)
