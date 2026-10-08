"""A file nested past what the CLI can hold is an operational error, not a traceback.

``json.loads`` raises ``RecursionError`` on a document nested past its stack, which is not a
``ValueError``, so the handlers of ``dottore diff`` and ``dottore calibrate`` let it through as a
traceback with exit 1: in this tool, findings below ``--fail-on``, so a CI step read a malformed
report as an almost clean result (pre-merge audit of #51, 2026-10-07). Clause A-9 (u12). The
pre-commit audit of the fix found the same exit 1 where a parsed value is formatted, and in YAML
whose anchors build a deep value from shallow text. The run store's columns, which ``replay`` and
``run --resume`` read from ``--run-db``, are in ``test_replay.py`` and
``test_resume_integrity.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import Result
from typer.testing import CliRunner

from ildottore import safe_yaml
from ildottore.cli import diff as diff_mod
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.registry.schema import SafeLoadError, safe_load_yaml

from .conftest import (
    deep_json,
    deep_yaml_anchors,
    make_spec,
    write_scope,
    write_spec_tree,
    written_nesting,
)

runner = CliRunner()

#: A report named after a commit, as CI names them: the CLI masks a high-entropy token unless
#: it is an existing path, and a colon after the path made it one that does not exist.
SHA_NAME = "report-9f86d081884c7d659a2feaa0c55ad015b3a4f6e2.json"


def error_line(result: Result) -> str:
    """The single line on stderr, an ``error:`` line (the traceback ran to dozens)."""

    lines = result.stderr.splitlines()
    assert len(lines) == 1, (result.exception, result.stderr)
    assert lines[0].startswith("error: ")
    # The message quotes none of the file.
    assert "[[" not in lines[0] and '{"a"' not in lines[0]
    return lines[0]


@pytest.mark.parametrize("shape", ["array", "object"])
@pytest.mark.parametrize("side", ["baseline", "current"])
def test_diff_refuses_a_report_nested_too_deeply(tmp_path: Path, shape: str, side: str) -> None:
    deep = tmp_path / SHA_NAME
    deep.write_text(deep_json(shape), encoding="utf-8")
    clean = tmp_path / "clean.json"
    clean.write_text("[]", encoding="utf-8")
    pair = [deep, clean] if side == "baseline" else [clean, deep]

    result = runner.invoke(app, ["diff", *map(str, pair)])

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert str(deep) in line and "nested too deeply" in line


@pytest.mark.parametrize("shape", ["array", "object"])
def test_calibrate_refuses_a_report_nested_too_deeply(tmp_path: Path, shape: str) -> None:
    report = tmp_path / SHA_NAME
    report.write_text(deep_json(shape), encoding="utf-8")
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-DIRECT-001: fail\n", encoding="utf-8")

    result = runner.invoke(app, ["calibrate", str(report), str(labels)])

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert str(report) in line and "nested too deeply" in line


def test_a_relative_report_path_keeps_its_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A CI step passes a relative path, which the CLI does not recognise as one it may keep, so
    the SHA in the name was masked: the report is named by its absolute path (delta audit)."""

    monkeypatch.chdir(tmp_path)
    (tmp_path / SHA_NAME).write_text(deep_json(), encoding="utf-8")
    (tmp_path / "clean.json").write_text("[]", encoding="utf-8")

    result = runner.invoke(app, ["diff", "clean.json", SHA_NAME])

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert SHA_NAME in line and "nested too deeply" in line


def test_a_report_name_is_written_as_it_is_on_disk(tmp_path: Path) -> None:
    """Escaping the name (`repr`) made it a path that does not exist, so the CLI masked a SHA
    named report inside a directory holding a backslash (delta audit of #61)."""

    directory = tmp_path / "back\\dir"
    directory.mkdir()
    bad = directory / SHA_NAME
    bad.write_text("{not json", encoding="utf-8")
    other = tmp_path / "other.json"
    other.write_text("[]", encoding="utf-8")

    result = runner.invoke(app, ["diff", str(other), str(bad)])

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert str(bad) in line and "not valid JSON" in line


def test_load_findings_refuses_a_report_nested_too_deeply(tmp_path: Path) -> None:
    """The commands read the file through `incomplete_reason` first, so this is the reader
    `diff_reports` and `calibrate_reports` reach on their own."""

    deep = tmp_path / "deep.json"
    deep.write_text(deep_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="nested too deeply") as caught:
        diff_mod.load_findings(deep)
    assert str(deep) in str(caught.value)


def _halted_report(tmp_path: Path, status: str) -> Path:
    """A report whose run status says it did not complete, with ``status`` spliced in raw."""

    path = tmp_path / SHA_NAME
    path.write_text('{"summary": {"status": ' + status + '}, "findings": []}', encoding="utf-8")
    return path


@pytest.mark.parametrize("command", ["diff", "calibrate"])
def test_a_run_status_nested_too_deeply_is_not_formatted(tmp_path: Path, command: str) -> None:
    """On 3.14 the parser holds 100,000 levels and formatting them into the refusal overflowed
    (a traceback and exit 1); an older parser refuses the file before that. Exit 3 either way."""

    report = _halted_report(
        tmp_path, '{"complete": false, "reason": ' + "[" * 100_000 + "]" * 100_000 + "}"
    )
    other = tmp_path / "other.json"
    other.write_text("[]", encoding="utf-8")
    labels = tmp_path / "labels.yaml"
    labels.write_text("{}\n", encoding="utf-8")
    args = [str(other), str(report)] if command == "diff" else [str(report), str(labels)]

    result = runner.invoke(app, [command, *args])

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert "did not complete" in line or "nested too deeply" in line


def test_a_run_status_that_is_not_text_is_not_quoted(tmp_path: Path) -> None:
    """This tool writes the state and the reason as text; anything else reads as `incomplete`."""

    report = _halted_report(
        tmp_path, '{"complete": false, "state": ["sk-quoted"], "reason": {"sk-quoted": 1}}'
    )

    assert diff_mod.incomplete_reason(report) == "incomplete"
    halted = _halted_report(tmp_path, '{"complete": false, "state": "halted", "reason": "budget"}')
    assert diff_mod.incomplete_reason(halted) == "halted: budget"


def test_calibrate_refuses_labels_nested_too_deeply(tmp_path: Path) -> None:
    """A JSON labels file is read as YAML, whose loader already refused this: kept as a guard."""

    report = tmp_path / "report.json"
    report.write_text("[]", encoding="utf-8")
    labels = tmp_path / "labels.json"
    labels.write_text(deep_json("array"), encoding="utf-8")

    result = runner.invoke(app, ["calibrate", str(report), str(labels)])

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert str(labels) in line and "nested too deeply" in line


@pytest.mark.parametrize(
    ("content", "reason"), [(b"{not json", "not valid JSON"), (b"\xff\xfe[]", "not UTF-8 text")]
)
@pytest.mark.parametrize("command", ["diff", "calibrate"])
def test_a_report_that_cannot_be_read_is_named(
    tmp_path: Path, command: str, content: bytes, reason: str
) -> None:
    """``Expecting value: line 1 column 1 (char 0)`` did not say which of two files it was."""

    bad = tmp_path / SHA_NAME
    bad.write_bytes(content)
    other = tmp_path / "other.json"
    other.write_text("[]", encoding="utf-8")
    labels = tmp_path / "labels.yaml"
    labels.write_text("{}\n", encoding="utf-8")
    args = [str(other), str(bad)] if command == "diff" else [str(bad), str(labels)]

    result = runner.invoke(app, [command, *args])

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert str(bad) in line and reason in line


# --- YAML: depth built by aliases ------------------------------------------------------------


@pytest.mark.parametrize("load", [safe_yaml.safe_load, safe_load_yaml])
def test_a_yaml_value_is_bounded_at_max_depth(load: object) -> None:
    def refused(text: str, reason: str = "nested too deeply") -> bool:
        try:
            load(text)  # type: ignore[operator]
        except (yaml.YAMLError, SafeLoadError) as exc:
            return reason in str(exc)
        return False

    limit = safe_yaml.MAX_DEPTH
    # In block style: flow style past 20 levels is refused by its own limit (A-58).
    assert not refused("- " * (limit - 1) + "[]")
    # Refused where the nesting crosses the limit, not at the top of the document.
    assert refused("- " * limit + "[]", f"line 1, column {2 * limit + 1}")
    # Through aliases: 160 levels once expanded, no nesting as written deeper than 21.
    through_aliases = deep_yaml_anchors(20, 8) + "value: *deep\n"
    assert written_nesting(through_aliases) == (21, 20)
    assert refused(through_aliases)
    # A recursive alias has no depth at all.
    assert refused("a: &loop [*loop]\n", "recursive alias")


#: Anchors and levels for the CLI cases: 80,000 levels, deep enough for `repr` to overflow on 3.14
#: (from about 69,500) as well as on older versions, with no nesting as written past 21 levels, 20
#: in flow style. With 100 levels per anchor, as here until A-58, each anchor was written 101 deep,
#: and since #84 these files were refused as they were written, not for their aliases.
ANCHORS, PER_ANCHOR = 4_000, 20


def test_calibrate_refuses_labels_deep_through_aliases(tmp_path: Path) -> None:
    """`str()` of the verdict overflowed (a traceback and exit 1)."""

    report = tmp_path / "report.json"
    report.write_text("[]", encoding="utf-8")
    labels = tmp_path / "labels.yaml"
    labels.write_text(
        deep_yaml_anchors(PER_ANCHOR, ANCHORS) + "PI-DIRECT-001: *deep\n", encoding="utf-8"
    )
    assert written_nesting(labels.read_text(encoding="utf-8")) == (21, 20)

    result = runner.invoke(app, ["calibrate", str(report), str(labels)])

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert str(labels) in line and "nested too deeply" in line


def test_run_refuses_a_target_deep_through_aliases(tmp_path: Path) -> None:
    """Printing the refused `type` overflowed in the target loader (a traceback and exit 1)."""

    target = tmp_path / "target.yaml"
    target.write_text(
        deep_yaml_anchors(PER_ANCHOR, ANCHORS) + "id: mock-target\ntype: *deep\n",
        encoding="utf-8",
    )
    assert written_nesting(target.read_text(encoding="utf-8")) == (21, 20)
    specs = write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])

    result = runner.invoke(
        app,
        [
            *("run", "-t", str(target), "--scope", str(write_scope(tmp_path))),
            *("--spec-path", str(specs), "--dry-run"),
        ],
    )

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert str(target) in line and "nested too deeply" in line


def test_lint_reports_a_spec_deep_through_aliases(tmp_path: Path) -> None:
    """The linter's text walk, which recurses in Python, overflowed on 1,600 levels from 4 KB (a
    traceback where a finding belongs): a setup document takes any key, so the chain is
    schema-valid, and it stays under the spec loader's node cap, which 80,000 levels do not."""

    specs = tmp_path / "specs"
    specs.mkdir()
    spec = json.loads(make_spec("PI-DIRECT-001").model_dump_json())
    chain = deep_yaml_anchors(20, 80, line="    - chain: {value}")
    text = yaml.safe_dump(spec, sort_keys=False) + "setup:\n  documents:\n" + chain
    assert written_nesting(text) == (24, 20)  # 1,600 levels only through the aliases
    (specs / "PI-DIRECT-001.yaml").write_text(text, encoding="utf-8")

    result = runner.invoke(app, ["lint", str(specs)])

    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "PARSE_ERROR" in result.stdout and "nested too deeply" in result.stdout
