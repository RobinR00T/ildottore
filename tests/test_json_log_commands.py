"""A JSON output carries no CI log command, and reads as the same data (OD-20, 2026-10-11).

A GitHub Actions runner reads the legacy ``##[<command>]`` form anywhere in a line of a step's
output, and the Azure Pipelines agent ``##vso[<area>.<event>]`` (see
``tests/test_terminal_log_commands.py``, which checks the text outputs with the runners' own
parsers). The text outputs write the second ``#`` of ``##<letters>[`` as ``\\x23``; the JSON
outputs kept every value as it is, so ``lint --json``, ``coverage --json``, ``dottore
fingerprint``, the JSON report and the SARIF report, printed to a CI log, still carried one from a
pack's file name or a target id.

Decided on 2026-10-11 under the owner's delegation (best practice), revisable: every JSON output
writes that ``#`` as ``\\u0023``, the escape JSON gives every character (RFC 8259 §7). Any JSON
reader parses the same value: these tests check that the parsed document is the one the plain
serializer wrote, and that serializing it again with the output's own options gives the plain
bytes back, byte for byte.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from ildottore.cli.app import app
from ildottore.redactor import log_safe_json

REPO = Path(__file__).resolve().parents[1]

#: Any ``##<letters>[`` written raw: what either runner needs to read a command.
_RAW_PREFIX = re.compile(r"##[A-Za-z]*\[")

#: The ``json.dumps`` options of each JSON output (lint, coverage and the schema export use the
#: defaults with an indent and sorted keys; the reporters the ASCII form with explicit separators;
#: the fingerprint fallback an indent alone), and two the outputs do not use, to show the rule
#: does not depend on them.
_OPTIONS: list[dict[str, Any]] = [
    {"indent": 2, "sort_keys": True},
    {"sort_keys": True, "ensure_ascii": True, "indent": 2, "separators": (",", ": ")},
    {"indent": 2},
    {"ensure_ascii": False},
    {"separators": (",", ":")},
]

#: Strings rich in what the rule and JSON's escapes are made of.
_TEXT = st.text(alphabet=st.sampled_from(list('#[]\\"u0023aZvso \n\t/\u00e9\u2028')), max_size=24)
_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | _TEXT,
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(_TEXT, inner, max_size=4),
    max_leaves=12,
)


@pytest.mark.parametrize(
    ("plain", "written"),
    [
        ('"x ##[error file=a.py]pwned"', '"x #\\u0023[error file=a.py]pwned"'),
        ('"##vso[task.setvariable variable=X]1"', '"#\\u0023vso[task.setvariable variable=X]1"'),
        ('"##VSO[task.setvariable variable=X]1"', '"#\\u0023VSO[task.setvariable variable=X]1"'),
        ('"###[error]x"', '"##\\u0023[error]x"'),
        ('"\\\\##[error]x"', '"\\\\#\\u0023[error]x"'),
        ('{"##[k]": "##[v]"}', '{"#\\u0023[k]": "#\\u0023[v]"}'),
    ],
)
def test_the_second_hash_is_written_as_its_json_escape(plain: str, written: str) -> None:
    assert log_safe_json(plain) == written
    assert json.loads(written) == json.loads(plain)


@pytest.mark.parametrize(
    "plain", ['"# [x]"', '"#[x]"', '"## [x]"', '"##1[x]"', '"x##"', '{"a": 1}']
)
def test_json_without_a_command_is_written_as_it_was(plain: str) -> None:
    assert log_safe_json(plain) == plain


@settings(max_examples=400, deadline=None)
@given(value=_JSON, options=st.sampled_from(_OPTIONS))
def test_the_escaped_document_is_the_same_data_byte_for_byte(
    value: object, options: dict[str, Any]
) -> None:
    plain = json.dumps(value, **options)
    escaped = log_safe_json(plain)
    assert json.loads(escaped) == json.loads(plain)
    # Serialized again with the output's own options, the parsed document is the plain bytes.
    assert json.dumps(json.loads(escaped), **options) == plain
    assert _RAW_PREFIX.search(escaped) is None
    assert log_safe_json(escaped) == escaped
    if _RAW_PREFIX.search(plain) is None:
        assert escaped == plain


# --- every JSON output, through the CLI ----------------------------------------------------

_FILE_NAME = "x ##[error file=a.py,line=1]pwned.yaml"
_TARGET_ID = "t ##vso[task.setvariable variable=GATE]pass"


def _good() -> str:
    return (REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text()


def _broken_pack(root: Path) -> Path:
    pack = root / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: pack\npack_version: '1.0'\nname: pack\n")
    (pack / "attacks" / "PI-DIRECT-001.yaml").write_text(_good())
    broken = _good().replace("id: PI-DIRECT-001", "id: PI-TYPO-001").replace("severity:", "sev:")
    (pack / "attacks" / _FILE_NAME).write_text(broken)
    return pack


def _scope_and_target(root: Path) -> tuple[Path, Path]:
    scope, target = root / "scope.yaml", root / "target.yaml"
    scope.write_text(
        f'version: "1.0"\ntargets:\n  - id: "{_TARGET_ID}"\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    target.write_text(
        f'id: "{_TARGET_ID}"\ntype: chatbot\nmock_scenario: hardened\n'
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    return scope, target


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


def _assert_safe_and_same(text: str, carried: str) -> None:
    """``text`` carries no raw command, and its parsed data holds ``carried`` as it was."""

    assert _RAW_PREFIX.search(text) is None, text
    assert "#\\u0023" in text
    document = json.loads(text)
    assert any(carried in s for s in _strings(document))
    # The bytes are the plain serializer's but for the escape: undo it and nothing else differs.
    assert log_safe_json(text.replace("#\\u0023", "##")) == text


@pytest.mark.parametrize("command", ["coverage", "lint"])
def test_lint_and_coverage_json_carry_no_command(tmp_path: Path, command: str) -> None:
    result = CliRunner().invoke(app, [command, "--json", str(_broken_pack(tmp_path))])
    _assert_safe_and_same(result.stdout, _FILE_NAME)


def test_the_fingerprint_json_carries_no_command(tmp_path: Path) -> None:
    scope, target = _scope_and_target(tmp_path)
    argv = ["fingerprint", str(target), "--scope", str(scope), "--offline"]
    result = CliRunner().invoke(app, argv)
    assert result.exit_code == 0, result.output
    _assert_safe_and_same(result.stdout, _TARGET_ID)
    assert json.loads(result.stdout)["target_id"] == _TARGET_ID


def test_the_json_and_sarif_reports_carry_no_command(tmp_path: Path) -> None:
    scope, target = _scope_and_target(tmp_path)
    argv = [
        *("run", "-t", str(target), "--scope", str(scope), "--spec", "PI-DIRECT-001"),
        *("--runs", "1", "--evidence-root", str(tmp_path / "ev"), "--run-db"),
        *(str(tmp_path / "r.sqlite"), "--no-color", "-q"),
        *("-oJ", str(tmp_path / "r.json"), "-oS", str(tmp_path / "r.sarif")),
    ]
    result = CliRunner().invoke(app, argv)
    assert result.exit_code == 0, result.output
    for name in ("r.json", "r.sarif"):
        _assert_safe_and_same((tmp_path / name).read_text(encoding="utf-8"), _TARGET_ID)
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert report["run"]["targets"][0]["id"] == _TARGET_ID


def test_the_schema_export_is_json_the_rule_leaves_alone() -> None:
    result = CliRunner().invoke(app, ["schema", "export"])
    assert result.exit_code == 0, result.output
    assert log_safe_json(result.stdout) == result.stdout
    json.loads(result.stdout)
