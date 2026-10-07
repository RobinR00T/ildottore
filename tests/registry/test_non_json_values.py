"""A spec value JSON cannot hold is a SCHEMA finding, not a run traceback (A-54, u02).

A spec is a JSON document written in YAML, but YAML builds more than JSON holds: an unquoted
``2026-01-01`` is a ``datetime.date``, ``!!set`` a ``set``, each entry of ``!!omap`` and
``!!pairs`` a ``tuple``, ``!!binary`` ``bytes``, and ``.nan`` and ``.inf`` floats no JSON number
writes. The JSON schema leaves a tool's ``returns``, a document, a memory entry and a fixture's
tool-call arguments free-form, so such a value passed ``dottore lint`` and ``dottore run`` then
died where it first turned the value into JSON: ``TypeError: Object of type date is not JSON
serializable``, a traceback and exit 1, which this tool uses for "findings below the threshold"
(found 2026-10-07 by the pre-commit audit of ``fix/huge-int-repr``, finding F6).
"""

from __future__ import annotations

import datetime
import decimal
import json
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from click.testing import Result
from tests.cli.conftest import write_scope
from typer.testing import CliRunner

from ildottore.cli.main import app
from ildottore.registry import LintCode, lint
from ildottore.registry.schema import validate_attack_spec_schema

runner = CliRunner()

_ROOT = Path(__file__).resolve().parents[2]
_ATTACKS = _ROOT / "specs" / "attacks"
_TOOL = "PI-INDIRECT-TOOL-001"
_RETURNS = "lookup_ticket"  # the tool whose `returns` block the tests replace
_SELFCORRECT = "AG-AUTONOMY-SELFCORRECT-001"
_VULN_ARG = 'qualifier: "bad"'
_CANNOT = "which JSON cannot hold"
_BS = chr(92)  # a backslash, so no tool or editor turns the escapes below into characters
_HALF = "half a character (a lone surrogate"


def _non_json_values(data: object) -> list[str]:
    """The walk on its own, imported here so the CLI tests run on a base without it."""

    from ildottore.registry.schema import _non_json_values as walk

    return walk(data)


def _shipped(spec_id: str) -> str:
    return (_ATTACKS / f"{spec_id}.yaml").read_text(encoding="utf-8")


def _with_returns(value: str) -> str:
    """PI-INDIRECT-TOOL-001 with its tool's multi-line ``returns`` replaced by ``value``."""

    text = _shipped(_TOOL)
    start = text.index("      returns: |\n")
    end = text.index("\nattack:")
    assert text.count("      returns: |\n") == 1  # the edit lands once, or the test proves nothing
    return text[:start] + f"      returns: {value}\n" + text[end:]


def _replaced(spec_id: str, old: str, new: str) -> str:
    text = _shipped(spec_id)
    assert text.count(old) == 1, old
    return text.replace(old, new)


def _spec_dir(tmp_path: Path, spec_id: str, text: str) -> Path:
    specs = tmp_path / "specs"
    specs.mkdir()
    (specs / f"{spec_id}.yaml").write_text(text, encoding="utf-8")
    return specs


def _lint(tmp_path: Path, spec_id: str, text: str, *extra: str) -> Result:
    return runner.invoke(app, ["lint", str(_spec_dir(tmp_path, spec_id, text)), *extra])


def _findings(result: Result) -> list[str]:
    return [line for line in result.output.splitlines() if line.startswith("[ERROR] SCHEMA")]


def _assert_finding(result: Result, spec_id: str, *fragments: str) -> str:
    """Exit 1 on one SCHEMA finding for ``spec_id``, no traceback; returns its line."""

    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "Traceback" not in result.output
    assert result.exit_code == 1, result.output
    lines = _findings(result)
    assert len(lines) == 1, result.output
    assert f"({spec_id})" in lines[0]
    for fragment in fragments:
        assert fragment in lines[0], lines[0]
    return lines[0]


_RETURNS_PATH = "setup/tools/0/returns"

# (YAML written under `returns:`, path of the finding, what the message calls the value)
_VALUES = [
    ("2026-01-01", _RETURNS_PATH, "a date (YAML reads an unquoted 2026-01-01 as one)"),
    ("2026-01-01T10:00:00Z", _RETURNS_PATH, "a timestamp (YAML reads an unquoted"),
    ("2026-01-01 10:00:00", _RETURNS_PATH, "a timestamp (YAML reads an unquoted"),
    ('!!timestamp "2026-01-01"', _RETURNS_PATH, "a date"),
    ("!!set {plain: null}", _RETURNS_PATH, "a set (!!set)"),
    ("!!set {}", _RETURNS_PATH, "a set (!!set)"),
    ("!!omap [{a: 1}]", f"{_RETURNS_PATH}/0", "a key and value pair (an entry of !!omap"),
    ("!!pairs [{a: 1}]", f"{_RETURNS_PATH}/0", "a key and value pair"),
    ("!!binary aGVsbG8=", _RETURNS_PATH, "binary data (!!binary)"),
    (".nan", _RETURNS_PATH, "NaN (YAML reads .nan as one)"),
    (".inf", _RETURNS_PATH, "an infinity (YAML reads .inf or -.inf as one)"),
    ("-.inf", _RETURNS_PATH, "an infinity"),
    ("[ok, 2026-01-01]", f"{_RETURNS_PATH}/1", "a date"),
    ("{status: ok, when: 2026-01-01}", f"{_RETURNS_PATH}/when", "a date"),
    (f'"ok {_BS}ud800"', _RETURNS_PATH, f"text holding {_HALF}"),
    # PyYAML builds each escape of a pair on its own, so even a whole emoji written this way is two
    # halves, and the walk reports the text once.
    (f'"{_BS}ud83d{_BS}ude00"', _RETURNS_PATH, f"text holding {_HALF}"),
    (f'{{"x{_BS}udfff": 1}}', f"{_RETURNS_PATH}/'x{_BS}udfff'", f"a key holding {_HALF}"),
]


@pytest.mark.parametrize(("value", "path", "kind"), _VALUES)
def test_lint_reports_a_value_json_cannot_hold(
    tmp_path: Path, value: str, path: str, kind: str
) -> None:
    line = _assert_finding(_lint(tmp_path, _TOOL, _with_returns(value)), _TOOL, f"{path}: {kind}")

    assert _CANNOT in line


def test_the_omap_and_pairs_entries_are_each_reported(tmp_path: Path) -> None:
    """Each entry is its own tuple; the list that holds them is a JSON list."""

    result = _lint(tmp_path, _TOOL, _with_returns("!!pairs [{a: 1}, {a: 2}]"))

    assert result.exit_code == 1, result.output
    lines = _findings(result)
    assert [line.split(": ", 2)[1] for line in lines] == [
        f"{_RETURNS_PATH}/0",
        f"{_RETURNS_PATH}/1",
    ]


def test_an_id_holding_half_a_character_is_reported_without_it(tmp_path: Path) -> None:
    """The finding header prints the spec id, and printing it raised ``UnicodeEncodeError``: a
    lint traceback with exit 1 for the very finding that reports it (delta audit of A-54)."""

    text = _replaced(_TOOL, f"id: {_TOOL}\n", f'id: "{_TOOL}{_BS}ud800"\n')

    result = _lint(tmp_path, _TOOL, text)

    assert "Traceback" not in result.output
    assert result.exit_code == 1, result.output
    (line,) = _findings(result)
    assert f"id: text holding {_HALF}" in line


def test_a_suite_reference_holding_half_a_character_is_reported_without_it(
    tmp_path: Path,
) -> None:
    """The unknown-reference finding printed the suite's spec id in its header, and printing it
    raised ``UnicodeEncodeError``, as for a spec's own id (pre-merge audit of A-54)."""

    pack = tmp_path / "reffy"
    (pack / "attacks").mkdir(parents=True)
    (pack / "suites").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: reffy\npack_version: '1.0'\nname: reffy\n")
    (pack / "suites" / "s.yaml").write_text(
        f'id: s\nsuite_version: "1.0"\nname: s\nspecs:\n  - spec_id: "GHOST-999{_BS}ud800"\n'
    )

    result = runner.invoke(app, ["lint", str(pack)])

    assert "Traceback" not in result.output
    assert result.exit_code == 1, result.output
    assert "references unknown spec id 'GHOST-999" + _BS + "ud800'" in result.output


def test_the_json_report_names_the_file(tmp_path: Path) -> None:
    result = _lint(tmp_path, _TOOL, _with_returns("2026-01-01"), "--json")

    assert result.exit_code == 1, result.output
    (error,) = json.loads(result.output)["errors"]
    assert error["code"] == "SCHEMA"
    assert error["path"] == f"{_TOOL}.yaml"
    assert error["spec_id"] == _TOOL
    assert error["message"].startswith(f"{_RETURNS_PATH}: a date")


def test_a_value_in_fixture_tool_call_arguments_is_found(tmp_path: Path) -> None:
    """The schema types a tool call as an object and says nothing about its arguments."""

    text = _replaced(_SELFCORRECT, _VULN_ARG, "qualifier: 2026-01-01")

    _assert_finding(
        _lint(tmp_path, _SELFCORRECT, text),
        _SELFCORRECT,
        "fixtures/vulnerable/tool_calls/0/args/qualifier: a date",
    )


def test_a_value_in_a_typed_field_gets_this_message_not_the_schemas(tmp_path: Path) -> None:
    """The schema would say ``datetime.date(2026, 1, 1) is not of type 'string'``."""

    text = _replaced(
        _TOOL, "name: Indirect prompt injection via tool / function output", "name: 2026-01-01"
    )

    line = _assert_finding(_lint(tmp_path, _TOOL, text), _TOOL, "name: a date")

    assert "datetime.date" not in line


def _run(tmp_path: Path, specs: Path, *extra: str) -> Result:
    target = tmp_path / "target.yaml"
    target.write_text(
        "id: mock-target\ntype: model\nmock_scenario: vulnerable\n"
        "capabilities:\n  tools: true\n  rag: true\n  memory: true\n",
        encoding="utf-8",
    )
    return runner.invoke(
        app,
        [
            "run",
            "-t",
            str(target),
            "--scope",
            str(write_scope(tmp_path)),
            "--spec-path",
            str(specs),
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            *extra,
        ],
    )


@pytest.mark.parametrize("mode", [["--dry-run"], ["--estimate"], []], ids=["dry", "est", "run"])
@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("2026-01-01", "a date"),
        ("!!set {plain: null}", "a set"),
        ("2026-01-01T10:00:00Z", "a timestamp"),
        ("!!binary aGVsbG8=", "binary data"),
        # On the base the dry run passed and the run stopped with exit 3 where it encoded the
        # request: `'utf-8' codec can't encode character` (pre-commit audit of A-54).
        (f'"ok {_BS}ud800"', "text holding half a character"),
    ],
)
def test_run_refuses_the_campaign_naming_the_file(
    tmp_path: Path, value: str, kind: str, mode: list[str]
) -> None:
    """``run --dry-run`` died with ``TypeError: Object of type date is not JSON serializable``."""

    specs = _spec_dir(tmp_path, _TOOL, _with_returns(value))

    result = _run(tmp_path, specs, *mode)

    assert "Traceback" not in result.output
    assert result.exit_code == 3, result.output
    errors = [line for line in result.output.splitlines() if line.startswith("error:")]
    assert len(errors) == 1, result.output
    assert f"{_TOOL}.yaml: {_RETURNS_PATH}: {kind}" in errors[0]
    assert not (tmp_path / "ev").exists(), "nothing ran before the refusal"


def test_a_container_shared_through_an_alias_is_reported_once(tmp_path: Path) -> None:
    text = _with_returns("&r {when: 2026-01-01}\n      description: *r")

    _assert_finding(_lint(tmp_path, _TOOL, text), _TOOL, f"{_RETURNS_PATH}/when: a date")


def test_a_value_aliased_in_two_places_is_reported_in_each(tmp_path: Path) -> None:
    """Only a container is entered once: a scalar is reported wherever it is used."""

    text = _with_returns("&d 2026-01-01\n      description: *d")

    result = _lint(tmp_path, _TOOL, text)

    assert result.exit_code == 1, result.output
    assert [line.split(": ", 2)[1] for line in _findings(result)] == [
        _RETURNS_PATH,
        "setup/tools/0/description",
    ]


def test_findings_are_capped(tmp_path: Path) -> None:
    dates = (
        ", ".join(f"2026-01-{day:02d}" for day in range(1, 29))
        + ", "
        + ", ".join(f"2025-02-{day:02d}" for day in range(1, 23))
    )

    result = _lint(tmp_path, _TOOL, _with_returns(f"[{dates}]"))

    assert result.exit_code == 1, result.output
    lines = _findings(result)
    assert len(lines) == 21, result.output
    assert lines[0].split(": ", 2)[1] == f"{_RETURNS_PATH}/0"
    assert lines[19].split(": ", 2)[1] == f"{_RETURNS_PATH}/19"
    assert lines[20].endswith("<root>: and 30 more values that JSON cannot hold")


def test_the_value_inside_a_set_or_pair_is_not_walked() -> None:
    """The container is the finding; a date inside it would only repeat it."""

    data = {"a": {datetime.date(2026, 1, 1)}, "b": [("k", datetime.date(2026, 1, 1))]}

    assert [message.split(": ", 1)[0] for message in _non_json_values(data)] == ["a", "b/0"]


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        (frozenset({"x"}), "a set (!!set)"),
        (bytearray(b"x"), "binary data (!!binary)"),
        (decimal.Decimal("1.5"), "a value of type Decimal"),
        (object(), "a value of type object"),
        (datetime.time(10, 0), "a value of type time"),
    ],
)
def test_a_value_built_in_code_is_named_by_its_type(value: object, kind: str) -> None:
    """The check keeps what JSON holds rather than refusing a list of what it does not."""

    assert validate_attack_spec_schema({"id": value}) == [f"id: {kind}, {_CANNOT}; {_advice(kind)}"]


def _advice(kind: str) -> str:
    if kind.startswith(("a set", "a key and value")):
        return "write a list or a mapping"
    if kind.startswith("binary"):
        return "write it as text"
    return "write a JSON value"


@pytest.mark.parametrize(
    "value", [None, True, 0, -1, 1.5, 1e308, "", "2026-01-01", [], {}, {"a": [1, "x", None]}]
)
def test_every_json_value_passes(value: object) -> None:
    assert _non_json_values({"id": value}) == []


def test_a_document_that_is_a_single_value_is_checked_at_its_root() -> None:
    """The loader refuses a root that is not a mapping first; the walk does not depend on it."""

    assert _non_json_values("a spec") == []
    assert _non_json_values(datetime.date(2026, 1, 1)) == [
        "<root>: a date (YAML reads an unquoted 2026-01-01 as one), which JSON cannot hold; "
        "write it in quotes, without a tag"
    ]


def test_a_whole_character_outside_the_basic_plane_passes() -> None:
    assert _non_json_values({"a": "caf" + chr(0xE9) + " " + chr(0x1F600)}) == []


def test_no_shipped_spec_holds_one() -> None:
    """The auditor checked the 105 shipped YAML files; the specs are pinned here."""

    paths = sorted(_ATTACKS.glob("*.yaml"))
    assert len(paths) >= 75
    for path in paths:
        assert _non_json_values(yaml.safe_load(path.read_text(encoding="utf-8"))) == [], path


def test_the_shipped_battery_lints_clean() -> None:
    report = lint([_ROOT / "specs"])

    assert [e for e in report.errors if e.code is LintCode.SCHEMA] == []


def test_a_key_on_the_path_that_the_terminal_would_act_on_is_escaped() -> None:
    """The path holds keys of free-form objects, which a message would otherwise print raw."""

    key = f"a{chr(0x1B)}[31m{chr(0x0A)}[ERROR] forged"

    (message,) = _non_json_values({"setup": {"tools": [{key: datetime.date(2026, 1, 1)}]}})

    assert chr(0x1B) not in message
    assert chr(0x0A) not in message
    assert message.startswith(f"setup/tools/0/{key!r}: a date")


def test_a_key_that_is_not_text_is_written_as_its_repr() -> None:
    """Such a key is A-44's finding where that check exists (#80); this walk never fails on one."""

    data = {"a": {5: datetime.date(2026, 1, 1), None: float("nan")}}

    assert [message.split(": ", 1)[0] for message in _non_json_values(data)] == ["a/5", "a/None"]


@pytest.fixture
def low_digit_limit() -> Iterator[None]:
    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(before)


@pytest.mark.usefixtures("low_digit_limit")
def test_a_key_too_long_to_write_out_does_not_break_the_path() -> None:
    """``repr`` of such an int raises ``ValueError`` (A-40 reports the key itself, first)."""

    (message,) = _non_json_values({"a": {10**700: datetime.date(2026, 1, 1)}})

    assert message.startswith("a/<number>: a date")


def test_a_long_key_on_the_path_is_cut() -> None:
    long_key = "k" * 5000

    (message,) = _non_json_values({long_key: datetime.date(2026, 1, 1)})

    assert message.startswith("k" * 300 + f"... ({len(long_key)} characters): a date")
