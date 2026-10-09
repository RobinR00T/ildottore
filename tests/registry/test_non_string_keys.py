"""A mapping key that is not a string is a SCHEMA finding, not a lint traceback (A-44, u02).

A spec is a JSON document written in YAML, and JSON keys are strings, but YAML builds a key from
whatever the scalar resolves to: ``5:`` is an int, a bare ``on:`` or ``no:`` a bool, ``~:`` None,
``2026-10-07:`` a date. The JSON schema says nothing about the keys of a free-form object (the
arguments of a fixture's tool call), so such a key reached the offline ``tool_call`` stub, whose
``key.lower()`` raised ``AttributeError``: a traceback and exit 1, which this tool uses for
"findings below the threshold" (found 2026-10-07 by the session on ``fix/huge-int-repr``). A key
of two types in one mapping crashed earlier, in the schema validator's error sort, and a
``!!binary`` key passed lint without a word (``bytes`` has a ``lower``).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from click.testing import Result
from typer.testing import CliRunner

from ildottore.cli.main import app
from ildottore.registry import LintCode, lint
from ildottore.registry.fixtures_engine import DEFAULT_STUB_TABLE, evaluate_fixture
from ildottore.registry.schema import validate_attack_spec_schema
from ildottore.shared import AttackSpec, FixtureCase, VerdictStatus

runner = CliRunner()

_ATTACKS = Path(__file__).resolve().parents[2] / "specs" / "attacks"
_SELFCORRECT = "AG-AUTONOMY-SELFCORRECT-001"
_ARGSMUGGLE = "FUNCALL-ARGSMUGGLE-001"
_TOOLCHAIN = "AG-TOOLCHAIN-EXFIL-001"
_VULN_ARG = 'qualifier: "bad"'
_HARD_ARGS = 'args: { display_name: "Dani" }'
_ADVICE = "not a string; write it in quotes, without a tag"


def _shipped(spec_id: str) -> str:
    return (_ATTACKS / f"{spec_id}.yaml").read_text(encoding="utf-8")


def _replaced(spec_id: str, old: str, new: str) -> str:
    text = _shipped(spec_id)
    assert text.count(old) == 1, old  # the edit lands exactly once, or the test proves nothing
    return text.replace(old, new)


def _lint(tmp_path: Path, spec_id: str, text: str, *extra: str) -> Result:
    specs = tmp_path / "specs"
    specs.mkdir()
    (specs / f"{spec_id}.yaml").write_text(text, encoding="utf-8")
    return runner.invoke(app, ["lint", str(specs), *extra])


def _assert_finding(result: Result, spec_id: str, *fragments: str) -> str:
    """Exit 1 on a SCHEMA finding for ``spec_id``, no traceback; returns its line."""

    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "Traceback" not in result.output
    assert result.exit_code == 1, result.output
    lines = [line for line in result.output.splitlines() if line.startswith("[ERROR] SCHEMA")]
    assert len(lines) == 1, result.output
    assert f"({spec_id})" in lines[0]
    for fragment in fragments:
        assert fragment in lines[0], lines[0]
    return lines[0]


@pytest.mark.parametrize(
    ("key", "shown", "kind"),
    [
        ("5", "key 5", "an integer"),
        ("on", "key true", "a boolean"),  # YAML 1.1: a bare on, off, yes, no is a bool
        ("No", "key false", "a boolean"),
        ("~", "key null", "is null (YAML reads"),
        ("", "key null", "is null (YAML reads"),  # an empty key is null too
        ("2026-10-07", "key 2026-10-07", "a date"),
        ("2026-10-07T10:00:00Z", "key 2026-10-07T10:00:00", "a timestamp"),
        ("1.5", "key 1.5", "a number"),
        (".inf", "key inf", "a number"),
        ("!!binary aGk=", "key !!binary (2 bytes)", "binary data"),
        ('!!int "5"', "key 5", "an integer"),  # quoted but tagged: hence "without a tag"
        ("!!binary YQ==", "key !!binary (1 byte)", "binary data"),
    ],
)
def test_lint_reports_a_non_string_key_in_tool_call_arguments(
    tmp_path: Path, key: str, shown: str, kind: str
) -> None:
    text = _replaced(_SELFCORRECT, _VULN_ARG, f'{key}: "bad"' if key else '? : "bad"')

    result = _lint(tmp_path, _SELFCORRECT, text)

    _assert_finding(
        result,
        _SELFCORRECT,
        "fixtures/vulnerable/tool_calls/0/args:",
        shown,
        kind,
        "not a string",
    )


def test_the_json_report_names_the_file(tmp_path: Path) -> None:
    text = _replaced(_SELFCORRECT, _VULN_ARG, '5: "bad"')

    result = _lint(tmp_path, _SELFCORRECT, text, "--json")

    assert result.exit_code == 1, result.output
    (error,) = json.loads(result.output)["errors"]
    assert error["code"] == "SCHEMA"
    assert error["path"] == f"{_SELFCORRECT}.yaml"
    assert error["spec_id"] == _SELFCORRECT


def test_a_nested_key_is_found_where_it_is(tmp_path: Path) -> None:
    text = _replaced(_SELFCORRECT, _VULN_ARG, 'qualifier: { 5: "bad" }')

    _assert_finding(
        _lint(tmp_path, _SELFCORRECT, text),
        _SELFCORRECT,
        "fixtures/vulnerable/tool_calls/0/args/qualifier: key 5",
    )


def test_a_hardened_fixture_is_checked_too(tmp_path: Path) -> None:
    """The forbidden-argument walk (``_stub_forbidden_hit``) crashed on the hardened fixture."""

    text = _replaced(_ARGSMUGGLE, _HARD_ARGS, 'args: { display_name: "Dani", 5: "x" }')

    _assert_finding(
        _lint(tmp_path, _ARGSMUGGLE, text),
        _ARGSMUGGLE,
        "fixtures/hardened/tool_calls/0/args: key 5",
    )


def test_keys_of_two_types_do_not_crash_the_schema_errors(tmp_path: Path) -> None:
    """Two schema errors under keys ``5`` and ``"a"`` were sorted by path: int against str."""

    old = 'send_email: "@(?!ourcompany\\\\.example\\\\b)"'
    text = _replaced(_TOOLCHAIN, old, f"{old}\n      5: 1\n      a: 2")

    _assert_finding(
        _lint(tmp_path, _TOOLCHAIN, text),
        _TOOLCHAIN,
        "evaluators/0/step_arg_patterns: key 5",
    )


def test_findings_are_capped(tmp_path: Path) -> None:
    keys = ", ".join(f'{n}: "x"' for n in range(50))
    text = _replaced(_SELFCORRECT, _VULN_ARG, f"{_VULN_ARG}, {keys}")

    result = _lint(tmp_path, _SELFCORRECT, text)

    assert result.exit_code == 1, result.output
    lines = [line for line in result.output.splitlines() if line.startswith("[ERROR] SCHEMA")]
    assert len(lines) == 21, result.output
    assert lines[0].endswith(f"key 0 is an integer, {_ADVICE}")
    assert lines[19].startswith(f"[ERROR] SCHEMA ({_SELFCORRECT}): ")
    assert "key 19 is" in lines[19]
    assert "and 30 more keys that are not strings" in lines[20]


def test_a_mapping_shared_through_an_alias_is_reported_once(tmp_path: Path) -> None:
    text = _replaced(
        _SELFCORRECT,
        'args: { table: "config_info", qualifier: "bad" } }',
        'args: &a { table: "config_info", 5: "bad" } }\n      - { name: drop_table, args: *a }',
    )

    _assert_finding(
        _lint(tmp_path, _SELFCORRECT, text),
        _SELFCORRECT,
        "fixtures/vulnerable/tool_calls/0/args: key 5",
    )


@pytest.fixture
def low_digit_limit() -> Iterator[None]:
    """Python's lowest int-to-text limit, under which a 600-digit hex key is too long to print."""

    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(before)


@pytest.mark.usefixtures("low_digit_limit")
def test_a_key_too_long_to_print_is_described_not_quoted(tmp_path: Path) -> None:
    """``repr`` of such an int raises ``ValueError``; the message must not.

    A-40 runs first and reports this key in its own words, so only the path, the description and
    the absence of the digits are pinned (pre-merge audit of #80).
    """

    big = "0x" + "f" * 600
    text = (
        _replaced(
            _SELFCORRECT,
            'args: { table: "config_info", qualifier: "bad" } }',
            ('args: { table: "config_info" } }'),
        )
        + f"x-check:\n  ? {big}\n  : 1\n"
    )
    # The key sits at the root, beside an unknown property: the key is reported, not the property.

    line = _assert_finding(_lint(tmp_path, _SELFCORRECT, text), _SELFCORRECT, "x-check: ")

    assert "too long to write out" in line
    assert "fff" not in line


def _spec(spec_id: str) -> AttackSpec:
    return AttackSpec.model_validate(yaml.safe_load(_shipped(spec_id)))


def _verdict(spec: AttackSpec, case: FixtureCase, args: dict[object, object]) -> VerdictStatus:
    call = (case.tool_calls or [])[0]
    edited = case.model_copy(update={"tool_calls": [{**call, "args": args}]})
    verdict, missing = evaluate_fixture(spec, edited, DEFAULT_STUB_TABLE)
    assert missing == []
    return verdict


def test_the_offline_stub_reads_only_string_keys_as_the_evaluator_does() -> None:
    """``lint_packs`` also takes specs built in code, where pydantic keeps a nested key as it is.

    The stub mirrors ``evaluators/tool_call.py``, which reads only string keys, and called
    ``.lower()`` on every key: the confirmation walk on a destructive call, the forbidden-argument
    walk on every call. A non-string key now changes neither verdict. Since OD-38 the stub has no
    confirmation walk (a flag the model set on its own destructive call is not a confirmation),
    so the destructive call fails with the flag too.
    """

    smuggle = _spec(_ARGSMUGGLE)
    assert _verdict(smuggle, smuggle.fixtures.hardened, {"display_name": "Dani", 5: True}) is (
        VerdictStatus.PASS
    )
    assert (
        _verdict(smuggle, smuggle.fixtures.vulnerable, {"bypass_review": True, None: 1})
        is VerdictStatus.FAIL
    )

    drop = _spec(_SELFCORRECT)
    assert _verdict(drop, drop.fixtures.vulnerable, {"table": "t", True: 1}) is (VerdictStatus.FAIL)
    assert _verdict(drop, drop.fixtures.vulnerable, {"table": "t", 5: 1, "confirm": True}) is (
        VerdictStatus.FAIL
    )


def test_a_long_key_on_the_path_is_cut(tmp_path: Path) -> None:
    """A string key on the way can be as long as the file allows (``? `` keys have no 1,024 cap)."""

    long_key = "k" * 5000
    text = _shipped(_SELFCORRECT) + f"x-check:\n  ? {long_key}\n  : {{5: 1}}\n"

    line = _assert_finding(_lint(tmp_path, _SELFCORRECT, text), _SELFCORRECT, "key 5")

    assert f"... ({len('x-check/' + long_key)} characters): key 5 is an integer" in line
    assert len(line) < 500


def test_a_key_of_another_type_is_named_by_its_type() -> None:
    """Built in code, a document can hold a key YAML never builds."""

    assert validate_attack_spec_schema({"id": {(1, 2): "x"}}) == [
        f"id: key (1, 2) is a tuple, {_ADVICE}"
    ]


def _fixture_calls() -> Iterator[tuple[str, str, int, str]]:
    """Every fixture tool call with an argument mapping in the shipped specs."""

    for path in sorted(_ATTACKS.glob("*.yaml")):
        fixtures = yaml.safe_load(path.read_text(encoding="utf-8"))["fixtures"]
        for case in ("vulnerable", "hardened"):
            for index, call in enumerate(fixtures[case].get("tool_calls") or []):
                for field in ("args", "arguments", "parameters", "input"):
                    if isinstance(call.get(field), dict):
                        yield path.stem, case, index, field
                        break


_CALLS = list(_fixture_calls())


def test_the_sweep_is_not_empty() -> None:
    """A sweep that found no call would pass by testing nothing.

    On ``0501752`` the shipped specs had 41 such calls, and an int key added after the others
    crashed lint in 5 (the confirmation walk on a destructive call, the forbidden-argument walk)
    and passed unreported in the other 36; added first, in 6 and 35 (a walk stops at the first
    forbidden key it meets).
    """

    assert len(_CALLS) >= 41


@pytest.mark.parametrize(("spec_id", "case", "index", "field"), _CALLS)
def test_an_int_key_in_any_shipped_fixture_call_is_a_finding(
    tmp_path: Path, spec_id: str, case: str, index: int, field: str
) -> None:
    data = yaml.safe_load(_shipped(spec_id))
    data["fixtures"][case]["tool_calls"][index][field][5] = "x"
    (tmp_path / f"{spec_id}.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")

    report = lint([tmp_path])

    assert [(e.code, e.message) for e in report.errors] == [
        (
            LintCode.SCHEMA,
            f"fixtures/{case}/tool_calls/{index}/{field}: key 5 is an integer, {_ADVICE}",
        )
    ]


def test_a_key_on_the_path_that_the_terminal_would_act_on_is_escaped(tmp_path: Path) -> None:
    """This check prints keys of free-form objects that no message printed before; one holding an
    escape sequence and a newline forged a finding line of its own (pre-commit audit of A-44)."""

    bs = chr(92)
    key = f'"x{bs}e[31mRED{bs}e[0m{bs}n[ERROR] SCHEMA (FAKE-SPEC-001): forged"'
    text = _replaced(_SELFCORRECT, _VULN_ARG, f"{_VULN_ARG}, {key}: {{ 5: 1 }}")

    line = _assert_finding(_lint(tmp_path, _SELFCORRECT, text), _SELFCORRECT, "key 5 is an integer")

    assert "'x" + bs + "x1b[31mRED" + bs + "x1b[0m" + bs + "n[ERROR] SCHEMA (FAKE" in line


@pytest.mark.parametrize(
    "char",
    [0x1B, 0x0A, 0x0D, 0x85, 0x9B, 0x2028, 0x202E, 0x200B],
    ids=["ESC", "LF", "CR", "NEL", "CSI", "LSEP", "RLO", "ZWSP"],
)
def test_no_unprintable_character_of_a_key_on_the_path_reaches_the_message(char: int) -> None:
    """Checked on the message itself: ``CliRunner`` strips ANSI escapes from what it captures."""

    key = f"a{chr(char)}b"
    data = {"fixtures": {"vulnerable": {"tool_calls": [{"args": {key: {5: 1}}}]}}}

    (message,) = validate_attack_spec_schema(data)

    assert chr(char) not in message
    assert message.startswith(f"fixtures/vulnerable/tool_calls/0/args/{key!r}: key 5 is an integer")


def test_the_value_under_a_non_string_key_is_not_walked(tmp_path: Path) -> None:
    """Its path would need the key, which is the thing being reported."""

    text = _replaced(_SELFCORRECT, _VULN_ARG, f"{_VULN_ARG}, 5: {{ 6: x }}")

    _assert_finding(_lint(tmp_path, _SELFCORRECT, text), _SELFCORRECT, "args: key 5 is")


@pytest.mark.parametrize(
    ("tag", "entry", "where"),
    [
        ("!!omap", "{ a: { 5: x } }", "0/1"),
        ("!!pairs", "{ a: { 5: x } }", "0/1"),
        ("!!pairs", "? { 5: x } : v", "0/0"),  # a mapping as the entry's own key
    ],
)
def test_a_mapping_inside_an_ordered_map_is_checked(
    tmp_path: Path, tag: str, entry: str, where: str
) -> None:
    """YAML builds each entry of these as a tuple, which the walk first left out."""

    text = _replaced(_SELFCORRECT, _VULN_ARG, f"{_VULN_ARG}, extra: {tag} [ {entry} ]")

    _assert_finding(
        _lint(tmp_path, _SELFCORRECT, text),
        _SELFCORRECT,
        f"fixtures/vulnerable/tool_calls/0/args/extra/{where}: key 5 is an integer",
    )
