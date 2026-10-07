"""A number too long to write out is reported with its file, not raised from where it is printed.

Python refuses to turn an int of more than ``sys.get_int_max_str_digits()`` decimal digits into
text (4,300 by default, 640 at the lowest), and YAML builds one from ``0x`` and 4,000 ``f``. Put
in a spec's ``name``, jsonschema's message ``<value> is not of type 'string'`` raised it: a lint
traceback with exit 1, ``run --spec-path`` exiting 3 with ``error: Exceeds the limit`` naming no
file, and ``calibrate`` the same with one as a labels key (pre-commit audit of
``fix/yaml-alias-expansion-cap``, 2026-10-07). A key or a value the schema accepts got further:
``lint`` passed and the live run failed on writing it. A report's JSON fails the same way at
5,000 digits. Clause A-40 (u02).

The low-limit cases use a 600-character literal, under any cap on literal length, so they test
these checks on their own whatever the YAML loader refuses first.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner, Result

from ildottore.cli import wiring
from ildottore.cli.calibrate import load_labels
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.registry.schema import validate_attack_spec_schema
from ildottore.shared import digits

from .conftest import write_scope

REPO = Path(__file__).resolve().parents[2]
SPEC = REPO / "specs" / "attacks" / "AC-BFLA-001.yaml"
runner = CliRunner()

#: The finding's literal: 4,817 digits, past the default limit of 4,300.
HEX_DEFAULT = "0x" + "f" * 4000
#: About 723 digits: past the lowest limit (640) and a simple YAML key (under 1,024 characters).
HEX_LOW = "0x" + "f" * 600
_SENTINEL = "HUGENUMBERHERE"


@pytest.fixture
def low_limit() -> Iterator[None]:
    """The lowest digit limit Python allows, as ``PYTHONINTMAXSTRDIGITS=640`` sets it."""

    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(before)


def _planted(path: tuple[Any, ...], *, key: bool = False, literal: str = HEX_LOW) -> str:
    """``AC-BFLA-001`` with ``literal`` as the value at ``path``, or as the key it ends with."""

    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    parent = doc
    for part in path[:-1]:
        parent = parent[part]
    if key:
        items = list(parent.items())
        parent.clear()
        parent.update((_SENTINEL if k == path[-1] else k, v) for k, v in items)
    else:
        parent[path[-1]] = _SENTINEL
    text = yaml.safe_dump(doc, sort_keys=False, width=10**6, allow_unicode=True)
    assert text.count(_SENTINEL) == 1
    return text.replace(_SENTINEL, literal)


def _spec_dir(tmp_path: Path, text: str) -> Path:
    specs = tmp_path / "specs"
    specs.mkdir()
    (specs / "huge.yaml").write_text(text, encoding="utf-8")
    return specs


def error_line(result: Result) -> str:
    """The single ``error:`` line on stderr, which quotes none of the number."""

    lines = result.stderr.splitlines()
    assert len(lines) == 1, (result.exception, result.stderr)
    assert lines[0].startswith("error: ")
    assert "ffff" not in lines[0] and "Exceeds the limit" not in lines[0]
    return lines[0]


#: Where the number goes: the finding's three fields; a key the schema refuses; and two places
#: the schema took it, so lint passed and the run failed later (a tool's ``mode``, an argument
#: key of a fixture's tool call).
PLACES = [
    pytest.param(("name",), False, id="name"),
    pytest.param(("owasp",), False, id="owasp"),
    pytest.param(("spec_version",), False, id="spec_version"),
    pytest.param(("severity",), True, id="key-at-root"),
    pytest.param(("setup", "tools", 0, "mode"), False, id="tool-mode"),
    pytest.param(("fixtures", "vulnerable", "tool_calls", 0, "args", "scope"), True, id="arg-key"),
]


def _lint_json(specs: Path) -> tuple[Result, list[dict[str, Any]]]:
    result = runner.invoke(app, ["lint", "--json", str(specs)])
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert result.exit_code == 1, result.output
    assert "ffff" not in result.stdout
    errors: list[dict[str, Any]] = json.loads(result.stdout)["errors"]
    return result, errors


@pytest.mark.usefixtures("low_limit")
@pytest.mark.parametrize(("path", "key"), PLACES)
def test_lint_reports_the_number_as_a_schema_finding(
    tmp_path: Path, path: tuple[Any, ...], key: bool
) -> None:
    specs = _spec_dir(tmp_path, _planted(path, key=key))

    _, errors = _lint_json(specs)

    where = "/".join(map(str, path[:-1] if key else path)) or "<root>"
    what = "a key that is a number" if key else "a number"
    assert [(e["code"], e["path"], e["spec_id"], e["message"]) for e in errors] == [
        (
            "SCHEMA",
            "huge.yaml",
            "AC-BFLA-001",
            f"{where}: {what} too long to write out (over 640 digits)",
        )
    ]


def test_lint_reports_the_findings_own_literal(tmp_path: Path) -> None:
    """The reproduction as found, at the default limit: a finding naming the file, exit 1."""

    specs = _spec_dir(tmp_path, _planted(("name",), literal=HEX_DEFAULT))

    _, errors = _lint_json(specs)

    # SCHEMA here; PARSE_ERROR once the YAML loader caps a literal's length, no less right.
    assert errors and {e["path"] for e in errors} == {"huge.yaml"}
    assert {e["code"] for e in errors} <= {"SCHEMA", "PARSE_ERROR"}


@pytest.mark.usefixtures("low_limit")
@pytest.mark.parametrize(("path", "key"), PLACES)
@pytest.mark.parametrize("dry_run", [True, False], ids=["dry-run", "live"])
def test_run_refuses_the_spec_and_names_it(
    tmp_path: Path, path: tuple[Any, ...], key: bool, dry_run: bool
) -> None:
    specs = _spec_dir(tmp_path, _planted(path, key=key))
    target = tmp_path / "target.yaml"
    target.write_text(
        "id: mock-target\ntype: model\nmock_scenario: vulnerable\n"
        "capabilities:\n  tools: true\n  rag: true\n  memory: true\n",
        encoding="utf-8",
    )
    evidence = tmp_path / "ev"

    result = runner.invoke(
        app,
        [
            *("run", "-t", str(target), "--scope", str(write_scope(tmp_path))),
            *("--spec-path", str(specs), "--evidence-root", str(evidence)),
            *("--run-db", str(tmp_path / "runs.sqlite"), "--no-color", "-q"),
            *(["--dry-run"] if dry_run else []),
        ],
    )

    assert result.exit_code == ExitCode.ERROR, result.output
    line = error_line(result)
    assert "1 spec file(s) failed to load" in line and "huge.yaml: " in line
    assert "a number too long to write out" in line
    assert not evidence.exists() or not any(evidence.iterdir())


@pytest.mark.usefixtures("low_limit")
@pytest.mark.parametrize("entry", ["? {n}\n: pass\n", "PI-DIRECT-001: fail\n{n}: pass\n"])
def test_calibrate_names_the_labels_file_for_a_number_as_spec_id(
    tmp_path: Path, entry: str
) -> None:
    """``str(spec_id)`` raised inside the verdict's ``except``, whose message formatted the id
    again: ``error: Exceeds the limit`` with exit 3, naming no file."""

    report = tmp_path / "report.json"
    report.write_text("[]", encoding="utf-8")
    labels = tmp_path / "labels.yaml"
    labels.write_text(entry.format(n=HEX_LOW), encoding="utf-8")

    result = runner.invoke(app, ["calibrate", str(report), str(labels)])

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert f"labels file {labels}: " in line
    assert "the spec id of entry " in line and "a number too long to write out" in line


def test_calibrate_names_the_labels_file_at_the_default_limit(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text("[]", encoding="utf-8")
    labels = tmp_path / "labels.yaml"
    labels.write_text(f"? {HEX_DEFAULT}\n: pass\n", encoding="utf-8")

    result = runner.invoke(app, ["calibrate", str(report), str(labels)])

    assert result.exit_code == ExitCode.ERROR
    assert f"labels file {labels}" in error_line(result)


@pytest.mark.usefixtures("low_limit")
def test_a_number_as_verdict_was_already_named(tmp_path: Path) -> None:
    """The value is never formatted, so it was refused as an invalid verdict, and still is."""

    labels = tmp_path / "labels.yaml"
    labels.write_text(f"PI-DIRECT-001: {HEX_LOW}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="spec 'PI-DIRECT-001' has an invalid verdict"):
        load_labels(labels)


def _report(number: str) -> str:
    finding = {
        "spec_id": "PI-DIRECT-001",
        "target_id": "t",
        "status": "fail",
        "risk": {
            "impact": 3,
            "exploitability": 3,
            "reproducibility": 1.0,
            "risk": 9.0,
            "confidence": 0.9,
            "band": "high",
        },
        "confirmed": True,
        "attempts": [],
        "evidence": [],
        "reasoning": "x",
    }
    return json.dumps({"findings": [finding]}).replace('"impact": 3', f'"impact": {number}')


@pytest.mark.parametrize("command", ["diff-baseline", "diff-current", "calibrate"])
def test_a_report_with_a_number_too_long_to_read_is_named(tmp_path: Path, command: str) -> None:
    """``json.loads`` raises a plain ``ValueError``, not ``JSONDecodeError``, past the limit:
    the reader caught neither, and the line named no report."""

    bad = tmp_path / "bad.json"
    bad.write_text(_report("9" * 5000), encoding="utf-8")
    clean = tmp_path / "clean.json"
    clean.write_text("[]", encoding="utf-8")
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-DIRECT-001: fail\n", encoding="utf-8")
    args = {
        "diff-baseline": ["diff", str(bad), str(clean)],
        "diff-current": ["diff", str(clean), str(bad)],
        "calibrate": ["calibrate", str(bad), str(labels)],
    }[command]

    result = runner.invoke(app, args)

    assert result.exit_code == ExitCode.ERROR
    line = error_line(result)
    assert f"the report {bad} holds a number too long to read (over 4300 digits)" in line


@pytest.mark.usefixtures("low_limit")
@pytest.mark.parametrize(
    ("body", "said"),
    [
        pytest.param(
            "id: mock-target\ntype: {n}\n",
            "has invalid type a number too long to write out (over 640 digits); expected one of",
            id="type",
        ),
        pytest.param(
            "id: mock-target\ntype: [{n}]\n",
            "has invalid type a value holding a number too long to write out (over 640 digits);",
            id="type-list",
        ),
        pytest.param(
            "id: mock-target\ntype: rag\nseeded_setup:\n  {n}: []\n",
            "'seeded_setup' has unknown key(s) a number too long to write out (over 640 digits);",
            id="seeded-key",
        ),
        pytest.param(
            "id: mock-target\ntype: model\nmock_scenario: {n}\n",
            "has invalid mock_scenario a number too long to write out (over 640 digits);",
            id="mock-scenario",
        ),
    ],
)
def test_run_names_a_target_file_with_a_number_too_long(
    tmp_path: Path, body: str, said: str
) -> None:
    """The refusal quoted the value (``type``, ``mock_scenario``) or listed the unknown keys
    (``seeded_setup``), and formatting it raised: exit 3 with ``error: Exceeds the limit`` and
    no file."""

    target = tmp_path / "target.yaml"
    target.write_text(body.format(n=HEX_LOW), encoding="utf-8")
    specs = _spec_dir(tmp_path, SPEC.read_text(encoding="utf-8"))

    result = runner.invoke(
        app,
        [
            *("run", "-t", str(target), "--scope", str(write_scope(tmp_path))),
            *("--spec-path", str(specs), "--dry-run"),
        ],
    )

    assert result.exit_code == ExitCode.ERROR
    assert f"target file {target} {said}" in error_line(result)


@pytest.mark.usefixtures("low_limit")
@pytest.mark.parametrize("field", ["provider", "transport"])
def test_a_number_as_provider_or_transport_is_ignored_as_any_value_not_text(
    tmp_path: Path, field: str
) -> None:
    """The target loader reads both only as text, but the mock routing called ``str`` on them
    first: exit 3 with ``error: Exceeds the limit`` and no file (pre-commit audit of A-40). Now
    the number is read as ``5`` always was, as no provider."""

    scope = write_scope(tmp_path)
    plain = REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml"  # a chatbot spec, no setup
    specs = _spec_dir(tmp_path, plain.read_text(encoding="utf-8"))
    outputs = []
    for value in (HEX_LOW, "5"):
        target = tmp_path / "target.yaml"
        target.write_text(f"id: mock-target\ntype: chatbot\n{field}: {value}\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "run",
                "-t",
                str(target),
                "--scope",
                str(scope),
                "--spec-path",
                str(specs),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        outputs.append(result.output)
    assert outputs[0] == outputs[1]


@pytest.mark.usefixtures("low_limit")
def test_the_schema_check_holds_without_a_yaml_loader_in_front() -> None:
    """A value can come from JSON or be built in code: the validator itself must not raise."""

    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    doc["name"] = int("9" * 600) ** 2  # 1,200 digits, built without text

    assert validate_attack_spec_schema(doc) == [
        "name: a number too long to write out (over 640 digits)"
    ]


@pytest.mark.usefixtures("low_limit")
def test_the_schema_check_lists_twenty_and_counts_the_rest() -> None:
    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    huge = int("9" * 600) ** 2
    doc["tags"] = [huge] * 25  # one number aliased 25 times, as YAML shares it

    messages = validate_attack_spec_schema(doc)

    assert messages[:2] == [
        "tags/0: a number too long to write out (over 640 digits)",
        "tags/1: a number too long to write out (over 640 digits)",
    ]
    assert len(messages) == 21
    assert messages[-1] == "<root>: and 5 more numbers too long to write out"


@pytest.mark.usefixtures("low_limit")
def test_a_number_up_to_the_limit_is_validated_as_before() -> None:
    """640 digits is still a number: the check refuses only what cannot be written."""

    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    assert validate_attack_spec_schema(doc) == []
    doc["sampling"]["seed"] = 10**640 - 1  # 640 digits
    assert validate_attack_spec_schema(doc) == []
    doc["sampling"]["seed"] = 10**640  # 641
    assert validate_attack_spec_schema(doc) == [
        "sampling/seed: a number too long to write out (over 640 digits)"
    ]


@pytest.mark.usefixtures("low_limit")
def test_a_long_key_on_the_path_is_cut() -> None:
    """The path is printed once per finding, up to 20 times: a 100,000-character key on it is
    cut as a long schema message is."""

    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    doc["setup"]["k" * 100_000] = int("9" * 600) ** 2

    [message] = validate_attack_spec_schema(doc)

    assert message.startswith("setup/kkk") and len(message) < 500
    assert message.endswith(
        "... (100006 characters): a number too long to write out (over 640 digits)"
    )


def test_with_no_digit_limit_nothing_is_refused_for_its_length() -> None:
    """``PYTHONINTMAXSTRDIGITS=0`` lifts the limit, and every number can be written out."""

    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
        doc["sampling"]["seed"] = 10**5000
        assert validate_attack_spec_schema(doc) == []
    finally:
        sys.set_int_max_str_digits(before)


@pytest.mark.usefixtures("low_limit")
def test_a_list_shared_through_an_alias_is_reported_once() -> None:
    """YAML hands the same list to every alias of it: walked once, at the first place it is."""

    shared = [int("9" * 600) ** 2]
    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    doc["setup"]["first"] = shared
    doc["setup"]["second"] = shared

    assert validate_attack_spec_schema(doc) == [
        "setup/first/0: a number too long to write out (over 640 digits)"
    ]


#: A YAML collection that is not a mapping or a list: ``!!set`` builds a set whose members are
#: its keys, ``!!omap`` and ``!!pairs`` a list of tuples. The walk saw only mappings and lists,
#: so a number inside these was the same traceback (pre-commit audit of A-40).
COLLECTIONS = [
    pytest.param("!!set {{{n}: null}}", True, "", id="set"),
    pytest.param("!!omap [{{a: {n}}}]", False, "/0/1", id="omap"),
    pytest.param("!!pairs [{{a: {n}}}]", False, "/0/1", id="pairs"),
]


@pytest.mark.usefixtures("low_limit")
@pytest.mark.parametrize(("collection", "key", "below"), COLLECTIONS)
@pytest.mark.parametrize("path", [("name",), ("setup", "tools", 0, "mode")], ids=["name", "mode"])
def test_lint_finds_the_number_inside_a_set_or_pairs(
    tmp_path: Path, collection: str, key: bool, below: str, path: tuple[Any, ...]
) -> None:
    specs = _spec_dir(tmp_path, _planted(path, literal=collection.format(n=HEX_LOW)))

    _, errors = _lint_json(specs)

    where = "/".join(map(str, path)) + below
    what = "a key that is a number" if key else "a number"
    assert [(e["code"], e["path"], e["message"]) for e in errors] == [
        ("SCHEMA", "huge.yaml", f"{where}: {what} too long to write out (over 640 digits)")
    ]


@pytest.mark.usefixtures("low_limit")
@pytest.mark.parametrize(("collection", "key", "below"), COLLECTIONS)
@pytest.mark.parametrize("dry_run", [True, False], ids=["dry-run", "live"])
def test_run_refuses_a_spec_with_the_number_inside_a_set_or_pairs(
    tmp_path: Path, collection: str, key: bool, below: str, dry_run: bool
) -> None:
    """A tool's ``mode`` takes any value, so lint and the dry run passed and the live run exited
    3 naming no file where it wrote the number."""

    literal = collection.format(n=HEX_LOW)
    specs = _spec_dir(tmp_path, _planted(("setup", "tools", 0, "mode"), literal=literal))
    target = tmp_path / "target.yaml"
    target.write_text(
        "id: mock-target\ntype: model\nmock_scenario: vulnerable\n"
        "capabilities:\n  tools: true\n  rag: true\n  memory: true\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            *("run", "-t", str(target), "--scope", str(write_scope(tmp_path))),
            *("--spec-path", str(specs), "--evidence-root", str(tmp_path / "ev")),
            *("--run-db", str(tmp_path / "runs.sqlite"), "--no-color", "-q"),
            *(["--dry-run"] if dry_run else []),
        ],
    )

    assert result.exit_code == ExitCode.ERROR, result.output
    line = error_line(result)
    assert "1 spec file(s) failed to load" in line and "huge.yaml: setup/tools/0/mode" in line


@pytest.mark.usefixtures("low_limit")
def test_a_key_that_holds_more_on_its_path_is_masked() -> None:
    """The path of a number below a key too long to write out names the key ``<number>``:
    printing the key itself raised."""

    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    doc[int("9" * 600) ** 2] = {"inner": int("8" * 600) ** 2}

    assert validate_attack_spec_schema(doc) == [
        "<root>: a key that is a number too long to write out (over 640 digits)",
        "<number>/inner: a number too long to write out (over 640 digits)",
    ]


@pytest.mark.usefixtures("low_limit")
def test_each_number_is_converted_once_however_often_it_is_shared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    huge = int("9" * 600) ** 2
    seen: list[int] = []
    real = digits.too_long

    def counting(value: object) -> bool:
        if value is huge:
            seen.append(1)
        return real(value)

    monkeypatch.setattr(digits, "too_long", counting)
    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    doc["tags"] = [huge] * 25

    assert len(validate_attack_spec_schema(doc)) == 21
    assert len(seen) == 1


def _shared_set(doc: dict[str, Any], n: int, m: int) -> None:
    shared = {n}  # one set object at two places, as an alias hands it out
    doc["setup"]["first"] = shared
    doc["setup"]["second"] = shared


@pytest.mark.usefixtures("low_limit")
@pytest.mark.parametrize(
    ("place", "said"),
    [
        pytest.param(
            lambda doc, n, m: doc.__setitem__("name", frozenset({n})),
            ["name: a key that is a number too long to write out (over 640 digits)"],
            id="frozenset-value",
        ),
        pytest.param(
            lambda doc, n, m: doc["setup"].__setitem__((1, n), "v"),
            ["setup: a key that is a number too long to write out (over 640 digits)"],
            id="tuple-key",
        ),
        pytest.param(
            lambda doc, n, m: doc["setup"].__setitem__(frozenset({n}), {"x": m}),
            [
                "setup: a key that is a number too long to write out (over 640 digits)",
                "setup/<value>/x: a number too long to write out (over 640 digits)",
            ],
            id="frozenset-key-over-a-number",
        ),
        pytest.param(
            _shared_set,
            ["setup/first: a key that is a number too long to write out (over 640 digits)"],
            id="shared-set",
        ),
    ],
)
def test_a_value_built_in_code_is_walked_as_yaml_would_build_it(
    place: Any, said: list[str]
) -> None:
    """Members of a set, and of a key built as a tuple or a frozenset, are reported as keys (a
    YAML ``!!set`` is a mapping whose keys are its members); a part of a path that cannot be
    written is ``<value>``; a set shared through an alias is walked once."""

    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    place(doc, int("9" * 600) ** 2, int("8" * 600) ** 2)

    assert validate_attack_spec_schema(doc) == said


def test_a_stdio_mcp_target_is_recognised_whatever_the_case_and_spaces(tmp_path: Path) -> None:
    """``provider`` and ``transport`` are compared stripped and lowercased, as before A-40."""

    target = tmp_path / "target.yaml"
    target.write_text(
        'id: t\ntype: api\nprovider: " MCP "\ntransport: STDIO\ncommand: ["mcp-server"]\n',
        encoding="utf-8",
    )

    assert wiring.target_uses_mock(target) is False


@pytest.mark.usefixtures("low_limit")
def test_a_key_on_the_path_that_is_not_printable_is_written_as_repr() -> None:
    """A spec chooses its keys: a newline in one forged a finding line on the terminal, and an
    escape sequence reached it raw (pre-merge audit of #80, with this check in)."""

    key = "x" + chr(27) + "[31m" + chr(10) + "[ERROR] SCHEMA (FAKE-SPEC-001): forged"
    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    doc["setup"][key] = int("9" * 600) ** 2

    [message] = validate_attack_spec_schema(doc)

    assert message == f"setup/{key!r}: a number too long to write out (over 640 digits)"
    assert chr(27) not in message and chr(10) not in message


@pytest.mark.usefixtures("low_limit")
def test_a_lone_surrogate_in_a_key_on_the_path_is_written_escaped(tmp_path: Path) -> None:
    """Printing the path wrote the key as it was, and a lone surrogate in it cannot be encoded:
    lint exited 1 with a ``UnicodeEncodeError`` traceback (found by the delta audit of
    ``fix/spec-non-json-values``, on main at ``c3e70d8``)."""

    escape = chr(92) + "ud800"  # YAML's escape for a lone surrogate, written without one
    text = _planted(("setup", "tools", 0, "mode")).replace(
        "  - name:", f'  - "a{escape}b": {HEX_LOW}\n    name:', 1
    )
    specs = _spec_dir(tmp_path, text)

    result = runner.invoke(app, ["lint", str(specs)])

    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert result.exit_code == 1
    assert (
        "[ERROR] SCHEMA (AC-BFLA-001): setup/tools/0/'a" + escape + "b': a number" in result.stdout
    )


@pytest.mark.usefixtures("low_limit")
def test_a_printable_key_that_is_not_ascii_stays_readable() -> None:
    """Only what cannot be printed is escaped: a key in Spanish or Chinese reads as written."""

    spanish = "a" + chr(0xF1) + "o"
    chinese = chr(0x4E2D) + chr(0x6587)
    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    doc["setup"][spanish] = {chinese: int("9" * 600) ** 2}

    assert validate_attack_spec_schema(doc) == [
        f"setup/{spanish}/{chinese}: a number too long to write out (over 640 digits)"
    ]


def test_a_schema_error_under_a_key_with_a_lone_surrogate_is_a_finding(tmp_path: Path) -> None:
    """jsonschema's location printed the key with ``str``: a lone surrogate under
    ``step_arg_patterns`` made lint exit 1 with a ``UnicodeEncodeError`` traceback, before A-40
    too (pre-commit audit of its follow-up)."""

    escape = chr(92) + "ud800"
    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    doc["evaluators"][0]["step_arg_patterns"] = {"KEYHERE": 5}
    text = yaml.safe_dump(doc, sort_keys=False, width=10**6).replace("KEYHERE", f"a{escape}b")
    specs = _spec_dir(tmp_path, text.replace(f"a{escape}b:", f'"a{escape}b":'))

    result = runner.invoke(app, ["lint", str(specs)])

    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert result.exit_code == 1
    assert f"evaluators/0/step_arg_patterns/'a{escape}b': " in result.stdout


def test_a_schema_error_location_stays_readable_and_names_the_root() -> None:
    """The location of an ordinary schema error reads as before: a printable key as written, and
    an error about the document itself at ``<root>``."""

    spanish = "a" + chr(0xF1) + "o"
    doc = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    doc["evaluators"][0]["step_arg_patterns"] = {spanish: 5}
    del doc["id"]

    messages = validate_attack_spec_schema(doc)

    assert "<root>: 'id' is a required property" in messages
    assert any(
        m.startswith(f"evaluators/0/step_arg_patterns/{spanish}: 5 is not") for m in messages
    )
