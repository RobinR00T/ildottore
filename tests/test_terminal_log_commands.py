"""CI log commands a runner reads anywhere in a line (2026-10-07).

Left open by PR #51 and pre-existing on main (`d19b221`): a GitHub Actions runner reads the
legacy `##[<command>]` form anywhere in a line of a step's output, not only at its start
(`ActionCommand.TryParse` looks for `##[` with `IndexOf`, and `ActionCommandManager` falls back
to it when the `::` form does not parse). A spec file named `x ##[error file=a.py,line=1]...`
reached a line of `dottore run` on stderr and of `dottore coverage` on stdout, and a spec named
`Direct ##[add-mask]FAIL` the end of a line of `registry ls` and `describe`.

Verified on 2026-10-07 with the runner's own code (actions/runner `67f01c2`, v2.338.0): every
line `dottore` printed with `##[` in it, fed to the runner's `OutputManager` with its real
`ActionCommandManager`, was taken as a command. It raised `error` and `warning` annotations (with
the `file` the name gave), `add-mask` masked the word `FAIL` in every later line of the log, and
`set-output` set a step output (`verdict=clean`). On PR #51 one more line carried it: the run's
off-universe warning, printed without markup since, where `rich` used to eat `[warning]`.

The Azure Pipelines agent reads `##vso[<area>.<event>]` the same way, with an ordinal `IndexOf`
(`Command.TryParse`, microsoft/azure-pipelines-agent `59c86a8`, whose own test parses
`>>>   ##vso[area.event k1=v1;]msg`); run the same way through `Command.TryParse` alone, its
lines gave `task.logissue` and `task.setvariable`, which sets a pipeline variable.

The prefix match of the GitHub runner is culture-sensitive, so ICU ignores a zero-width character
inside `##[`. The match then still starts at the first `#`, and the runner reads the command name
3 characters after it, which lands on `[`: with one of 18 such characters between the two `#` or
between `#` and `[`, nothing parsed, in 3 cultures. Placed before `##[` it parsed (the prefix is
raw), right after it the name matched no command. Only a raw `##[` is a command, and that is
what these tests look for.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from ildottore import redactor as redactor_mod
from ildottore.cli.app import _masked, app
from ildottore.redactor import Redactor, visible_controls

REPO = Path(__file__).resolve().parents[1]

#: Any `##<letters>[` written raw. Both parsers need one: GitHub's finds `##[` (ordinal, or with
#: ICU ignoring a zero-width character inside it, which then reads the name from `[`), Azure's
#: finds `##vso[` (ordinal). A line without one is no command to either.
_RAW_PREFIX = re.compile(r"##[A-Za-z]*\[")


def _commands(output: str) -> list[str]:
    """Lines that still carry a raw prefix, so a runner could act on them."""

    return [line for line in output.splitlines() if _RAW_PREFIX.search(line)]


# --- visible_controls ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "written"),
    [
        ("x ##[error file=a.py,line=1]pwned.yaml", "x #\\x23[error file=a.py,line=1]pwned.yaml"),
        ("##vso[task.setvariable variable=X]1", "#\\x23vso[task.setvariable variable=X]1"),
        ("##VSO[task.setvariable variable=X]1", "#\\x23VSO[task.setvariable variable=X]1"),
        ("##teamcity[message text='x']", "#\\x23teamcity[message text='x']"),
        ("###[error]x", "##\\x23[error]x"),
        ("####[error]x", "###\\x23[error]x"),
        ("##[##[error]x", "#\\x23[#\\x23[error]x"),
        ("a ##[add-mask]FAIL", "a #\\x23[add-mask]FAIL"),
        ("#\n#[error]x", "#\u240a#[error]x"),
    ],
)
def test_visible_controls_writes_a_log_command_prefix_out(text: str, written: str) -> None:
    once = visible_controls(text)
    assert once == written
    assert visible_controls(once) == once
    assert _commands(once) == []


@pytest.mark.parametrize(
    "text",
    [
        "# heading",
        "#[x]",
        "## [x]",
        "C## and F#",
        "##",
        "##1[x]",
        "##-vso[x]",
        "a#b#[c]",
        "#\\x23[error] already written out",
        "\uff03\uff03[error]",
    ],
)
def test_visible_controls_leaves_other_hashes_alone(text: str) -> None:
    assert visible_controls(text) == text


_ALPHABET = st.sampled_from(
    [
        *("#", "##", "[", "]", "v", "s", "o", "V", "x", "u", "U", "e", "\\", "2", "3", "a", " "),
        *("\n", "\x85", "\u200b", "\ufeff", "\U000e0041"),
    ]
)


@settings(max_examples=400)
@given(st.lists(_ALPHABET, max_size=40).map("".join))
def test_visible_controls_leaves_no_prefix_and_is_its_own_fixed_point(text: str) -> None:
    once = visible_controls(text)
    assert not _RAW_PREFIX.search(once), once
    assert visible_controls(once) == once
    assert [ch for ch in once if unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp", "Cs"}] == []


#: Any character, lone surrogates included, with `#`, `[` and letters often.
_ANY = st.lists(
    st.one_of(
        st.sampled_from(["#", "##", "[", "vso", "a", "\udc9b", "\x85"]),
        st.characters(exclude_categories=()),
    ),
    max_size=40,
).map("".join)


@settings(max_examples=400)
@given(_ANY)
def test_text_without_a_prefix_is_written_out_as_before(text: str) -> None:
    """Only the prefix is new: any other text is written out exactly as PR #51 wrote it."""

    assume(not _RAW_PREFIX.search(text))
    controls_only = redactor_mod._TERMINAL_CONTROLS.sub(redactor_mod._visible_control, text)
    assert visible_controls(text) == controls_only


# --- the CLI end to end --------------------------------------------------------------------

#: The file name of the finding, and one in the runner's own property syntax (`;`).
_FILE_NAMES = [
    "x ##[error file=a.py,line=1]pwned.yaml",
    "x ##[error file=a.py;line=1]pwned.yaml",
    "x ##vso[task.logissue type=error]pwned.yaml",
]


def _good() -> str:
    return (REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text()


def _pack(root: Path, files: dict[str, str]) -> Path:
    pack = root / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: pack\npack_version: '1.0'\nname: pack\n")
    for name, body in files.items():
        (pack / "attacks" / name).write_text(body)
    return pack


def _broken_pack(root: Path, name: str) -> Path:
    broken = (
        _good()
        .replace("id: PI-DIRECT-001", "id: PI-TYPO-001")
        .replace("severity: high", "severty: high")
    )
    return _pack(root, {"PI-DIRECT-001.yaml": _good(), name: broken})


def _named_pack(root: Path, name: str) -> Path:
    head, _, rest = _good().partition("\nname:")
    _, _, rest = rest.partition("\n")
    return _pack(root, {"PI-DIRECT-001.yaml": f"{head}\nname: {json.dumps(name)}\n{rest}"})


def _scope_and_target(root: Path) -> tuple[Path, Path]:
    scope, target = root / "scope.yaml", root / "target.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    target.write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: hardened\n"
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    return scope, target


def _run(root: Path, pack: Path, *extra: str) -> list[str]:
    scope, target = _scope_and_target(root)
    return [
        *("run", "-t", str(target), "--scope", str(scope), "--spec-path", str(pack)),
        *("--evidence-root", str(root / "ev"), "--run-db", str(root / "r.sqlite"), "--no-color"),
        *extra,
    ]


@pytest.mark.parametrize("name", _FILE_NAMES)
def test_dottore_run_writes_a_file_name_s_log_command_out(tmp_path: Path, name: str) -> None:
    result = CliRunner().invoke(app, _run(tmp_path, _broken_pack(tmp_path, name), "-q"))
    assert result.exit_code == 3, result.output
    assert len(result.stderr.splitlines()) == 1, result.stderr
    assert _commands(result.stderr) == [], result.stderr
    assert f"attacks/{visible_controls(name)}: " in result.stderr
    assert "#\\x23" in result.stderr


@pytest.mark.parametrize("name", _FILE_NAMES)
def test_dottore_coverage_writes_a_file_name_s_log_command_out(tmp_path: Path, name: str) -> None:
    pack, written = _broken_pack(tmp_path, name), visible_controls(name)
    for path, shown in ((pack, f"attacks/{written}"), (pack / "attacks", written)):
        result = CliRunner().invoke(app, ["coverage", str(path)])
        assert result.exit_code == 0, result.output
        assert "failed to load and are NOT counted" in result.stdout
        assert _commands(result.stdout) == [], result.stdout
        assert f"    - {shown}  " in result.stdout, result.stdout


@pytest.mark.parametrize(
    "name",
    [
        "Direct ##[add-mask]FAIL",
        "Direct ##[set-output name=verdict]clean",
        "Direct ##vso[task.setvariable variable=DOTTORE_GATE]pass",
    ],
)
def test_registry_ls_and_describe_write_a_spec_name_s_log_command_out(
    tmp_path: Path, name: str
) -> None:
    """A spec's name ends both lines, so the runner takes the rest of it as the command's data:
    `add-mask` masked `FAIL` in every later line of the log, `set-output` set an output."""

    pack = _named_pack(tmp_path, name)
    listed = CliRunner().invoke(app, ["registry", "ls", "--spec-path", str(pack)])
    assert listed.exit_code == 0, listed.output
    assert _commands(listed.stdout) == [], listed.stdout
    assert listed.stdout.endswith(f"\t{visible_controls(name)}\n")

    card = CliRunner().invoke(app, ["describe", "PI-DIRECT-001", "--spec-path", str(pack)])
    assert card.exit_code == 0, card.output
    assert _commands(card.stdout) == [], card.stdout
    assert f"name:        {visible_controls(name)}\n" in card.stdout


def _tactic_pack(root: Path, tactic: str) -> Path:
    good = _good()
    assert "  tactic: Initial Access\n" in good
    return _pack(
        root,
        {"PI-DIRECT-001.yaml": good.replace("Initial Access", json.dumps(tactic), 1)},
    )


def test_coverage_writes_an_off_universe_value_s_log_command_out(tmp_path: Path) -> None:
    """The value is printed as its `repr`, which escapes control characters and not `##[`."""

    result = CliRunner().invoke(app, ["coverage", str(_tactic_pack(tmp_path, "##[warning]x"))])
    assert result.exit_code == 0, result.output
    assert "mitre_atlas.tactic = '#\\x23[warning]x'" in result.stdout
    assert _commands(result.stdout) == [], result.stdout


def test_the_run_summary_writes_an_off_universe_value_s_log_command_out(tmp_path: Path) -> None:
    """On PR #51 this line is printed without markup; on main `rich` ate `[warning]`."""

    result = CliRunner().invoke(app, _run(tmp_path, _tactic_pack(tmp_path, "##[warning]x")))
    assert result.exit_code == 0, result.output
    assert "mitre_atlas.tactic='#\\x23[warning]x'" in result.stdout
    assert _commands(result.output) == [], result.output


def test_lint_writes_a_quoted_pack_value_s_log_command_out(tmp_path: Path) -> None:
    """A key of `step_arg_patterns` is free text, and the schema error quotes it."""

    key = json.dumps("k ##[error]from-key")
    body = (
        _good()
        .replace("id: PI-DIRECT-001", "id: PI-BAD-001")
        .replace(
            "evaluators:\n",
            f"evaluators:\n  - type: tool_sequence\n    step_arg_patterns: {{{key}: 5}}\n",
            1,
        )
    )
    pack = _pack(tmp_path, {"PI-BAD-001.yaml": body})
    for command in ("lint", "coverage"):
        result = CliRunner().invoke(app, [command, str(pack)])
        assert "k #\\x23[error]from-key" in result.stdout, result.stdout
        assert _commands(result.stdout) == [], result.stdout


def test_masked_writes_a_log_command_out() -> None:
    assert _masked(ValueError("failed: attacks/x ##[error]p.yaml")) == (
        "failed: attacks/x #\\x23[error]p.yaml"
    )


def test_the_incomplete_run_line_writes_a_target_s_log_command_out() -> None:
    """The reason quotes a target's transport error: a target chooses that text."""

    from ildottore.cli.run import _incomplete_lines

    (line,) = _incomplete_lines(
        {"t": "every attempt failed on transport: ##[set-output name=verdict]clean"},
        Redactor(salt="s"),
    )
    assert line.endswith("transport: #\\x23[set-output name=verdict]clean")
    assert _commands(line) == []


@pytest.mark.parametrize(
    "value",
    [
        "x ##[error file=src/app.py,line=1,title=Il Dottore]prompt injection confirmed",
        "##vso[task.setvariable variable=DOTTORE_GATE]pass",
    ],
)
def test_the_run_plan_writes_a_requires_policy_value_s_log_command_out(
    tmp_path: Path, value: str
) -> None:
    """Under `-vv` the plan lists each spec the policy pack refused with its reason, which quotes
    the pack's `requires_policy` values as their `repr` (pre-commit audit of this block)."""

    good = _good()
    blocked = good.replace("id: PI-DIRECT-001", "id: PI-BLOCK-001").replace(
        "evaluator_logic: weighted",
        f"evaluator_logic: weighted\nrequires_policy: [{json.dumps(value)}]",
    )
    assert "requires_policy" in blocked
    pack = _pack(tmp_path, {"PI-DIRECT-001.yaml": good, "PI-BLOCK-001.yaml": blocked})
    result = CliRunner().invoke(app, _run(tmp_path, pack, "--dry-run", "-vv"))
    assert result.exit_code == 0, result.output
    assert "    - PI-BLOCK-001: spec 'PI-BLOCK-001' requires policy" in result.stdout
    assert visible_controls(value) in result.stdout
    assert _commands(result.output) == [], result.output


def test_the_resume_note_writes_a_stored_scope_entry_out(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The run store keeps any string in its scope list, and a resume quotes its first and last
    entries (delta audit of this block: an edited or restored store)."""

    import sqlite3
    from contextlib import closing

    from ildottore.cli.run import _record_scope

    db, run_id = tmp_path / "runs.sqlite", "run-abc123def456"
    _record_scope(db, run_id, "a" * 64, resumed=False)
    # `closing`: a connection's own `with` commits and leaves it open (a ResourceWarning).
    with closing(sqlite3.connect(db)) as conn, conn:
        query = "SELECT context_json FROM runs WHERE run_id = ?"
        (context,) = conn.execute(query, (run_id,)).fetchone()
        stored = {**json.loads(context), "scope_sha256s": ["##[error]pwn", "x\n::error::pw"]}
        conn.execute(
            "UPDATE runs SET context_json = ? WHERE run_id = ?", (json.dumps(stored), run_id)
        )
    _record_scope(db, run_id, "b" * 64, resumed=True)
    err = capsys.readouterr().err
    assert len(err.splitlines()) == 1, err
    assert "under scope sha256 #\\x23[error]pwn..." in err
    assert "last ran under x\u240a::error::p..." in err
    assert _commands(err) == []


# --- what this does not change -------------------------------------------------------------


@pytest.mark.parametrize("command", ["coverage", "lint"])
def test_json_output_keeps_the_value_as_it_is(tmp_path: Path, command: str) -> None:
    """JSON is data for a program, not a log line for a reader: its values are not rewritten.
    Printed to a CI log it still carries the prefix (an open decision, see CHANGELOG)."""

    name = _FILE_NAMES[0]
    result = CliRunner().invoke(app, [command, "--json", str(_broken_pack(tmp_path, name))])
    payload = json.loads(result.stdout)
    assert name in json.dumps(payload, ensure_ascii=False)
    assert _RAW_PREFIX.search(result.stdout), "the bytes still carry it: OD-20 is open"
    assert "#\\\\x23" not in result.stdout
