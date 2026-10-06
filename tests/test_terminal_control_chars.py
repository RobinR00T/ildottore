"""Control characters on the terminal (2026-10-06).

Found by the pre-merge audit of PR #49 and reproduced on main (`d54097c`): every CLI error goes
through `cli/app._masked`, which redacts secrets and left control characters as they were. A
spec file whose name holds a newline (a third-party pack author chooses file names,
`docs/02-threat-model.md` §4) made `dottore run` print, on stderr, a line GitHub Actions reads
as a workflow command (`::error ...`). The same text reached the terminal raw on paths that
bypass `_masked`: the text output of `lint` and `coverage`, the spec name in `registry ls` and
`describe`, a halted report's reason in `diff`, the `replay` warning, the spend warning, and the
"run did not complete" line, whose reason quotes a target's error. That last line went through
`rich`, which also wrapped it at 80 columns in a CI log (a target could place `::error` at the
start of a line with no control character at all), read `[/]` as markup (`MarkupError`, a
traceback before the reports were written) and turned `:warning:` into an emoji.

A registered credential split by a newline was printed in two readable halves; split by
``\\x00`` it was masked (the redactor drops its stash delimiters first).
"""

from __future__ import annotations

import json
import sys
import unicodedata
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore import redactor as redactor_mod
from ildottore.cli.app import _masked, app
from ildottore.redactor import register_known_secret

REPO = Path(__file__).resolve().parents[1]

#: The injected name of the repro: a newline, then a GitHub Actions workflow command.
INJECTED = "x\n::error title=pwned::injected.yaml"

#: Unicode categories of what must never reach the terminal raw: controls (C0, DEL, C1), the
#: line and paragraph separators, lone surrogates, and the format characters (Cf, since
#: 2026-10-07: a bidi control reorders what is read, a zero-width or tag character hides text).
_RAW: frozenset[str] = frozenset({"Cc", "Zl", "Zp", "Cs", "Cf"})

#: One format character of each kind: soft hyphen, zero-width space and joiner, word joiner,
#: right-to-left override, left-to-right isolate, byte order mark, language tag, tag letter A.
_FORMATS = [
    chr(c) for c in (0xAD, 0x200B, 0x200D, 0x2060, 0x202E, 0x2066, 0xFEFF, 0xE0001, 0xE0041)
]

#: One of every character class the terminal must see written out.
_CONTROLS = [
    *(chr(c) for c in range(0x20)),
    "\x7f",
    *(chr(c) for c in range(0x80, 0xA0)),
    "\u2028",
    "\u2029",
    "\ud800",
    "\udc9b",
    "\udfff",
    *_FORMATS,
]


def _expected(ch: str) -> str:
    code = ord(ch)
    if code < 0x20:
        return chr(0x2400 + code)
    if code == 0x7F:
        return "\u2421"
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"


def _raw_controls(text: str) -> list[str]:
    return [ch for ch in text if unicodedata.category(ch) in _RAW]


def _injected_lines(output: str) -> list[str]:
    """Lines a GitHub Actions runner would read as a workflow command (leading space trimmed)."""

    return [line for line in output.splitlines() if line.lstrip().startswith("::")]


@pytest.fixture
def no_known_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Registered credentials are process-wide: a test's own do not outlive it."""

    monkeypatch.setattr(redactor_mod, "_KNOWN_SECRETS", set())


# --- _masked -------------------------------------------------------------------------------


def test_masked_writes_the_newline_of_a_spec_file_name_instead_of_starting_a_line() -> None:
    out = _masked(ValueError(f"1 spec file(s) failed to load: attacks/{INJECTED}: bad"))
    assert out == (
        "1 spec file(s) failed to load: attacks/x\u240a::error title=pwned::injected.yaml: bad"
    )


@pytest.mark.parametrize("ch", _CONTROLS, ids=lambda ch: f"U+{ord(ch):04X}")
def test_masked_writes_every_control_character_out(ch: str) -> None:
    out = _masked(ValueError(f"name a{ch}b end"))
    assert _raw_controls(out) == []
    assert out == f"name a{_expected(ch)}b end"


def test_masked_leaves_no_control_character_inside_a_kept_path(tmp_path: Path) -> None:
    """An existing path is kept unredacted; it is written out like the rest."""

    folder = tmp_path / "a\nb"
    folder.mkdir()
    out = _masked(OSError(f"cannot write {folder}/report.json"))
    assert _raw_controls(out) == [] and "a\u240ab" in out


@pytest.mark.parametrize(
    "sep", ["\n", "\r", "\x00", "\x01", "\x1b", "\x7f", "\x85", "\u2028", "\u2029", "\udc9b"]
)
@pytest.mark.usefixtures("no_known_secrets")
def test_a_registered_credential_split_by_a_control_character_is_masked_whole(sep: str) -> None:
    register_known_secret("Zq9vT4mXa81LpR2w")
    whole = _masked(ValueError("auth failed: Zq9vT4mXa81LpR2w end"))
    out = _masked(ValueError(f"auth failed: Zq9vT4mX{sep}a81LpR2w end"))
    assert "Zq9vT4mX" not in out and "a81LpR2w" not in out
    assert out == whole, "the same mask, digest included, as the credential in one piece"
    assert _raw_controls(out) == []


@pytest.mark.usefixtures("no_known_secrets")
def test_a_credential_split_several_times_and_by_mixed_controls_is_masked_whole() -> None:
    register_known_secret("Zq9vT4mXa81LpR2w")
    out = _masked(ValueError("a Zq9v\nT4mX\x1ba81L\u2028pR2w\r\nb"))
    for piece in ("Zq9v", "T4mX", "a81L", "pR2w"):
        assert piece not in out
    assert out.startswith("a «REDACTED:credential:") and out.endswith("»\u240d\u240ab")
    assert _raw_controls(out) == []


@pytest.mark.usefixtures("no_known_secrets")
def test_a_credential_split_by_printable_characters_is_still_kept() -> None:
    """Only control characters are ignored: an escape sequence's own `[0m`, like a space,
    still splits a credential the redactor sees in one piece only (documented limit)."""

    register_known_secret("Zq9vT4mXa81LpR2w")
    out = _masked(ValueError("a Zq9vT4mX\x1b[0ma81LpR2w b"))
    assert out == "a Zq9vT4mX\u241b[0ma81LpR2w b"


@pytest.mark.usefixtures("no_known_secrets")
def test_controls_around_a_credential_are_written_out_and_the_credential_masked() -> None:
    register_known_secret("Zq9vT4mXa81LpR2w")
    out = _masked(ValueError("x\nZq9vT4mXa81LpR2w\n::error::y"))
    assert "Zq9vT4mX" not in out and _raw_controls(out) == []
    assert out.endswith("\u240a::error::y") and out.startswith("x\u240a«REDACTED:credential:")


# --- the CLI end to end --------------------------------------------------------------------


def _pack(root: Path, broken_name: str = INJECTED) -> Path:
    pack = root / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: pack\npack_version: '1.0'\nname: pack\n")
    good = (REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text()
    (pack / "attacks" / "PI-DIRECT-001.yaml").write_text(good)
    (pack / "attacks" / broken_name).write_text(
        good.replace("id: PI-DIRECT-001", "id: PI-TYPO-001").replace(
            "severity: high", "severty: high"
        )
    )
    return pack


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


def test_dottore_run_prints_the_load_refusal_on_one_line(tmp_path: Path) -> None:
    scope, target = _scope_and_target(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            *("run", "-t", str(target), "--scope", str(scope)),
            *("--spec-path", str(_pack(tmp_path))),
            *("--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "r.sqlite")),
            *("--no-color", "-q"),
        ],
    )
    assert result.exit_code == 3, result.output
    assert len(result.stderr.splitlines()) == 1, result.stderr
    assert _injected_lines(result.stderr) == [] and _raw_controls(result.stderr.rstrip("\n")) == []
    assert "x\u240a::error title=pwned::injected.yaml" in result.stderr


def test_dottore_lint_prints_a_broken_file_name_on_its_own_line(tmp_path: Path) -> None:
    """Lint names a file by its spec id when it has one, by its path when it does not parse."""

    pack = _pack(tmp_path, broken_name="ok.yaml")
    (pack / "attacks" / INJECTED).write_text("id: [unclosed\n")
    result = CliRunner().invoke(app, ["lint", str(pack)])
    assert result.exit_code == 1, result.output
    assert _injected_lines(result.stdout) == []
    for line in result.stdout.rstrip("\n").split("\n"):
        assert _raw_controls(line) == [], line
    assert "x\u240a::error title=pwned::injected.yaml" in result.stdout


@pytest.mark.parametrize("name", [INJECTED, "::error title=pwned::bare.yaml"])
def test_dottore_coverage_starts_no_line_with_a_file_name(tmp_path: Path, name: str) -> None:
    """The unloaded files were listed one per line, indented: a file named `::error ...`
    in the folder given to `coverage` started a line, which a runner trims and reads."""

    pack = _pack(tmp_path, broken_name=name)
    for path in (pack, pack / "attacks"):
        result = CliRunner().invoke(app, ["coverage", str(path)])
        assert result.exit_code == 0, result.output
        assert "failed to load and are NOT counted" in result.stdout
        assert _injected_lines(result.stdout) == [], result.stdout
        for line in result.stdout.rstrip("\n").split("\n"):
            assert _raw_controls(line) == [], line


def _named_spec_pack(root: Path, name: str) -> Path:
    pack = root / "named"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: named\npack_version: '1.0'\nname: named\n")
    good = (REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text()
    head, _, rest = good.partition("\nname:")
    _, _, rest = rest.partition("\n")
    (pack / "attacks" / "PI-DIRECT-001.yaml").write_text(
        f"{head}\nname: {json.dumps(name)}\n{rest}"
    )
    return pack


def test_registry_ls_and_describe_write_a_spec_name_out(tmp_path: Path) -> None:
    pack = _named_spec_pack(tmp_path, "Direct\n::error title=pwned::x\u2028y")
    listed = CliRunner().invoke(app, ["registry", "ls", "--spec-path", str(pack)])
    assert listed.exit_code == 0, listed.output
    assert listed.stdout.count("\n") == 1 and _injected_lines(listed.stdout) == []
    assert "\t" in listed.stdout, "the column separators stay tabs"
    assert "Direct\u240a::error title=pwned::x\\u2028y" in listed.stdout

    card = CliRunner().invoke(app, ["describe", "PI-DIRECT-001", "--spec-path", str(pack)])
    assert card.exit_code == 0, card.output
    assert _injected_lines(card.stdout) == []
    assert "name:        Direct\u240a::error title=pwned::x\\u2028y\n" in card.stdout


def test_a_missing_spec_path_is_named_on_one_line(tmp_path: Path) -> None:
    missing = tmp_path / "no\n::error title=pwned::such"
    result = CliRunner().invoke(app, ["registry", "ls", "--spec-path", str(missing)])
    assert len(result.stderr.splitlines()) == 1 and _injected_lines(result.stderr) == []
    assert "no\u240a::error title=pwned::such" in result.stderr


def test_dottore_diff_writes_a_halted_report_reason_out(tmp_path: Path) -> None:
    """A report's status reason quotes a target's transport error."""

    halted = tmp_path / "halted.json"
    halted.write_text(
        json.dumps(
            {
                "findings": [],
                "summary": {
                    "status": {
                        "state": "unreachable",
                        "complete": False,
                        "reason": "t: refused\n::error title=pwned::x",
                    }
                },
            }
        )
    )
    result = CliRunner().invoke(app, ["diff", str(halted), str(halted)])
    assert result.exit_code == 3
    assert len(result.stderr.splitlines()) == 1 and _injected_lines(result.stderr) == []
    assert "refused\u240a::error title=pwned::x" in result.stderr


def test_the_replay_warning_is_written_out(monkeypatch: pytest.MonkeyPatch) -> None:
    from ildottore.cli import replay as replay_mod

    monkeypatch.setattr(
        replay_mod,
        "replay_checked",
        lambda *_a, **_k: (object(), "no run store at x\n::error title=pwned::y: ..."),
    )
    monkeypatch.setattr(replay_mod, "render_replay", lambda _r: "replayed")
    result = CliRunner().invoke(app, ["replay", "run-1"])
    assert result.exit_code == 0, result.output
    assert _injected_lines(result.stderr) == []
    assert "x\u240a::error title=pwned::y" in result.stderr


# --- the run's own lines -------------------------------------------------------------------


def test_the_spend_warning_is_written_out(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    from ildottore.cli import run as run_mod
    from ildottore.core.budgets import Spend

    def _fail(*_a: object, **_k: object) -> None:
        raise OSError("disk full\n::error title=pwned::x")

    monkeypatch.setattr(run_mod, "_persist_spend", _fail)
    run_mod._record_spend_quietly(tmp_path / "r.sqlite", "run-x", Spend(requests=1))
    err = capsys.readouterr().err
    assert len(err.splitlines()) == 1 and _injected_lines(err) == []
    assert "full\u240a::error title=pwned::x" in err


def test_the_printer_writes_an_error_as_one_line_of_plain_text(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`rich` wrapped at 80 columns in a CI log, read `[/]` as markup and `:warning:` as an
    emoji; a target's text reaches this line."""

    from ildottore.cli.render import ProgressPrinter

    # Wrapped at 80 columns, the second line of this one began `::error title=pwned::x`.
    line = "error: run on t did not complete: refused " + "a " * 17 + "::error title=pwned::x"
    ProgressPrinter(no_color=True).error(line)
    ProgressPrinter(no_color=True).error("error: [/] :warning:")
    assert capsys.readouterr().err == f"{line}\nerror: [/] :warning:\n"


def test_the_summary_prints_its_coverage_lines_unwrapped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The off-universe line quotes a pack's values (`mitre_atlas.tactic` is free text, and a
    run does not lint): wrapped at 80 columns, `::error` could start a line."""

    from ildottore.cli import render as render_mod

    head = "WARNING: 1 framework value(s) outside their pinned universe were NOT counted: "
    # Wrapped at 80 columns, the third line of this one began `::error title=pwned::x'`.
    wrapped = head + "PI-X-001 mitre_atlas.tactic='" + "a " * 25 + "::error title=pwned::x'"
    markup = head + "PI-X-002 mitre_atlas.tactic='[/] :warning:'"
    monkeypatch.setattr(render_mod, "coverage_lines", lambda *_a, **_k: [wrapped, markup])
    render_mod.ProgressPrinter(no_color=True).summary([], {})
    out = capsys.readouterr().out
    assert f"{wrapped}\n{markup}\n" in out and _injected_lines(out) == []


def test_the_incomplete_run_line_writes_a_target_error_out() -> None:
    from ildottore.cli.run import _incomplete_lines
    from ildottore.redactor import Redactor

    lines = _incomplete_lines(
        {"t\u2028x": "every attempt failed on transport: refused\n::error title=pwned::x"},
        Redactor(salt="s"),
    )
    assert lines == [
        "error: run on t\\u2028x did not complete: every attempt failed on transport: "
        "refused\u240a::error title=pwned::x"
    ]


@pytest.mark.usefixtures("no_known_secrets")
def test_the_incomplete_run_line_masks_a_credential_a_target_split() -> None:
    from ildottore.cli.run import _incomplete_lines
    from ildottore.redactor import Redactor

    register_known_secret("Zq9vT4mXa81LpR2w")
    (line,) = _incomplete_lines({"t": "echo Zq9vT4mX\na81LpR2w"}, Redactor(salt="s"))
    assert "Zq9vT4mX" not in line and "a81LpR2w" not in line and _raw_controls(line) == []


# --- the helpers ---------------------------------------------------------------------------


@pytest.mark.parametrize("ch", _CONTROLS, ids=lambda ch: f"U+{ord(ch):04X}")
def test_visible_controls_writes_every_class_out_and_is_stable(ch: str) -> None:
    from ildottore.redactor import visible_controls

    once = visible_controls(f"a{ch}b")
    assert once == f"a{_expected(ch)}b" and visible_controls(once) == once


def test_visible_controls_writes_every_format_character_of_this_python_out() -> None:
    from ildottore.redactor import visible_controls

    formats = [chr(c) for c in range(0x110000) if unicodedata.category(chr(c)) == "Cf"]
    once = visible_controls("".join(formats))
    assert _raw_controls(once) == [] and visible_controls(once) == once
    assert once == "".join(_expected(ch) for ch in formats)


def test_the_format_characters_are_every_cf_character_of_this_python() -> None:
    """Pinned to Unicode 16.0 so the output never depends on the Python's Unicode version."""

    pinned = {c for low, high in redactor_mod._FORMAT_RANGES for c in range(low, high + 1)}
    here = {c for c in range(0x110000) if unicodedata.category(chr(c)) == "Cf"}
    assert here <= pinned and len(pinned) == 170
    # An older Python (3.11 has Unicode 14.0) does not know the newest ones yet.
    assert {unicodedata.category(chr(c)) for c in pinned - here} <= {"Cn"}


@pytest.mark.parametrize("sep", _FORMATS, ids=lambda ch: f"U+{ord(ch):04X}")
@pytest.mark.usefixtures("no_known_secrets")
def test_a_registered_credential_split_by_a_format_character_is_masked_whole(sep: str) -> None:
    """Written out, the format character would leave the two halves readable around it."""

    register_known_secret("Zq9vT4mXa81LpR2w")
    whole = _masked(ValueError("auth failed: Zq9vT4mXa81LpR2w end"))
    out = _masked(ValueError(f"auth failed: {sep}Zq9vT4mX{sep}a81LpR2w{sep} end"))
    assert "Zq9vT4mX" not in out and "a81LpR2w" not in out
    assert out == whole.replace(" end", f"{_expected(sep)} end").replace(
        "failed: ", f"failed: {_expected(sep)}"
    )
    assert _raw_controls(out) == []


def test_visible_controls_matches_the_redactor_s_own_delimiter_pictures() -> None:
    from ildottore.redactor import visible_controls, visible_stash_delimiters

    assert visible_controls("\x00\x01") == visible_stash_delimiters("\x00\x01") == "\u2400\u2401"


def test_visible_controls_leaves_ordinary_text_alone() -> None:
    from ildottore.redactor import visible_controls

    text = "café «REDACTED:x» 東京 \\n tab-free, emoji 🙂 and RTL שלום"
    assert visible_controls(text) == text


def test_a_surrogate_written_out_can_be_encoded_strictly() -> None:
    """A Linux file name with a byte that is not UTF-8 arrives as a lone surrogate, which a
    strict stdout cannot encode and a `surrogateescape` one writes back as the raw byte (a C1
    control for 0x80 to 0x9f)."""

    from ildottore.redactor import visible_controls

    name = b"attacks/x\x9b2J.yaml".decode(sys.getfilesystemencoding(), "surrogateescape")
    visible_controls(name).encode("utf-8")  # does not raise


@pytest.mark.usefixtures("no_known_secrets")
def test_mask_split_credentials_leaves_text_without_a_split_credential_unchanged() -> None:
    from ildottore.redactor import Redactor

    register_known_secret("Zq9vT4mXa81LpR2w")
    redactor = Redactor(salt="s")
    for text in ("plain text", "line\nbreak", "Zq9vT4mXa81LpR2w whole", "Zq9v T4mXa81LpR2w"):
        assert redactor.mask_split_credentials(text) == text


@pytest.mark.usefixtures("no_known_secrets")
def test_two_overlapping_credentials_are_masked_as_one() -> None:
    """Masking one of two overlapping credentials left the other's tail readable."""

    from ildottore.redactor import Redactor

    register_known_secret("ABCDEFGHIJ12")
    register_known_secret("HIJ12KLMNOPQ")
    out = Redactor(salt="s").for_terminal("x ABCDEFGHIJ12K\nLMNOPQ y")
    assert out.startswith("x «REDACTED:credential:") and out.endswith("» y")
    assert out.count("«") == 1


@pytest.mark.usefixtures("no_known_secrets")
def test_a_credential_shorter_than_eight_without_its_controls_is_not_matched() -> None:
    """Registered values shorter than 8 characters are not masked by value; one that is that
    short once its control characters are removed is not matched either."""

    from ildottore.redactor import Redactor

    register_known_secret("ab\n\n\n\n\n\ncd")
    assert Redactor(salt="s").mask_split_credentials("x abcd\ny") == "x abcd\ny"


@pytest.mark.usefixtures("no_known_secrets")
def test_with_no_registered_credential_the_text_is_returned_as_it_is() -> None:
    from ildottore.redactor import Redactor

    assert Redactor(salt="s").mask_split_credentials("a\nb\x00c") == "a\nb\x00c"


# --- the pre-commit audit of this block ------------------------------------------------------

#: The control picture of a newline, as `visible_controls` writes it.
LF = chr(0x240A)


@pytest.mark.usefixtures("no_known_secrets")
def test_every_occurrence_of_a_split_credential_is_masked() -> None:
    register_known_secret("Zq9vT4mXa81LpR2w")
    out = _masked(ValueError("a Zq9vT4mX\na81LpR2w b Zq9vT4mX\na81LpR2w c"))
    assert "Zq9vT4mX" not in out and "a81LpR2w" not in out and out.count("«") == 2


@pytest.mark.usefixtures("no_known_secrets")
def test_a_split_credential_of_exactly_eight_characters_is_masked() -> None:
    register_known_secret("Zq9vT4mX")
    out = _masked(ValueError("a Zq9v\nT4mX b"))
    assert "Zq9v" not in out and "T4mX" not in out


@pytest.mark.usefixtures("no_known_secrets")
def test_a_split_key_is_masked_before_its_head_matches_a_key_pattern() -> None:
    """Redacted first, the `sk-` pattern took the head and left the tail readable."""

    key = "sk-Ab3dE5gH7jK9mN1pQ3sT5vW7TAILzz99"
    register_known_secret(key)
    out = _masked(ValueError(f"echo {key[:27]}\n{key[27:]} end"))
    assert "TAILzz99" not in out and out.startswith("echo «REDACTED:credential:")


@pytest.mark.usefixtures("no_known_secrets")
def test_a_key_after_a_c1_control_is_still_recognised() -> None:
    """Written out first, `\\x85sk-...` had no word boundary before the key's pattern."""

    from ildottore.redactor import Redactor

    key = "sk-" + "a" * 24
    out = Redactor(salt="s").for_terminal(f"refused{chr(0x85)}{key} end")
    assert key not in out and out.startswith("refused\\x85«REDACTED:")


@pytest.mark.usefixtures("no_known_secrets")
def test_a_periodic_credential_overlapping_itself_is_masked_whole() -> None:
    register_known_secret("Q7wQ7wQ7wQ7w")
    out = _masked(ValueError("x Q7wQ7w\nQ7wQ7wQ7w y"))
    assert "Q7w" not in out


@pytest.mark.usefixtures("no_known_secrets")
def test_a_key_read_with_a_trailing_cr_gets_the_mask_of_the_key() -> None:
    """Both forms are registered; the split one took the digest of the form with the CR."""

    register_known_secret("Zq9vT4mXa81LpR2w\r")
    whole = _masked(ValueError("a Zq9vT4mXa81LpR2w b"))  # the redactor alone: no control
    assert _masked(ValueError("a Zq9vT4mX\na81LpR2w b")) == whole


@pytest.mark.parametrize("text", ["token=AAAAAAAA\udc9b", "password: Secret\ud800x1"])
def test_a_lone_surrogate_in_a_labelled_value_does_not_crash_the_masking(text: str) -> None:
    """The digest encoded the value strictly: `UnicodeEncodeError`, and the CLI printed the
    error it was masking as a traceback."""

    from ildottore.redactor import Redactor

    for out in (_masked(ValueError(text)), Redactor(salt="s").for_terminal(text)):
        assert _raw_controls(out) == [] and "«REDACTED:" in out


@pytest.mark.usefixtures("no_known_secrets")
def test_no_index_is_built_for_text_that_holds_no_credential() -> None:
    """About 140 MB a megabyte of controls, before any credential was looked for (9 MB with
    the index built late, or the controls dropped by a regex); now the text without them."""

    import tracemalloc

    from ildottore.redactor import Redactor

    register_known_secret("Zq9vT4mXa81LpR2w")
    text = "a\n" * 500_000
    redactor = Redactor(salt="s")
    tracemalloc.start()
    try:
        assert redactor.mask_split_credentials(text) is text
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 3 * len(text), peak


def test_a_stream_that_cannot_encode_a_control_picture_escapes_it(tmp_path: Path) -> None:
    """On a cp1252 stdout (a Windows pipe) `registry ls` exited 1 and printed nothing."""

    pack = _named_spec_pack(tmp_path, "Direct\n::error title=pwned::x")
    result = CliRunner(charset="cp1252").invoke(app, ["registry", "ls", "--spec-path", str(pack)])
    assert result.exit_code == 0, result.output
    assert "Direct\\u240a::error title=pwned::x" in result.stdout


def _schema_error_pack(root: Path) -> Path:
    """A key of `step_arg_patterns` is free text, and the schema error quotes it."""

    pack = root / "keyed"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: keyed\npack_version: '1.0'\nname: keyed\n")
    good = (REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text()
    key = json.dumps("k\n::error title=pwned::from-key")
    (pack / "attacks" / "PI-BAD-001.yaml").write_text(
        good.replace("id: PI-DIRECT-001", "id: PI-BAD-001").replace(
            "evaluators:\n",
            f"evaluators:\n  - type: tool_sequence\n    step_arg_patterns: {{{key}: 5}}\n",
            1,
        )
    )
    return pack


@pytest.mark.parametrize("command", ["lint", "coverage"])
def test_a_message_quoting_a_pack_value_is_written_out(tmp_path: Path, command: str) -> None:
    result = CliRunner().invoke(app, [command, str(_schema_error_pack(tmp_path))])
    assert _injected_lines(result.stdout) == [], result.stdout
    assert f"k{LF}::error title=pwned::from-key" in result.stdout


def test_describe_writes_every_field_out(tmp_path: Path) -> None:
    pack = _named_spec_pack(tmp_path, "Direct prompt injection")
    spec = pack / "attacks" / "PI-DIRECT-001.yaml"
    text = spec.read_text()
    head, _, rest = text.partition("\ndescription:")
    _, _, rest = rest.partition("\n")
    while rest.startswith("  "):  # the folded body of the old description
        _, _, rest = rest.partition("\n")
    description = json.dumps("d\n::error title=pwned::from-description")
    spec.write_text(f"{head}\ndescription: {description}\n{rest}")
    card = CliRunner().invoke(app, ["describe", "PI-DIRECT-001", "--spec-path", str(pack)])
    assert card.exit_code == 0, card.output
    assert _injected_lines(card.stdout) == []
    assert f"description: d{LF}::error title=pwned::from-description" in card.stdout


def _report(path: Path, spec_id: str) -> Path:
    path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "spec_id": spec_id,
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
                ]
            }
        )
    )
    return path


@pytest.mark.parametrize(
    "spec_id", ["::error title=pwned::bare", "PI-X-001\n::error title=pwned::split"]
)
def test_diff_and_calibrate_refuse_a_report_whose_spec_id_is_not_one(
    tmp_path: Path, spec_id: str
) -> None:
    """Every row of `diff` starts with a spec id: `::error ...` there needs no control."""

    report = _report(tmp_path / "r.json", spec_id)
    good = _report(tmp_path / "g.json", "PI-X-001")
    labels = tmp_path / "labels.yaml"
    labels.write_text("PI-X-001: fail\n")
    for args in (["diff", str(good), str(report)], ["calibrate", str(report), str(labels)]):
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 3, result.output
        assert result.stdout == "" and len(result.stderr.splitlines()) == 1
        assert result.stderr.startswith("error: ") and "is not a spec id" in result.stderr


def test_calibrate_writes_a_label_s_spec_id_out(tmp_path: Path) -> None:
    report = _report(tmp_path / "r.json", "PI-X-001")
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({"PI-X-001": "fail", "Y\n::error title=pwned::label": "pass"}))
    result = CliRunner().invoke(app, ["calibrate", str(report), str(labels)])
    assert result.exit_code == 0, result.output
    assert _injected_lines(result.stdout) == []
    assert f"Y{LF}::error title=pwned::label" in result.stdout


def test_replay_writes_stored_fields_out(tmp_path: Path) -> None:
    from ildottore.shared.models import Attempt, ModelRequest
    from ildottore.store.evidence_fs import FsEvidenceStore

    store = FsEvidenceStore(tmp_path / "ev")
    store.put_probe(
        "run-1",
        Attempt(
            attempt_id="probe::self_id#0",
            spec_id="PROBE",
            request=ModelRequest(prompt="hi"),
            error="ConnectError: refused\n::error title=pwned::from-probe-error",
        ),
    )
    store.put(
        "run-1",
        Attempt(
            attempt_id="a1",
            spec_id="PI-X-001\n::error title=pwned::from-spec-id",
            mutation="identity",
            request=ModelRequest(prompt="hi"),
        ),
    )
    result = CliRunner().invoke(
        app,
        [
            *("replay", "run-1", "--evidence-root", str(tmp_path / "ev")),
            *("--run-db", str(tmp_path / "none.sqlite")),
        ],
    )
    assert result.exit_code == 0, result.output
    assert _injected_lines(result.stdout) == [], result.stdout
    assert f"refused{LF}::error title=pwned::from-probe-error" in result.stdout
    assert f"PI-X-001{LF}::error title=pwned::from-spec-id" in result.stdout


def test_fingerprint_prints_ascii_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """pydantic left a C1 control, DEL and U+2028 raw; on a cp1252 stdout the stream wrote
    `\\x81`, which is not a JSON escape."""

    from ildottore.cli import fingerprint as fingerprint_mod

    echoed = "llama-3 " + "".join(map(chr, (0x81, 0x7F, 0x2028, 0x1F642, 0x6771)))

    class _Fingerprint:
        def model_dump(self, *, mode: str) -> dict[str, object]:
            return {"target_id": "t", "family": {"guess": echoed, "confidence": 0.5}}

        def model_dump_json(self, *, indent: int) -> str:  # what pydantic writes
            return json.dumps(self.model_dump(mode="json"), ensure_ascii=False, indent=indent)

    monkeypatch.setattr(fingerprint_mod, "fingerprint_target", lambda *_a, **_k: _Fingerprint())
    result = CliRunner(charset="cp1252").invoke(app, ["fingerprint", "t.yaml", "--offline"])
    assert result.exit_code == 0, result.output
    assert result.stdout.isascii() and json.loads(result.stdout)["family"]["guess"] == echoed


def test_the_streams_get_their_setting_back_after_the_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = (sys.stdout.errors, sys.stderr.errors)
    with pytest.raises(SystemExit):
        app(["registry", "ls", "--spec-path", str(tmp_path)])
    capsys.readouterr()
    assert (sys.stdout.errors, sys.stderr.errors) == before


def test_a_run_id_with_a_trailing_newline_is_refused() -> None:
    from ildottore.store.paths import UnsafePathError, validate_run_id

    with pytest.raises(UnsafePathError):
        validate_run_id("run-1" + chr(10))
    assert validate_run_id("run-1") == "run-1"
