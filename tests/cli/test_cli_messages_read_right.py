"""What a CLI error says is what happened, and the mask takes only what it must (u12 A-82; CLI
audit of 2026-10-11, L8 and L10).

L8, measured on ``de122e26``:

* the tool's own figures read as phone numbers: ``invalid -T template «REDACTED:phone»``, and a
  spec's ``impact: 99999999999999999999`` as ``scoring/impact: «REDACTED:phone» is greater than
  the maximum of 4``; a figure is now written with thousands separators, which no phone has;
* ``--suite ../../etc/passwd`` lost the word ``resolved`` to the mask (``passwd`` read as the
  label of a password, ``(resolved`` as its value); the resolved id is named only for an alias;
* ``--timeout 1e-300`` ran, every attempt timed out at once, and the run ended
  ``failed on transport ...: TimeoutError: ``, with nothing after: a timeout is at least 1 second
  and at most a day, and a timeout or any other error with no message of its own says what it is;
* ``http://127.0.0.1:9/...`` in an allowlist refusal read ``http://«REDACTED:ipv4»:9/...``:
  ``127.0.0.1`` is one of the allowlist's own loopback entries, kept readable in a URL.

L10: ``new-spec --family`` wrote its value raw into the YAML scaffold, so a control character made
a file lint then refused, and a ``:`` or a ``]`` one that did not parse. A control or format
character is refused; anything else is written as a YAML string that reads back as written.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from ildottore.cli.app import _masked, app
from ildottore.cli.new_spec import scaffold_spec
from ildottore.shared.error_text import error_text

from .conftest import write_scope, write_target

runner = CliRunner()
_REPO = Path(__file__).resolve().parents[2]
_SPEC = (_REPO / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text(encoding="utf-8")


def _run(tmp_path: Path, *extra: str) -> Any:
    return runner.invoke(
        app,
        [
            "run",
            "-t",
            str(write_target(tmp_path, mock_scenario="vulnerable")),
            "--scope",
            str(write_scope(tmp_path)),
            "--spec",
            "PI-DIRECT-001",
            "--dry-run",
            "-q",
            *extra,
        ],
    )


# --- figures ---------------------------------------------------------------------------------


def test_a_timing_template_figure_is_not_a_phone_number(tmp_path: Path) -> None:
    result = _run(tmp_path, "-T", "12345678901")
    assert result.exit_code == 3, result.output
    assert "invalid -T template 12,345,678,901; expected 0..5" in result.output
    assert "REDACTED" not in result.output


@pytest.mark.parametrize(
    ("flag", "said"),
    [
        ("--rate", "--rate must be greater than 0 requests per second (got -12,345,678,901.0)"),
        (
            "--timeout",
            "--timeout must be at least 1 second and at most 86,400 (a day; got -12,345,678,901.0)",
        ),
    ],
)
def test_a_float_flag_figure_is_not_a_phone_number(tmp_path: Path, flag: str, said: str) -> None:
    result = _run(tmp_path, flag, "-12345678901")
    assert result.exit_code == 3, result.output
    assert said in result.output.replace("\n", "")
    assert "REDACTED" not in result.output


def test_a_spec_figure_is_not_a_phone_number(tmp_path: Path) -> None:
    sp = tmp_path / "sp"
    sp.mkdir()
    (sp / "PI-DIRECT-001.yaml").write_text(
        _SPEC.replace("impact: 3", "impact: 99999999999999999999")
    )
    assert "impact: 99999999999999999999" in (sp / "PI-DIRECT-001.yaml").read_text()
    result = runner.invoke(app, ["lint", str(sp)])
    assert result.exit_code == 1, result.output
    assert "scoring/impact: 99,999,999,999,999,999,999 is greater than the maximum of 4" in (
        result.output
    )
    result = _run(tmp_path, "--spec-path", str(sp))
    assert result.exit_code == 3
    assert "99,999,999,999,999,999,999 is greater than the maximum of 4" in result.output
    assert "REDACTED:phone" not in result.output


def test_a_file_name_too_long_says_its_length_not_a_phone_number(tmp_path: Path) -> None:
    result = _run(tmp_path, "-t", "9" * 5000)
    assert result.exit_code == 3, result.output
    assert "File name too long: a name of 5,000 characters" in result.output
    assert "REDACTED:phone" not in result.output


# --- the suite's word ----------------------------------------------------------------------


@pytest.mark.parametrize("command", [["run"], ["coverage"], ["registry", "ls"]])
def test_an_unknown_suite_keeps_its_words(tmp_path: Path, command: list[str]) -> None:
    if command == ["run"]:
        result = _run(tmp_path, "--suite", "../../etc/passwd")
    else:
        result = runner.invoke(app, [*command, "--suite", "../../etc/passwd"])
    assert result.exit_code == 3, result.output
    assert "suite '../../etc/passwd' is not registered. Registered suites: " in result.output
    assert "REDACTED" not in result.output


def test_an_alias_names_what_it_resolves_to(tmp_path: Path) -> None:
    result = _run(tmp_path, "--suite", "mitre:atlas")
    assert result.exit_code == 3, result.output
    assert "suite 'mitre:atlas' (an alias of 'mitre-atlas') is not registered" in result.output


# --- a timeout, and an error with nothing to say ----------------------------------------------


@pytest.mark.parametrize("value", ["1e-300", "0.5", "0", "nan", "inf", "86401"])
def test_a_timeout_outside_one_second_to_a_day_is_refused(tmp_path: Path, value: str) -> None:
    result = _run(tmp_path, "--timeout", value)
    assert result.exit_code == 3, result.output
    assert "--timeout must be at least 1 second and at most 86,400" in result.output.replace(
        "\n", ""
    )


@pytest.mark.parametrize("value", ["1", "45", "86400"])
def test_a_timeout_in_range_is_taken(tmp_path: Path, value: str) -> None:
    assert _run(tmp_path, "--timeout", value).exit_code == 0


def test_an_error_with_no_message_says_what_it_is() -> None:
    assert error_text(TimeoutError()) == "TimeoutError (no detail given)"
    assert error_text(ValueError("bad")) == "ValueError: bad"
    assert error_text(OSError("  ")) == "OSError (no detail given)"


def test_an_attempt_that_times_out_says_the_timeout() -> None:
    from ildottore.core.execute import _send_with_timeout
    from ildottore.shared.models import ModelRequest, ModelResponse

    class Slow:
        id = "slow"

        async def send(self, request: ModelRequest) -> ModelResponse:
            await asyncio.sleep(5)
            return ModelResponse(text="late")

    async def sleep(_s: float) -> None:
        return None

    with pytest.raises(TimeoutError) as info:
        asyncio.run(_send_with_timeout(Slow(), ModelRequest(prompt="p"), 0.01, sleep))  # type: ignore[arg-type]
    assert str(info.value) == "no reply within the per-attempt timeout of 0.01 s"
    assert (
        error_text(info.value) == "TimeoutError: no reply within the per-attempt timeout of 0.01 s"
    )


# --- the allowlist's own loopback entries ------------------------------------------------------


def test_a_loopback_host_in_an_allowlist_refusal_stays_readable(tmp_path: Path) -> None:
    (tmp_path / "t.yaml").write_text(
        'id: t\ntype: chatbot\nprovider: openai\nendpoint: "http://127.0.0.1:9/v1/chat/completions"\n'
    )
    (tmp_path / "s.yaml").write_text(
        'version: "1.0"\ntargets:\n  - id: t\n    base_url: "http://127.0.0.1:8/v1"\n'
        '    endpoints:\n      - host: "127.0.0.1:8"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    result = runner.invoke(
        app,
        ["run", "-t", str(tmp_path / "t.yaml"), "--scope", str(tmp_path / "s.yaml"), "--dry-run"],
    )
    assert result.exit_code == 3, result.output
    assert "endpoint 'http://127.0.0.1:9/v1/chat/completions' not on allowlist" in result.output


def test_only_the_loopback_entries_are_kept() -> None:
    shown = _masked(
        ValueError(
            "endpoint 'http://127.0.0.1:9/a' and 'http://[::1]:9/a' and 'http://10.1.2.3:9/a' "
            "and 'http://127.0.0.2:9/a', host 127.0.0.1:9"
        )
    )
    assert "http://127.0.0.1:9/a" in shown and "http://[::1]:9/a" in shown
    assert "10.1.2.3" not in shown and "127.0.0.2" not in shown
    assert "host «REDACTED:ipv4»:9" in shown  # outside a URL, the rule applies as before


# --- new-spec --family ---------------------------------------------------------------------


@pytest.mark.parametrize("family", ["evil\x1b[2J", "two\nlines", "rtl‮override", "nul\x00", ""])
def test_new_spec_refuses_a_family_with_a_control_character(tmp_path: Path, family: str) -> None:
    result = runner.invoke(
        app,
        ["new-spec", "--id", "PI-NEW-001", "--family", family, "--out", str(tmp_path / "o")],
    )
    assert result.exit_code == 3, result.output
    assert "--family" in result.output
    assert "\x1b" not in result.output and "‮" not in result.output
    assert not (tmp_path / "o").exists()


@pytest.mark.parametrize(
    "family",
    ["key: value", "a]b", "#hash", "tag, other", "'quoted'", "dólar", "yes", "null", "123", "1.0"],
)
def test_new_spec_writes_any_other_family_as_a_string_that_reads_back(family: str) -> None:
    doc = yaml.safe_load(scaffold_spec("PI-NEW-001", family=family))
    assert doc["tags"] == [family]
    assert doc["name"] == f"TODO short human name for {family}"


def test_a_plain_family_scaffold_is_unchanged() -> None:
    text = scaffold_spec("PI-NEW-001", family="jailbreak")
    assert "name: TODO short human name for jailbreak\n" in text
    assert text.endswith("tags: [jailbreak]\n")


# --- what the operator typed, echoed (pre-merge audit of A-82, LOW a) --------------------------

_KEY = "sk-ant-api03-Q7xZ2mV9pL4kR8tN1wB6yH3jF5dS0aC-QwErTyUiOpAsDfGh"


@pytest.mark.parametrize(
    "argv",
    [
        ["lint", _KEY],
        ["lint", "--json", _KEY],
        ["describe", _KEY, "--spec-path", str(_REPO / "specs")],
        ["schema", "export", "--name", _KEY],
    ],
    ids=["lint", "lint-json", "describe", "schema-export"],
)
def test_a_key_typed_where_a_name_belongs_is_masked(argv: list[str]) -> None:
    result = runner.invoke(app, argv)
    assert result.exit_code == 3, result.output
    assert _KEY[:16] not in result.output and _KEY[-16:] not in result.output
    assert "«REDACTED" in result.output or "\\u00abREDACTED" in result.output


def test_a_scope_name_too_long_says_its_length(tmp_path: Path) -> None:
    """`--scope <5,000 digits>` printed «REDACTED:phone» twice (pre-merge audit of A-82, LOW e)."""

    result = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(write_target(tmp_path, mock_scenario="vulnerable")),
            "--scope",
            "9" * 5000,
        ],
    )
    assert result.exit_code == 3, result.output
    assert "cannot read scope file, a name of 5,000 characters: File name too long" in result.output
    assert "REDACTED" not in result.output


def test_new_spec_stdout_checks_the_id_too() -> None:
    """`--stdout` printed a scaffold with any id, a key included, which lint then refused."""

    result = runner.invoke(app, ["new-spec", "--id", _KEY, "--family", "f", "--stdout"])
    assert result.exit_code == 3, result.output
    assert "invalid spec id" in result.output and _KEY[:16] not in result.output


def test_new_spec_refuses_a_family_shaped_like_a_key() -> None:
    result = runner.invoke(app, ["new-spec", "--id", "PI-NEW-001", "--family", _KEY, "--stdout"])
    assert result.exit_code == 3, result.output
    # A credential format since main's u01 A-78 reads Anthropic's keys; a high-entropy token
    # before it. Either is the shape of a key.
    assert "--family is a credential format, the shape of a key (not shown)" in result.output
    assert _KEY[:16] not in result.output
    for family in ("prompt_injection", "deepteam-mapped", "nova-iopc-mapped", "rai01"):
        assert (
            runner.invoke(
                app, ["new-spec", "--id", "PI-NEW-001", "--family", family, "--stdout"]
            ).exit_code
            == 0
        )


def test_new_spec_takes_a_family_that_only_the_pii_rules_would_mask() -> None:
    """`CVE-2021-44228` read as a phone number (round-2 audit of A-82, LOW 4)."""

    for family in ("CVE-2021-44228", "alice@example.com", "+1-415-555-0100"):
        result = runner.invoke(
            app, ["new-spec", "--id", "PI-NEW-001", "--family", family, "--stdout"]
        )
        assert result.exit_code == 0, (family, result.output)


def test_a_spec_path_name_too_long_says_its_length(tmp_path: Path) -> None:
    """`--spec-path <5,000 digits>` printed `path not found: «REDACTED:phone»` (LOW 6)."""

    result = _run(tmp_path, "--spec-path", "9" * 5000)
    assert result.exit_code == 3, result.output
    assert "path not found: a name of 5,000 characters" in result.output
    assert "REDACTED" not in result.output


def test_a_report_name_too_long_says_its_length_not_that_it_was_read(tmp_path: Path) -> None:
    """`-oJ <5,000 characters>` said "cannot read" for a write (LOW 5)."""

    result = runner.invoke(
        app,
        [
            "run",
            "-t",
            str(write_target(tmp_path, mock_scenario="vulnerable")),
            "--scope",
            str(write_scope(tmp_path)),
            "--spec",
            "PI-DIRECT-001",
            "--runs",
            "1",
            "-q",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "r.db"),
            "-oJ",
            str(tmp_path / ("r" * 5000)),
        ],
    )
    assert result.exit_code == 3, result.output
    assert "File name too long: a name of" in result.output and "cannot read" not in result.output
