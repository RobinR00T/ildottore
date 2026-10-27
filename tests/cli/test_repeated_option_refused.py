"""An option that keeps one value is refused when given two (u12 A-103, found 2026-10-27).

Click keeps the last value of a repeated option and says nothing, so ``dottore run --suite mcp
--suite owasp:llm`` ran one suite while the operator believed it ran two (found writing the
manual's campaign example). The root group now reads the words as typed and refuses, as a usage
error (exit 3), any option that is neither repeatable nor counted given again with another
value, or a flag pair given both ways, on every command, before anything runs. Given again as
it was, an option loses nothing and is let through (a test's base arguments plus an override).

Every such option of every command is tried, found by walking the command tree, so an option
added later is covered without a list to keep in step.
"""

from __future__ import annotations

import pytest

from tests.cli.test_usage_errors_masked import _commands, _invoke


def _single_valued_options() -> list[tuple[list[str], str, list[str]]]:
    """(command words, the option, two conflicting givings of it) for each one-value option.

    A value option is given "x" then "y"; a flag pair one way then the other. A lone flag
    cannot conflict with itself and is left out.
    """

    found = []
    for path, command in _commands():
        for param in command.params:
            if param.param_type_name != "option" or param.multiple or param.count:
                continue
            if param.is_eager or (param.is_flag and not param.secondary_opts):
                continue
            option = max(param.opts, key=len)
            if param.is_flag:
                twice = [option, param.secondary_opts[0]]
            else:
                twice = [option, *(["x"] * param.nargs), option, *(["y"] * param.nargs)]
            found.append((path, option, twice))
    return found


SINGLE = _single_valued_options()


def test_the_option_that_was_found_is_among_those_tried() -> None:
    tried = {(" ".join(path), option) for path, option, _ in SINGLE}
    for expected in [("run", "--suite"), ("coverage", "--suite"), ("registry ls", "--suite")]:
        assert expected in tried, sorted(tried)


@pytest.mark.parametrize(
    ("path", "option", "twice"), SINGLE, ids=[f"{' '.join(p)} {o}" for p, o, _ in SINGLE]
)
def test_a_one_value_option_given_two_values_is_refused(
    path: list[str], option: str, twice: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _invoke([*path, *twice], capsys)
    assert code == 3, err
    assert "Traceback" not in out + err
    assert f"error: {option} " in err and "with two values" in err, err
    assert err.splitlines()[0].split("[OPTIONS]")[0].rstrip().endswith(" ".join(path)), err


@pytest.mark.parametrize(
    "argv",
    [
        ["run", "--suite=mcp", "--suite", "owasp:llm"],  # one spelled with =
        ["run", "-t", "a.yaml", "--suite", "mcp", "--target", "b.yaml", "--suite", "agentic"],
    ],
    ids=["equals", "between-others"],
)
def test_every_spelling_counts(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = _invoke(argv, capsys)
    assert code == 3 and "error: --suite given twice" in err, err


def test_two_spellings_of_one_option_are_named_both(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = _invoke(["coverage", "--gaps", "--no-gaps"], capsys)
    assert code == 3 and "error: --gaps and --no-gaps both given" in err, err


@pytest.mark.parametrize(
    "argv",
    [
        # A repeatable option, a counted one, and a value that looks like the option.
        ["run", "-t", "a.yaml", "-t", "b.yaml", "--spec", "PI-*", "--spec", "JB-*"],
        ["-v", "-v", "run", "--spec", "--suite", "--suite", "mcp"],
        # Past `--`, a word is no option.
        ["run", "--suite", "mcp", "--", "--suite"],
        # The same value again, spelled either way, and a lone flag twice: nothing is lost.
        ["run", "--suite", "mcp", "--concurrency", "1", "--suite=mcp", "--concurrency", "1"],
        ["coverage", "--json", "--json"],
    ],
    ids=["repeatable", "counted-and-value", "after-double-dash", "same-value", "same-flag"],
)
def test_what_is_not_a_repeat_is_not_refused_for_it(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    _, _, err = _invoke(argv, capsys)
    assert "given twice" not in err, err
