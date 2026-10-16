"""A path under a directory whose name holds a space reads as one under any other (u12 A-83).

The CLI keeps the existing part of a path out of the entropy rule (A-38): the part main's rule
reads, an absolute path up to the first whitespace or one of ``'"()[],;``, and a path that exists
written whole. A missing file under a directory holding a space was neither: main's rule stopped
at the space, and the entropy rule read the rest of the directories and the missing name as one
token and masked it, so with ``TMPDIR`` under "AI projects" 15 tests of the suite failed on
``7d01521f`` (``cannot write evidence under /Users/.../AI «REDACTED:high_entropy:...»``). The walk
that reads a whole path now keeps the existing part of one that does not exist when main's rule
could not read it, and what follows is judged from its ``/`` on, as main judges the rest of a
path whose directories it reads; the token there is checked for a registered credential's part
with the kept text, and a ``//``, ``/./`` or ``/../`` ends the kept part, as main keeps nothing
past one.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore import redactor as redactor_mod
from ildottore.cli.app import _masked, app
from ildottore.redactor import register_known_secret, visible_controls

from .conftest import make_spec, write_scope, write_spec_tree, write_target

#: Registered credentials are process-wide: none from an earlier test changes a mask here.
pytestmark = pytest.mark.usefixtures("no_known_secrets")

#: A character main's rule stops a path at, in a directory's name.
STOPS = [" ", "(", ")", "[", "]", ",", ";", "'", '"', "\t"]
#: Names a missing file may have: each is masked or kept as it is under a plain directory.
NAMES = [
    "missing.json",
    "r.db",
    "nope",
    "report-9f86d081884c7d659a2feaa0c55ad015b3a4f6e2.json",
    "Xy9Kq2Lm3NpQ8rT5vW1zA4bC.json",
    "sk-ant-api03-Q7xZ2mV9pL4kR8tN1wB6yH3jF5dS0aC.yaml",
    "8edfde5b-3c4a-4e1f-9b2d-7a6c5e4f3a2b/ev",
    "aaaaaaaaaaaaaaaaaaaaaaaa",
]


def _named(directory: Path, name: str) -> str:
    return _masked(ValueError(f"cannot write {directory}/{name}: denied"))


@pytest.mark.parametrize("stop", STOPS, ids=[repr(c) for c in STOPS])
def test_a_missing_file_under_such_a_directory_keeps_its_directories(
    tmp_path: Path, stop: str
) -> None:
    # After the stop, names the entropy rule reads as one token and masks: a `_` after a `/`,
    # an upper-case letter (the shape of the real case, "AI projects/_ildottore-tren/...").
    directory = tmp_path / f"with{stop}char" / "_Sub-Dir" / "T"
    directory.mkdir(parents=True)
    shown = visible_controls(f"{directory}/missing.json: denied")  # a tab is written out
    assert shown in _named(directory, "missing.json")


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("stop", [" ", "("], ids=["space", "bracket"])
def test_the_name_is_judged_as_under_a_directory_without_one(
    tmp_path: Path, stop: str, name: str
) -> None:
    spaced = tmp_path / f"AI{stop}projects" / "tmp"
    plain = tmp_path / "AIprojects" / "tmp"
    spaced.mkdir(parents=True)
    plain.mkdir(parents=True)
    assert _named(spaced, name).replace(str(spaced), "<dir>") == _named(plain, name).replace(
        str(plain), "<dir>"
    )


def test_a_secret_as_the_name_is_still_masked(tmp_path: Path) -> None:
    directory = tmp_path / "with space"
    directory.mkdir()
    key = "sk-ant-api03-Q7xZ2mV9pL4kR8tN1wB6yH3jF5dS0aC"
    shown = _named(directory, f"{key}.yaml")
    assert key not in shown and f"{directory}/«REDACTED:" in shown


def test_a_registered_credential_s_part_glued_after_the_kept_part_drops_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The part is checked with the kept text, as a kept token is (A-38)."""

    monkeypatch.setattr(redactor_mod, "_KNOWN_SECRETS", set())
    key = "U5XO+XIdlu/a+iCOoxvSQSNFnviw2Vue"
    register_known_secret(key)
    directory = tmp_path / "with space"
    directory.mkdir()
    for name in (key[:16], f"report-{key[:10]}.json"):
        assert key[:8] not in _named(directory, name)


#: A directory name the entropy rule masks when it judges it, as it is not kept.
HIGH = "Xy9Kq2Lm3NpQ8rT5vW1zA4bC"


@pytest.mark.parametrize("step", ["//", "/./", "/../with space/"])
def test_the_kept_part_ends_where_main_s_rule_keeps_nothing(tmp_path: Path, step: str) -> None:
    """Main's rule keeps nothing of a path holding `//` or `/./` (`Path` drops them), so neither
    does the existing part; it stops before a `..` (fuzz of A-83 against main)."""

    directory = tmp_path / "with space"
    (directory / HIGH).mkdir(parents=True)
    shown = _masked(ValueError(f"cannot write {directory}{step}{HIGH}/missing.json: denied"))
    assert HIGH not in shown, shown
    # Without the step the directory is kept, as an existing part.
    shown = _masked(ValueError(f"cannot write {directory}/{HIGH}/missing.json: denied"))
    assert f"{directory}/{HIGH}/missing.json" in shown, shown


def test_through_the_cli_an_evidence_root_under_a_regular_file(tmp_path: Path) -> None:
    """The preflight's refusal under a directory with a space (``tmp_path`` on CI holds none)."""

    home = tmp_path / "AI projects" / "_ildottore-tren" / "Scratch"
    home.mkdir(parents=True)
    spec_dir = write_spec_tree(home, [make_spec("PI-DIRECT-001")])
    (home / "plain").write_text("x")
    root = home / "plain" / "ev"
    result = CliRunner().invoke(
        app,
        [
            *("run", "-t", str(write_target(home, mock_scenario="vulnerable"))),
            *("--scope", str(write_scope(home)), "--spec-path", str(spec_dir)),
            *("--runs", "1", "-q", "--no-color", "--evidence-root", str(root)),
            *("--run-db", str(home / "runs.sqlite")),
        ],
    )
    assert result.exit_code == 3, result.output
    assert f"cannot write evidence under {root}: {home / 'plain'} is not a directory" in (
        result.output
    )
