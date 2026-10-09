"""A run id is never masked as a phone number (2026-10-09).

A run id is ``run-`` and the first 12 hexadecimal digits of a UUID4. When all twelve came out
decimal, (10/16) ** 12 of the draws or about one run in 281, the redactor every report and every
CLI error goes through read them as a phone number: the JSON report named the run
``run-«REDACTED:phone»``, in its ``run`` and in every evidence reference, and ``dottore
replay`` refused that id as unsafe (exit 3). Such a draw is now drawn again (u12 A-61). The
redactor keeps its phone rule, and the id keeps its shape, so a run minted before, all digits or
not, still replays and resumes by the id its evidence directory carries.

The UUID source is replaced, so the all-digit draw comes first every time.
"""

from __future__ import annotations

import json
import random
import re
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import Result
from typer.testing import CliRunner

from ildottore.cli import run as run_mod
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.redactor import Redactor

from .conftest import make_spec, write_scope, write_spec_tree, write_target

ALL_DIGITS = "123456789012"
ID_SHAPE = re.compile(r"run-[0-9a-f]{12}")


def _uuid_source(suffixes: Iterator[str]) -> SimpleNamespace:
    """A stand-in for the ``uuid`` module whose ``uuid4`` starts with each suffix in turn."""

    return SimpleNamespace(uuid4=lambda: uuid.UUID(hex=next(suffixes) + "0" * 20))


def _campaign(tmp_path: Path) -> tuple[list[str], Path, Path, Path]:
    """The argv of a one-spec run that writes a JSON report; the report, evidence and store."""

    write_target(tmp_path, mock_scenario="vulnerable")
    write_scope(tmp_path)
    write_spec_tree(tmp_path, [make_spec("PI-DIRECT-001")])
    report, evidence, run_db = tmp_path / "report.json", tmp_path / "ev", tmp_path / "runs.sqlite"
    argv = [
        "run",
        *("-t", str(tmp_path / "target.yaml"), "--scope", str(tmp_path / "scope.yaml")),
        *("--spec-path", str(tmp_path / "specs"), "--runs", "1", "-q", "-oJ", str(report)),
        *("--evidence-root", str(evidence), "--run-db", str(run_db)),
    ]
    return argv, report, evidence, run_db


def _ids_in_report(report: Path) -> set[str]:
    """Every run id the JSON report names: the run's own and each evidence reference's."""

    data = json.loads(report.read_text(encoding="utf-8"))
    refs = {ref["run_id"] for finding in data["findings"] for ref in finding["evidence"]}
    assert refs, "the report cites no evidence"
    return {data["run"]["run_id"], *refs}


def _replay(run_id: str, evidence: Path, run_db: Path) -> Result:
    return CliRunner().invoke(
        app, ["replay", run_id, "--evidence-root", str(evidence), "--run-db", str(run_db)]
    )


def test_an_all_digit_draw_is_drawn_again_and_the_report_id_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The id read back from the JSON report is the one `dottore replay` takes."""

    monkeypatch.setattr(run_mod, "uuid", _uuid_source(iter([ALL_DIGITS, "0123456789ab"])))
    argv, report, evidence, run_db = _campaign(tmp_path)

    ran = CliRunner().invoke(app, argv)

    assert ran.exit_code == ExitCode.FINDINGS_AT_OR_ABOVE, (ran.exception, ran.stderr)
    assert _ids_in_report(report) == {"run-0123456789ab"}
    assert [path.name for path in evidence.iterdir()] == ["run-0123456789ab"]
    (run_id,) = _ids_in_report(report)
    replayed = _replay(run_id, evidence, run_db)
    assert replayed.exit_code == ExitCode.CLEAN, replayed.stderr
    assert f"run: {run_id}" in replayed.stdout
    assert "warning" not in replayed.stderr


def test_a_run_minted_all_digits_before_still_replays_by_its_directory_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An id an older version minted: its report masks it, as it always did, but the id its
    evidence directory carries replays. The redactor's rule is unchanged."""

    monkeypatch.setattr(run_mod, "new_run_id", lambda: f"run-{ALL_DIGITS}")
    argv, report, evidence, run_db = _campaign(tmp_path)

    ran = CliRunner().invoke(app, argv)

    assert ran.exit_code == ExitCode.FINDINGS_AT_OR_ABOVE, (ran.exception, ran.stderr)
    assert _ids_in_report(report) == {"run-«REDACTED:phone»"}
    assert _replay("run-«REDACTED:phone»", evidence, run_db).exit_code == ExitCode.ERROR
    (directory,) = (path.name for path in evidence.iterdir())
    assert directory == f"run-{ALL_DIGITS}"
    assert _replay(directory, evidence, run_db).exit_code == ExitCode.CLEAN


def test_every_id_the_generator_mints_survives_the_redactor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Draws weighted towards decimal digits, so about one in four is all digits (2,693 draws
    for 2,000 ids): none of them is minted, each id is the first draw that is not, and the
    redactor leaves it as is, alone, quoted in a message and in a path."""

    rng = random.Random(20261009)  # noqa: S311
    draws: list[str] = []

    def draw() -> str:
        suffix = "".join(rng.choice("0123456789" * 5 + "abcdef") for _ in range(12))
        draws.append(suffix)
        return suffix

    def endless() -> Iterator[str]:
        while True:
            yield draw()

    monkeypatch.setattr(run_mod, "uuid", _uuid_source(endless()))
    redactor = Redactor()
    redrawn = 0
    for _ in range(2000):
        start = len(draws)
        run_id = run_mod.new_run_id()
        drawn = draws[start:]
        assert all(d.isdigit() for d in drawn[:-1]) and not drawn[-1].isdigit(), drawn
        redrawn += len(drawn) - 1
        assert ID_SHAPE.fullmatch(run_id) and run_id == f"run-{drawn[-1]}"
        for text in (run_id, f"run {run_id!r} has already spent", f".dottore/evidence/{run_id}/"):
            assert redactor.redact_text(text) == text
    assert redrawn == 693  # all-digit draws, each drawn again (the seed fixes the count)


@pytest.mark.parametrize("position", range(12))
def test_one_letter_anywhere_keeps_twelve_digits_readable(position: int) -> None:
    """The least an id the generator mints can hold: eleven decimal digits and one letter."""

    suffix = ALL_DIGITS[:position] + "a" + ALL_DIGITS[position + 1 :]
    assert Redactor().redact_text(f"run-{suffix}") == f"run-{suffix}"
    assert Redactor().redact_text(f"run-{ALL_DIGITS}") == "run-«REDACTED:phone»"
