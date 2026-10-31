"""The estimate in euros and the escalating judge, through the CLI (u12 A-108, u06 A-109).

A target file may declare ``pricing:`` (euros per million tokens in and out); ``--estimate``
then prints a figure in euros per model, the ``--judge`` and ``--judge-escalate`` models
included. ``--judge-escalate`` names a second judge model, asked only when the first cannot
settle an attempt: priced as if every judgement went to it, bound by a resume as the judge is.
Nothing here sends a request: the judges are live files the estimate only reads.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import resume as resume_mod
from ildottore.cli import run as run_mod
from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.shared.digest import target_digest
from ildottore.shared.enums import EvaluatorType
from ildottore.shared.models import AttackSpec, Pricing
from ildottore.store.run_sqlite import SqliteRunStore

from .conftest import make_spec, write_spec_tree, write_target

_PRICED = "pricing:\n  input_eur_per_mtok: 2.5\n  output_eur_per_mtok: 10\n"


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yaml"
    judges = "".join(
        f"  - id: judge-{size}\n"
        '    base_url: "https://judge.example.org"\n'
        "    endpoints:\n"
        '      - host: "judge.example.org"\n'
        '        path_prefixes: ["/v1/"]\n'
        "    identities:\n"
        "      - name: default\n"
        '        auth_ref: "env://NONE"\n'
        for size in ("small", "large")
    )
    path.write_text(
        'version: "1.0"\n'
        "targets:\n"
        "  - id: mock-target\n"
        '    base_url: "mock://mock-target"\n'
        "    endpoints:\n"
        '      - host: "mock-target"\n'
        '        path_prefixes: ["/"]\n'
        "    identities:\n"
        "      - name: default\n"
        '        auth_ref: "env://MOCK_KEY"\n' + judges,
        encoding="utf-8",
    )
    return path


def _judge(tmp_path: Path, size: str, rates: tuple[float, float] | None) -> Path:
    path = tmp_path / f"judge-{size}.yaml"
    pricing = (
        f"pricing:\n  input_eur_per_mtok: {rates[0]}\n  output_eur_per_mtok: {rates[1]}\n"
        if rates is not None
        else ""
    )
    path.write_text(
        f"id: judge-{size}\ntype: model\nprovider: openai\n"
        "endpoint: https://judge.example.org/v1/chat/completions\n"
        f"model: judge-{size}-model\nauth_ref: env://NONE\n{pricing}",
        encoding="utf-8",
    )
    return path


def _priced_target(tmp_path: Path, pricing: str = _PRICED) -> Path:
    path = write_target(tmp_path, mock_scenario="vulnerable")
    path.write_text(path.read_text(encoding="utf-8") + pricing, encoding="utf-8")
    return path


def _judged_spec() -> AttackSpec:
    return make_spec(evaluators=(EvaluatorType.REFUSAL, EvaluatorType.SEMANTIC_JUDGE))


def _argv(tmp_path: Path, target: Path, *extra: str) -> list[str]:
    return [
        "run",
        str(target),
        "--scope",
        str(_scope(tmp_path)),
        "--spec-path",
        str(write_spec_tree(tmp_path, [_judged_spec()])),
        "--no-color",
        "--runs",
        "2",
        "--run-db",
        str(tmp_path / "runs.db"),
        "--evidence-root",
        str(tmp_path / "evidence"),
        *extra,
    ]


# --- pricing: in a target file -------------------------------------------------------------


def test_a_target_file_declares_its_rates(tmp_path: Path) -> None:
    target = wiring.load_target(_priced_target(tmp_path))
    assert target.pricing == Pricing(input_eur_per_mtok=2.5, output_eur_per_mtok=10.0)


@pytest.mark.parametrize(
    ("block", "said"),
    [
        ("pricing: 3\n", "'pricing' must be a mapping"),
        ("pricing:\n  input_eur_per_mtok: -1\n  output_eur_per_mtok: 1\n", "input_eur_per_mtok"),
        ("pricing:\n  input_eur_per_mtok: .inf\n  output_eur_per_mtok: 1\n", "input_eur_per_mtok"),
        ("pricing:\n  input_eur_per_mtok: 1\n", "output_eur_per_mtok: Field required"),
        ("pricing:\n  input: 1\n  output: 1\n", "Extra inputs are not permitted"),
    ],
)
def test_a_rate_it_cannot_read_is_refused(tmp_path: Path, block: str, said: str) -> None:
    with pytest.raises(ValueError, match="'pricing'") as caught:
        wiring.load_target(_priced_target(tmp_path, block))
    assert said in str(caught.value)


def test_a_rate_is_no_part_of_the_target_digest_nor_of_an_unpriced_dump(tmp_path: Path) -> None:
    priced = wiring.load_target(_priced_target(tmp_path))
    plain = priced.model_copy(update={"pricing": None})
    assert target_digest(priced) == target_digest(plain)
    assert "pricing" not in plain.model_dump()
    assert priced.model_dump()["pricing"] == {
        "input_eur_per_mtok": 2.5,
        "output_eur_per_mtok": 10.0,
    }


def test_euros_are_counted_per_million_tokens() -> None:
    rates = Pricing(input_eur_per_mtok=3.0, output_eur_per_mtok=15.0)
    assert run_mod.eur(1_000_000, 0, rates) == 3.0
    assert run_mod.eur(200_000, 100_000, rates) == pytest.approx(2.1)
    assert (run_mod.euros(2.104), run_mod.euros(0.0041), run_mod.euros(0.0)) == (
        "2.10",
        "0.0041",
        "0.00",
    )


# --- the estimate in euros -----------------------------------------------------------------


def test_the_estimate_prints_euros_for_a_priced_target(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, [*_argv(tmp_path, _priced_target(tmp_path)), "--estimate"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "~cost: " in out and " EUR at the rates the target files declare (pricing:)" in out
    assert "    mock-target: " in out and "at 2.50 / 10.00 EUR per million" in out
    assert "no per-model pricing known" not in out

    quiet = CliRunner().invoke(
        app, [*_argv(tmp_path, _priced_target(tmp_path)), "--estimate", "-q"]
    )
    assert quiet.exit_code == 0, quiet.output
    assert quiet.output.strip().endswith(" EUR")


def test_an_unpriced_estimate_prints_as_before(tmp_path: Path) -> None:
    target = write_target(tmp_path, mock_scenario="vulnerable")
    result = CliRunner().invoke(app, [*_argv(tmp_path, target), "--estimate"])
    assert result.exit_code == 0, result.output
    assert "~cost" not in result.output
    assert "no per-model pricing known" in result.output
    assert "declare pricing: in the target file for a figure in EUR" in result.output


def test_both_judges_are_priced_apart_and_an_unpriced_one_makes_a_floor(tmp_path: Path) -> None:
    target = _priced_target(tmp_path)
    small = _judge(tmp_path, "small", (0.1, 0.5))
    large = _judge(tmp_path, "large", (4.0, 20.0))
    argv = [*_argv(tmp_path, target), "--judge", str(small), "--judge-escalate", str(large)]
    result = CliRunner().invoke(app, [*argv, "--estimate"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "request(s) to the judge models" in out
    assert "of which up to 4 to the --judge-escalate model" in out
    assert "    --judge judge-small: " in out and "at 0.10 / 0.50 EUR per million" in out
    assert "    --judge-escalate judge-large: " in out and "at 4.00 / 20.00 EUR" in out
    assert "at least" not in out

    dry = CliRunner().invoke(app, [*argv, "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert "escalate: up to 4 of them to the --judge-escalate model" in dry.output

    unpriced = _judge(tmp_path, "large", None)
    floor = CliRunner().invoke(
        app,
        [
            *_argv(tmp_path, target),
            "--judge",
            str(small),
            "--judge-escalate",
            str(unpriced),
            "--estimate",
        ],
    )
    assert floor.exit_code == 0, floor.output
    assert "~cost: at least " in floor.output
    assert "    --judge-escalate judge-large: unpriced (no pricing: in its target file)" in (
        floor.output
    )


def test_the_estimate_counts_every_judgement_once_more_for_the_second_judge() -> None:
    spec = _judged_spec()
    plain = run_mod.estimate_plan([spec], runs=2, judge=True)
    up = run_mod.estimate_plan([spec], runs=2, judge=True, escalate=True)
    judged = 2 * run_mod.JUDGE_PASSES
    assert up.judge_requests == plain.judge_requests + judged
    assert (plain.escalate_requests, up.escalate_requests) == (0, judged)
    assert up.judge_tokens == plain.judge_tokens + up.escalate_tokens
    assert up.judge_output_tokens == plain.judge_output_tokens
    assert run_mod.estimate_plan([spec], runs=2, judge=False, escalate=True).escalate_requests == 0


# --- --judge-escalate: refused alone, bound by a resume ------------------------------------


def test_a_second_judge_without_a_first_is_refused(tmp_path: Path) -> None:
    large = _judge(tmp_path, "large", None)
    result = CliRunner().invoke(
        app,
        [*_argv(tmp_path, _priced_target(tmp_path)), "--judge-escalate", str(large), "--estimate"],
    )
    assert result.exit_code != 0
    assert "--judge-escalate needs --judge" in " ".join(result.output.split())


def test_a_resume_is_bound_to_the_second_judge_its_run_recorded(tmp_path: Path) -> None:
    target_path = write_target(tmp_path, mock_scenario="vulnerable")
    result = CliRunner().invoke(app, _argv(tmp_path, target_path))
    assert result.exit_code == 2, result.output
    with closing(sqlite3.connect(tmp_path / "runs.db")) as conn:
        (run_id,) = conn.execute("SELECT run_id FROM runs").fetchone()
    context = SqliteRunStore(tmp_path / "runs.db").get_run_context(run_id)
    assert context is not None and context["judge_escalate_digest"] is None
    target = wiring.load_target(target_path)
    large = wiring.load_target(_judge(tmp_path, "large", None))

    with pytest.raises(ValueError, match="none stored, one now"):
        resume_mod._assert_same_context(
            tmp_path / "runs.db",
            run_id,
            target,
            mock_scenario="vulnerable",
            runs=None,
            judge_escalate=large,
        )
    resume_mod._assert_same_context(
        tmp_path / "runs.db", run_id, target, mock_scenario="vulnerable", runs=None
    )
