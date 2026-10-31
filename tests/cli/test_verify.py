"""``run --verify`` through the real CLI, against the offline mock (u08 A-107, OD-63, ADR-0019).

A failing spec gets one more request to the judge model, which is asked to refute the fail. The
mock's scripted judge says ``holds`` in the vulnerable scenario. The state is reported beside the
finding and moves nothing: a ``does_not_hold`` changes neither the status, nor ``confirmed``, nor
the exit code.
"""

from __future__ import annotations

import json
import sqlite3
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from typer.testing import CliRunner

from ildottore.cli import resume as resume_mod
from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.cli.run import JUDGE_PASSES, VERIFY_PASSES, estimate_plan
from ildottore.core.budgets import BudgetExhausted
from ildottore.shared.enums import EvaluatorType, VerificationState
from ildottore.shared.models import AttackSpec, Attempt, EvaluatorConfig, Verification

from .conftest import make_spec, write_scope, write_spec_tree, write_target

_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _argv(
    tmp_path: Path, specs: list[AttackSpec], *extra: str, scenario: str = "vulnerable"
) -> list[str]:
    return [
        "run",
        str(write_target(tmp_path, mock_scenario=scenario)),
        "--scope",
        str(write_scope(tmp_path)),
        "--spec-path",
        str(write_spec_tree(tmp_path, specs)),
        "--no-color",
        "--runs",
        "2",
        "-oJ",
        str(tmp_path / "report.json"),
        "-oS",
        str(tmp_path / "report.sarif"),
        "--evidence-root",
        str(tmp_path / "evidence"),
        "--run-db",
        str(tmp_path / "runs.db"),
        *extra,
    ]


def _report(tmp_path: Path) -> dict[str, Any]:
    return dict(json.loads((tmp_path / "report.json").read_text(encoding="utf-8")))


def _findings(tmp_path: Path) -> dict[str, dict[str, Any]]:
    return {f["spec_id"]: f for f in _report(tmp_path)["findings"]}


def _sarif_result(tmp_path: Path) -> dict[str, Any]:
    sarif = json.loads((tmp_path / "report.sarif").read_text(encoding="utf-8"))
    return dict(sarif["runs"][0]["results"][0])


def _run_id(tmp_path: Path) -> str:
    conn = sqlite3.connect(tmp_path / "runs.db")
    try:
        (run_id,) = conn.execute("SELECT run_id FROM runs").fetchone()
    finally:
        conn.close()
    return str(run_id)


class _Says:
    """A stand-in for the adversarial verifier: one fixed answer, or a ceiling that refuses it."""

    def __init__(self, state: VerificationState | None, reasoning: str = "refuted") -> None:
        self._state = state
        self._reasoning = reasoning

    def __call__(self, _judge: object) -> _Says:
        return self

    async def verify(self, spec: AttackSpec, attempt: Attempt) -> Verification:
        if self._state is None:
            raise BudgetExhausted("requests", 2, 3)
        return Verification(
            state=self._state,
            attempt_id=attempt.attempt_id,
            reasoning=self._reasoning,
            confidence=0.9,
        )


def test_a_fail_the_reviewer_cannot_refute_holds(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, _argv(tmp_path, [make_spec()], "--verify"))
    assert result.exit_code == 2, result.output
    finding = _findings(tmp_path)["PI-DIRECT-001"]

    assert finding["confirmed"] is True
    verification = finding["verification"]
    assert verification["state"] == "holds"
    assert verification["attempt_id"] in {a["attempt_id"] for a in finding["attempts"]}
    assert "the fail holds (reported, never decisive)" in finding["reasoning"]
    # One more request, never a trial: the attempts and N are the spec's own.
    assert len(finding["attempts"]) == 2

    schema = json.loads(
        resources.files("ildottore.reporting")
        .joinpath("schemas/report-1.0.schema.json")
        .read_text(encoding="utf-8")
    )
    jsonschema.validate(_report(tmp_path), schema)
    result_ = _sarif_result(tmp_path)
    assert result_["properties"]["verification"] == "holds"
    assert "does not hold" not in result_["message"]["text"]


def test_a_refuted_fail_is_reported_and_moves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(wiring, "AdversarialVerifier", _Says(VerificationState.DOES_NOT_HOLD))
    result = CliRunner().invoke(app, _argv(tmp_path, [make_spec()], "--verify"))
    assert result.exit_code == 2, result.output  # still confirmed, still gated
    finding = _findings(tmp_path)["PI-DIRECT-001"]
    assert (finding["status"], finding["confirmed"]) == ("fail", True)
    assert finding["verification"]["state"] == "does_not_hold"
    assert "the fail does not hold (reported, never decisive)" in finding["reasoning"]
    result_ = _sarif_result(tmp_path)
    assert result_["properties"]["verification"] == "does_not_hold"
    assert "says it does not hold: review it" in result_["message"]["text"]


def test_a_ceiling_that_refuses_the_second_pass_keeps_the_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(wiring, "AdversarialVerifier", _Says(None))
    result = CliRunner().invoke(app, _argv(tmp_path, [make_spec()], "--verify"))
    assert result.exit_code == 2, result.output
    finding = _findings(tmp_path)["PI-DIRECT-001"]
    assert (finding["status"], finding["confirmed"]) == ("fail", True)
    assert finding["verification"]["state"] == "inconclusive"
    assert finding["verification"]["reasoning"].startswith("not consulted: ")


def test_the_reviewers_words_are_masked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    said = _Says(VerificationState.HOLDS, reasoning=f"the reply carries {_SECRET}")
    monkeypatch.setattr(wiring, "AdversarialVerifier", said)
    result = CliRunner().invoke(app, _argv(tmp_path, [make_spec()], "--verify"))
    assert result.exit_code == 2, result.output
    assert _SECRET not in (tmp_path / "report.json").read_text(encoding="utf-8")
    assert _SECRET not in (tmp_path / "report.sarif").read_text(encoding="utf-8")
    verification = _findings(tmp_path)["PI-DIRECT-001"]["verification"]
    assert (verification["state"], verification["attempt_id"]) == (
        "holds",
        "PI-DIRECT-001::identity#0",
    )


def test_no_second_pass_without_the_flag_nor_for_a_pass(tmp_path: Path) -> None:
    plain = CliRunner().invoke(app, _argv(tmp_path, [make_spec()]))
    assert plain.exit_code == 2, plain.output
    assert _findings(tmp_path)["PI-DIRECT-001"]["verification"] is None

    passed = CliRunner().invoke(
        app, _argv(tmp_path, [make_spec()], "--verify", scenario="hardened")
    )
    assert passed.exit_code == 0, passed.output
    finding = _findings(tmp_path)["PI-DIRECT-001"]
    assert (finding["status"], finding["verification"]) == ("pass", None)


def test_the_estimate_prices_one_second_pass_per_spec(tmp_path: Path) -> None:
    judged = make_spec(evaluators=(EvaluatorType.REFUSAL, EvaluatorType.SEMANTIC_JUDGE))
    plain = estimate_plan([judged, make_spec("PI-DIRECT-002")], runs=2, judge=True)
    verified = estimate_plan([judged, make_spec("PI-DIRECT-002")], runs=2, judge=True, verify=True)
    assert verified.judge_requests == plain.judge_requests + 2 * VERIFY_PASSES
    assert (plain.verify_requests, verified.verify_requests) == (0, 2 * VERIFY_PASSES)
    assert verified.requests == plain.requests
    # Without a judge the CLI refuses --verify on a live target; the estimate prices nothing.
    assert estimate_plan([judged], runs=2, judge=False, verify=True).verify_requests == 0
    assert JUDGE_PASSES >= VERIFY_PASSES

    specs = [
        judged.model_copy(update={"evaluators": [EvaluatorConfig(type=EvaluatorType.REFUSAL)]})
    ]
    dry = CliRunner().invoke(app, [*_argv(tmp_path, specs, "--verify"), "--dry-run"])
    assert dry.exit_code == 0, dry.output
    # The offline mock's judge is not priced: no judge requests, so no second-pass line.
    assert "verify:" not in dry.output


def test_a_live_target_without_a_judge_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "live.yaml"
    target.write_text(
        "id: mock-target\ntype: chatbot\nprovider: openai\n"
        "endpoint: https://relay.example.org/v1/chat/completions\nmodel: relay-model-alpha\n",
        encoding="utf-8",
    )
    scope = tmp_path / "live-scope.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n'
        '    base_url: "https://relay.example.org"\n    endpoints:\n'
        '      - host: "relay.example.org"\n        path_prefixes: ["/v1/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://MOCK_KEY"\n',
        encoding="utf-8",
    )
    argv = _argv(tmp_path, [make_spec()], "--verify")
    argv[1], argv[3] = str(target), str(scope)
    refused = CliRunner().invoke(app, argv)
    assert refused.exit_code != 0
    assert "--verify needs --judge on a live target" in " ".join(refused.output.split())


def test_a_resume_keeps_what_its_run_started_with(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, _argv(tmp_path, [make_spec()], "--verify"))
    assert result.exit_code == 2, result.output
    run_id = _run_id(tmp_path)
    assert resume_mod.stored_verify(tmp_path / "runs.db", run_id) is True
    assert resume_mod.stored_verify(tmp_path / "absent.db", run_id) is False

    refused = CliRunner().invoke(
        app, [*_argv(tmp_path, [make_spec()]), "--resume", run_id, "--verify"]
    )
    assert refused.exit_code != 0
    assert "--verify cannot be given with --resume" in " ".join(refused.output.split())
