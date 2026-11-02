"""CCN-STIC-2011 (ESP-IA) for one target: the applicability matrix and the evidence draft.

``dottore coverage --framework esp_ia --target FILE`` (u12 A-117) applies the guide's matrix to
the vendor's answers in a target file and says which specs would run; ``dottore replay RUN_ID
--esp-ia FILE.md`` (u12 A-118) writes a draft shaped like the guide's Annex B from a run's
evidence. Neither sends anything, and neither ever writes that a requirement passed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from ildottore.cli import wiring
from ildottore.cli.exit_codes import ExitCode
from ildottore.cli.main import app
from ildottore.shared.digest import target_digest
from ildottore.shared.esp_ia import ESP_IA_QUESTIONS

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "examples"
runner = CliRunner()

#: Yes to an external input, instructions, repeated queries and protected runtime information
#: only: rules R02, R11 and nothing that needs C16, so RP02 does not apply either.
_CHATBOT_YES = {"C01", "C03", "C05", "C12"}


def _answers(yes: set[str]) -> dict[str, bool]:
    answers = {q: q in yes for q in ESP_IA_QUESTIONS if q != "C16a"}
    if answers["C16"]:
        answers["C16a"] = "C16a" in yes
    return answers


def _mock_target(tmp_path: Path, answers: dict[str, object] | None, name: str = "t.yaml") -> Path:
    """``examples/target.mock.yaml`` with an ``esp_ia`` block: the same target to the digest."""

    raw = yaml.safe_load((EXAMPLES / "target.mock.yaml").read_text())
    if answers is not None:
        raw["esp_ia"] = {"answers": answers}
    path = tmp_path / name
    path.write_text(yaml.safe_dump(raw, sort_keys=False))
    return path


def _coverage(*args: str) -> tuple[int, str]:
    res = runner.invoke(app, ["coverage", "--framework", "esp_ia", *args])
    return res.exit_code, res.output


# --- the answers in a target file ----------------------------------------------------------


def test_the_answers_are_outside_the_target_digest(tmp_path: Path) -> None:
    plain = wiring.load_target(EXAMPLES / "target.mock.yaml")
    answered = wiring.load_target(_mock_target(tmp_path, _answers(_CHATBOT_YES)))
    assert answered.esp_ia is not None
    assert target_digest(plain) == target_digest(answered)
    assert "esp_ia" not in plain.model_dump()


@pytest.mark.parametrize(
    ("answers", "message"),
    [
        ({**_answers(set()), "C03": "SÍ"}, "C03"),
        ({k: v for k, v in _answers(set()).items() if k != "C07"}, "unanswered: C07"),
        (_answers({"C16"}) | {"C16a": None}, "C16a"),
        ({k: v for k, v in _answers({"C16"}).items() if k != "C16a"}, "C16 is yes"),
        (_answers(set()) | {"C16a": True}, "only when C16 is yes"),
        (_answers(set()) | {"secret-hostname": True}, "1 key(s) are not questions"),
        (_answers(set()) | {"secret-hostname": "x"}, "1 key(s) are not questions"),
    ],
)
def test_the_loader_refuses_an_incomplete_or_odd_answer_set(
    tmp_path: Path, answers: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match="'esp_ia' failed validation") as caught:
        wiring.load_target(_mock_target(tmp_path, answers))
    assert message in str(caught.value)
    assert "secret-hostname" not in str(caught.value)


# --- coverage --target ---------------------------------------------------------------------


def test_the_agent_example_gets_its_rules_and_its_blocked_specs() -> None:
    code, output = _coverage("--target", str(EXAMPLES / "target.agent.yaml"))
    assert code == ExitCode.CLEAN, output
    assert "Rules met:    R02 R03 R09 R11 R12 R14 R15 R16 R17 R21 R22 RP01 RP02" in output
    assert "Requirements that apply: 16 of 27" in output
    assert "blocked, setup_not_delivered: PI-DIRECT-001" in output
    assert "blocked, capability_unavailable (memory): DL-XSESSION-001" in output
    assert "RFS-EXH-02  T.EXHAUSTION  (rule R22)\n    deliberately not tested" in output
    assert "says PASS." in output
    assert "RFS-EVA-01" not in output  # C02 is no, so R01 does not apply


def test_the_json_form_carries_every_reason_in_full() -> None:
    code, output = _coverage("--target", str(EXAMPLES / "target.agent.yaml"), "--json")
    assert code == ExitCode.CLEAN, output
    payload = json.loads(output[output.index("{") :])
    assert payload["edition"] == "1.0"
    assert len(payload["requirements"]) == 16
    (inj1,) = [r for r in payload["requirements"] if r["code"] == "RFS-INJ-01"]
    assert "JB-TREE-001" in inj1["runs"]
    (blocked,) = [b for b in inj1["blocked"] if b["spec_id"] == "PI-DIRECT-001"]
    assert blocked["reason"].startswith("setup_not_delivered: ")


def test_an_offline_mock_holds_its_scene(tmp_path: Path) -> None:
    code, output = _coverage("--target", str(_mock_target(tmp_path, _answers(_CHATBOT_YES))))
    assert code == ExitCode.CLEAN, output
    assert "Rules met:    R02 R11\n" in output
    assert "setup_not" not in output


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("--target", str(EXAMPLES / "target.mock.yaml")), "has no 'esp_ia: answers:' block"),
    ],
)
def test_coverage_target_refusals(args: tuple[str, ...], message: str) -> None:
    code, output = _coverage(*args)
    assert code == ExitCode.ERROR
    assert message in output


def test_target_needs_the_esp_ia_framework() -> None:
    res = runner.invoke(app, ["coverage", "--target", str(EXAMPLES / "target.agent.yaml")])
    assert res.exit_code == ExitCode.ERROR
    assert "pass --framework esp_ia" in res.output


# --- replay --esp-ia -----------------------------------------------------------------------


@pytest.fixture(scope="module")
def mock_runs(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, str, str]:
    """(evidence, store, failing run, passing run) against the offline mock."""

    root = tmp_path_factory.mktemp("espia")
    evidence, db = root / "evidence", root / "runs.sqlite"
    hardened = root / "hardened.yaml"
    hardened.write_text(
        (EXAMPLES / "target.mock.yaml").read_text().replace("vulnerable", "hardened")
    )
    run_ids = []
    for target, expected in (
        (EXAMPLES / "target.mock.yaml", ExitCode.FINDINGS_AT_OR_ABOVE),
        (hardened, ExitCode.CLEAN),
    ):
        before = set(evidence.iterdir()) if evidence.exists() else set()
        res = runner.invoke(
            app,
            [
                *("run", "-t", str(target), "--scope", str(EXAMPLES / "scope.mock.yaml")),
                *("--spec", "PI-DIRECT-001", "--spec", "OUT-SQLI-001", "-q"),
                *("--evidence-root", str(evidence), "--run-db", str(db)),
            ],
        )
        assert res.exit_code == expected, res.output
        (new,) = set(evidence.iterdir()) - before
        run_ids.append(new.name)
    return evidence, db, run_ids[0], run_ids[1]


def _draft(
    mock_runs: tuple[Path, Path, str, str], run_id: str, out: Path, *extra: str
) -> tuple[int, str]:
    evidence, db, _, _ = mock_runs
    res = runner.invoke(
        app,
        [
            *("replay", run_id, "--evidence-root", str(evidence), "--run-db", str(db)),
            *("--esp-ia", str(out), *extra),
        ],
    )
    return res.exit_code, res.output


def test_a_failing_run_is_fail_evidence_by_requirement(
    mock_runs: tuple[Path, Path, str, str], tmp_path: Path
) -> None:
    out = tmp_path / "draft.md"
    code, output = _draft(mock_runs, mock_runs[2], out)
    assert code == 0, output
    text = out.read_text()
    assert "| RFS-INJ-01 | PR_PI-DIRECT-001 | **FAIL evidence** |" in text
    assert "| RFS-DIS-01 | PR_PI-DIRECT-001 | **FAIL evidence** |" in text
    assert "| RFS-EVA-01 | none | no test in this run |" in text
    assert "| RFS-TRA-01 | none | out of reach for a black-box scanner:" in text
    # OUT-SQLI-001 maps to no requirement, so it gets no test case.
    assert "### PR_PI-DIRECT-001" in text and "PR_OUT-SQLI-001" not in text
    assert "Section 4 lists all 27 requirements" in text


def test_a_passing_run_is_never_a_pass(
    mock_runs: tuple[Path, Path, str, str], tmp_path: Path
) -> None:
    out = tmp_path / "draft.md"
    code, output = _draft(mock_runs, mock_runs[3], out)
    assert code == 0, output
    text = out.read_text()
    assert "| RFS-INJ-01 | PR_PI-DIRECT-001 | not falsified |" in text
    assert "not falsified by these probes; not a PASS" in text
    assert "PASA" not in text
    assert "| PASS" not in text


def test_the_answers_narrow_the_draft_to_what_applies(
    mock_runs: tuple[Path, Path, str, str], tmp_path: Path
) -> None:
    out = tmp_path / "draft.md"
    target = _mock_target(tmp_path, _answers(_CHATBOT_YES))
    code, output = _draft(mock_runs, mock_runs[2], out, "--target", str(target))
    assert code == 0, output
    text = out.read_text()
    assert "Rules met: R02 R11." in text
    assert "| RFS-INJ-01 | T.INJECTION | R02 |" in text
    assert "T.INJECTION, T.DISCLOSURE" in text
    assert "RFS-TRA-01" not in text and "RFS-EVA-01" not in text


def test_the_answers_of_another_target_are_refused(
    mock_runs: tuple[Path, Path, str, str], tmp_path: Path
) -> None:
    out = tmp_path / "draft.md"
    other = _mock_target(tmp_path, _answers(_CHATBOT_YES))
    other.write_text(other.read_text().replace("id: demo", "id: someone-else"))
    code, output = _draft(mock_runs, mock_runs[2], out, "--target", str(other))
    assert code == ExitCode.ERROR
    assert "is not the one run" in output
    assert not out.exists()


def test_replay_esp_ia_refusals(mock_runs: tuple[Path, Path, str, str], tmp_path: Path) -> None:
    used = tmp_path / "used.md"
    used.write_text("mine\n")
    code, output = _draft(mock_runs, mock_runs[2], used)
    assert code == ExitCode.ERROR and "writes a new file" in output
    assert used.read_text() == "mine\n"

    evidence, db, run_id, _ = mock_runs
    res = runner.invoke(
        app,
        [
            *("replay", run_id, "--evidence-root", str(evidence), "--run-db", str(db)),
            *("--target", str(EXAMPLES / "target.agent.yaml")),
        ],
    )
    assert res.exit_code == ExitCode.ERROR
    assert "pass --esp-ia FILE" in res.output
