"""A run halted inside an identity sweep or inside a batch of attempts, then resumed.

Through the real CLI against a loopback OpenAI-compatible stub. Found by the delta audit of
`fix/authz-leak-identity-sweep` on 2026-10-07, on main as it stood (0f936b6): a request ceiling
that stopped a run inside `DL-XTENANT-001`'s identity sweep, or between two attempts of one batch,
stored nothing for that spec, and `--resume` was refused with "a run that sent nothing has
nothing to continue" while the run store recorded the requests that went out. The attempts the
batch had answered were dropped with the exception, so even a resume that was allowed would have
sent them again and paid for them twice.

What a halted run keeps now: every reply the target gave is stored, judged when the ceiling
leaves room for the judge and without a verdict when it does not (the resume sends that one
again and judges it); the spend is in the run store; and a run that spent requests and stored no
reply (an identity sweep, a conversation stopped mid-way) is resumed from nothing with its spend
carried. Each test checks the three things the operator pays for: what the halted run spent, what
`--estimate --resume` says is left, and what the resume actually sends.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ildottore.cli.app import app

_JUDGE_SAYS_SECURE = json.dumps(
    {
        "verdict": "secure",
        "confidence": 0.95,
        "reasoning": "the reply refused",
        "observed_injection_attempt": False,
    }
)


def _reply(content: str, total_tokens: int) -> bytes:
    return json.dumps(
        {
            "id": "stub",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 5,
                "completion_tokens": total_tokens - 5,
                "total_tokens": total_tokens,
            },
        }
    ).encode()


@pytest.fixture
def stub() -> Iterator[tuple[int, dict[str, Any]]]:
    """A target under `/v1` and a judge under `/judge/v1`, each counting what it served."""

    state: dict[str, Any] = {"target": 0, "judge": 0, "usage": 10}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("content-length", "0")))
            if self.path.startswith("/judge/"):
                state["judge"] += 1
                body = _reply(_JUDGE_SAYS_SECURE, 10)
            else:
                state["target"] += 1
                body = _reply("I cannot help with that.", state["usage"])
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], state
    finally:
        server.shutdown()
        server.server_close()


def _command(tmp_path: Path, port: int, spec: str, runs: int, *, judge: bool = False) -> list[str]:
    """`dottore run` against the stub: two scope identities, a multi_identity target."""

    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    judge_endpoint = f"http://127.0.0.1:{port}/judge/v1/chat/completions"
    (tmp_path / "scope.yaml").write_text(
        f'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "{endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/v1/chat/completions"]\n'
        "    identities:\n"
        '      - name: tenant-a\n        auth_ref: "env://NONE"\n'
        '        canary: "CANARY_A_{{run_id}}"\n'
        '      - name: tenant-b\n        auth_ref: "env://NONE"\n'
        '        canary: "CANARY_B_{{run_id}}"\n'
        f'  - id: judge\n    base_url: "{judge_endpoint}"\n'
        f'    endpoints:\n      - host: "127.0.0.1:{port}"\n'
        '        path_prefixes: ["/judge/v1/chat/completions"]\n'
        '    identities:\n      - name: judge\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        f'id: stub\ntype: chatbot\nprovider: openai\nendpoint: "{endpoint}"\nmodel: m\n'
        "capabilities:\n  tools: false\n  rag: false\n  multi_identity: true\n"
    )
    (tmp_path / "judge.yaml").write_text(
        f'id: judge\ntype: chatbot\nprovider: openai\nendpoint: "{judge_endpoint}"\nmodel: j\n'
    )
    command = [
        "run",
        "-t",
        str(tmp_path / "target.yaml"),
        "--scope",
        str(tmp_path / "scope.yaml"),
        "--spec",
        spec,
        "--runs",
        str(runs),
        "--rate",
        "1000",
        "--concurrency",
        "1",
        "--evidence-root",
        str(tmp_path / "ev"),
        "--run-db",
        str(tmp_path / "runs.sqlite"),
        "--no-color",
    ]
    return [*command, "--judge", str(tmp_path / "judge.yaml")] if judge else command


def _run_id(tmp_path: Path) -> str:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        rows = conn.execute("SELECT run_id FROM runs").fetchall()
    finally:
        conn.close()
    assert len(rows) == 1, rows
    return str(rows[0][0])


def _spent(tmp_path: Path, run_id: str) -> int:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        row = conn.execute("SELECT spend_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    finally:
        conn.close()
    return int(json.loads(row[0])["requests"])


def _artifacts(tmp_path: Path, run_id: str) -> list[dict[str, Any]]:
    attempts = tmp_path / "ev" / run_id / "attempts"
    if not attempts.is_dir():
        return []
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(attempts.glob("*.json"))]


def _still_to_send(output: str) -> tuple[int, int]:
    """(target, judge) requests `--estimate --resume` says the resume will send."""

    total = int(re.search(r"^estimate: (\d+) requests", output, re.M).group(1))  # type: ignore[union-attr]
    done = re.search(r"minus (\d+) request\(s\) already done", output)
    target = total - (int(done.group(1)) if done else 0)
    judge_total = re.search(r"\+ (\d+) request\(s\) to the --judge model", output)
    judge_done = re.search(r"minus (\d+) judge request\(s\)", output)
    judge = (int(judge_total.group(1)) if judge_total else 0) - (
        int(judge_done.group(1)) if judge_done else 0
    )
    return target, judge


def _halt_estimate_resume(
    tmp_path: Path, state: dict[str, Any], base: list[str], ceiling: list[str]
) -> dict[str, Any]:
    """Halt the run, estimate its resume, resume it; return what each step spent and said."""

    cli = CliRunner()
    halted = cli.invoke(app, [*base, *ceiling])
    assert halted.exit_code == 3, halted.output
    assert "budget ceiling reached" in halted.output, halted.output
    run_id = _run_id(tmp_path)
    sent_by_halt = state["target"] + state["judge"]
    stored = _artifacts(tmp_path, run_id)
    spent_by_halt = _spent(tmp_path, run_id)

    state["usage"] = 10
    estimate = cli.invoke(app, [*base, "--resume", run_id, "--estimate"])
    assert estimate.exit_code == 0, estimate.output
    assert state["target"] + state["judge"] == sent_by_halt, "the estimate sent nothing"

    before = (state["target"], state["judge"])
    report = tmp_path / "report.json"
    resumed = cli.invoke(app, [*base, "--resume", run_id, "-oJ", str(report)])
    assert resumed.exit_code != 3, resumed.output
    return {
        "run_id": run_id,
        "sent_by_halt": sent_by_halt,
        "spent_by_halt": spent_by_halt,
        "stored": stored,
        "estimate": _still_to_send(estimate.output),
        "resume_output": resumed.output,
        "resume_sent": (state["target"] - before[0], state["judge"] - before[1]),
        "spent_after": _spent(tmp_path, run_id),
        "report": json.loads(report.read_text(encoding="utf-8")),
    }


def _attempts(report: dict[str, Any], spec_id: str) -> list[dict[str, Any]]:
    finding = next(f for f in report["findings"] if f["spec_id"] == spec_id)
    return list(finding["attempts"])


# --- a halt inside the identity sweep ------------------------------------------------------


@pytest.mark.parametrize("ceiling", [1, 2])
def test_a_run_halted_inside_the_identity_sweep_is_resumed_with_its_spend(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], ceiling: int
) -> None:
    """1: the second identity's request was refused; 2: both swept, the attempt refused.

    Either way no reply was stored, and the resume was refused although requests went out.
    """

    port, state = stub
    base = _command(tmp_path, port, "DL-XTENANT-001", runs=1)
    got = _halt_estimate_resume(tmp_path, state, base, ["--budget-requests", str(ceiling)])

    assert got["sent_by_halt"] == ceiling
    assert got["spent_by_halt"] == ceiling, "the spend of the halted run is recorded"
    assert got["stored"] == [], "a sweep is not an attempt: nothing to store"
    assert "stored no answered attempt before it stopped" in got["resume_output"]
    # The sweep (two identities) and the one attempt, all sent again.
    assert got["resume_sent"] == (3, 0)
    assert got["spent_after"] == ceiling + 3, "the resumed run's spend includes the halted one"
    attempts = _attempts(got["report"], "DL-XTENANT-001")
    assert [a["attempt_id"] for a in attempts] == ["DL-XTENANT-001::identity#0"]


@pytest.mark.xfail(
    strict=True,
    reason="main does not price the identity sweep in --estimate; PR #60 "
    "(fix/authz-leak-identity-sweep) does. Whoever lands second runs "
    "`pytest --runxfail -k prices_the_sweep` on this file, expects 3 passed, and removes "
    "this marker (if #60 prints the sweep on a line `_still_to_send` does not read, the "
    "three stay quietly xfailed: teach it that line).",
)
@pytest.mark.parametrize(("runs", "ceiling"), [(1, 1), (1, 2), (2, 3)])
def test_the_estimate_of_a_resume_after_a_sweep_halt_prices_the_sweep(
    tmp_path: Path, stub: tuple[int, dict[str, Any]], runs: int, ceiling: int
) -> None:
    """The three sweeping shapes above: inside the sweep, after it, and inside the batch."""

    port, state = stub
    base = _command(tmp_path, port, "DL-XTENANT-001", runs=runs)
    got = _halt_estimate_resume(tmp_path, state, base, ["--budget-requests", str(ceiling)])
    assert got["estimate"] == got["resume_sent"]


# --- a halt inside a batch of attempts --------------------------------------------------------


def test_a_run_halted_inside_a_batch_keeps_the_attempts_it_had_answered(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """Two of `identity`'s three attempts answered, the third refused: both used to be lost."""

    port, state = stub
    base = _command(tmp_path, port, "PI-DIRECT-001", runs=3)
    got = _halt_estimate_resume(tmp_path, state, base, ["--budget-requests", "2"])

    assert got["sent_by_halt"] == got["spent_by_halt"] == 2
    assert sorted(a["attempt_id"] for a in got["stored"]) == [
        "PI-DIRECT-001::identity#0",
        "PI-DIRECT-001::identity#1",
    ]
    assert all(a["response"] and a["verdict"] for a in got["stored"]), "answered and judged"
    assert "keeps 2 attempt(s)" in got["resume_output"]
    # Three mutations at --runs 3, less the two already answered.
    assert got["resume_sent"] == (7, 0)
    assert got["estimate"] == got["resume_sent"], "--estimate --resume prices what is sent"
    assert got["spent_after"] == 2 + 7
    attempts = _attempts(got["report"], "PI-DIRECT-001")
    assert len(attempts) == len({a["attempt_id"] for a in attempts}) == 9
    assert all(a["response"] is not None for a in attempts)


def test_a_sweeping_spec_halted_inside_its_batch_keeps_its_answer_and_sweeps_again(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """The audit's shape: two sweep requests and one answered attempt, then the halt."""

    port, state = stub
    base = _command(tmp_path, port, "DL-XTENANT-001", runs=2)
    got = _halt_estimate_resume(tmp_path, state, base, ["--budget-requests", "3"])

    assert got["sent_by_halt"] == got["spent_by_halt"] == 3
    assert [a["attempt_id"] for a in got["stored"]] == ["DL-XTENANT-001::identity#0"]
    # The spec is not finished, so the sweep goes out again with the attempt still missing.
    assert got["resume_sent"] == (3, 0)
    assert got["spent_after"] == 3 + 3
    attempts = _attempts(got["report"], "DL-XTENANT-001")
    assert sorted(a["attempt_id"] for a in attempts) == [
        "DL-XTENANT-001::identity#0",
        "DL-XTENANT-001::identity#1",
    ]


def test_a_halt_that_refuses_the_judge_stores_the_reply_and_the_resume_judges_it(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """`identity` answered and judged (2 + 4), `roleplay_wrap#0` answered (7), then the ceiling.

    The reply whose judge request the ceiling refused was dropped with the batch. Stored with a
    verdict it never got, it would be scored as an inconclusive for good; stored without one, the
    resume sends it again and judges it, and the first reply stays cited.
    """

    port, state = stub
    base = _command(tmp_path, port, "PI-DIRECT-001", runs=2, judge=True)
    got = _halt_estimate_resume(tmp_path, state, base, ["--budget-requests", "7"])

    assert got["sent_by_halt"] == got["spent_by_halt"] == 7
    unjudged = [a["attempt_id"] for a in got["stored"] if a["verdict"] is None]
    assert unjudged == ["PI-DIRECT-001::roleplay_wrap#0"]
    assert all(a["response"] for a in got["stored"]), "only answered attempts are stored"
    resend = "1 answered but not evaluated before the halt will be sent again"
    assert resend in got["resume_output"]
    assert "ended in an environment error" not in got["resume_output"], "not an env error"
    # roleplay_wrap#0 again, roleplay_wrap#1 and both refusal_suppression_prefix attempts,
    # each judged twice.
    assert got["resume_sent"] == (4, 8)
    assert got["estimate"] == got["resume_sent"], "the judge's share is priced too"
    assert got["spent_after"] == 7 + 4 + 8
    attempts = _attempts(got["report"], "PI-DIRECT-001")
    assert len(attempts) == 6
    assert all(a["verdict"] and a["verdict"]["status"] == "pass" for a in attempts)
    finding = next(f for f in got["report"]["findings"] if f["spec_id"] == "PI-DIRECT-001")
    assert len(finding["evidence"]) == 7, "the unjudged first reply stays cited"


def test_a_reply_that_crosses_the_token_ceiling_is_stored(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """The provider billed the reply, the ledger recorded it and halted, and the reply was lost."""

    port, state = stub
    state["usage"] = 5000
    base = _command(tmp_path, port, "PI-DIRECT-001", runs=2)
    got = _halt_estimate_resume(tmp_path, state, base, ["--budget-tokens", "1500"])

    assert got["sent_by_halt"] == got["spent_by_halt"] == 1
    assert [a["attempt_id"] for a in got["stored"]] == ["PI-DIRECT-001::identity#0"]
    assert got["stored"][0]["verdict"] is not None
    assert got["resume_sent"] == (5, 0)
    assert got["estimate"] == got["resume_sent"]
    assert got["spent_after"] == 1 + 5


# --- what is still refused -----------------------------------------------------------------


def test_a_run_that_spent_no_request_is_still_refused(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """A zero ceiling refuses the first request: there the refusal's reason is true."""

    port, state = stub
    base = _command(tmp_path, port, "PI-DIRECT-001", runs=1)
    cli = CliRunner()
    assert cli.invoke(app, [*base, "--budget-requests", "0"]).exit_code == 3
    run_id = _run_id(tmp_path)
    assert _spent(tmp_path, run_id) == 0
    resumed = cli.invoke(app, [*base, "--resume", run_id])
    assert resumed.exit_code == 3
    assert "a run that sent nothing has nothing to continue" in resumed.output
    assert state["target"] == 0


def test_a_resume_from_the_wrong_evidence_root_is_refused_not_restarted(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """An empty tree looks like a sweep halt from the tree alone; the journal tells them apart."""

    port, state = stub
    base = _command(tmp_path, port, "PI-DIRECT-001", runs=3)
    cli = CliRunner()
    assert cli.invoke(app, [*base, "--budget-requests", "2"]).exit_code == 3
    run_id = _run_id(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    swapped = [str(elsewhere) if arg == str(tmp_path / "ev") else arg for arg in base]
    sent = state["target"]
    resumed = cli.invoke(app, [*swapped, "--resume", run_id])
    assert resumed.exit_code == 3, resumed.output
    assert "not the tree the run wrote" in resumed.output
    assert state["target"] == sent, "nothing was sent again"


def _set_run_column(tmp_path: Path, run_id: str, column: str, value: str) -> None:
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        conn.execute(f"UPDATE runs SET {column} = ? WHERE run_id = ?", (value, run_id))  # noqa: S608
        conn.commit()
    finally:
        conn.close()


def test_an_empty_tree_is_refused_when_the_journal_holds_only_pending_rows(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """A pending row is an artifact written, or about to be, somewhere: not proof of nothing."""

    port, state = stub
    base = _command(tmp_path, port, "PI-DIRECT-001", runs=3)
    cli = CliRunner()
    assert cli.invoke(app, [*base, "--budget-requests", "2"]).exit_code == 3
    run_id = _run_id(tmp_path)
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        conn.execute("UPDATE artifacts SET state = 'pending'")
        conn.commit()
    finally:
        conn.close()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    swapped = [str(elsewhere) if arg == str(tmp_path / "ev") else arg for arg in base]
    sent = state["target"]
    resumed = cli.invoke(app, [*swapped, "--resume", run_id])
    assert resumed.exit_code == 3, resumed.output
    assert "began writing 2 attempt artifact(s) that it never confirmed" in resumed.output
    assert "not the tree the run wrote" not in resumed.output, "it may be, if the writes failed"
    assert state["target"] == sent


def test_an_empty_tree_of_a_run_that_predates_the_journal_is_refused(
    tmp_path: Path, stub: tuple[int, dict[str, Any]]
) -> None:
    """Before the journal, its silence proves nothing: the run may have written to another tree.

    The marker is the scope list a run records before it sends (D-17, built after the journal);
    a sweep halt stripped of it stands for a run made before either.
    """

    port, state = stub
    base = _command(tmp_path, port, "DL-XTENANT-001", runs=1)
    cli = CliRunner()
    assert cli.invoke(app, [*base, "--budget-requests", "1"]).exit_code == 3
    run_id = _run_id(tmp_path)
    conn = sqlite3.connect(tmp_path / "runs.sqlite")
    try:
        (context,) = conn.execute(
            "SELECT context_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    finally:
        conn.close()
    stripped = {k: v for k, v in json.loads(context).items() if k != "scope_sha256s"}
    _set_run_column(tmp_path, run_id, "context_json", json.dumps(stripped))
    sent = state["target"]
    resumed = cli.invoke(app, [*base, "--resume", run_id])
    assert resumed.exit_code == 3, resumed.output
    assert "predates the artifact journal" in resumed.output
    assert state["target"] == sent


def test_a_negative_spend_is_not_a_spend(tmp_path: Path, stub: tuple[int, dict[str, Any]]) -> None:
    port, state = stub
    sent_before = state["target"]
    base = _command(tmp_path, port, "DL-XTENANT-001", runs=1)
    cli = CliRunner()
    assert cli.invoke(app, [*base, "--budget-requests", "1"]).exit_code == 3
    run_id = _run_id(tmp_path)
    _set_run_column(
        tmp_path,
        run_id,
        "spend_json",
        json.dumps({"tokens": 0, "requests": -1, "attempts": 0, "wall_s": 0.0}),
    )
    sent_by_halt = state["target"] - sent_before
    resumed = cli.invoke(app, [*base, "--resume", run_id])
    assert resumed.exit_code == 3, resumed.output
    assert "stored no answered attempt" not in resumed.output
    assert state["target"] - sent_before == sent_by_halt, "nothing was sent again"


# --- the judge's share of a resume, attempt by attempt -------------------------------------


def _kept(attempt_id: str, *, response: bool, verdict: bool, error: str | None = None) -> Any:
    from ildottore.shared.models import Attempt, ModelRequest, ModelResponse, Verdict

    return Attempt(
        attempt_id=attempt_id,
        spec_id=attempt_id.split("::")[0],
        request=ModelRequest(prompt="x"),
        response=ModelResponse(text="no") if response else None,
        error=error,
        verdict=(
            Verdict(status="pass", confidence=1.0, reasoning="ok", evaluator_type="refusal")
            if verdict
            else None
        ),
    )


def test_the_judge_share_comes_off_only_for_what_the_resume_will_not_judge() -> None:
    """Off: an answered and judged attempt, and an error a retry would repeat (never judged,
    never sent again). Not off: an environment error and an unjudged reply, which the resume
    sends and judges, and anything of a spec the judge does not read."""

    from ildottore import safe_yaml
    from ildottore.cli.run import JUDGE_PASSES, _judge_requests_kept
    from ildottore.core.execute import NOT_RETRYABLE_MARK
    from ildottore.shared.enums import ScanBand
    from ildottore.shared.models import AttackSpec, Finding, RiskScore, TestRun

    attacks = Path(__file__).resolve().parents[2] / "specs" / "attacks"

    def load(spec_id: str) -> AttackSpec:
        return AttackSpec.model_validate(
            safe_yaml.safe_load((attacks / f"{spec_id}.yaml").read_text(encoding="utf-8"))
        )

    judged = load("PI-DIRECT-001")
    unjudged_spec = load("MCP-TOOLPOISON-001")  # declares no semantic_judge
    risk = RiskScore(
        impact=1, exploitability=1, reproducibility=0.0, risk=0.0, band=ScanBand.INFO,
        confidence=0.0,
    )  # fmt: skip
    attempts = [
        _kept("PI-DIRECT-001::identity#0", response=True, verdict=True),
        _kept(
            "PI-DIRECT-001::identity#1",
            response=False,
            verdict=True,
            error="ResponseTooLarge: over the cap" + NOT_RETRYABLE_MARK,
        ),
        _kept("PI-DIRECT-001::identity#2", response=False, verdict=True, error="ConnectError"),
        _kept("PI-DIRECT-001::identity#3", response=True, verdict=False),
    ]
    other = [_kept("MCP-TOOLPOISON-001::identity#0", response=True, verdict=True)]
    run = TestRun(
        run_id="r",
        findings=[
            Finding(
                spec_id=spec_id,
                target_id="t",
                status="inconclusive",
                risk=risk,
                confirmed=False,
                attempts=found,
            )
            for spec_id, found in (("PI-DIRECT-001", attempts), ("MCP-TOOLPOISON-001", other))
        ],
    )
    assert _judge_requests_kept(run, [judged, unjudged_spec]) == 2 * JUDGE_PASSES
    assert _judge_requests_kept(None, [judged]) == 0
