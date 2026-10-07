"""Leftovers of the 2026-10-03 audit, fixed on 2026-10-04 after the residuals (PR #35).

Each test reproduces one item the earlier passes left open on purpose: path forms only some
origins decode (review of PR #32). The compressed-reply cases live beside the response cap,
in ``tests/adapters/test_response_cap.py``.
"""

from __future__ import annotations

import asyncio
import re
import sqlite3
from pathlib import Path

import pytest

from ildottore.core.budgets import DEFAULT_COMPLETION_TOKENS, BudgetLedger
from ildottore.core.execute import execute_attempt, reserve_tokens
from ildottore.core.planner import PlanBudgets
from ildottore.core.runner import CampaignRunner
from ildottore.evaluators import build_default_registry as build_evaluators
from ildottore.mutators import build_default_registry as build_mutators
from ildottore.policy.allowlist import EndpointAllowlist
from ildottore.policy.scope import Endpoint
from ildottore.scoring import DefaultRiskScorer
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse
from ildottore.store.evidence_fs import FsEvidenceStore
from ildottore.store.run_sqlite import SqliteRunStore
from tests.core.conftest import AllowAllPolicy, make_spec, make_target, no_sleep

_ALLOWLIST = EndpointAllowlist([Endpoint(host="127.0.0.1:18081", path_prefixes=["/v1/chat"])])


@pytest.mark.parametrize(
    "path",
    [
        "/v1/chat/..;/admin",  # Tomcat and Jetty read `..;` as `..`
        "/v1/chat;jsessionid=x/../../admin",
        "/v1/chat/%u002e%u002e/admin",  # IIS %u escape
        "/v1/chat/%U002E%U002E/admin",
        "/v1/chat/%c0%ae%c0%ae/admin",  # overlong UTF-8 `.`
        "/v1/chat/..%c0%afadmin",  # overlong UTF-8 `/`
        "/v1/chat/%e0%80%ae%e0%80%ae/admin",  # overlong 3-byte `.`
        "/v1/chat/%f0%80%80%ae/admin",  # overlong 4-byte `.`
        "/v1/chat/%ef%bc%8e%ef%bc%8e/admin",  # fullwidth full stop, NFKC `.`
        "/v1/chat/..%EF%BC%8Fadmin",  # fullwidth solidus, NFKC `/`
        "/v1/chat/\uff0e\uff0e\uff0fadmin",  # the same, literal: httpx encodes it after the gate
        "/v1/chat/%e2%80%a4%e2%80%a4/admin",  # one dot leader
        "/v1/chat/%e2%80%a5/admin",  # two dot leader, NFKC `..`
        "/v1/chat/%ef%b9%92%ef%b9%92/admin",  # small full stop
        "/v1/chat/..%EF%BC%BCadmin",  # fullwidth reverse solidus, NFKC `\\`
        "/v1/chat/%EF%BC%852f",  # fullwidth percent sign, NFKC `%`
        "/v1/chat/..\u037e/admin",  # Greek question mark, `;` under NFC: `..;`
        "/v1/chat/..%CD%BE/admin",
        "/v1/chat/..%3b/admin",  # encoded `;`
        "/v1/chat/%f8%80%80%80%ae/admin",  # 5-byte overlong `.`
        "/v1/chat/%f5%80%80%80/admin",  # lead byte UTF-8 never allows
        "/v1/chat/..%c2%a0/admin",  # no-break space, a space after NFKC
        "/v1/chat/..%e3%80%80/admin",  # ideographic space
        "/v1/chat/..%e2%80%83/admin",  # em space
        "/v1/chat/..%20/admin",  # Windows strips the trailing space
        "/v1/chat/.../admin",
    ],
)
def test_a_path_form_some_origins_decode_is_refused(path: str) -> None:
    assert not _ALLOWLIST.is_allowed(f"http://127.0.0.1:18081{path}")


@pytest.mark.parametrize(
    "path",
    [
        "/v1/chat/completions",
        "/v1/chat/caf%C3%A9",  # valid UTF-8 outside the refused ranges
        "/v1/chat/%E2%80%93",
        "/v1/chat/caf\u00e9",  # literal non-ASCII that normalises to no separator
        "/v1/chat/x/../completions",  # a dot segment that stays inside the prefix
    ],
)
def test_ordinary_paths_still_pass(path: str) -> None:
    assert _ALLOWLIST.is_allowed(f"http://127.0.0.1:18081{path}")


# --- token reservations (block 4 leftover) -------------------------------------------------


def _token_runner(tmp_path: Path, target: object, *, concurrency: int = 4) -> CampaignRunner:
    return CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=build_mutators(discover=False),
        evaluators=build_evaluators(discover=False),
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev"),
        run_store=SqliteRunStore(tmp_path / "runs.sqlite"),
        adapter_factory=lambda _t, _s: target,  # type: ignore[arg-type,return-value]
        n=1,
        concurrency=concurrency,
        sleep=no_sleep,
        now=lambda: 0.0,
    )


class _Billed:
    """Answers after yielding, so concurrent sends overlap, and reports a fixed usage."""

    id = "t1"

    def __init__(self, tokens: int) -> None:
        self.tokens = tokens
        self.sends = 0

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        await asyncio.sleep(0.01)
        return ModelResponse(text="I cannot help with that.", usage={"total_tokens": self.tokens})

    def capabilities(self) -> Capabilities:
        return Capabilities()


def test_concurrent_sends_without_max_tokens_stay_under_the_token_ceiling(tmp_path: Path) -> None:
    """Specs with no `sampling.max_tokens` reserved nothing, so four concurrent sends all passed
    the ceiling check before any reply came back: 2000 tokens recorded under a 1200 ceiling."""

    target = _Billed(tokens=500)
    specs = [make_spec(f"JB-REFUSAL-00{i}") for i in range(1, 5)]
    assert all(s.sampling is None or not s.sampling.max_tokens for s in specs)
    result = asyncio.run(
        _token_runner(tmp_path, target).run(
            run_id="r1", target=make_target(), specs=specs, budgets=PlanBudgets(max_tokens=1200)
        )
    )
    assert result.spend.tokens <= 1200
    assert target.sends < 4


def test_the_unused_part_of_a_reservation_is_released(tmp_path: Path) -> None:
    target = _Billed(tokens=100)
    result = asyncio.run(
        _token_runner(tmp_path, target, concurrency=1).run(
            run_id="r1",
            target=make_target(),
            specs=[make_spec()],
            budgets=PlanBudgets(max_tokens=5000),
        )
    )
    assert result.spend.tokens == 100


def test_a_ceiling_below_the_default_estimate_still_lets_a_send_through() -> None:
    """Unclamped, a 513-token default estimate refused every send under a smaller ceiling."""

    ledger = BudgetLedger(max_tokens=100)
    target = _Billed(tokens=42)
    asyncio.run(
        execute_attempt(
            target,  # type: ignore[arg-type]
            ModelRequest(prompt="hi"),
            attempt_id="a1",
            spec_id="S-1",
            mutation="identity",
            sampling=None,
            ledger=ledger,
            sleep=no_sleep,
            now=lambda: 0.0,
        )
    )
    assert ledger.snapshot().tokens == 42


# --- -sV probes: every send metered, retries included (block 4 leftover) ------------------


class _FlakyProbeTarget:
    """Fails every first try of a probe with an environment error, answers the retry."""

    id = "live"

    def __init__(self) -> None:
        self.sends = 0

    async def send(self, request: ModelRequest) -> ModelResponse:
        from ildottore.adapters.base import AdapterEnvError

        self.sends += 1
        if self.sends % 2:
            raise AdapterEnvError("HTTP 429")
        return ModelResponse(text=f"answer {self.sends}")

    def capabilities(self) -> Capabilities:
        return Capabilities()


def test_every_probe_send_is_counted_and_recorded_retries_included(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """17 nominal probes were 34 requests on a target answering 429 to every first try: the
    live probe adapter retried inside one pacer slot and the ledger was charged 17."""

    from ildottore.cli import wiring
    from ildottore.shared.models import Target

    flaky = _FlakyProbeTarget()
    seen: dict[str, object] = {}

    def _probe_adapter(*_a: object, **kw: object) -> _FlakyProbeTarget:
        seen.update(kw)
        return flaky

    monkeypatch.setattr(wiring, "build_probe_adapter", _probe_adapter)
    monkeypatch.setattr("ildottore.core.execute.RetryPolicy.delay_for", _no_delay)
    store = FsEvidenceStore(tmp_path / "ev")
    result = wiring.fingerprint_probe(
        None,  # type: ignore[arg-type]
        Target(id="live", type="chatbot"),  # type: ignore[arg-type]
        evidence=store,
        run_id="run-abc123def456",
    )
    probes = list((tmp_path / "ev" / "run-abc123def456" / "probes").glob("*.json"))
    assert seen["retry"] is wiring.NO_ADAPTER_RETRIES, "the adapter's own retries are off"
    assert result.requests == flaky.sends == len(probes)
    assert flaky.sends > wiring_probe_count()


def test_a_probe_pass_past_the_request_ceiling_stops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.cli import wiring
    from ildottore.shared.models import Target

    flaky = _FlakyProbeTarget()
    monkeypatch.setattr(wiring, "build_probe_adapter", lambda *_a, **_k: flaky)
    monkeypatch.setattr("ildottore.core.execute.RetryPolicy.delay_for", _no_delay)
    with pytest.raises(wiring.ProbeCeilingReached) as reached:
        wiring.fingerprint_probe(
            None,  # type: ignore[arg-type]
            Target(id="live", type="chatbot"),  # type: ignore[arg-type]
            max_requests=20,
        )
    assert flaky.sends == 20 == reached.value.requests


def _no_delay(_self: object, _index: int) -> float:
    return 0.0


def wiring_probe_count() -> int:
    from ildottore.cli.run import fingerprint_probe_count

    return fingerprint_probe_count()


# --- run timestamps and live latency -----------------------------------------------------


def test_a_run_records_when_it_started_and_finished(tmp_path: Path) -> None:
    """No caller ever filled `started_at` / `finished_at`: every report and run row said null."""

    stamps = iter(["2026-10-04T15:00:00Z", "2026-10-04T15:00:09Z"])
    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=build_mutators(discover=False),
        evaluators=build_evaluators(discover=False),
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev"),
        run_store=SqliteRunStore(tmp_path / "runs.sqlite"),
        adapter_factory=lambda _t, _s: _Billed(tokens=10),  # type: ignore[arg-type,return-value]
        n=1,
        sleep=no_sleep,
        now=lambda: 0.0,
        timestamp=stamps.__next__,
    )
    result = asyncio.run(runner.run(run_id="r1", target=make_target(), specs=[make_spec()]))
    assert (result.run.started_at, result.run.finished_at) == (
        "2026-10-04T15:00:00Z",
        "2026-10-04T15:00:09Z",
    )
    row = SqliteRunStore(tmp_path / "runs.sqlite").get_run("r1")
    assert row is not None and row["started_at"] == "2026-10-04T15:00:00Z"


def test_a_cli_report_carries_iso_timestamps(tmp_path: Path) -> None:
    import json
    import re

    from typer.testing import CliRunner

    from ildottore.cli.app import app

    scope = tmp_path / "scope.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    target = tmp_path / "target.yaml"
    target.write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: hardened\n"
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    out = tmp_path / "r.json"
    CliRunner().invoke(
        app,
        [
            "run", "-t", str(target), "--scope", str(scope), "--spec", "PI-DIRECT-001",
            "--evidence-root", str(tmp_path / "ev"), "--run-db", str(tmp_path / "runs.sqlite"),
            "-oJ", str(out),
        ],
    )  # fmt: skip
    run = json.loads(out.read_text())["run"]
    iso = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    assert iso.match(run["started_at"]) and iso.match(run["finished_at"])
    assert run["started_at"] <= run["finished_at"]


def test_a_live_route_measures_latency_with_a_real_clock(tmp_path: Path) -> None:
    """The deterministic counter (1.0 per read) was wired on live routes too, so a 1 ms
    loopback reply was stored as 2000.0 or 4000.0 milliseconds."""

    import time

    from ildottore.cli import wiring
    from ildottore.shared.models import Target

    scope = wiring.build_scope(_write_live_scope(tmp_path))
    live = Target(  # type: ignore[call-arg]
        id="live",
        type="chatbot",
        provider="openai",
        endpoint="http://127.0.0.1:9/v1/chat/completions",
        model="m",
    )
    built = wiring.build_runner(
        scope=scope,
        specs=[],
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
        real_target=live,
    )
    assert built.runner._now is time.monotonic
    offline = wiring.build_runner(
        scope=scope, specs=[], evidence_root=tmp_path / "ev2", run_db=tmp_path / "r2.sqlite"
    )
    assert offline.runner._now is not time.monotonic


def _write_live_scope(tmp_path: Path) -> Path:
    scope = tmp_path / "live-scope.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n  - id: live\n    base_url: "http://127.0.0.1:9/v1"\n'
        '    endpoints:\n      - host: "127.0.0.1:9"\n        path_prefixes: ["/v1"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    return scope


def test_the_no_judge_warning_counts_what_will_run() -> None:
    """It said "74 of 75 selected specs" beside a plan of 34: the 41 skipped or blocked specs
    are inconclusive with or without a judge."""

    from typer.testing import CliRunner

    from ildottore.cli.app import app

    repo = Path(__file__).resolve().parents[1]
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(repo / "examples" / "target.local.yaml"),
            "--scope",
            str(repo / "examples" / "scope.local.yaml"),
            "--dry-run",
            "--no-color",
        ],
    )
    text = " ".join(result.output.split())
    assert "33 of the 34 specs that will run on local-llama use semantic_judge" in text
    assert "34 specs selected" in text


# --- token accounting details (pre-commit audit of the leftovers) ------------------------


def _attempt_with(usage: dict[str, int], ledger: BudgetLedger, **kw: object) -> None:
    class Reply:
        id = "t1"
        sends = 0

        async def send(self, request: ModelRequest) -> ModelResponse:
            Reply.sends += 1
            return ModelResponse(text="ok", usage=usage)

        def capabilities(self) -> Capabilities:
            return Capabilities()

    asyncio.run(
        execute_attempt(
            Reply(),
            kw.pop("request", ModelRequest(prompt="hi")),  # type: ignore[arg-type]
            attempt_id="a1",
            spec_id="S-1",
            mutation="identity",
            sampling=None,
            ledger=ledger,
            sleep=no_sleep,
            now=lambda: 0.0,
        )
    )


@pytest.mark.parametrize(
    "usage",
    [
        {"input_tokens": 10, "output_tokens": 1024},  # Anthropic reports no total
        {"prompt_tokens": 10, "completion_tokens": 1024},
        {"total_tokens": 1034},
    ],
)
def test_the_reported_usage_is_recorded_exactly_in_either_shape(usage: dict[str, int]) -> None:
    """Anthropic's replies were never trued up: 1034 billed, the 513 reserved recorded."""

    ledger = BudgetLedger(max_tokens=100_000)
    _attempt_with(usage, ledger)
    assert ledger.snapshot().tokens == 1034


def test_a_nonsense_usage_leaves_the_reservation_standing() -> None:
    ledger = BudgetLedger(max_tokens=100_000)
    _attempt_with({"total_tokens": -5}, ledger)
    assert ledger.snapshot().tokens == reserve_tokens(ModelRequest(prompt="hi"), None)


def test_the_reservation_counts_conversation_messages() -> None:
    request = ModelRequest(messages=[{"role": "user", "content": "x" * 400}])
    assert reserve_tokens(request, None) == 100 + DEFAULT_COMPLETION_TOKENS


def test_remaining_tokens() -> None:
    ledger = BudgetLedger(max_tokens=100)
    ledger.debit_request(tokens=30)
    assert ledger.remaining_tokens() == 70
    assert BudgetLedger().remaining_tokens() is None


def test_an_undecodable_reply_is_sent_once_by_the_runner_too() -> None:
    from ildottore.adapters.base import ResponseUndecodable
    from ildottore.core.execute import RetryPolicy

    class Undecodable:
        id = "t1"
        sends = 0

        async def send(self, request: ModelRequest) -> ModelResponse:
            Undecodable.sends += 1
            raise ResponseUndecodable("br, not decoded")

        def capabilities(self) -> Capabilities:
            return Capabilities()

    result = asyncio.run(
        execute_attempt(
            Undecodable(),
            ModelRequest(prompt="hi"),
            attempt_id="a1",
            spec_id="S-1",
            mutation="identity",
            sampling=None,
            ledger=BudgetLedger(),
            retry=RetryPolicy(max_retries=3),
            sleep=no_sleep,
            now=lambda: 0.0,
        )
    )
    assert result.env_error and Undecodable.sends == 1


# --- probe pacing, probe spend and resume (pre-commit audit of the leftovers) ------------


def test_every_probe_send_passes_the_rate_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.cli import wiring
    from ildottore.shared.models import Target

    acquired: list[float | None] = []

    class CountingLimiter:
        def __init__(self, rate_rps: float | None) -> None:
            self.rate = rate_rps

        async def acquire(self) -> None:
            acquired.append(self.rate)

    flaky = _FlakyProbeTarget()
    monkeypatch.setattr(wiring, "build_probe_adapter", lambda *_a, **_k: flaky)
    monkeypatch.setattr(wiring, "RateLimiter", CountingLimiter)
    monkeypatch.setattr("ildottore.core.execute.RetryPolicy.delay_for", _no_delay)
    wiring.fingerprint_probe(
        None,  # type: ignore[arg-type]
        Target(id="live", type="chatbot"),  # type: ignore[arg-type]
        rate_rps=2.0,
    )
    assert len(acquired) == flaky.sends and set(acquired) == {2.0}


def _probe_returning(requests: int, calls: list[dict[str, object]]):  # type: ignore[no-untyped-def]
    from ildottore.cli import wiring
    from ildottore.shared.models import FingerprintGuess, ModelFingerprint

    def probe(_scope: object, target: object, **kw: object) -> wiring.ProbePass:
        calls.append(kw)
        fingerprint = ModelFingerprint(
            target_id=getattr(target, "id", "?"),
            family=FingerprintGuess(guess="unknown", confidence=0.0),
        )
        return wiring.ProbePass(fingerprint=fingerprint, requests=requests)

    return probe


def test_the_real_probe_count_is_charged_to_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.cli import wiring
    from ildottore.cli.run import execute_run
    from tests.cli.conftest import make_spec as cli_spec
    from tests.cli.conftest import write_scope, write_spec_tree, write_target
    from tests.cli.test_resume_cmd import _opts

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(wiring, "fingerprint_probe", _probe_returning(23, calls))
    target = write_target(tmp_path, mock_scenario="vulnerable")
    specs = write_spec_tree(tmp_path, [cli_spec("PI-DIRECT-001")])
    opts = _opts(tmp_path, target, write_scope(tmp_path), fingerprint_first=True, runs=1)
    outcome = execute_run(opts, [specs])
    attempts = sum(len(f.attempts) for f in outcome.findings)
    assert outcome.results[0].spend.requests == 23 + attempts


def test_a_resumed_probe_pass_at_the_ceiling_records_what_it_spent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each retry of the same `--resume -sV` spent the ceiling again: 60 allowed, 106 sent."""

    from ildottore.cli import wiring
    from ildottore.cli.exit_codes import ExitCode
    from ildottore.cli.run import execute_run
    from ildottore.store.run_sqlite import SqliteRunStore
    from tests.cli.conftest import make_spec as cli_spec
    from tests.cli.conftest import write_scope, write_spec_tree, write_target
    from tests.cli.test_resume_cmd import _opts

    # A halted -sV run first (the resume must keep its planning mode): 17 probes, then the
    # request ceiling stops the attack traffic.
    monkeypatch.setattr(wiring, "fingerprint_probe", _probe_returning(17, []))
    target = write_target(tmp_path, mock_scenario="vulnerable")
    specs = [write_spec_tree(tmp_path, [cli_spec(f"PI-DIRECT-{i:03d}") for i in range(1, 5)])]
    opts = _opts(
        tmp_path,
        target,
        write_scope(tmp_path),
        fingerprint_first=True,
        budget_requests=21,
        concurrency=1,
    )
    assert execute_run(opts, specs).exit_code is ExitCode.ERROR
    run_id = next(p.name for p in (tmp_path / "ev").iterdir() if (p / "attempts").is_dir())
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        before = store.get_run_spend(run_id) or {}
    calls: list[dict[str, object]] = []

    def at_ceiling(_scope: object, _target: object, **kw: object) -> wiring.ProbePass:
        calls.append(kw)
        raise wiring.ProbeCeilingReached(5, "requests ceiling")

    monkeypatch.setattr(wiring, "fingerprint_probe", at_ceiling)
    opts.resume = run_id
    opts.budget_requests = int(before["requests"]) + 30
    with pytest.raises(ValueError, match=r"probe pass .* reached the --budget-requests ceiling"):
        execute_run(opts, specs)
    assert calls[0]["max_requests"] == 30, "the ceiling left after the prior spend"
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        after = store.get_run_spend(run_id) or {}
    assert after["requests"] == before["requests"] + 5


def test_a_resume_keeps_the_start_of_the_run_it_finishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from itertools import count

    from ildottore.cli import wiring
    from ildottore.cli.run import execute_run
    from ildottore.store.run_sqlite import SqliteRunStore
    from tests.cli.test_resume_cmd import _truncate_a_run

    ticks = count()
    monkeypatch.setattr(wiring, "utc_timestamp", lambda: f"2026-10-04T15:00:{next(ticks):02d}Z")
    opts, specs, run_id = _truncate_a_run(tmp_path)
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        started = (store.get_run(run_id) or {})["started_at"]
    assert started
    opts.resume = run_id
    opts.budget_requests = None
    outcome = execute_run(opts, specs)
    assert outcome.results[0].run.started_at == started


def test_invalid_utf8_gets_an_answer_not_an_exception() -> None:
    assert _ALLOWLIST.is_allowed("http://127.0.0.1:18081/v1/chat/%80x") is True


@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        ({"tokens": 700}, 700),  # a REST template's single figure
        ({"total_tokens": 9, "tokens": 700}, 9),  # the total wins
        (
            {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_creation_input_tokens": 3000,
                "cache_read_input_tokens": 5000,
            },
            8030,
        ),
        ({"tools": 2, "resources": 1, "prompts": 0, "total_tokens": 0}, 0),  # MCP discovery
    ],
)
def test_other_usage_shapes_are_recorded(usage: dict[str, int], expected: int) -> None:
    ledger = BudgetLedger(max_tokens=100_000)
    _attempt_with(usage, ledger)
    assert ledger.snapshot().tokens == expected


def test_a_fresh_probe_pass_at_the_ceiling_exits_3_and_records_no_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.cli import wiring
    from ildottore.cli.run import execute_run
    from tests.cli.conftest import make_spec as cli_spec
    from tests.cli.conftest import write_scope, write_spec_tree, write_target
    from tests.cli.test_resume_cmd import _opts

    def at_ceiling(_scope: object, _target: object, **kw: object) -> wiring.ProbePass:
        raise wiring.ProbeCeilingReached(20, "requests ceiling")

    monkeypatch.setattr(wiring, "fingerprint_probe", at_ceiling)
    target = write_target(tmp_path, mock_scenario="vulnerable")
    specs = [write_spec_tree(tmp_path, [cli_spec("PI-DIRECT-001")])]
    opts = _opts(tmp_path, target, write_scope(tmp_path), fingerprint_first=True)
    opts.budget_requests = 20
    with pytest.raises(ValueError, match=r"after 20 request\(s\)") as refused:
        execute_run(opts, specs)
    run_id = next((tmp_path / "ev").iterdir()).name if (tmp_path / "ev").exists() else None
    assert re.search(r"[/\\]ev[/\\]run-[0-9a-f]{12}[/\\]probes", str(refused.value))
    db = tmp_path / "runs.sqlite"
    rows = 0
    if db.exists():
        conn = sqlite3.connect(db)
        try:
            rows = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        finally:
            conn.close()
    assert rows == 0, f"no run row for a run that never started ({run_id})"


def test_the_recorded_start_precedes_the_probe_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runner stamped the start after the -sV probes: 66 s of traffic before it."""

    from itertools import count

    from ildottore.cli import wiring
    from ildottore.cli.run import execute_run
    from tests.cli.conftest import make_spec as cli_spec
    from tests.cli.conftest import write_scope, write_spec_tree, write_target
    from tests.cli.test_resume_cmd import _opts

    ticks = count()
    monkeypatch.setattr(wiring, "utc_timestamp", lambda: f"2026-10-04T15:00:{next(ticks):02d}Z")
    probe = _probe_returning(17, [])

    def slow_probe(scope: object, target: object, **kw: object) -> wiring.ProbePass:
        wiring.utc_timestamp()  # time passes while probing
        return probe(scope, target, **kw)  # type: ignore[no-any-return]

    monkeypatch.setattr(wiring, "fingerprint_probe", slow_probe)
    target = write_target(tmp_path, mock_scenario="vulnerable")
    specs = [write_spec_tree(tmp_path, [cli_spec("PI-DIRECT-001")])]
    opts = _opts(tmp_path, target, write_scope(tmp_path), fingerprint_first=True, runs=1)
    outcome = execute_run(opts, specs)
    assert outcome.results[0].run.started_at == "2026-10-04T15:00:00Z"


@pytest.mark.parametrize("fingerprint_first", [False, True])
def test_each_target_records_its_own_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fingerprint_first: bool
) -> None:
    """One stamp shared by every target put the second target's start before the first had
    run (pre-commit audit of the leftovers)."""

    from itertools import count

    from ildottore.cli import wiring
    from ildottore.cli.run import RunOptions, execute_run
    from tests.cli.conftest import make_spec as cli_spec
    from tests.cli.conftest import write_spec_tree

    ticks = count()
    monkeypatch.setattr(wiring, "utc_timestamp", lambda: f"2026-10-04T15:00:{next(ticks):02d}Z")
    scope = tmp_path / "scope.yaml"
    entries = "".join(
        f'  - id: {t}\n    base_url: "mock://{t}"\n    endpoints:\n      - host: "{t}"\n'
        '        path_prefixes: ["/"]\n    identities:\n      - name: default\n'
        '        auth_ref: "env://NONE"\n'
        for t in ("ta", "tb")
    )
    scope.write_text('version: "1.0"\ntargets:\n' + entries)
    targets = []
    for t in ("ta", "tb"):
        path = tmp_path / f"{t}.yaml"
        path.write_text(f"id: {t}\ntype: chatbot\nmock_scenario: vulnerable\n")
        targets.append(path)
    specs = write_spec_tree(tmp_path, [cli_spec("PI-DIRECT-001")])
    opts = RunOptions(
        targets=targets,
        scope=scope,
        runs=1,
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
        fingerprint_first=fingerprint_first,
    )
    outcome = execute_run(opts, [specs])
    first, second = (r.run for r in outcome.results)
    assert first.finished_at is not None and second.started_at is not None
    # Under -sV every probe pass runs before the first battery, so the second target's run
    # starts (its probes) before the first one finishes; it still starts after the first.
    assert second.started_at > (first.started_at if fingerprint_first else first.finished_at)


def test_a_resume_with_sv_keeps_the_start_of_the_run_it_finishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The -sV loop stamps each target's start; a resume must keep the stored one."""

    from itertools import count

    from ildottore.cli import wiring
    from ildottore.cli.run import execute_run, fingerprint_probe_count
    from tests.cli.conftest import make_spec as cli_spec
    from tests.cli.conftest import write_scope, write_spec_tree, write_target
    from tests.cli.test_resume_cmd import _opts

    ticks = count()
    monkeypatch.setattr(wiring, "utc_timestamp", lambda: f"2026-10-04T15:00:{next(ticks):02d}Z")
    target = write_target(tmp_path, mock_scenario="vulnerable")
    specs = [write_spec_tree(tmp_path, [cli_spec(f"PI-DIRECT-{i:03d}") for i in range(1, 5)])]
    opts = _opts(tmp_path, target, write_scope(tmp_path), fingerprint_first=True, concurrency=1)
    opts.budget_requests = fingerprint_probe_count() + 4
    halted = execute_run(opts, specs).results[0].run
    assert halted.started_at == "2026-10-04T15:00:00Z"
    opts.resume = halted.run_id
    opts.budget_requests = None
    outcome = execute_run(opts, specs)
    assert outcome.results[0].run.started_at == halted.started_at


# --- hygiene block: spend recorded however a campaign stops ---------------------------------


def test_a_campaign_interrupted_while_sending_records_its_spend(tmp_path: Path) -> None:
    """Ctrl-C during a send left the spend unrecorded, so a resume's ceiling under-counted it."""

    recorded: list[object] = []

    class Interrupting(_Billed):
        async def send(self, request: ModelRequest) -> ModelResponse:
            self.sends += 1
            if self.sends == 3:
                raise KeyboardInterrupt
            return ModelResponse(text="I cannot help with that.", usage={"total_tokens": 10})

    runner = CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=build_mutators(discover=False),
        evaluators=build_evaluators(discover=False),
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev"),
        run_store=SqliteRunStore(tmp_path / "runs.sqlite"),
        adapter_factory=lambda _t, _s: Interrupting(tokens=10),  # type: ignore[arg-type,return-value]
        n=5,
        concurrency=1,
        sleep=no_sleep,
        now=lambda: 0.0,
        spend_sink=recorded.append,
    )
    with pytest.raises(KeyboardInterrupt):
        asyncio.run(runner.run(run_id="r1", target=make_target(), specs=[make_spec()]))
    assert len(recorded) == 1
    assert recorded[0].requests == 3  # type: ignore[attr-defined]


def test_the_cli_closes_the_run_store_it_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.cli import wiring
    from ildottore.cli.run import execute_run
    from tests.cli.conftest import make_spec as cli_spec
    from tests.cli.conftest import write_scope, write_spec_tree, write_target
    from tests.cli.test_resume_cmd import _opts

    closed: list[bool] = []
    original = wiring.BuiltRunner.close

    def spy(self: wiring.BuiltRunner) -> None:
        closed.append(True)
        original(self)

    stores: list[object] = []

    def spy_store(self: wiring.BuiltRunner) -> None:
        stores.append(self.run_store)
        spy(self)

    monkeypatch.setattr(wiring.BuiltRunner, "close", spy_store)
    target = write_target(tmp_path, mock_scenario="vulnerable")
    specs = [write_spec_tree(tmp_path, [cli_spec("PI-DIRECT-001")])]
    execute_run(_opts(tmp_path, target, write_scope(tmp_path), runs=1), specs)
    assert closed == [True]
    store = stores[0]
    assert store is not None, "the runner's store is handed to BuiltRunner"
    with pytest.raises(sqlite3.ProgrammingError):
        store._conn.execute("SELECT 1")  # type: ignore[attr-defined]  # closed


# --- hygiene block: CLI errors keep the operator's own paths readable -------------------------


def test_a_cli_error_keeps_an_existing_dated_directory_readable(tmp_path: Path) -> None:
    """The phone rule read the dashed clock of `...-2026-07-09-13-20-51-...` as a number; the
    masked token no longer existed on disk, so the whole path went to the entropy rule."""

    from ildottore.cli.app import _masked

    stamped = tmp_path / "export-2026-07-09-13-20-51-ff1bc959c022456f8cd065c7172c9e98"
    stamped.mkdir()
    assert str(stamped) in _masked(ValueError(f"{stamped}/r.json is not a directory"))


def test_a_cli_error_keeps_an_existing_path_readable(tmp_path: Path) -> None:
    """A temp or CI workspace path read `«REDACTED:high_entropy»` in the report-path errors."""

    import hashlib

    from ildottore.cli.app import _masked

    workspace = tmp_path / "x9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0"
    workspace.mkdir()
    shown = _masked(ValueError(f"cannot write the report {workspace}/out/r.json"))
    assert str(workspace) in shown
    key = hashlib.sha256(b"a key in a path").hexdigest()
    shown = _masked(ValueError(f"cannot write {workspace}/{key}/r.json"))
    assert str(workspace) in shown and key not in shown, "only what exists is kept"
    url_pw = hashlib.sha256(b"a url password").hexdigest()
    shown = _masked(ValueError(f"bad endpoint http://bob:{url_pw}@127.0.0.1{workspace}"))
    assert url_pw not in shown
    for url in (f"http://127.0.0.1{workspace}/v1", f"http://[::1]{workspace}/v1"):
        assert str(workspace) not in _masked(ValueError(f"bad endpoint {url}")), (
            "a URL's path is not a filesystem path"
        )


def test_a_kept_path_still_goes_through_every_rule_but_entropy(tmp_path: Path) -> None:
    """Keeping a path raw skipped the email and key-shape rules too."""

    from ildottore.cli.app import _masked

    mail = tmp_path / "GoogleDrive-john.doe@example.com"
    mail.mkdir()
    shown = _masked(ValueError(f"cannot write {mail}/r.json"))
    assert "john.doe@example.com" not in shown and str(tmp_path) in shown


def test_the_not_exercised_line_names_network_failures_too() -> None:
    """It said "produced no request" for a spec whose every send failed on the network."""

    from ildottore.cli.render import coverage_lines
    from ildottore.shared.models import Attempt
    from tests.reporting.conftest import make_finding

    spec = make_spec("JB-REFUSAL-001")
    failed = Attempt(
        attempt_id="a1", spec_id=spec.id, request=ModelRequest(prompt="x"), error="ConnectError"
    )
    finding = make_finding(spec.id).model_copy(update={"attempts": [failed]})
    text = " ".join(coverage_lines([finding], {spec.id: spec}))
    assert "got no reply that could be scored" in text
    assert "every send ended in an environment error" in text


def test_the_dry_run_names_a_filtered_selection_and_counts_per_target(tmp_path: Path) -> None:
    """It said "full battery" for `--spec PI-*` and summed the selection across targets."""

    from typer.testing import CliRunner

    from ildottore.cli.app import app

    entries = "".join(
        f'  - id: {t}\n    base_url: "mock://{t}"\n    endpoints:\n      - host: "{t}"\n'
        '        path_prefixes: ["/"]\n    identities:\n      - name: default\n'
        '        auth_ref: "env://NONE"\n'
        for t in ("ta", "tb")
    )
    (tmp_path / "scope.yaml").write_text('version: "1.0"\ntargets:\n' + entries)
    args = ["run", "--scope", str(tmp_path / "scope.yaml"), "--dry-run", "--no-color"]
    for t, tools in (("ta", "false"), ("tb", "true")):
        (tmp_path / f"{t}.yaml").write_text(
            f"id: {t}\ntype: chatbot\nmock_scenario: vulnerable\ncapabilities:\n  tools: {tools}\n"
        )
        args += ["-t", str(tmp_path / f"{t}.yaml")]
    full = " ".join(CliRunner().invoke(app, args).output.split())
    assert "battery: full battery," in full and "specs selected per target" in full
    counts = full.split("battery: full battery, ")[1].split(" specs selected")[0]
    assert len(set(counts.split(", "))) == 2, "two targets with different capabilities"
    filtered = " ".join(CliRunner().invoke(app, [*args, "--spec", "PI-DIRECT-001"]).output.split())
    assert "battery: filtered selection, 1, 1 specs selected per target" in filtered
    by_category = " ".join(CliRunner().invoke(app, [*args, "-p", "pi"]).output.split())
    assert "battery: filtered selection," in by_category


def test_a_failure_to_record_the_spend_is_a_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from ildottore.cli.run import _record_spend_quietly
    from ildottore.core.budgets import Spend

    blocked = tmp_path / "file"
    blocked.write_text("not a directory")
    _record_spend_quietly(blocked / "runs.sqlite", "run-x", Spend(requests=3))
    assert "could not be recorded" in capsys.readouterr().err


def test_the_fail_on_error_lists_info() -> None:
    from ildottore.cli.exit_codes import fail_on_band

    with pytest.raises(ValueError, match="expected one of: info, low"):
        fail_on_band("bogus")


# --- second audit of the hygiene block -------------------------------------------------------


@pytest.mark.skipif(not hasattr(__import__("signal"), "SIGHUP"), reason="POSIX signals")
def test_sigterm_and_sighup_become_an_interrupt_and_are_restored() -> None:
    import signal

    from ildottore.cli.run import _termination_as_interrupt

    def custom(_signum: int, _frame: object) -> None:
        return None

    before_term = signal.signal(signal.SIGTERM, custom)
    before_hup = signal.signal(signal.SIGHUP, custom)
    try:
        with _termination_as_interrupt():
            assert signal.getsignal(signal.SIGTERM) is signal.default_int_handler
            assert signal.getsignal(signal.SIGHUP) is signal.default_int_handler
        assert signal.getsignal(signal.SIGTERM) is custom
        assert signal.getsignal(signal.SIGHUP) is custom
    finally:
        signal.signal(signal.SIGTERM, before_term)
        signal.signal(signal.SIGHUP, before_hup)


@pytest.mark.skipif(not hasattr(__import__("signal"), "SIGHUP"), reason="POSIX signals")
def test_an_ignored_hangup_stays_ignored() -> None:
    """`nohup dottore run` aborted on logout once SIGHUP was mapped regardless."""

    import signal

    from ildottore.cli.run import _termination_as_interrupt

    before = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        with _termination_as_interrupt():
            assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, before)


def test_an_interrupted_campaign_whose_spend_cannot_be_written_still_raises_the_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A locked database replaced a Ctrl-C with an OperationalError traceback."""

    from ildottore.cli import run as run_mod
    from tests.cli.conftest import make_spec as cli_spec
    from tests.cli.conftest import write_scope, write_spec_tree, write_target
    from tests.cli.test_resume_cmd import _opts

    def locked(*_a: object, **_k: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    async def interrupted(self: object, **_k: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(run_mod, "_persist_spend", locked)
    monkeypatch.setattr(CampaignRunner, "_run_selected", interrupted)
    target = write_target(tmp_path, mock_scenario="vulnerable")
    specs = [write_spec_tree(tmp_path, [cli_spec("PI-DIRECT-001")])]
    with pytest.raises(KeyboardInterrupt):
        run_mod.execute_run(_opts(tmp_path, target, write_scope(tmp_path), runs=1), specs)
    assert "could not be recorded" in capsys.readouterr().err


def test_a_path_longer_than_path_max_is_not_walked(tmp_path: Path) -> None:
    from ildottore.cli.app import _existing_prefixes

    token = str(tmp_path) + "/x" * 2100
    assert len(token) > 4096
    assert _existing_prefixes(f"cannot write {token}") == []
    assert _existing_prefixes(f"cannot write {tmp_path}/x") == [str(tmp_path)]


def test_an_interrupted_report_write_leaves_no_truncated_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ildottore.cli import run as run_mod
    from tests.cli.conftest import make_spec as cli_spec
    from tests.cli.conftest import write_scope, write_spec_tree, write_target
    from tests.cli.test_resume_cmd import _opts

    real_replace = run_mod.os.replace

    def fail(source: object, target: object) -> None:
        if str(source).endswith(".partial"):  # only the report write, not the evidence store
            raise OSError("interrupted")
        real_replace(source, target)  # type: ignore[arg-type]

    monkeypatch.setattr(run_mod.os, "replace", fail)
    target = write_target(tmp_path, mock_scenario="vulnerable")
    specs = [write_spec_tree(tmp_path, [cli_spec("PI-DIRECT-001")])]
    opts = _opts(tmp_path, target, write_scope(tmp_path), runs=1)
    opts.outputs = {"json": tmp_path / "r.json"}
    with pytest.raises(OSError, match="interrupted"):
        run_mod.execute_run(opts, specs)
    assert not (tmp_path / "r.json").exists(), "never a half-written report under its name"
    assert not list(tmp_path.glob(".*.partial")), "the partial file is removed on failure"


def test_the_atomic_report_write_keeps_links_and_modes_and_falls_back(tmp_path: Path) -> None:
    import os
    import stat

    from ildottore.cli.run import _write_atomically

    real = tmp_path / "real.json"
    real.write_text("old")
    os.chmod(real, 0o600)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    _write_atomically(link, b"new")
    assert link.is_symlink() and real.read_bytes() == b"new", "written through the link"
    assert stat.S_IMODE(real.stat().st_mode) == 0o600, "the permission bits are kept"

    locked = tmp_path / "ro"
    locked.mkdir()
    report = locked / "r.json"
    report.write_text("old")
    os.chmod(locked, 0o500)
    try:
        _write_atomically(report, b"new")
    finally:
        os.chmod(locked, 0o700)
    assert report.read_bytes() == b"new", "a read-only directory falls back to a direct write"


def test_the_spend_warning_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import hashlib

    from ildottore.cli import run as run_mod
    from ildottore.core.budgets import Spend

    secret = hashlib.sha256(b"a key in an error").hexdigest()

    def leaky(*_a: object, **_k: object) -> None:
        raise sqlite3.OperationalError(f"token={secret}")

    monkeypatch.setattr(run_mod, "_persist_spend", leaky)
    run_mod._record_spend_quietly(tmp_path / "runs.sqlite", "run-x", Spend(requests=1))
    err = capsys.readouterr().err
    assert "could not be recorded" in err and secret not in err


def test_every_surface_names_both_reasons_a_spec_was_not_exercised() -> None:
    from ildottore.cli.render import coverage_lines
    from ildottore.shared.enums import ReportFormat
    from ildottore.shared.models import Attempt
    from tests.reporting.conftest import make_finding, make_run

    spec = make_spec("JB-REFUSAL-001")
    failed = Attempt(
        attempt_id="a1", spec_id=spec.id, request=ModelRequest(prompt="x"), error="ResponseTooLarge"
    )
    finding = make_finding(spec.id).model_copy(update={"attempts": [failed]})
    terminal = " ".join(coverage_lines([finding], {spec.id: spec}))
    assert "a reply over the size cap" in terminal and "could not be decoded" in terminal
    from ildottore.cli import wiring

    reporter = wiring.build_reporter(ReportFormat.HTML, specs={spec.id: spec})
    html = reporter.render(make_run(findings=[finding]), [finding])
    text = " ".join(html.decode().split())
    assert "got no reply that could be scored" in text
    assert "every send ended in an environment error" in text


def test_a_failed_partial_write_leaves_the_previous_report_and_no_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from ildottore.cli import run as run_mod

    report = tmp_path / "r.json"
    report.write_bytes(b"PREVIOUS")
    real_fdopen = os.fdopen

    class Half:
        def __init__(self, handle: object) -> None:
            self.handle = handle

        def __enter__(self) -> Half:
            return self

        def __exit__(self, *_exc: object) -> None:
            self.handle.close()  # type: ignore[attr-defined]

        def write(self, data: bytes) -> None:
            self.handle.write(data[: len(data) // 2])  # type: ignore[attr-defined]
            raise KeyboardInterrupt

    monkeypatch.setattr(run_mod.os, "fdopen", lambda fd, mode: Half(real_fdopen(fd, mode)))
    with pytest.raises(KeyboardInterrupt):
        run_mod._write_atomically(report, b"NEW REPORT CONTENT")
    assert report.read_bytes() == b"PREVIOUS"
    assert not list(tmp_path.glob(".*.partial"))


def test_a_planted_symlink_at_the_partial_name_is_not_followed(tmp_path: Path) -> None:
    from ildottore.cli.run import _write_atomically

    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    (tmp_path / ".r.json.partial").symlink_to(victim)
    _write_atomically(tmp_path / "r.json", b"REPORT")
    assert victim.read_text() == "untouched"
    assert (tmp_path / "r.json").read_bytes() == b"REPORT"
    assert not (tmp_path / "r.json").is_symlink()


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="POSIX FIFOs")
def test_a_fifo_report_path_is_written_in_place(tmp_path: Path) -> None:
    import os
    import threading

    from ildottore.cli.run import _write_atomically

    fifo = tmp_path / "pipe.json"
    os.mkfifo(fifo)
    received: list[bytes] = []
    reader = threading.Thread(target=lambda: received.append(fifo.read_bytes()), daemon=True)
    reader.start()
    _write_atomically(fifo, b"REPORT")
    reader.join(timeout=10)
    assert received == [b"REPORT"]
    assert fifo.is_fifo(), "the pipe is kept, not replaced by a regular file"


def test_a_symlink_planted_between_the_unlink_and_the_open_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exclusive, no-follow open is what guards the race the unlink cannot."""

    import os

    from ildottore.cli import run as run_mod

    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    real_open = run_mod.os.open

    def racing_open(path: object, flags: int, mode: int = 0o777) -> int:
        if str(path).endswith(".partial"):
            os.symlink(victim, path)  # planted after the unlink, before the open
        return real_open(path, flags, mode)  # type: ignore[arg-type]

    monkeypatch.setattr(run_mod.os, "open", racing_open)
    with pytest.raises(OSError):
        run_mod._write_atomically(tmp_path / "r.json", b"REPORT")
    assert victim.read_text() == "untouched"


def test_the_partial_of_a_private_report_is_never_wider_than_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Created with the umask mode, it was world-readable while it held the full report."""

    import os
    import stat

    from ildottore.cli import run as run_mod

    report = tmp_path / "r.json"
    report.write_text("old")
    os.chmod(report, 0o600)
    seen: list[int] = []
    real_fdopen = run_mod.os.fdopen

    def watch(descriptor: int, mode: str) -> object:
        seen.append(stat.S_IMODE(os.fstat(descriptor).st_mode))  # as created, before writing
        return real_fdopen(descriptor, mode)

    monkeypatch.setattr(run_mod.os, "fdopen", watch)
    run_mod._write_atomically(report, b"new")
    assert seen and seen[0] & 0o077 == 0, f"partial created as {oct(seen[0])}"
