"""Budget and rate: block 4 of the 2026-10-03 audit, one test per finding.

Threat model S8 and clauses A-5 and A-11: a declared ceiling binds every request the tool
makes, and every send passes the rate gate. The judge and the multi-identity sweep sent outside
both (F6 / F-7); retries were nested so one attempt was 12 wire requests billed as 4 (F10);
billed tokens went unrecorded and failed sends kept their reservation (F7 / F18); ``--rate 0``
switched pacing off (R8); and the tests that should have caught the first two only counted at
two leaf functions, or compared the store against itself (F-4 / F-16). F-15: a resume that
changes the judge or the planning mode had no test.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from ildottore.adapters.openai import OpenAIAdapter
from ildottore.cli.app import app
from ildottore.cli.wiring import NO_ADAPTER_RETRIES
from ildottore.core.budgets import BudgetLedger
from ildottore.core.execute import RetryPolicy, execute_attempt
from ildottore.core.metering import MeteredAdapter, SendMeter
from ildottore.core.pacing import RateLimiter
from ildottore.core.runner import CampaignRunner, IdentityProbe
from ildottore.evaluators import build_default_registry as build_evaluators
from ildottore.mutators import build_default_registry as build_mutators
from ildottore.policy import Endpoint, EndpointAllowlist
from ildottore.scoring import DefaultRiskScorer
from ildottore.shared.enums import EvaluatorType
from ildottore.shared.models import (
    Attack,
    Capabilities,
    ModelRequest,
    ModelResponse,
    PlanBudgets,
    Sampling,
)
from ildottore.store.evidence_fs import FsEvidenceStore
from ildottore.store.run_sqlite import SqliteRunStore
from tests.core.conftest import AllowAllPolicy, make_spec, make_target, no_sleep
from tests.evaluators.test_semantic_judge import _jv

REPO = Path(__file__).resolve().parents[1]


class CountingPacer(RateLimiter):
    def __init__(self) -> None:
        super().__init__(1.0)
        self.acquired = 0

    async def acquire(self) -> None:
        self.acquired += 1


class CountingTarget:
    """A deterministic target that counts every send."""

    def __init__(self, text: str = "I'm sorry, I can't help with that.", tid: str = "t1") -> None:
        self.id = tid
        self.sends = 0
        self._text = text

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        return ModelResponse(text=self._text, usage={"total_tokens": 10})

    def capabilities(self) -> Capabilities:
        return Capabilities()


class CountingJudge(CountingTarget):
    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        return ModelResponse(text=_jv("secure", 0.95))


def _runner(tmp_path: Path, target: CountingTarget, **kw: object) -> CampaignRunner:
    return CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=build_mutators(discover=False),
        evaluators=kw.pop("evaluators", build_evaluators(discover=False)),  # type: ignore[arg-type]
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev"),
        run_store=SqliteRunStore(tmp_path / "runs.sqlite"),
        adapter_factory=lambda _t, _s: target,
        n=2,
        concurrency=1,
        sleep=no_sleep,
        now=lambda: 0.0,
        **kw,  # type: ignore[arg-type]
    )


def _judged_spec(spec_id: str = "JB-JUDGED-001"):  # type: ignore[no-untyped-def]
    return make_spec(spec_id, evaluators=(EvaluatorType.REFUSAL, EvaluatorType.SEMANTIC_JUDGE))


# --- F6 / F-7: the judge and the identity sweep are inside the ceiling and the rate gate -----


def test_every_judge_send_is_debited_and_paced(tmp_path: Path) -> None:
    target, judge = CountingTarget(), CountingJudge(tid="judge")
    meter, pacer = SendMeter(), CountingPacer()
    runner = _runner(
        tmp_path,
        target,
        evaluators=build_evaluators(judge=MeteredAdapter(judge, meter), discover=False),
        send_meter=meter,
        pacer=pacer,
    )
    result = asyncio.run(runner.run(run_id="r1", target=make_target(), specs=[_judged_spec()]))
    assert judge.sends == 4, "two judge passes for each of the two attempts"
    assert result.spend.requests == target.sends + judge.sends == 6
    assert pacer.acquired == target.sends + judge.sends


def test_a_request_ceiling_binds_the_judge(tmp_path: Path) -> None:
    """`--budget-requests 5` sent 15 with a judge: the target's 5 and the judge's 10."""

    target, judge = CountingTarget(), CountingJudge(tid="judge")
    meter = SendMeter()
    runner = _runner(
        tmp_path,
        target,
        evaluators=build_evaluators(judge=MeteredAdapter(judge, meter), discover=False),
        send_meter=meter,
    )
    result = asyncio.run(
        runner.run(
            run_id="r1",
            target=make_target(),
            specs=[_judged_spec()],
            budgets=PlanBudgets(max_requests=3),
        )
    )
    assert result.run.summary is not None
    assert target.sends + judge.sends <= 3
    assert result.status == "budget_exhausted"


def _identity_runner(tmp_path: Path, probes: list[IdentityProbe], **kw: object) -> CampaignRunner:
    return _runner(tmp_path, CountingTarget(), identity_adapters=lambda _t: probes, **kw)


def _probes(n: int) -> tuple[list[IdentityProbe], list[CountingTarget]]:
    adapters = [CountingTarget(text=f"record of tenant {i}", tid=f"id-{i}") for i in range(n)]
    probes = [IdentityProbe(identity_id=a.id, adapter=a, canary=None) for a in adapters]
    return probes, adapters


def _xtenant():  # type: ignore[no-untyped-def]
    from tests.core.test_multi_identity import _xtenant_spec

    return _xtenant_spec()


def test_the_identity_sweep_is_inside_the_request_ceiling(tmp_path: Path) -> None:
    """Ten identities went out under a ceiling of two and the run reported complete."""

    probes, adapters = _probes(10)
    runner = _identity_runner(tmp_path, probes)
    from tests.core.test_multi_identity import _mi_target

    result = asyncio.run(
        runner.run(
            run_id="r1",
            target=_mi_target(),
            specs=[_xtenant()],
            budgets=PlanBudgets(max_requests=2),
        )
    )
    assert sum(a.sends for a in adapters) <= 2
    assert result.status == "budget_exhausted"


def test_a_resume_of_a_finished_spec_does_not_resend_the_identity_sweep(tmp_path: Path) -> None:
    from tests.core.test_multi_identity import _mi_target

    probes, adapters = _probes(2)
    first = asyncio.run(
        _identity_runner(tmp_path, probes).run(run_id="r1", target=_mi_target(), specs=[_xtenant()])
    )
    swept = sum(a.sends for a in adapters)
    assert swept == 2
    asyncio.run(
        _identity_runner(tmp_path, probes).run(
            run_id="r1", target=_mi_target(), specs=[_xtenant()], resume_from=first.run
        )
    )
    assert sum(a.sends for a in adapters) == swept, "nothing left to evaluate, nothing re-sent"


# --- F-4: the rate gate is counted at the sink, through the whole runner ----------------------


def test_every_runner_send_passes_the_rate_gate(tmp_path: Path) -> None:
    """Single-turn and multi-turn specs through `CampaignRunner.run`, counted at the adapter.
    The suite used to drive two leaf functions only, so dropping the pacer from the runner's
    own call sites left it green."""

    target, pacer = CountingTarget(), CountingPacer()
    single = make_spec("JB-SINGLE-001", mutations=["base64_wrap"])
    multi = make_spec("JB-MULTI-001").model_copy(
        update={"attack": Attack(turns=["first turn", "second turn", "third turn"])}
    )
    asyncio.run(
        _runner(tmp_path, target, pacer=pacer).run(
            run_id="r1", target=make_target(), specs=[single, multi]
        )
    )
    assert target.sends == 2 * 2 + 3 * 2
    assert pacer.acquired == target.sends


def test_every_identity_send_passes_the_rate_gate(tmp_path: Path) -> None:
    from tests.core.test_multi_identity import _mi_target

    probes, adapters = _probes(3)
    pacer = CountingPacer()
    runner = _identity_runner(tmp_path, probes, pacer=pacer)
    asyncio.run(runner.run(run_id="r1", target=_mi_target(), specs=[_xtenant()]))
    primary = 2  # n=2 attempts of the spec itself
    assert pacer.acquired == primary + sum(a.sends for a in adapters)


# --- F10: one retry layer, every wire request debited and paced ---------------------------


async def test_a_429_storm_is_four_metered_sends_not_twelve() -> None:
    wire = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal wire
        wire += 1
        return httpx.Response(429, json={"error": "slow down"})

    adapter = OpenAIAdapter(
        id="t1",
        base_url="https://api.example.test",
        allowlist=EndpointAllowlist([Endpoint(host="api.example.test", path_prefixes=["/"])]),
        api_key="placeholder-key-0000",
        model="m",
        retry=NO_ADAPTER_RETRIES,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    ledger = BudgetLedger.from_plan_budgets(PlanBudgets(max_requests=100))
    pacer = CountingPacer()
    result = await execute_attempt(
        adapter,
        ModelRequest(prompt="hi"),
        attempt_id="a1",
        spec_id="PI-DIRECT-001",
        mutation="identity",
        sampling=None,
        ledger=ledger,
        retry=RetryPolicy(max_retries=3),
        sleep=lambda _s: asyncio.sleep(0),
        now=lambda: 0.0,
        pacer=pacer,
    )
    assert result.env_error
    assert wire == 4
    assert ledger.snapshot().requests == wire
    assert pacer.acquired == wire


def test_the_campaign_adapters_are_built_without_their_own_retries() -> None:
    from ildottore.cli import wiring
    from ildottore.policy.scope import Identity, Scope, ScopeTarget
    from ildottore.shared.enums import TargetType
    from ildottore.shared.models import Target

    scope = Scope(
        version="1.0",
        targets=[
            ScopeTarget(
                id="live",
                base_url="https://api.example.test/v1/chat/completions",
                endpoints=[Endpoint(host="api.example.test", path_prefixes=["/v1"])],
                identities=[Identity(name="default", auth_ref="env://NONE")],
            )
        ],
    )
    target = Target(
        id="live",
        type=TargetType.CHATBOT,
        provider="openai",
        endpoint="https://api.example.test/v1/chat/completions",
    )
    adapter = wiring.real_adapter_factory(scope, target)(target, make_spec())
    assert adapter.retry.max_retries == 0  # type: ignore[attr-defined]
    judge = wiring.build_judge_adapter(scope, target, meter=SendMeter())
    assert isinstance(judge, MeteredAdapter)
    assert judge.inner.retry.max_retries == 0  # type: ignore[attr-defined]


# --- F7 / F18: the ledger records what was billed and only that --------------------------


def test_a_failed_send_releases_its_token_reservation() -> None:
    """Three reservations of 100 against a ceiling of 150 halted a flaky run with zero tokens
    consumed, and persisted that phantom spend for the resume."""

    calls = 0

    class Flaky(CountingTarget):
        async def send(self, request: ModelRequest) -> ModelResponse:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise TimeoutError("transient")
            return ModelResponse(text="ok", usage={"total_tokens": 30})

    ledger = BudgetLedger.from_plan_budgets(PlanBudgets(max_tokens=150))
    asyncio.run(
        execute_attempt(
            Flaky(),
            ModelRequest(prompt="hi", sampling=Sampling(temperature=0.0, max_tokens=100)),
            attempt_id="a1",
            spec_id="PI-DIRECT-001",
            mutation="identity",
            sampling=Sampling(temperature=0.0, max_tokens=100),
            ledger=ledger,
            retry=RetryPolicy(max_retries=3),
            sleep=lambda _s: asyncio.sleep(0),
            now=lambda: 0.0,
        )
    )
    # 30, the usage the provider reported: since every send reserves an estimate, the unused
    # part of the reservation is released too (leftovers of the audit, 2026-10-04).
    assert ledger.snapshot().tokens == 30
    assert ledger.snapshot().requests == 3


# --- the estimate and the derived ceilings count the judge --------------------------------


def test_the_estimate_counts_the_judge_and_the_derived_ceiling_makes_room_for_it() -> None:
    from ildottore.cli.run import JUDGE_PASSES, budgets_for, estimate_plan

    spec = _judged_spec()
    without = estimate_plan([spec], runs=5)
    with_judge = estimate_plan([spec], runs=5, judge=True)
    assert without.judge_requests == 0
    assert with_judge.judge_requests == with_judge.requests * JUDGE_PASSES
    assert with_judge.total_tokens > without.total_tokens
    big = with_judge.__class__(
        specs=1,
        requests=2000,
        input_tokens=0,
        output_tokens=0,
        by_category={},
        judge_requests=4000,
    )
    assert (budgets_for(big).max_requests or 0) >= big.total_requests


def test_the_dry_run_shows_the_judge_traffic() -> None:
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(REPO / "examples" / "target.local.yaml"),
            "--scope",
            str(REPO / "examples" / "scope.local.yaml"),
            "--judge",
            str(REPO / "examples" / "target.judge.yaml"),
            "--quick",
            "--dry-run",
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "request(s) to the --judge model" in result.output


# --- R8: a non-positive rate is refused, not read as "unpaced" ----------------------------


@pytest.mark.parametrize("rate", ["0", "-1"])
def test_a_non_positive_rate_is_refused_before_anything_is_sent(rate: str) -> None:
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(REPO / "examples" / "target.local.yaml"),
            "--scope",
            str(REPO / "examples" / "scope.local.yaml"),
            "--rate",
            rate,
            "--dry-run",
        ],
    )
    assert result.exit_code == 3
    assert "--rate must be greater than 0" in result.output


# --- F-16: the spend tests count real sends, and the merge is monotonic -------------------


def test_a_resume_under_the_same_ceiling_sends_nothing_past_it(tmp_path: Path) -> None:
    """The old test compared the stored spend with the ceiling; the store merges with max(),
    so a resume that spent a second full ceiling still read 6. This counts the attempts that
    really reached the evidence store across the halt and the resume."""

    from ildottore.cli.run import execute_run
    from tests.cli.test_resume_integrity import _BUDGET, _halted_run, _opts, _specs

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    attempts = tmp_path / "ev" / run_id / "attempts"
    after_halt = len(list(attempts.glob("*.json")))
    execute_run(_opts(tmp_path, spec_dir, resume=run_id), [spec_dir])
    after_resume = len(list(attempts.glob("*.json")))
    assert after_halt <= _BUDGET
    assert after_resume <= _BUDGET, f"{after_resume} sends against a ceiling of {_BUDGET}"


def test_a_stored_spend_only_ever_grows(tmp_path: Path) -> None:
    with SqliteRunStore(tmp_path / "runs.sqlite") as store:
        store.save_run_context("r1", spend={"requests": 5, "tokens": 100})
        store.save_run_context("r1", spend={"requests": 3, "tokens": 900})
        spend = store.get_run_spend("r1")
    assert spend is not None
    assert spend["requests"] == 5 and spend["tokens"] == 900


# --- F-15: a resume cannot change the judge or the planning mode --------------------------


def test_a_resume_with_a_judge_the_halted_run_did_not_have_is_refused(tmp_path: Path) -> None:
    from ildottore.cli.run import execute_run
    from tests.cli.test_resume_integrity import _halted_run, _opts, _specs

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    judge = tmp_path / "judge.yaml"
    judge.write_text(
        "id: mock-target\ntype: model\nprovider: openai\n"
        'endpoint: "mock://mock-target/v1/chat/completions"\n'
    )
    with pytest.raises(ValueError, match="judged by a different model"):
        execute_run(_opts(tmp_path, spec_dir, resume=run_id, judge=judge), [spec_dir])


def test_a_resume_that_turns_adaptive_planning_on_is_refused(tmp_path: Path) -> None:
    from ildottore.cli.run import execute_run
    from tests.cli.test_resume_integrity import _halted_run, _opts, _specs

    spec_dir = _specs(tmp_path)
    run_id = _halted_run(tmp_path, spec_dir)
    with pytest.raises(ValueError, match="adaptive planning"):
        execute_run(
            _opts(tmp_path, spec_dir, resume=run_id, deep=True, budget_requests=100), [spec_dir]
        )


def test_the_cli_composition_meters_the_judge(tmp_path: Path) -> None:
    """The metering lives at the composition root (the runner cannot import adapters), so the
    path `dottore run` really takes is the one asserted: `build_runner` with a judge."""

    from ildottore.cli import wiring
    from ildottore.policy.scope import Identity, Scope, ScopeTarget
    from ildottore.shared.enums import TargetType
    from ildottore.shared.models import Target

    scope = Scope(
        version="1.0",
        targets=[
            ScopeTarget(
                id=tid,
                base_url=f"https://{tid}.example.test/v1/chat/completions",
                endpoints=[Endpoint(host=f"{tid}.example.test", path_prefixes=["/v1"])],
                identities=[Identity(name="default", auth_ref="env://NONE")],
            )
            for tid in ("live", "judge")
        ],
    )

    def target(tid: str) -> Target:
        return Target(
            id=tid,
            type=TargetType.CHATBOT,
            provider="openai",
            endpoint=f"https://{tid}.example.test/v1/chat/completions",
        )

    built = wiring.build_runner(
        scope=scope,
        specs=[_judged_spec()],
        evidence_root=tmp_path / "ev",
        run_db=tmp_path / "runs.sqlite",
        real_target=target("live"),
        judge_target=target("judge"),
    )
    assert built.runner._send_meter is not None
    judge = built.runner._evaluators.get("semantic_judge")._judge  # type: ignore[attr-defined]
    assert isinstance(judge, MeteredAdapter)
    assert judge.meter is built.runner._send_meter
