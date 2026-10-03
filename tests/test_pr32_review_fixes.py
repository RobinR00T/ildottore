"""The review of PR #32: defects the audit fixes introduced or left, one test per finding.

Three reviewers ran the PR in isolated worktrees on 2026-10-03 and reproduced each item by
running code. Every test below fails on the PR head before this commit (329a891) and passes
after it, except two positive controls that pin what must keep holding (the identity mask is
the same in every process; a variant with enough attempts still decides on its own).
Placeholder values only.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from ildottore import redactor as redactor_mod
from ildottore.adapters import MCPAdapter, RetryConfig
from ildottore.adapters.base import MAX_RESPONSE_BYTES, ResponseTooLarge
from ildottore.cli.app import _masked, app
from ildottore.policy import EndpointAllowlist
from ildottore.policy.allowlist import _remove_dot_segments
from ildottore.policy.scope import Endpoint
from ildottore.redactor import Redactor, redact_identity, register_known_secret
from ildottore.reporting import get_reporter
from ildottore.reporting.masking import mask_findings
from ildottore.shared.enums import InconclusiveReason, ReportFormat, VerdictStatus
from ildottore.shared.models import EvidenceRef, ModelRequest
from ildottore.store import ReplayResult, TamperError, check_manifest
from tests.reporting.conftest import make_finding, make_run
from tests.scoring.conftest import make_attempt
from tests.store.test_evidence_manifest import _run, _workspace

REPO = Path(__file__).resolve().parents[1]

# --- redactor ----------------------------------------------------------------------------


def test_a_long_run_of_label_words_is_redacted_in_linear_time() -> None:
    """48 KB of ``token token ...`` took 4.9 s and 96 KB took 20 s: quadratic in text the target
    controls. 384 KB now takes well under a second; the bound is generous on purpose."""

    started = time.perf_counter()
    Redactor().redact_text("token " * 64_000)
    assert time.perf_counter() - started < 3.0


@pytest.mark.parametrize(
    "text",
    [
        "password: Password!2026x",
        "password: Secret-Placeholder-1",
        "api_key=token.PLACEHOLDER42",
        "password: Tokens-are-fake-7",
    ],
)
def test_a_labelled_value_that_starts_with_a_label_word_is_masked(text: str) -> None:
    value = text.split(maxsplit=1)[-1] if " " in text else text.split("=", 1)[1]
    assert value not in Redactor().redact_text(text)


def test_a_credential_with_an_embedded_control_character_is_refused_unechoed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ildottore.cli.wiring import resolve_auth_ref

    monkeypatch.setenv("REVIEW_CTRL_KEY", "placeholder-part-one\nplaceholder-part-two")
    with pytest.raises(ValueError, match="control character") as raised:
        resolve_auth_ref("env://REVIEW_CTRL_KEY")
    assert "placeholder-part" not in str(raised.value)


def test_a_credential_is_masked_in_the_form_an_http_library_quotes_it() -> None:
    key = "placeholder-quoted-a\rplaceholder-quoted-b"
    register_known_secret(key)
    quoted = "LocalProtocolError: Illegal header value " + repr(f"Bearer {key}".encode())
    assert "placeholder-quoted" not in Redactor().redact_text(quoted)


def test_a_credential_inside_the_mask_template_still_converges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``credential`` is part of the mask itself; it nested on every pass and the evidence
    store's fixed-point guard aborted the campaign."""

    monkeypatch.setattr(redactor_mod, "_KNOWN_SECRETS", set())
    register_known_secret("credential")
    redactor = Redactor()
    once = redactor.redact_text("the credential value")
    assert redactor.redact_text(once) == once
    assert "«REDACTED:«" not in once


def test_a_url_password_with_a_raw_at_sign_is_masked_whole() -> None:
    register_known_secret("p@ss-placeholder-99")
    masked = Redactor().redact_text("http://alice:p@ss-placeholder-99@localhost:8080/v1")
    assert "ss-placeholder-99" not in masked
    assert masked.endswith("@localhost:8080/v1")


def test_a_cli_error_masks_a_url_password_and_keeps_an_artifact_name() -> None:
    digest = hashlib.sha256(b"x").hexdigest()
    text = _masked(
        ValueError(
            "endpoint 'http://alice:pwplaceholder99@127.0.0.1:1/x' not on allowlist; "
            f"artifact {digest}.json"
        )
    )
    assert "pwplaceholder99" not in text
    assert f"{digest}.json" in text


def test_the_identity_mask_is_stable_across_processes_for_a_value_that_is_masked() -> None:
    """The earlier test used a tenant the redactor never masked, so it passed trivially."""

    tenant = "TenantA7fK2pQ9xLm4Rz7VwB3"
    assert redact_identity(tenant) != tenant
    code = f"from ildottore.redactor import redact_identity;print(redact_identity({tenant!r}))"
    outputs = {
        subprocess.run(  # noqa: S603 - our own interpreter, a fixed snippet
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "ILDOTTORE_REDACTION_SALT": salt},
        ).stdout.strip()
        for salt in ("one", "two")
    }
    assert outputs == {redact_identity(tenant)}


# --- reports -----------------------------------------------------------------------------


def _finding_with_evidence(spec_id: str = "PI-DIRECT-001"):  # type: ignore[no-untyped-def]
    digest = hashlib.sha256(spec_id.encode()).hexdigest()
    finding = make_finding().model_copy(
        update={
            "spec_id": spec_id,
            "evidence": [
                EvidenceRef(
                    run_id="run-1",
                    attempt_id="a" * 40,
                    uri=f"/evidence/run-1/attempts/{digest}.json",
                    sha256=digest,
                )
            ],
        }
    )
    return finding, digest


def test_the_json_report_keeps_evidence_readable_in_both_copies_of_a_finding() -> None:
    """``run.findings`` kept 103 of 110 digests masked; the old test searched the whole blob,
    which the top-level copy satisfied."""

    finding, digest = _finding_with_evidence()
    report = json.loads(
        get_reporter(ReportFormat.JSON).render(make_run(findings=[finding]), [finding])
    )
    assert report["findings"][0]["evidence"][0]["sha256"] == digest
    assert report["run"]["findings"][0]["evidence"][0]["sha256"] == digest
    assert report["run"]["findings"][0]["evidence"][0]["uri"].endswith(f"{digest}.json")


def test_a_custom_spec_id_reads_the_same_under_any_salt() -> None:
    """Masked with the per-process salt, a custom id changed digest every run, so `diff` saw
    two unrelated specs and reported no regression."""

    finding, _ = _finding_with_evidence("ACME-SYSPROMPT2-DOS-003")
    ids = {mask_findings([finding], Redactor(salt=salt))[0].spec_id for salt in ("run-a", "run-b")}
    assert ids == {"ACME-SYSPROMPT2-DOS-003"}


# --- evidence manifest -------------------------------------------------------------------


def _replay(*attempts: tuple[str, str]) -> ReplayResult:
    """A replay result of ``(spec_id, digest)`` attempts."""

    built = tuple(make_attempt(spec_id=spec) for spec, _ in attempts)
    return ReplayResult(run_id="r", attempts=built, attempt_hashes=tuple(d for _, d in attempts))


def test_a_deleted_recorded_artifact_is_refused() -> None:
    with pytest.raises(TamperError, match="missing"):
        check_manifest(_replay(("A-1", "1" * 64)), {"A-1": {"1" * 64, "2" * 64}})


def test_an_artifact_under_a_spec_whose_finding_cites_no_evidence_is_refused() -> None:
    with pytest.raises(TamperError, match="not one the run store recorded"):
        check_manifest(_replay(("A-1", "1" * 64)), {"A-1": set()})


def test_a_run_stored_before_the_fix_replays_with_its_masked_digests(tmp_path: Path) -> None:
    """Old stores kept a few digests readable by chance; a partial manifest then refused the
    untouched artifacts of that spec as tampered, through the default --run-db path."""

    d = _workspace(tmp_path)
    assert _run(d).exit_code == 0
    run_id = next(p.name for p in (d / "ev").iterdir())
    import sqlite3
    from contextlib import closing

    with closing(sqlite3.connect(d / "runs.sqlite")) as conn, conn:
        for finding_id, raw in conn.execute(
            "SELECT finding_id, evidence_refs_json FROM findings"
        ).fetchall():
            refs = json.loads(raw)
            for ref in refs[1:]:
                ref["sha256"] = "«REDACTED:high_entropy:0badc0de»"
            conn.execute(
                "UPDATE findings SET evidence_refs_json = ? WHERE finding_id = ?",
                (json.dumps(refs), finding_id),
            )
    result = CliRunner().invoke(
        app,
        ["replay", run_id, "--evidence-root", str(d / "ev"), "--run-db", str(d / "runs.sqlite")],
    )
    assert result.exit_code == 0, result.output


def test_replay_says_when_it_could_not_check_the_manifest(tmp_path: Path) -> None:
    d = _workspace(tmp_path)
    assert _run(d).exit_code == 0
    run_id = next(p.name for p in (d / "ev").iterdir())
    result = CliRunner().invoke(
        app,
        ["replay", run_id, "--evidence-root", str(d / "ev"), "--run-db", str(d / "typo.sqlite")],
    )
    assert result.exit_code == 0
    assert "warning: no run store" in result.output


# --- scoring and judging -----------------------------------------------------------------


def test_one_exploit_among_single_shot_variants_is_neither_confirmed_nor_critical() -> None:
    """With --runs 1 every variant is 1 of 1; "the best variant" made this confirmed Critical."""

    from ildottore.core.runner import _is_confirmed
    from ildottore.scoring.risk import reproducibility_from_attempts
    from tests.core.conftest import make_spec

    attempts = [
        make_attempt(VerdictStatus.FAIL if i == 0 else VerdictStatus.PASS).model_copy(
            update={"mutation": f"variant-{i}"}
        )
        for i in range(6)
    ]
    assert reproducibility_from_attempts(attempts) == pytest.approx(1 / 6)
    assert not _is_confirmed(VerdictStatus.FAIL, attempts, make_spec())


def test_a_variant_with_enough_attempts_still_decides_on_its_own() -> None:
    from ildottore.scoring.risk import reproducibility_from_attempts

    plain = [make_attempt(VerdictStatus.FAIL) for _ in range(5)]
    refused = [
        make_attempt(VerdictStatus.PASS).model_copy(update={"mutation": "base64"}) for _ in range(5)
    ]
    assert reproducibility_from_attempts(plain + refused) == 1.0


async def test_an_unparseable_judge_is_no_judge() -> None:
    """It abstained without a reason, the runner dropped it, and the spec passed on the
    deterministic arms while an outage on the same spec stayed inconclusive."""

    from ildottore.evaluators.semantic_judge import SemanticJudgeEvaluator
    from tests.evaluators.test_semantic_judge import ScriptedJudge, _ctx

    verdict = await SemanticJudgeEvaluator(ScriptedJudge(["", ""])).evaluate(_ctx())
    assert verdict.status is VerdictStatus.INCONCLUSIVE
    assert verdict.inconclusive_reason is InconclusiveReason.CAPABILITY_UNAVAILABLE


# --- transport ---------------------------------------------------------------------------


async def test_an_oversized_reply_is_not_retried() -> None:
    import asyncio

    from ildottore.core.budgets import BudgetLedger
    from ildottore.core.execute import RetryPolicy, execute_attempt
    from ildottore.shared.models import PlanBudgets, Sampling

    class Oversized:
        sends = 0

        async def send(self, request: ModelRequest) -> object:
            Oversized.sends += 1
            raise ResponseTooLarge("t1: response exceeded the cap")

    result = await execute_attempt(
        Oversized(),  # type: ignore[arg-type]
        ModelRequest(prompt="hi"),
        attempt_id="a1",
        spec_id="PI-DIRECT-001",
        mutation="identity",
        sampling=Sampling(temperature=0.0),
        ledger=BudgetLedger.from_plan_budgets(PlanBudgets(max_requests=10)),
        retry=RetryPolicy(max_retries=3),
        sleep=lambda _s: asyncio.sleep(0),
        now=lambda: 0.0,
    )
    assert result.env_error and Oversized.sends == 1


async def test_the_mcp_adapter_stops_reading_at_the_cap() -> None:
    """It buffered the whole body with `client.post` and measured it afterwards."""

    pulled = 0
    chunk = b"x" * (1024 * 1024)

    async def body() -> AsyncIterator[bytes]:
        nonlocal pulled
        for _ in range(20):
            pulled += 1
            yield chunk

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body(), headers={"content-type": "application/json"})

    adapter = MCPAdapter(
        id="mcp-test",
        base_url="https://mcp.example.test/mcp",
        allowlist=EndpointAllowlist([Endpoint(host="mcp.example.test", path_prefixes=["/mcp"])]),
        retry=RetryConfig(backoff_base_s=0.0, backoff_cap_s=0.0, timeout_s=5.0),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(ResponseTooLarge):
        await adapter.send(ModelRequest(prompt="list"))
    assert pulled <= MAX_RESPONSE_BYTES // len(chunk) + 1


# --- path allowlist ----------------------------------------------------------------------


def test_the_gate_resolves_every_path_exactly_as_httpx_sends_it() -> None:
    """``/v1/chat/x//../../admin`` resolved under the prefix here while httpx sent
    ``/v1/admin``. A differential over generated paths pins the gate to the wire."""

    segments = ["a", "b", "", ".", "..", "v1"]
    for n in range(1, 6):
        for combo in itertools.product(segments, repeat=n):
            path = "/" + "/".join(combo)
            assert _remove_dot_segments(path) == httpx.URL("http://h" + path).raw_path.decode()


def test_the_empty_segment_escape_is_refused() -> None:
    allowlist = EndpointAllowlist(
        [Endpoint(host="127.0.0.1:18081", path_prefixes=["/v1/chat/completions"])]
    )
    assert not allowlist.is_allowed(
        "http://127.0.0.1:18081/v1/chat/completions/x//../../../../admin"
    )


# --- CLI ---------------------------------------------------------------------------------


def test_a_broken_mutator_plugin_is_a_lint_warning_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ildottore.mutators as mutators

    real = mutators.build_default_registry

    def broken(*, discover: bool = True):  # type: ignore[no-untyped-def]
        if discover:
            raise TypeError("mutator from entry-point 'broken' is missing a 'name' attribute")
        return real(discover=False)

    monkeypatch.setattr(mutators, "build_default_registry", broken)
    from ildottore.cli.lint import run_lint

    code, output = run_lint([REPO / "specs"])
    assert code == 0, output
    assert "MUTATOR_PLUGIN_ERROR" in output


def test_a_load_refusal_counts_files_not_problems(tmp_path: Path) -> None:
    d = _workspace(tmp_path)
    pack = tmp_path / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: pack\npack_version: '1.0'\nname: pack\n")
    # Valid YAML, invalid spec: one file, many schema problems (one per missing field).
    (pack / "attacks" / "broken.yaml").write_text("id: X-BROKEN-001\nname: only a name\n")
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(d / "target.yaml"),
            "--scope",
            str(d / "scope.yaml"),
            "--spec-path",
            str(pack),
            "--evidence-root",
            str(d / "ev"),
            "--run-db",
            str(d / "runs.sqlite"),
            "--dry-run",
        ],
    )
    assert result.exit_code == 3
    assert "1 spec file(s) failed to load" in result.output


def test_the_dry_run_shows_the_no_judge_warning() -> None:
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(REPO / "examples" / "target.local.yaml"),
            "--scope",
            str(REPO / "examples" / "scope.local.yaml"),
            "--quick",
            "--dry-run",
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "no --judge on a live target" in result.output


def test_a_refused_fleet_judge_leaves_no_directory(tmp_path: Path) -> None:
    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(
        'version: "1"\ntargets:\n  - id: m\n    endpoint: http://localhost:11434/v1/chat/completions\n'
    )
    judge = tmp_path / "judge.yaml"
    judge.write_text(
        'id: j\ntype: model\nprovider: openai\nendpoint: "http://localhost:11434/v1/chat/completions"\n'
    )
    out = tmp_path / "out"
    result = CliRunner().invoke(
        app, ["fleet", str(fleet), "--out", str(out), "--judge", str(judge)]
    )
    assert result.exit_code == 3
    assert not out.exists()
