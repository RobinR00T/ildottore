"""Residual findings of the 2026-10-03 audit, fixed after the seven blocks.

F11 (resume re-sending attempts that ended in an environment error) was withdrawn here and built
later the same day, once the run store journaled artifacts as they are written: see
`tests/test_f11_resume_resends.py`. The pieces kept from the withdrawal: one evidence reference per
artifact on resume, and one attempt per id in `replay`.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ildottore.core.runner import CampaignRunner
from ildottore.evaluators import build_default_registry as build_evaluators
from ildottore.mutators import build_default_registry as build_mutators
from ildottore.mutators.registry import MutatorRegistry
from ildottore.scoring import DefaultRiskScorer
from ildottore.shared.enums import VerdictStatus
from ildottore.shared.models import Capabilities, ModelRequest, ModelResponse
from ildottore.store.evidence_fs import FsEvidenceStore
from ildottore.store.run_sqlite import SqliteRunStore
from tests.core.conftest import (
    VULNERABLE_RESPONSE,
    AllowAllPolicy,
    make_spec,
    make_target,
    no_sleep,
)


class Endpoint:
    """Always answers, and counts the sends."""

    def __init__(self) -> None:
        self.id = "t1"
        self.sends = 0

    async def send(self, request: ModelRequest) -> ModelResponse:
        self.sends += 1
        return ModelResponse(text=VULNERABLE_RESPONSE)

    def capabilities(self) -> Capabilities:
        return Capabilities()


def _runner(
    tmp_path: Path, endpoint: Endpoint, mutators: MutatorRegistry | None = None
) -> CampaignRunner:
    return CampaignRunner(
        policy=AllowAllPolicy(),
        mutators=mutators if mutators is not None else build_mutators(discover=False),
        evaluators=build_evaluators(discover=False),
        scorer=DefaultRiskScorer(),
        evidence_store=FsEvidenceStore(tmp_path / "ev"),
        run_store=SqliteRunStore(tmp_path / "runs.sqlite"),
        adapter_factory=lambda _t, _s: endpoint,
        n=3,
        concurrency=1,
        sleep=no_sleep,
        now=lambda: 0.0,
    )


def test_a_resume_of_a_healthy_run_still_sends_nothing(tmp_path: Path) -> None:
    spec = make_spec()
    first = asyncio.run(
        _runner(tmp_path, Endpoint()).run(run_id="r1", target=make_target(), specs=[spec])
    )
    again = Endpoint()
    asyncio.run(
        _runner(tmp_path, again).run(
            run_id="r1", target=make_target(), specs=[spec], resume_from=first.run
        )
    )
    assert again.sends == 0


# --- block 6 residuals: R5, R6, R10, R12, R14, R16, and -oA ------------------------------


def test_needs_review_excludes_passes_and_never_sent_specs() -> None:
    """A clean hardened run read "Needs review: 75" because every non-confirmed finding
    counted (R5). An unconfirmed exploit and a sent-but-undecided result (an uncorroborated
    secret shape is inconclusive by design) still need review."""

    from ildottore.reporting.summary import build_run_summary
    from tests.reporting.conftest import make_finding

    findings = [
        make_finding("S-1", confirmed=True),
        make_finding("S-2", confirmed=False),
        make_finding("S-3", status=VerdictStatus.PASS, confirmed=False),
        make_finding("S-4", status=VerdictStatus.INCONCLUSIVE, confirmed=False),
        make_finding("S-5", status=VerdictStatus.INCONCLUSIVE, confirmed=False).model_copy(
            update={"attempts": []}
        ),
    ]
    summary = build_run_summary(findings)
    assert summary.confirmed_count == 1
    assert summary.needs_review_count == 2

    from ildottore.reporting.summary import finding_state

    assert [finding_state(f) for f in findings] == [
        "confirmed",
        "needs_review",
        "not_exploited",
        "needs_review",
        "not_tested",
    ]


def test_a_never_sent_spec_stays_out_of_the_distributions() -> None:
    """A capability skip measured nothing and diluted the averages with zeros (R14)."""

    from ildottore.reporting.summary import build_run_summary
    from tests.reporting.conftest import make_finding

    sent = make_finding("S-1")
    never = make_finding("S-2", status=VerdictStatus.INCONCLUSIVE, confirmed=False)
    never = never.model_copy(update={"attempts": []})
    summary = build_run_summary([sent, never])
    assert summary.repro_distribution["count"] == 1.0
    assert summary.total == 2


def test_an_unconfirmed_fail_says_so_on_its_progress_line() -> None:
    """It printed "FAIL (critical)" and the run exited 0 with no word on why (R6)."""

    from ildottore.cli.render import progress_line
    from tests.reporting.conftest import make_finding

    line = progress_line(1, 1, "S-1", make_finding("S-1", confirmed=False))
    assert "needs review" in line
    assert "needs review" not in progress_line(1, 1, "S-1", make_finding("S-1"))


def test_the_machine_formats_carry_the_framework_editions() -> None:
    """A-14: the HTML and the terminal printed the editions; JSON, SARIF and JUnit did not."""

    import json

    from ildottore.reporting import get_reporter
    from ildottore.shared.enums import ReportFormat
    from ildottore.shared.frameworks import OWASP_LLM_EDITION, framework_editions
    from tests.reporting.conftest import make_finding, make_run

    findings = [make_finding()]
    run = make_run(findings=findings)
    doc = json.loads(get_reporter(ReportFormat.JSON).render(run, findings))
    assert doc["summary"]["coverage"]["owasp"]["edition"] == OWASP_LLM_EDITION
    sarif = json.loads(get_reporter(ReportFormat.SARIF).render(run, findings))
    assert sarif["runs"][0]["properties"]["framework_editions"] == framework_editions()
    junit = get_reporter(ReportFormat.JUNIT).render(run, findings).decode()
    assert f'name="edition.owasp_llm_top10" value="{OWASP_LLM_EDITION}"' in junit


async def test_a_target_that_answers_every_probe_alike_gets_no_family() -> None:
    """A constant mock was named meta-llama at 0.67 (R16)."""

    from ildottore.fingerprint.engine import NON_DISCRIMINATING_FLAG, FingerprintEngine

    class Constant:
        id = "constant"

        async def send(self, request: ModelRequest) -> ModelResponse:
            return ModelResponse(text="I cannot help with that.")

        def capabilities(self) -> Capabilities:
            return Capabilities()

    fingerprint = await FingerprintEngine().run(Constant())
    assert fingerprint.family.guess == "unknown"
    assert fingerprint.family.confidence == 0.0
    assert fingerprint.version is None
    assert NON_DISCRIMINATING_FLAG in fingerprint.spoofing_flags


def test_an_output_prefix_keeps_its_dotted_name(tmp_path: Path) -> None:
    from ildottore.cli.run import RunOptions, _report_outputs

    opts = RunOptions(targets=[], scope=None, output_all_prefix=tmp_path / "report.v2")
    outputs = _report_outputs(opts)
    assert outputs["json"].name == "report.v2.json"
    assert outputs["junit"].name == "report.v2.xml"


def test_two_formats_cannot_write_the_same_file(tmp_path: Path) -> None:

    from ildottore.cli.run import RunOptions, _validate_options

    same = tmp_path / "out.txt"
    opts = RunOptions(targets=[], scope=None, outputs={"json": same, "html": same})
    with pytest.raises(ValueError, match="same file"):
        _validate_options(opts)


def test_the_multi_target_envelope_holds_every_target(tmp_path: Path) -> None:
    """run.findings and run.summary held the last target only, beside a top-level summary of
    all of them (R10)."""

    import json

    from ildottore.cli.run import RunOptions, _write_reports
    from ildottore.core.runner import CampaignResult
    from tests.reporting.conftest import make_finding, make_run

    a, b = make_finding("S-1", target_id="a"), make_finding("S-1", target_id="b")
    results = [
        CampaignResult(plan=None, run=make_run(run_id="run-a", findings=[a]), findings=[a]),  # type: ignore[arg-type]
        CampaignResult(plan=None, run=make_run(run_id="run-b", findings=[b]), findings=[b]),  # type: ignore[arg-type]
    ]
    out = tmp_path / "r.json"
    _write_reports(RunOptions(targets=[], scope=None, outputs={"json": out}), results, [a, b], {})
    doc = json.loads(out.read_text())
    assert len(doc["run"]["findings"]) == 2
    assert doc["run"]["summary"]["total"] == 2


# --- found while fixing block 7 ------------------------------------------------------------


def test_a_cli_error_keeps_the_digest_it_computed_readable_unless_it_is_a_credential() -> None:
    """The scope checksum mismatch printed "expected «REDACTED»", hiding the hash it names.
    Only the digest the tool computed is kept: the expected one is whatever the operator typed
    in `checksum:`, and a key typed there printed in clear (fourth audit of the residuals)."""

    import hashlib

    from ildottore.cli.app import _masked
    from ildottore.policy.errors import ScopeChecksumError
    from ildottore.redactor import register_known_secret

    typed = hashlib.sha256(b"a key typed in the checksum field").hexdigest()
    actual = hashlib.sha256(b"scope body").hexdigest()
    shown = _masked(ScopeChecksumError(typed, actual))
    assert actual in shown
    assert typed not in shown

    hex_key = hashlib.sha256(b"a registered hex credential").hexdigest()
    register_known_secret(hex_key)
    assert hex_key not in _masked(ScopeChecksumError(actual, hex_key))
    part = hashlib.sha256(b"registered inside a digest").hexdigest()
    register_known_secret(part[8:40])
    assert part not in _masked(ScopeChecksumError(actual, part)), "a secret inside one"
    assert f"{part}.json" not in _masked(ValueError(f"artifact {part}.json is missing"))


def test_a_malformed_carried_digest_is_ignored_not_compiled() -> None:
    """A carried value is matched as a sha256 before it enters the pattern: `abc(` crashed
    `dottore run` with a regex traceback in a mutant without that filter."""

    from ildottore.cli.app import _masked
    from ildottore.store.replay import TamperError

    assert "abc(" in _masked(TamperError("bad value abc(", digests=("abc(",)))


def test_a_tamper_refusal_shows_the_hash_the_content_now_has() -> None:
    import hashlib

    from ildottore.cli.app import _masked
    from ildottore.store.replay import TamperError

    name = hashlib.sha256(b"original").hexdigest()
    actual = hashlib.sha256(b"edited").hexdigest()
    exc = TamperError(
        f"artifact hash mismatch for {name}.json: content hashes to {actual}", digests=(actual,)
    )
    shown = _masked(exc)
    assert f"{name}.json" in shown and actual in shown


@pytest.mark.parametrize(
    "template",
    [
        "target 'stub' auth_ref '{key}' is not authorized by the scope",
        "unsupported auth_ref scheme in '{key}'",
        "token={key}",
        "bad endpoint https://api.test/v1?api_key={key}",
        "token: {key}",
        "the password is {key}",
    ],
)
def test_a_cli_error_masks_an_unregistered_64_hex_value(template: str) -> None:
    """Keeping every bare 64-hex readable printed a raw key pasted as an `auth_ref` in clear
    through `dottore run`; only the digests an error carries may stay readable (third audit
    of the residuals, F1)."""

    import hashlib

    from ildottore.cli.app import _masked
    from ildottore.policy.errors import PolicyError

    key = hashlib.sha256(template.encode()).hexdigest()
    assert key not in _masked(PolicyError(template.format(key=key)))
    # A digest carried by the error does not unmask a different value in the same message.
    carrying = PolicyError(template.format(key=key))
    carrying.digests = (hashlib.sha256(b"other").hexdigest(),)  # type: ignore[attr-defined]
    assert key not in _masked(carrying)


@pytest.mark.parametrize(
    "key",
    [
        "d103ac4f0985677e" * 4,  # hex with normal entropy
        "ab" * 32,  # hex with low entropy: the redactor's entropy rule never masked it
        "797c48a81f494d0f3e8d13bd49459b6f",  # 32-hex below the entropy threshold
    ],
)
def test_run_does_not_print_a_raw_key_pasted_as_an_auth_ref(tmp_path: Path, key: str) -> None:
    """An error quotes an `auth_ref` only when it is a reference (`scheme://NAME`). The
    redactor caught a pasted literal only by its entropy (fourth audit of the residuals)."""

    from typer.testing import CliRunner

    from ildottore.cli.app import app

    scope = tmp_path / "scope.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n  - id: stub\n    base_url: "http://127.0.0.1:9/v1"\n'
        '    endpoints:\n      - host: "127.0.0.1:9"\n        path_prefixes: ["/v1"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    target = tmp_path / "target.yaml"
    target.write_text(
        "id: stub\ntype: chatbot\nprovider: openai\nendpoint: http://127.0.0.1:9/v1\n"
        f'model: m\nauth_ref: "{key}"\ncapabilities:\n  tools: false\n  rag: false\n'
    )
    result = CliRunner().invoke(
        app, ["run", "-t", str(target), "--scope", str(scope), "--quick", "--dry-run"]
    )
    assert result.exit_code == 3, result.output
    assert key not in result.output
    assert "a literal value (not shown)" in result.output
    assert "'env://NONE'" in result.output, "a reference is still quoted"


def test_the_declared_list_does_not_quote_a_literal_in_the_scope() -> None:
    from ildottore.cli.wiring import check_target_credential
    from ildottore.policy.scope import Endpoint as ScopeEndpoint
    from ildottore.policy.scope import Identity, Scope, ScopeTarget
    from ildottore.shared.models import Target

    literal = "ab" * 32
    scope = Scope(
        version="1.0",
        targets=[
            ScopeTarget(
                id="t",
                base_url="http://127.0.0.1:9/v1",
                endpoints=[ScopeEndpoint(host="127.0.0.1:9", path_prefixes=["/v1"])],
                identities=[
                    Identity(name="pasted", auth_ref=literal),
                    Identity(name="default", auth_ref="env://NONE"),
                ],
            )
        ],
    )
    target = Target(id="t", type="chatbot", auth_ref="env://OTHER")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="is not authorized") as refused:
        check_target_credential(scope, target)
    message = str(refused.value)
    assert literal not in message
    assert "'env://NONE'" in message and "'env://OTHER'" in message


def test_a_checksum_mismatch_does_not_quote_the_recorded_value() -> None:
    """The redactor masked a real sha256 recorded there about 19 times in 20, so the recorded
    value mostly appeared in clear when it was not a digest: a key typed by mistake."""

    from ildottore.policy.errors import ScopeChecksumError

    message = str(ScopeChecksumError("ab" * 32, "c" * 64))
    assert "ab" * 32 not in message
    assert "c" * 64 in message


def test_a_malformed_scope_names_the_field_not_its_value(tmp_path: Path) -> None:
    """pydantic's message echoed the input, and the tail of a pasted key survived its
    truncation (fifth audit of the residuals)."""

    from ildottore.policy.errors import ScopeError
    from ildottore.policy.scope import load_scope

    literal = "797c48a81f494d0f3e8d13bd49459b6f" * 2
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        f'version: "1.0"\ntargets:\n  - id: t\n    base_url: "http://127.0.0.1:9/v1"\n'
        f'    endpoints: "{literal}"\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    with pytest.raises(ScopeError) as refused:
        load_scope(scope)
    message = str(refused.value)
    assert "targets.0.endpoints: Input should be a valid list" in message, "where and why"
    assert literal[-12:] not in message


def test_a_literal_auth_ref_in_the_scope_is_not_quoted_either() -> None:
    from ildottore.cli.wiring import resolve_auth_ref

    with pytest.raises(ValueError) as refused:
        resolve_auth_ref("ab" * 32)
    assert "ab" * 32 not in str(refused.value)
    assert "a literal value (not shown)" in str(refused.value)
    with pytest.raises(ValueError, match="'vault://kv/key'"):
        resolve_auth_ref("vault://kv/key")


def test_every_built_in_mutator_declares_its_parameters() -> None:
    """`None` means "not declared, pass any parameter through": right for a plugin, wrong for
    a built-in, whose parameters this repo knows."""

    registry = build_mutators(discover=False)
    undeclared = [n for n in registry.names() if registry.get(n).accepted_params is None]  # type: ignore[attr-defined]
    assert undeclared == []


def test_offline_fingerprint_honours_the_targets_mock_scenario(tmp_path: Path) -> None:
    """`dottore fingerprint --offline` ignored `mock_scenario: comprehending`, so every carrier
    scored 0.0 while `run -sV` on the same file measured comprehension (D-09)."""

    from ildottore.cli.fingerprint import fingerprint_target

    scope = tmp_path / "scope.yaml"
    scope.write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    target = tmp_path / "target.yaml"
    target.write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: comprehending\n"
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    fingerprint = fingerprint_target(target, scope, offline=True)
    assert fingerprint.capability_guess.get("effective_mutators"), (
        "the comprehending mock recovers some carriers"
    )


def test_lint_refuses_a_mutation_parameter_the_mutator_does_not_implement(tmp_path: Path) -> None:
    """`translate:klingon` passed lint, sent a language picked by hash, and the evidence said
    klingon (review of PR #32)."""

    from ildottore.cli.lint import lint

    pack = tmp_path / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: pack\npack_version: '1.0'\nname: pack\n")
    repo = Path(__file__).resolve().parents[1]
    source = (repo / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text()
    assert "mutations:" in source
    (pack / "attacks" / "PI-DIRECT-001.yaml").write_text(
        source.replace("mutations: [", "mutations: [translate:klingon, ", 1)
    )
    report = lint([pack])
    messages = [e.message for e in report.errors if e.code.value == "UNKNOWN_MUTATOR_TYPE"]
    assert any("'klingon' is not a parameter translate accepts" in m for m in messages)


def test_the_runner_sends_nothing_for_an_unaccepted_mutation_parameter(tmp_path: Path) -> None:
    endpoint = Endpoint()
    spec = make_spec(mutations=["translate:klingon"])
    result = asyncio.run(
        _runner(tmp_path, endpoint).run(run_id="r1", target=make_target(), specs=[spec])
    )
    assert endpoint.sends == 0
    assert result.findings[0].status is VerdictStatus.INCONCLUSIVE
    assert "unknown_mutator_parameter" in (result.findings[0].reasoning or "")


def test_an_output_prefix_with_a_report_extension_is_not_doubled(tmp_path: Path) -> None:
    from ildottore.cli.run import RunOptions, _report_outputs

    opts = RunOptions(targets=[], scope=None, output_all_prefix=tmp_path / "report.json")
    outputs = _report_outputs(opts)
    assert outputs["json"].name == "report.json"
    assert outputs["html"].name == "report.html"


def test_report_paths_differing_only_in_case_are_one_file(tmp_path: Path) -> None:

    from ildottore.cli.run import RunOptions, _validate_options

    opts = RunOptions(
        targets=[], scope=None, outputs={"json": tmp_path / "R.json", "html": tmp_path / "r.json"}
    )
    with pytest.raises(ValueError, match="same file"):
        _validate_options(opts)


async def test_a_constant_target_keeps_what_its_response_envelope_says() -> None:
    """The envelope (a provider's `model` field) is not text: a constant-text target that
    declares its model is still attributed from it, flagged (pre-commit audit, R16)."""

    from ildottore.cli import wiring
    from ildottore.fingerprint.engine import NON_DISCRIMINATING_FLAG

    class Enveloped:
        id = "enveloped"

        async def send(self, request: ModelRequest) -> ModelResponse:
            return ModelResponse(
                text="I cannot help with that.", raw_ids={"model": "gpt-4o-2024-08-06"}
            )

        def capabilities(self) -> Capabilities:
            return Capabilities()

    fingerprint = await wiring.build_fingerprint_engine().run(Enveloped())
    assert fingerprint.family.guess == "openai-gpt"
    assert NON_DISCRIMINATING_FLAG in fingerprint.spoofing_flags


async def test_carrier_answers_do_not_hide_a_target_that_attributes_nothing() -> None:
    """The comprehending mock answers carriers differently and everything else alike; it was
    still named meta-llama at 0.67 (pre-commit audit, R16)."""

    from ildottore.adapters.comprehending import ComprehendingMock
    from ildottore.cli import wiring

    fingerprint = await wiring.build_fingerprint_engine().run(ComprehendingMock(id="c"))
    assert fingerprint.family.guess == "unknown"
    assert fingerprint.capability_guess.get("effective_mutators"), "carriers still measured"


def test_replay_counts_one_attempt_per_id_and_prefers_the_answered_try() -> None:
    """Two artifacts can share an attempt id (an errored try and its retry): both are listed,
    one is counted, the answered one."""

    from ildottore.store import ReplayResult
    from tests.scoring.conftest import make_attempt

    answered = make_attempt(VerdictStatus.FAIL, attempt_id="a1").model_copy(
        update={"response": ModelResponse(text="leak")}
    )
    errored = make_attempt(None, attempt_id="a1", error="ConnectError")
    other = make_attempt(VerdictStatus.PASS, attempt_id="a2").model_copy(
        update={"response": ModelResponse(text="no")}
    )
    result = ReplayResult(
        run_id="r",
        attempts=(errored, answered, other),
        attempt_hashes=("1" * 64, "2" * 64, "3" * 64),
    )
    assert result.n == 2
    assert result.successful_attacks() == 1
    assert [a.attempt_id for a in result.effective_attempts()] == ["a1", "a2"]
    assert result.effective_attempts()[0].response is not None


# --- re-audit of the residual patch -------------------------------------------------------


async def test_a_constant_target_is_not_named_from_finish_reason_alone() -> None:
    """`finish_reason=stop` was in the meta-llama signature (dropped on 2026-10-05) and every
    OpenAI-compatible server sends it; only a `model=` field may attribute a target with no text
    signal (N2)."""

    from ildottore.cli import wiring

    class Server:
        id = "server"

        def __init__(self, raw: dict[str, str]) -> None:
            self.raw = raw

        async def send(self, request: ModelRequest) -> ModelResponse:
            return ModelResponse(text="I cannot help.", raw_ids=self.raw, finish_reason="stop")

        def capabilities(self) -> Capabilities:
            return Capabilities()

    engine = wiring.build_fingerprint_engine()
    plain = await engine.run(Server({}))
    assert plain.family.guess == "unknown"
    named = await engine.run(Server({"model": "gpt-4o-2024-08-06"}))
    assert named.family.guess == "openai-gpt"
    assert named.version is None, "a tie between versions is not broken alphabetically"


def test_a_cli_error_masks_a_registered_credential_that_contains_a_digest() -> None:
    """`sk-<64 hex>` printed in clear once 64-hex digests were kept readable (N5)."""

    import hashlib

    from ildottore.cli.app import _masked
    from ildottore.redactor import register_known_secret

    hexpart = hashlib.sha256(b"embedded credential body").hexdigest()
    register_known_secret(f"sk-{hexpart}")
    assert hexpart not in _masked(ValueError(f"rejected: sk-{hexpart}"))
    url_pw = hashlib.sha256(b"a url password").hexdigest()
    assert url_pw not in _masked(ValueError(f"bad endpoint http://bob:{url_pw}@127.0.0.1/x"))


def test_mutation_parameters_compare_case_insensitively_and_unparameterized_take_none(
    tmp_path: Path,
) -> None:
    """`translate:ES` was sent correctly and the first check refused it; `rot13:x` was sent as
    rot13 and recorded as `rot13:x` (N7)."""

    from ildottore.cli.lint import lint

    pack = tmp_path / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: pack\npack_version: '1.0'\nname: pack\n")
    repo = Path(__file__).resolve().parents[1]
    source = (repo / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text()
    (pack / "attacks" / "PI-DIRECT-001.yaml").write_text(
        source.replace("mutations: [", "mutations: [translate:ES, rot13:x, ", 1)
    )
    messages = [e.message for e in lint([pack]).errors]
    assert not any("translate:ES" in m for m in messages)
    assert any("'rot13:x': rot13 takes no parameter" in m for m in messages)

    endpoint = Endpoint()
    result = asyncio.run(
        _runner(tmp_path, endpoint).run(
            run_id="r1", target=make_target(), specs=[make_spec(mutations=["rot13:x"])]
        )
    )
    assert endpoint.sends == 0
    assert "unknown_mutator_parameter" in (result.findings[0].reasoning or "")


def test_report_paths_in_two_unicode_forms_are_one_file(tmp_path: Path) -> None:
    import unicodedata

    from ildottore.cli.run import RunOptions, _validate_options

    nfc = tmp_path / unicodedata.normalize("NFC", "café.json")
    nfd = tmp_path / unicodedata.normalize("NFD", "café.json")
    opts = RunOptions(targets=[], scope=None, outputs={"json": nfc, "html": nfd})
    with pytest.raises(ValueError, match="same file"):
        _validate_options(opts)


def test_replay_notes_the_history_it_does_not_count() -> None:
    from ildottore.cli.replay import render_replay
    from ildottore.store import ReplayResult
    from tests.scoring.conftest import make_attempt

    errored = make_attempt(None, attempt_id="a1", error="ConnectError")
    answered = make_attempt(VerdictStatus.FAIL, attempt_id="a1").model_copy(
        update={"response": ModelResponse(text="x")}
    )
    text = render_replay(
        ReplayResult(run_id="r", attempts=(errored, answered), attempt_hashes=("1" * 64, "2" * 64))
    )
    assert "1 more artifact shares an attempt id" in text
    assert "attempts: 1" in text


def test_a_never_sent_spec_is_listed_with_the_not_exploited_ones_in_html() -> None:
    from ildottore.reporting import get_reporter
    from ildottore.shared.enums import ReportFormat
    from tests.reporting.conftest import make_finding, make_run

    never = make_finding("S-9", status=VerdictStatus.INCONCLUSIVE, confirmed=False)
    never = never.model_copy(update={"attempts": []})
    html = get_reporter(ReportFormat.HTML).render(make_run(findings=[never]), [never]).decode()
    assert "Not exploited or not tested (1)" in html


def test_the_help_text_says_what_the_flags_do() -> None:
    import typer

    from ildottore.cli.app import app

    run = typer.main.get_command(app).commands["run"]  # type: ignore[attr-defined]
    helps = {opt: param.help for param in run.params for opt in param.opts}
    assert "same battery" in helps["--deep"]
    assert "adaptive only with -sV" in helps["--deep"]
    assert "owasp:llm, baseline, agentic" in helps["--suite"]
    assert "default command" not in (run.help or "")


# --- third audit of the residuals: behaviours its mutants showed untested ----------------


class _Plugin:
    """A plugin that does not subclass BaseMutator and declares no parameters."""

    name = "plug"

    def mutate(self, text: str, seed: str) -> str:
        return f"{text} [{seed.rsplit(':', 1)[-1]}]"


def _with_plugins() -> MutatorRegistry:
    from ildottore.mutators.base import BaseMutator

    class _Subclassed(BaseMutator):
        name = "subplug"

        def _transform(self, text: str, seed: str) -> tuple[str, dict[str, object]]:
            return text.upper(), {}

    registry = build_mutators(discover=False)
    registry.register(_Plugin())
    registry.register(_Subclassed())
    return registry


@pytest.mark.parametrize("mutation", ["translate:ES", "translate: es"])
def test_the_runner_reads_a_parameter_in_any_case_or_spacing(tmp_path: Path, mutation: str) -> None:
    endpoint = Endpoint()
    result = asyncio.run(
        _runner(tmp_path, endpoint).run(
            run_id="r1", target=make_target(), specs=[make_spec(mutations=[mutation])]
        )
    )
    assert endpoint.sends > 0
    assert "unknown_mutator_parameter" not in (result.findings[0].reasoning or "")


@pytest.mark.parametrize("mutation", ["plug:level3", "subplug:level3"])
def test_the_runner_does_not_second_guess_a_plugin_that_declares_no_parameters(
    tmp_path: Path, mutation: str
) -> None:
    """A plugin reads its own `name:param`; one that declares nothing is sent as before, and
    so is one that subclasses BaseMutator (its default is "not declared", third audit F5)."""

    endpoint = Endpoint()
    result = asyncio.run(
        _runner(tmp_path, endpoint, _with_plugins()).run(
            run_id="r1", target=make_target(), specs=[make_spec(mutations=[mutation])]
        )
    )
    assert endpoint.sends > 0
    assert "unknown_mutator_parameter" not in (result.findings[0].reasoning or "")


def test_lint_does_not_second_guess_a_plugin_that_declares_no_parameters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ildottore.mutators
    from ildottore.cli.lint import lint

    monkeypatch.setattr(ildottore.mutators, "build_default_registry", lambda **_: _with_plugins())
    pack = tmp_path / "pack"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: pack\npack_version: '1.0'\nname: pack\n")
    repo = Path(__file__).resolve().parents[1]
    source = (repo / "specs" / "attacks" / "PI-DIRECT-001.yaml").read_text()
    (pack / "attacks" / "PI-DIRECT-001.yaml").write_text(
        source.replace("mutations: [", "mutations: [plug:level3, subplug:level3, rot13:x, ", 1)
    )
    messages = [e.message for e in lint([pack]).errors]
    assert not any("plug:level3" in m for m in messages)
    assert any("rot13 takes no parameter" in m for m in messages), "built-ins still checked"


async def test_a_target_with_two_distinct_answers_is_not_called_constant() -> None:
    from ildottore.fingerprint.engine import NON_DISCRIMINATING_FLAG, FingerprintEngine

    class TwoAnswers:
        id = "two"

        def __init__(self) -> None:
            self.calls = 0

        async def send(self, request: ModelRequest) -> ModelResponse:
            self.calls += 1
            return ModelResponse(text="Yes." if self.calls % 2 else "No.")

        def capabilities(self) -> Capabilities:
            return Capabilities()

    fingerprint = await FingerprintEngine().run(TwoAnswers())
    assert NON_DISCRIMINATING_FLAG not in fingerprint.spoofing_flags


def test_run_sv_says_when_the_target_gave_no_text_signal(tmp_path: Path) -> None:
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
        "id: mock-target\ntype: chatbot\nmock_scenario: vulnerable\n"
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(target),
            "--scope",
            str(scope),
            "-sV",
            "--spec",
            "PI-DIRECT-001",
            "--no-color",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
        ],
    )
    assert "family=unknown" in result.output
    assert "answered every attributing probe alike: no text signal" in result.output


def test_needs_review_is_said_on_unconfirmed_fails_only() -> None:
    from ildottore.cli.render import progress_line
    from tests.reporting.conftest import make_finding

    for status in (VerdictStatus.PASS, VerdictStatus.INCONCLUSIVE):
        finding = make_finding("S-1", status=status, confirmed=False)
        assert "needs review" not in progress_line(1, 1, "S-1", finding)


def test_replay_counts_a_success_once_per_attempt_id() -> None:
    from ildottore.store import ReplayResult
    from tests.scoring.conftest import make_attempt

    first, second = (
        make_attempt(VerdictStatus.FAIL, attempt_id="a1").model_copy(
            update={"response": ModelResponse(text=text)}
        )
        for text in ("leak", "leak again")
    )
    result = ReplayResult(run_id="r", attempts=(first, second), attempt_hashes=("1" * 64, "2" * 64))
    assert result.successful_attacks() == 1
    assert result.reproducibility() == 1.0


@pytest.mark.parametrize(
    ("fleet_text", "expected"),
    [
        (
            'targets:\n  - id: a\n    endpoint: "https://api.openai.com/v1"\n'
            '    api_key: "797c48a81f494d0f3e8d13bd49459b6f"\n',
            "targets.0.api_key: Extra inputs are not permitted",
        ),
        (
            'targets:\n  - id: a\n    endpoint: "https://api.openai.com/v1"\n'
            "    api_key_env:797c48a81f494d0f3e8d13bd49459b6f\n    other: [\n",
            "is not valid YAML",
        ),
    ],
)
def test_a_fleet_file_error_says_where_and_why_never_the_value(
    tmp_path: Path, fleet_text: str, expected: str
) -> None:
    """`api_key: <key>` where `api_key_env` belongs was echoed by pydantic, and a YAML error
    escaped as a traceback with exit 1 and a snippet of the line (fifth audit)."""

    from typer.testing import CliRunner

    from ildottore.cli.app import app

    fleet = tmp_path / "fleet.yaml"
    fleet.write_text(fleet_text)
    result = CliRunner().invoke(app, ["fleet", str(fleet), "--out", str(tmp_path / "out")])
    assert result.exit_code == 3, result.output
    assert expected in result.output
    assert "797c48a81f494d0f3e8d13bd49459b6f"[:12] not in result.output


@pytest.mark.parametrize("kind", ["scope", "target", "labels"])
def test_a_yaml_error_in_an_operator_file_quotes_no_snippet(tmp_path: Path, kind: str) -> None:
    from ildottore.cli.calibrate import load_labels
    from ildottore.cli.wiring import load_target
    from ildottore.policy.errors import ScopeError
    from ildottore.policy.scope import load_scope

    path = tmp_path / f"{kind}.yaml"
    path.write_text("id: x\nauth_ref:797c48a81f494d0f3e8d13bd49459b6f\nbad: [\n")
    loader = {"scope": load_scope, "target": load_target, "labels": load_labels}[kind]
    with pytest.raises((ScopeError, ValueError)) as refused:
        loader(path)
    message = str(refused.value)
    assert "not valid YAML" in message or "invalid YAML" in message
    assert "could not find expected ':'" in message, "why"
    assert "entry starting at line 2" in message, "the typo's line, not only the next one"
    assert "797c48a8" not in message


def test_a_control_character_in_an_operator_file_says_what_and_where() -> None:
    import yaml

    from ildottore.shared.config_errors import yaml_problem

    try:
        yaml.safe_load("id: x\nauth_ref: \x1b[31m\n")
    except yaml.YAMLError as exc:
        message = yaml_problem(exc)
    assert "special characters are not allowed" in message
    assert "at character" in message


def test_a_judge_id_mismatch_still_quotes_the_id(tmp_path: Path) -> None:
    """Only the `auth_ref` field hides a literal: the id and endpoint stay quoted."""

    from ildottore.cli.fleet import _shown

    assert _shown("id", "other-judge") == "'other-judge'"
    assert _shown("endpoint", None) == "None"
    assert _shown("auth_ref", "ab" * 16) == "a literal value (not shown)"
