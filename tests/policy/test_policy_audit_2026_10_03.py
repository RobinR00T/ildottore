"""Policy and authorization: the gate defects of the 2026-10-03 audit.

Each test is the reproduction of one finding, kept so the defect cannot come back: F-22 (the
DL4 two-key gate never fired for the one shipped PII spec, because of a tag's spelling),
SEC-06 (an unmarked spec in a flagged family ran, although lint rejected it), SEC-03 (an
encoded slash walked out of an authorized path prefix) and SEC-13 (an IPv6 entry could not
be pinned to a port). The fleet half of SEC-13 and SEC-04 lives in ``tests/cli/test_fleet.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ildottore.cli import wiring
from ildottore.cli.app import app
from ildottore.config import SafetyFlags
from ildottore.policy.allowlist import EndpointAllowlist, _split_host_port
from ildottore.policy.packs import PolicyEngine, PolicyPack
from ildottore.policy.scope import Endpoint, Identity, Scope, ScopeTarget
from ildottore.shared.enums import FLAGGED_FAMILIES, Category
from ildottore.shared.models import AttackSpec

from .conftest import make_spec

REPO = Path(__file__).resolve().parents[2]
ENDPOINT = "https://api.acme.test/v1/chat"


def _engine(pack: PolicyPack, safety: SafetyFlags | None = None) -> PolicyEngine:
    scope = Scope(
        version="1.0",
        targets=[
            ScopeTarget(
                id="acme-bot",
                base_url="https://api.acme.test/v1",
                endpoints=[Endpoint(host="api.acme.test", path_prefixes=["/v1"])],
                identities=[Identity(name="a", auth_ref="vault://a")],
            )
        ],
    )
    return PolicyEngine(scope, pack, safety)


# --- F-22: the DL4 gate, on the spec the battery actually ships ---------------------------


def _shipped(spec_id: str) -> AttackSpec:
    return wiring.build_registry([REPO / "specs"]).get(spec_id)


def test_the_shipped_pii_spec_needs_both_dl4_keys_even_with_its_capability_enabled() -> None:
    """F-22. A pack enabling only `layer_b_pii` ran it, with neither DL4 key turned."""

    spec = _shipped("DL-PII-ELICIT-001")
    pack = PolicyPack(
        name="layer-b-only",
        allow_categories=[Category.DATA_LEAKAGE],
        enabled_capabilities=["layer_b_pii"],
    )
    result = _engine(pack).check("acme-bot", ENDPOINT, spec)
    assert result.decision == "blocked_by_policy"
    assert "DL4" in (result.reason or "")


def test_the_shipped_pii_spec_runs_when_every_key_is_turned() -> None:
    spec = _shipped("DL-PII-ELICIT-001")
    pack = PolicyPack(
        name="all-keys",
        allow_categories=[Category.DATA_LEAKAGE],
        enabled_capabilities=["layer_b_pii"],
        allow_pii_elicitation=True,
    )
    safety = SafetyFlags(allow_pii_elicitation=True)
    assert _engine(pack, safety).check("acme-bot", ENDPOINT, spec).allowed


@pytest.mark.parametrize("tag", ["pii-elicitation", "pii_elicitation", "PII-Elicitation"])
def test_any_spelling_of_the_pii_tag_engages_the_gate(tag: str) -> None:
    spec = make_spec("DL-X-001", category=Category.DATA_LEAKAGE, tags=[tag])
    pack = PolicyPack(name="p", allow_categories=[Category.DATA_LEAKAGE])
    assert not _engine(pack).check("acme-bot", ENDPOINT, spec).allowed


@pytest.mark.parametrize("tag", ["layer-b", "layer_b", "Layer_B"])
def test_any_spelling_of_the_layer_b_tag_engages_the_gate(tag: str) -> None:
    spec = make_spec("DL-X-002", category=Category.DATA_LEAKAGE, tags=[tag])
    pack = PolicyPack(name="p", allow_categories=[Category.DATA_LEAKAGE])
    result = _engine(pack).check("acme-bot", ENDPOINT, spec)
    assert not result.allowed
    assert "enable_layer_b" in (result.reason or "")


def test_declaring_the_pii_capability_engages_the_gate_without_any_tag() -> None:
    """Dropping the tag must not drop the gate: the capability names PII on its own."""

    spec = make_spec("DL-X-003", category=Category.DATA_LEAKAGE, requires_policy=["layer_b_pii"])
    pack = PolicyPack(
        name="p", allow_categories=[Category.DATA_LEAKAGE], enabled_capabilities=["layer_b_pii"]
    )
    assert "DL4" in (_engine(pack).check("acme-bot", ENDPOINT, spec).reason or "")


# --- SEC-06: test_only is enforced, not self-declared away --------------------------------


@pytest.mark.parametrize("family", sorted(FLAGGED_FAMILIES, key=lambda c: c.value))
def test_an_unmarked_spec_in_a_flagged_family_is_refused(family: Category) -> None:
    """SEC-06 and u01 §7 ("test_only unmarked payload -> blocked_by_policy")."""

    spec = make_spec("X-UNMARKED-001", category=family, test_only=False)
    pack = PolicyPack(name="p", allow_categories=[family])
    result = _engine(pack).check("acme-bot", ENDPOINT, spec)
    assert result.decision == "blocked_by_policy"
    assert "test_only" in (result.reason or "")


@pytest.mark.parametrize("family", sorted(set(Category) - FLAGGED_FAMILIES, key=lambda c: c.value))
def test_a_diagnostic_family_does_not_need_the_mark(family: Category) -> None:
    spec = make_spec("X-DIAG-001", category=family, test_only=False)
    pack = PolicyPack(name="p", allow_categories=[family])
    assert _engine(pack).check("acme-bot", ENDPOINT, spec).allowed


def test_the_gate_refuses_no_spec_the_battery_ships() -> None:
    """The new refusal must bite third-party copies only: every shipped flagged spec is marked."""

    registry = wiring.build_registry([REPO / "specs"])
    unmarked = [s.id for s in registry.list() if s.category in FLAGGED_FAMILIES and not s.test_only]
    assert unmarked == []


def test_run_refuses_a_copy_of_a_shipped_spec_with_the_mark_deleted(tmp_path: Path) -> None:
    """SEC-06 end to end. The copy is made here from a shipped file, so no payload is in this
    test. Before the fix it was sent and scored, while `dottore lint` reported it."""

    (tmp_path / "scope.yaml").write_text(
        'version: "1.0"\ntargets:\n  - id: mock-target\n    base_url: "mock://mock-target"\n'
        '    endpoints:\n      - host: "mock-target"\n        path_prefixes: ["/"]\n'
        '    identities:\n      - name: default\n        auth_ref: "env://NONE"\n'
    )
    (tmp_path / "target.yaml").write_text(
        "id: mock-target\ntype: chatbot\nmock_scenario: vulnerable\n"
        "capabilities:\n  tools: false\n  rag: false\n"
    )
    pack = tmp_path / "thirdparty"
    (pack / "attacks").mkdir(parents=True)
    (pack / "pack.yaml").write_text("id: thirdparty\npack_version: '1.0'\nname: thirdparty\n")
    source = (REPO / "specs" / "attacks" / "DOS-TOKEN-AMP-001.yaml").read_text()
    copy = re.sub(r"(?m)^test_only:.*\n", "", source).replace(
        "id: DOS-TOKEN-AMP-001", "id: TP-UNMARKED-001", 1
    )
    assert "test_only" not in copy.split("tags:")[0]
    (pack / "attacks" / "TP-UNMARKED-001.yaml").write_text(copy)

    result = CliRunner().invoke(
        app,
        [
            "run",
            "-t",
            str(tmp_path / "target.yaml"),
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--spec-path",
            str(pack),
            "--spec",
            "TP-UNMARKED-001",
            "--evidence-root",
            str(tmp_path / "ev"),
            "--run-db",
            str(tmp_path / "runs.sqlite"),
            "--no-color",
        ],
    )
    assert result.exit_code == 3, result.output
    assert "blocked by policy" in result.output
    attempts = (
        list((tmp_path / "ev").rglob("attempts/*.json")) if (tmp_path / "ev").exists() else []
    )
    assert attempts == [], "nothing may be sent for a refused spec"


# --- SEC-03: an encoded separator never reaches an origin that would decode it ------------


_ALLOWLIST = EndpointAllowlist([Endpoint(host="127.0.0.1:18081", path_prefixes=["/v1/chat"])])


@pytest.mark.parametrize(
    "path",
    [
        "/v1/chat/..%2f..%2fadmin",
        "/v1/chat/..%2F..%2Fadmin",
        "/v1/chat/%2e%2e%2f%2e%2e%2fadmin",
        "/v1/chat/..%5c..%5cadmin",
        "/v1/chat/..\\..\\admin",
        "/v1/chat/..%252f..%252fadmin",
    ],
)
def test_an_encoded_separator_is_refused(path: str) -> None:
    """SEC-03. The first three reached `/admin` on a decoding origin with the gate's blessing."""

    assert not _ALLOWLIST.is_allowed(f"http://127.0.0.1:18081{path}")


def test_the_authorized_prefix_still_passes() -> None:
    assert _ALLOWLIST.is_allowed("http://127.0.0.1:18081/v1/chat/completions")


# --- SEC-13: an IPv6 entry can be pinned to its port ----------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("[::1]:8080", ("::1", 8080)),
        ("[::1]", ("::1", None)),
        ("::1", ("::1", None)),
        ("api.vendor.test:443", ("api.vendor.test", 443)),
        ("API.Vendor.test", ("api.vendor.test", None)),
    ],
)
def test_host_and_port_split(value: str, expected: tuple[str, int | None]) -> None:
    assert _split_host_port(value) == expected


def test_a_port_pinned_ipv6_entry_matches_its_port_and_no_other() -> None:
    """SEC-13. A pinned IPv6 literal never matched, so IPv6 targets could not be pinned."""

    allowlist = EndpointAllowlist([Endpoint(host="[::1]:8080", path_prefixes=["/v1"])])
    assert allowlist.is_allowed("http://[::1]:8080/v1/chat/completions")
    assert not allowlist.is_allowed("http://[::1]:2375/v1/chat/completions")
