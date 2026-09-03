"""Policy pack loading + PolicyEngine default-deny gate matrix (S3/S4/S5, DL4/DL5)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from ildottore.config import SafetyFlags
from ildottore.policy.errors import PolicyPackError
from ildottore.policy.packs import (
    CheckResult,
    PolicyEngine,
    PolicyPack,
    enabled_specs,
    load_pack,
)
from ildottore.policy.scope import Endpoint, Identity, Scope, ScopeTarget
from ildottore.shared.enums import Category

from .conftest import make_spec

ENDPOINT = "https://api.acme.test/v1/chat"


def _scope() -> Scope:
    return Scope(
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


def _engine(pack: PolicyPack, safety: SafetyFlags | None = None) -> PolicyEngine:
    return PolicyEngine(_scope(), pack, safety)


BASE_PACK = PolicyPack(name="base", allow_categories=[Category.PROMPT_INJECTION])


# --- pack loading ------------------------------------------------------------------


def test_load_pack_valid(tmp_path: Path) -> None:
    text = (
        "name: engagement-1\n"
        "allow_categories:\n"
        "  - prompt_injection\n"
        "  - jailbreak\n"
        "allow_specs:\n"
        "  - DL-SECRET-SHAPE-001\n"
        "deny:\n"
        "  - availability_cost\n"
        "enable_layer_b: false\n"
        "budgets:\n"
        "  max_tokens: 1000\n"
    )
    p = tmp_path / "pack.yaml"
    p.write_text(text, encoding="utf-8")
    pack = load_pack(p)
    assert pack.name == "engagement-1"
    assert Category.JAILBREAK in pack.allow_categories
    assert pack.budgets == {"max_tokens": 1000}


def test_load_pack_rejects_unknown_field(tmp_path: Path) -> None:
    p = tmp_path / "pack.yaml"
    p.write_text("name: x\nbogus: true\n", encoding="utf-8")
    with pytest.raises(PolicyPackError):
        load_pack(p)


def test_load_pack_rejects_non_mapping(tmp_path: Path) -> None:
    p = tmp_path / "pack.yaml"
    p.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(PolicyPackError):
        load_pack(p)


def test_load_pack_rejects_bad_yaml(tmp_path: Path) -> None:
    p = tmp_path / "pack.yaml"
    p.write_text("name: x\n : : :\n", encoding="utf-8")
    with pytest.raises(PolicyPackError):
        load_pack(p)


def test_load_pack_no_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: object, **k: object) -> None:
        raise AssertionError("egress on pack load")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    p = tmp_path / "pack.yaml"
    p.write_text("name: x\nallow_categories: [prompt_injection]\n", encoding="utf-8")
    assert load_pack(p).name == "x"


# --- default-deny gate matrix ------------------------------------------------------


def test_allow_in_scope_enabled_category() -> None:
    res = _engine(BASE_PACK).check("acme-bot", ENDPOINT, make_spec())
    assert res == CheckResult(decision="allow")
    assert res.allowed is True


def _stdio_scope() -> Scope:
    return Scope(
        version="1.0",
        targets=[
            ScopeTarget(
                id="local-mcp",
                base_url="stdio://local",
                identities=[Identity(name="a", auth_ref="env://NONE")],
                commands=["python server.py"],
            )
        ],
    )


def test_stdio_authorized_command_allows() -> None:
    """A stdio MCP target is authorized by an exact command match against scope.commands."""
    eng = PolicyEngine(_stdio_scope(), BASE_PACK)
    res = eng.check("local-mcp", "stdio://python server.py", make_spec())
    assert res.allowed


def test_stdio_unauthorized_command_blocked() -> None:
    """A stdio command not on the scope's allowlist is blocked_by_policy (S3 default-deny)."""
    eng = PolicyEngine(_stdio_scope(), BASE_PACK)
    res = eng.check("local-mcp", "stdio://python OTHER.py", make_spec())
    assert not res.allowed
    assert "stdio command not authorized" in (res.reason or "")


def test_blocked_out_of_scope_target() -> None:
    res = _engine(BASE_PACK).check("ghost", ENDPOINT, make_spec())
    assert res.decision == "blocked_by_policy"
    assert "not in scope" in (res.reason or "")


def test_blocked_off_allowlist_path() -> None:
    res = _engine(BASE_PACK).check("acme-bot", "https://api.acme.test/admin", make_spec())
    assert res.decision == "blocked_by_policy"
    assert "allowlist" in (res.reason or "")


def test_blocked_unknown_host() -> None:
    res = _engine(BASE_PACK).check("acme-bot", "https://evil.test/v1/chat", make_spec())
    assert res.decision == "blocked_by_policy"


def test_blocked_unlisted_spec_category() -> None:
    spec = make_spec("JB-001", category=Category.JAILBREAK)  # not in BASE_PACK
    res = _engine(BASE_PACK).check("acme-bot", ENDPOINT, spec)
    assert res.decision == "blocked_by_policy"
    assert "not enabled by pack" in (res.reason or "")


def test_allow_via_explicit_spec_id_even_if_category_off() -> None:
    pack = PolicyPack(name="p", allow_specs=["JB-SPECIAL-001"])
    spec = make_spec("JB-SPECIAL-001", category=Category.JAILBREAK)
    assert _engine(pack).check("acme-bot", ENDPOINT, spec).allowed


def test_explicit_deny_overrides_allow() -> None:
    pack = PolicyPack(
        name="p",
        allow_categories=[Category.PROMPT_INJECTION],
        deny=["PI-BASIC-001"],
    )
    res = _engine(pack).check("acme-bot", ENDPOINT, make_spec("PI-BASIC-001"))
    assert res.decision == "blocked_by_policy"
    assert "denied" in (res.reason or "")


def test_deny_by_category_string() -> None:
    pack = PolicyPack(
        name="p",
        allow_categories=[Category.PROMPT_INJECTION],
        deny=["prompt_injection"],
    )
    res = _engine(pack).check("acme-bot", ENDPOINT, make_spec())
    assert res.decision == "blocked_by_policy"


def test_layer_b_blocked_when_pack_disabled() -> None:
    spec = make_spec("DL-MEM-001", category=Category.DATA_LEAKAGE, tags=["layer_b"])
    pack = PolicyPack(name="p", allow_categories=[Category.DATA_LEAKAGE], enable_layer_b=False)
    res = _engine(pack).check("acme-bot", ENDPOINT, spec)
    assert res.decision == "blocked_by_policy"
    assert "layer-B" in (res.reason or "")


def test_layer_b_allowed_when_pack_enables() -> None:
    spec = make_spec("DL-MEM-001", category=Category.DATA_LEAKAGE, tags=["layer_b"])
    pack = PolicyPack(name="p", allow_categories=[Category.DATA_LEAKAGE], enable_layer_b=True)
    assert _engine(pack).check("acme-bot", ENDPOINT, spec).allowed


def test_pii_elicitation_blocked_without_both_flags() -> None:
    spec = make_spec("DL-PII-001", category=Category.DATA_LEAKAGE, tags=["pii_elicitation"])
    # pack allows but run flag off → blocked
    pack = PolicyPack(
        name="p",
        allow_categories=[Category.DATA_LEAKAGE],
        allow_pii_elicitation=True,
    )
    res = _engine(pack, SafetyFlags(allow_pii_elicitation=False)).check("acme-bot", ENDPOINT, spec)
    assert res.decision == "blocked_by_policy"
    assert "PII-elicitation" in (res.reason or "")


def test_pii_elicitation_blocked_when_pack_off_but_flag_on() -> None:
    spec = make_spec("DL-PII-001", category=Category.DATA_LEAKAGE, tags=["pii_elicitation"])
    pack = PolicyPack(
        name="p",
        allow_categories=[Category.DATA_LEAKAGE],
        allow_pii_elicitation=False,
    )
    res = _engine(pack, SafetyFlags(allow_pii_elicitation=True)).check("acme-bot", ENDPOINT, spec)
    assert res.decision == "blocked_by_policy"


def test_pii_elicitation_allowed_with_both_flags() -> None:
    spec = make_spec("DL-PII-001", category=Category.DATA_LEAKAGE, tags=["pii_elicitation"])
    pack = PolicyPack(
        name="p",
        allow_categories=[Category.DATA_LEAKAGE],
        allow_pii_elicitation=True,
    )
    res = _engine(pack, SafetyFlags(allow_pii_elicitation=True)).check("acme-bot", ENDPOINT, spec)
    assert res.allowed


# --- requires_policy capability gate (OD-11, docs/11 §5 / docs/13 §4) ---------------


def test_requires_policy_blocked_by_default_pack() -> None:
    # A default pack (no enabled_capabilities) blocks a spec that requires one.
    spec = make_spec(
        "AG-EXTORT-CHAIN-001",
        category=Category.AGENT_TOOL_ABUSE,
        requires_policy=["offensive_simulation"],
    )
    pack = PolicyPack(name="p", allow_categories=[Category.AGENT_TOOL_ABUSE])
    res = _engine(pack).check("acme-bot", ENDPOINT, spec)
    assert res.decision == "blocked_by_policy"
    assert "offensive_simulation" in (res.reason or "")
    assert "requires policy capability" in (res.reason or "")


def test_requires_policy_allowed_when_capability_enabled() -> None:
    spec = make_spec(
        "AG-EXTORT-CHAIN-001",
        category=Category.AGENT_TOOL_ABUSE,
        requires_policy=["offensive_simulation"],
    )
    pack = PolicyPack(
        name="p",
        allow_categories=[Category.AGENT_TOOL_ABUSE],
        enabled_capabilities=["offensive_simulation"],
    )
    assert _engine(pack).check("acme-bot", ENDPOINT, spec).allowed


def test_requires_policy_blocked_if_any_capability_missing() -> None:
    # ANY missing capability blocks - partial enablement is not enough.
    spec = make_spec(
        "DL-PII-ELICIT-001",
        category=Category.DATA_LEAKAGE,
        requires_policy=["layer_b_pii", "offensive_simulation"],
    )
    pack = PolicyPack(
        name="p",
        allow_categories=[Category.DATA_LEAKAGE],
        enabled_capabilities=["layer_b_pii"],  # offensive_simulation still missing
    )
    res = _engine(pack).check("acme-bot", ENDPOINT, spec)
    assert res.decision == "blocked_by_policy"
    assert "offensive_simulation" in (res.reason or "")
    assert "layer_b_pii" not in (res.reason or "")  # only the missing one is reported


def test_requires_policy_empty_never_gated() -> None:
    # A spec with no requires_policy is unaffected by the capability gate.
    spec = make_spec("PI-BASIC-001")  # requires_policy defaults to []
    assert _engine(BASE_PACK).check("acme-bot", ENDPOINT, spec).allowed


def test_pack_enabled_capabilities_defaults_empty() -> None:
    assert PolicyPack(name="p").enabled_capabilities == []


def test_test_only_spec_still_runs() -> None:
    # test_only gates raw rendering (u11), not execution - check should allow.
    spec = make_spec("PI-DANGER-001", test_only=True)
    assert _engine(BASE_PACK).check("acme-bot", ENDPOINT, spec).allowed


def test_engine_exposes_safety() -> None:
    eng = _engine(BASE_PACK, SafetyFlags(unsafe_render=True))
    assert eng.safety.unsafe_render is True


# --- enabled_specs helper ----------------------------------------------------------


def test_enabled_specs_filters_by_pack() -> None:
    specs = [
        make_spec("PI-1", category=Category.PROMPT_INJECTION),
        make_spec("JB-1", category=Category.JAILBREAK),
        make_spec("PI-2", category=Category.PROMPT_INJECTION),
    ]
    pack = PolicyPack(
        name="p",
        allow_categories=[Category.PROMPT_INJECTION],
        deny=["PI-2"],
    )
    out = [s.id for s in enabled_specs(pack, specs)]
    assert out == ["PI-1"]


def test_pack_default_deny_empty() -> None:
    pack = PolicyPack(name="empty")
    res = _engine(pack).check("acme-bot", ENDPOINT, make_spec())
    assert res.decision == "blocked_by_policy"
