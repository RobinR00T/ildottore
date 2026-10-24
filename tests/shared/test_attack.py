"""The pinned MITRE ATT&CK Enterprise universe (``shared.attack``): its size, its shape, its
retired set, and the agreement between the version constant and the data file.

The pin is derived from the official STIX bundle by ``scripts/attack_universe.py``, so what can
be tested is that it is the derivation it says it is: the counts the module docstring states,
the matrix order, the v20 renames and revocations that motivated the axis, and that an ID the
release retired is refused with its replacement named.
"""

from __future__ import annotations

import json

import pytest

from ildottore.shared.attack import (
    ATTACK_DOMAIN,
    ATTACK_VERSION,
    TECHNIQUE_ID_RE,
    attack_pin,
    attack_retired,
    attack_tactic_universe,
    attack_tactics,
    attack_techniques,
    restrict_tactics,
    tactic_name,
    tactic_shortnames,
    unknown_attack_ids,
)
from ildottore.shared.package_data import package_path


def test_the_pin_is_the_derivation_the_docstring_claims() -> None:
    """v20.0 (2026-10-13): 15 tactics, 706 current techniques (227 + 479 sub), 161 retired.

    Counted from the bundle when it was derived (``enterprise-attack-20.0.json``, SHA-256 in
    the pin's ``source`` block). A changed number here means the pin changed, and the
    docstring, the manual and the coverage figures change with it.
    """

    assert ATTACK_VERSION == "20.0"
    assert len(attack_tactics()) == 15
    techniques = attack_techniques()
    assert len(techniques) == 706
    assert sum(1 for t in techniques.values() if not t.subtechnique) == 227
    assert sum(1 for t in techniques.values() if t.subtechnique) == 479
    assert len(attack_retired()) == 161


def test_the_pin_names_its_source_and_agrees_with_the_version_constant() -> None:
    pin = attack_pin()
    assert (pin["version"], pin["domain"]) == (ATTACK_VERSION, ATTACK_DOMAIN)
    assert pin["source"]["bundle_url"].endswith(f"enterprise-attack-{ATTACK_VERSION}.json")
    assert len(pin["source"]["bundle_sha256"]) == 64
    path = package_path("shared", "data", f"attack-enterprise-{ATTACK_VERSION}.json")
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == ATTACK_VERSION


def test_tactics_are_in_matrix_order_with_the_v20_names() -> None:
    """Defense Evasion became Stealth and Defense Impairment is new, both in v20.0."""

    assert attack_tactic_universe() == (
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Stealth",
        "Defense Impairment",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    )
    assert tactic_shortnames()["stealth"] == "Stealth"
    assert tactic_shortnames()["defense-impairment"] == "Defense Impairment"
    assert tactic_name("command-and-control") == "Command and Control"
    assert tactic_name("not-a-tactic") == "not-a-tactic"


def test_every_technique_sits_under_pinned_tactics_only() -> None:
    shortnames = set(tactic_shortnames())
    for technique in attack_techniques().values():
        assert technique.tactics, technique.id
        assert set(technique.tactics) <= shortnames, technique.id
        assert TECHNIQUE_ID_RE.match(technique.id), technique.id
        assert technique.subtechnique == ("." in technique.id), technique.id


def test_the_ai_techniques_the_axis_was_built_for_are_current() -> None:
    techniques = attack_techniques()
    assert techniques["T1699"].name == "Direct Prompt Injection"
    assert techniques["T1699"].tactics == ("execution",)
    assert techniques["T1698"].name == "Indirect Prompt Injection"
    assert techniques["T1700"].name == "AI-Enabled Exfiltration"
    assert techniques["T1685.007"].name == "Impair Autonomous Defenses"
    assert techniques["T1685.007"].tactics == ("defense-impairment",)
    assert techniques["T1053.003"].tactics == ("execution", "persistence", "privilege-escalation")


def test_a_retired_id_is_refused_with_its_replacement_named() -> None:
    """T1562 Impair Defenses was revoked into T1685 in v20.0: the motivating case."""

    retired = attack_retired()
    assert retired["T1562"].status == "revoked"
    assert retired["T1562"].replaced_by == "T1685"
    assert "T1562" not in attack_techniques()
    [(tid, why)] = unknown_attack_ids(["T1562"])
    assert tid == "T1562"
    assert "revoked" in why
    assert "T1685" in why
    assert "20.0" in why


def test_unknown_ids_are_reported_once_each_in_order_with_a_reason() -> None:
    out = unknown_attack_ids(["T1699", "T9999", "nope", "T9999", "T1070.002"])
    assert [tid for tid, _ in out] == ["T9999", "nope", "T1070.002"]
    reasons = dict(out)
    assert "not in ATT&CK Enterprise 20.0" in reasons["T9999"]
    assert "not a T####" in reasons["nope"]
    assert "T1685.006" in reasons["T1070.002"], "the log-clearing sub-technique moved in v20"
    assert unknown_attack_ids(None) == []


@pytest.mark.parametrize("bad", ["T169", "T16999", "T1699.1", "T1699.0001", "t1699", "T1699\n"])
def test_the_id_pattern_refuses_the_near_misses(bad: str) -> None:
    assert TECHNIQUE_ID_RE.match(bad) is None


def test_restrict_tactics_keeps_named_tactics_and_never_widens() -> None:
    cron = attack_techniques()["T1053.003"]
    assert restrict_tactics(cron, None) == (cron.tactics, ())
    kept, rejected = restrict_tactics(cron, ["persistence", "impact"])
    assert kept == ("persistence",) and rejected == ("impact",)
    assert restrict_tactics(cron, ["impact"]) == ((), ("impact",)), (
        "a contradicted restriction keeps nothing; it must not fall back to every tactic"
    )
