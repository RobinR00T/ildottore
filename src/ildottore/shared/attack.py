"""The MITRE ATT&CK Enterprise universe, pinned as data (a fifth coverage axis).

ATT&CK names what an **adversary does on a victim's estate**; the four other axes (OWASP LLM,
ATLAS, IoPC, AISVS) name what happens to a model or a control. The two met in ATT&CK v20.0
(2026-10-13), which added the AI techniques an agentic target can be shown performing: Direct and
Indirect Prompt Injection (``T1699``, ``T1698``, Execution), AI-Enabled Exfiltration (``T1700``),
Impair Autonomous Defenses (``T1685.007``), Query Public AI Services (``T1682``), and renamed
Defense Evasion to Stealth beside a new Defense Impairment tactic. Before v20 a battery like this
one had nothing honest to map to; after it, most agentic specs map directly.

The universe is read from ``shared/data/attack-enterprise-<version>.json``, derived from the
official STIX 2.1 bundle in ``mitre-attack/attack-stix-data`` by ``scripts/attack_universe.py``
(which also answers "is there a newer release?", the run-time check the Feedly *Map ATT&CK
Techniques* skill does and this repository does by hand, because a denominator must be
reproducible from the checkout alone). The file carries the release, its modification date, the
bundle's URL and SHA-256: a figure printed beside ``v20.0`` can be rebuilt from upstream.

**What a mapping claims, and what it does not.** A spec's ``mitre_attack.techniques`` entry
carries an ``occurrence`` borrowed from the skill's vocabulary, reduced to the two a test harness
can tell apart (``reported`` and ``source-assessed`` describe third-party reports, and the
harness is its own observer):

* ``observed``: the technique's behaviour appears in the target's own actions during the test:
  a mock tool call the trace records (a cron entry written, a credential store read, a record
  mailed out), or the reply itself being the technique's effect (an injected instruction obeyed,
  a targeting dossier synthesised). Only these count toward tactic coverage.
* ``capability-only``: the target produced an artefact that would enable the technique
  elsewhere (malware source, a phishing lure); nothing was executed. Listed, never counted.

A technique sits under one or more tactics upstream; a spec may restrict its claim to a subset
with ``tactics`` (``T1053.003`` Cron is Execution, Persistence and Privilege Escalation, and a
beacon spec exercises Persistence). The restriction is validated against the pin: a tactic the
technique does not sit under is a contradiction, not a widening.

A **retired** ID (revoked or deprecated upstream) is a lint error that names the replacement:
``T1562`` Impair Defenses became ``T1685`` in v20, and a spec still declaring it would match
nothing and shrink the numerator in silence, the failure every axis here is built against.

Only identifiers, names and tactic memberships are reproduced. ATT&CK is published by The MITRE
Corporation under its own terms of use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/);
the descriptions stay upstream.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from types import MappingProxyType
from typing import Any, Final

from ildottore.shared.package_data import package_path

__all__ = [
    "ATTACK_DOMAIN",
    "ATTACK_LAYER_FORMAT",
    "ATTACK_VERSION",
    "TECHNIQUE_ID_RE",
    "AttackTactic",
    "AttackTechnique",
    "RetiredTechnique",
    "attack_pin",
    "attack_retired",
    "attack_tactic_universe",
    "attack_tactics",
    "attack_techniques",
    "restrict_tactics",
    "tactic_name",
    "tactic_shortnames",
    "unknown_attack_ids",
]

#: The Enterprise release the pin was derived from. Printed beside every ATT&CK figure, and the
#: name of the data file: bump both together (``scripts/attack_universe.py refresh`` says so).
ATTACK_VERSION: Final = "20.0"
ATTACK_DOMAIN: Final = "enterprise"
#: The ATT&CK Navigator layer format this repository writes (``reporting.navigator``).
ATTACK_LAYER_FORMAT: Final = "4.5"

#: Well-formedness of a technique ID, ``T####`` or ``T####.###``. ``\Z``, not ``$``: in Python's
#: ``re`` a ``$`` also matches before a trailing newline (the same note ``shared.iopc`` carries).
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?\Z")


@dataclass(frozen=True)
class AttackTactic:
    """One column of the Enterprise matrix, in matrix order."""

    id: str
    shortname: str
    name: str


@dataclass(frozen=True)
class AttackTechnique:
    """One current technique or sub-technique: its name and the tactic shortnames it sits under."""

    id: str
    name: str
    tactics: tuple[str, ...]
    subtechnique: bool


@dataclass(frozen=True)
class RetiredTechnique:
    """An ID the release no longer counts: revoked (with a replacement) or deprecated."""

    id: str
    name: str
    status: str
    replaced_by: str | None


@cache
def attack_pin() -> dict[str, Any]:
    """The pinned file, parsed once. Raises if the file the version names is missing."""

    path = package_path("shared", "data", f"attack-enterprise-{ATTACK_VERSION}.json")
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if loaded.get("version") != ATTACK_VERSION or loaded.get("domain") != ATTACK_DOMAIN:
        raise ValueError(
            f"{path.name} says {loaded.get('domain')} {loaded.get('version')}, this module pins "
            f"{ATTACK_DOMAIN} {ATTACK_VERSION}: the file and ATTACK_VERSION moved apart"
        )
    return loaded


@cache
def attack_tactics() -> tuple[AttackTactic, ...]:
    """The tactics in matrix order (15 in v20.0)."""

    return tuple(AttackTactic(t["id"], t["shortname"], t["name"]) for t in attack_pin()["tactics"])


@cache
def attack_tactic_universe() -> tuple[str, ...]:
    """The tactic **names** in matrix order: the coverage denominator, like ATLAS's."""

    return tuple(t.name for t in attack_tactics())


@cache
def tactic_shortnames() -> MappingProxyType[str, str]:
    """``shortname -> name`` (``execution`` -> ``Execution``)."""

    return MappingProxyType({t.shortname: t.name for t in attack_tactics()})


def tactic_name(shortname: str) -> str:
    """The display name of a tactic shortname, or the shortname when it is not in the pin."""

    return tactic_shortnames().get(shortname, shortname)


@cache
def attack_techniques() -> MappingProxyType[str, AttackTechnique]:
    """``id -> AttackTechnique`` for every current technique and sub-technique."""

    return MappingProxyType(
        {
            tid: AttackTechnique(tid, t["name"], tuple(t["tactics"]), bool(t["subtechnique"]))
            for tid, t in attack_pin()["techniques"].items()
        }
    )


@cache
def attack_retired() -> MappingProxyType[str, RetiredTechnique]:
    """``id -> RetiredTechnique`` for every revoked or deprecated ID the release still lists."""

    return MappingProxyType(
        {
            tid: RetiredTechnique(tid, t["name"], t["status"], t.get("replaced_by"))
            for tid, t in attack_pin()["retired"].items()
        }
    )


def restrict_tactics(
    technique: AttackTechnique, restriction: Iterable[str] | None
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(kept, rejected)``: the technique's tactics a spec's ``tactics`` restriction keeps.

    The one rule both the coverage fold and the Navigator layer apply, so they cannot drift:
    no restriction keeps every tactic the technique sits under; a restriction keeps the named
    ones that are the technique's and rejects the rest. A restriction made only of rejected
    names keeps **nothing** (the linter calls it a contradiction): it must not fall back to the
    technique's own tactics, which would turn a refused claim into a widened one.
    """

    if restriction is None:
        return technique.tactics, ()
    kept = tuple(t for t in technique.tactics if t in restriction)
    rejected = tuple(t for t in restriction if t not in technique.tactics)
    return kept, rejected


def unknown_attack_ids(ids: Iterable[str] | None) -> list[tuple[str, str]]:
    """``(id, why)`` for every declared ID that is not a current technique, once each, in order.

    Three reasons, each worded for the fix: malformed (the schema catches it first, this is the
    backstop), retired (names the replacement, which is the whole point of pinning the retired
    set), and unknown to the release (a transposed digit, or an ID from a newer release than the
    pin).
    """

    current = attack_techniques()
    retired = attack_retired()
    out: list[tuple[str, str]] = []
    for tid in dict.fromkeys(ids or ()):
        if not TECHNIQUE_ID_RE.match(tid):
            out.append((tid, "is not a T#### or T####.### technique ID"))
        elif tid in current:
            continue
        elif (gone := retired.get(tid)) is not None:
            fate = f"{gone.status} in ATT&CK Enterprise {ATTACK_VERSION}"
            if gone.replaced_by:
                fate += f", replaced by {gone.replaced_by}"
            out.append((tid, f"({gone.name}) is {fate}"))
        else:
            out.append((tid, f"is not in ATT&CK Enterprise {ATTACK_VERSION}"))
    return out
