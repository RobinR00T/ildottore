"""The CCN-STIC-2011 (ESP-IA) requirement universe and applicability matrix, pinned as data.

ESP-IA (*Evaluación de Seguridad de Productos - Inteligencia Artificial*, Spain's National
Cryptologic Centre, version 1.0, October 2026) certifies a product with AI functionality. The
vendor describes its architecture and answers 21 yes/no characterization questions (``C01`` to
``C21``, plus ``C16.a``); an applicability matrix of 24 cumulative rules turns the answers into
the threats and policies that apply, and those into the Functional Security Requirements
(*Requisitos Funcionales de Seguridad*, ``RFS-...``) an accredited laboratory then verifies, each
one PASS or FAIL against the CCN's own test guides, plus at least three person-days of
penetration testing.

This module carries three things, and the reading they support is the AISVS one
(``shared.aisvs``), for the same reason: an RFS is a property the product must PROVIDE, and a
black-box scanner never sees the mechanism that provides it.

* **The 27 RFS codes**, each with the threat or policy it derives from. A spec's ``esp_ia`` list
  means "a FAIL of this spec is evidence that these requirements are not met". A PASS means
  these probes did not falsify them, never that they are met: an RFS is PASS only when a
  laboratory says so against the CCN's acceptance criteria, which this tool does not apply.
* **Which RFS a black box cannot reach**, and why, so coverage keeps them in the denominator and
  says so (clause A-26).
* **The matrix itself** (:data:`ESP_IA_RULES`), so a target file's answers yield the requirements
  that apply to it (``dottore coverage --framework esp-ia --target FILE``).

**Transcribed on 2026-11-02** from ``CCN-STIC-2011 Metodología de Evaluación de Seguridad de
Productos - Inteligencia Artificial (ESP-IA)``, version 1.0 (October 2026, sealed by the CCN on
2026-10-08), Tables 1 to 4, published at ccn-cert.cni.es (series 2000).

**Reproduction.** The CCN forbids reproducing the guide, in part or in whole, without its written
authorization. Only the **codes** are kept here (question, rule, threat and requirement
identifiers, and which codes each rule joins), the way ATLAS tactic names are, and the reasons
below are this project's own words. The question and requirement **text is deliberately not
copied**: read it in the guide.

Re-diff against the guide when the CCN issues a version after 1.0.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

__all__ = [
    "ESP_IA_CODE_RE",
    "ESP_IA_NOT_TESTED_BY_DESIGN",
    "ESP_IA_OUT_OF_REACH",
    "ESP_IA_QUESTIONS",
    "ESP_IA_REQUIREMENTS",
    "ESP_IA_RULES",
    "ESP_IA_SOURCE",
    "ESP_IA_VERSION",
    "EspIaRule",
    "applicable_rules",
    "unknown_esp_ia_codes",
]

#: The edition the codes below belong to, printed next to every ESP-IA figure (clause A-14).
ESP_IA_VERSION = "1.0"

#: Exactly what the tables were transcribed from, for whoever re-diffs them.
ESP_IA_SOURCE = "CCN-STIC-2011 v1.0 (ESP-IA), October 2026, Tables 1 to 4"

#: Shape of one requirement code. The schema enforces the same shape; the table, existence.
# ``\Z``, not ``$``: in Python's ``re`` a ``$`` also matches before a trailing newline.
ESP_IA_CODE_RE = re.compile(r"^RFS-[A-Z]{3}-0[1-9]\Z")

#: The characterization questions, in the guide's order. ``C16.a`` is answered only when
#: ``C16`` is yes; a target file spells it ``C16a`` (a YAML key with a dot reads as a path).
ESP_IA_QUESTIONS: tuple[str, ...] = (
    *(f"C{n:02d}" for n in range(1, 17)),
    "C16a",
    *(f"C{n:02d}" for n in range(17, 22)),
)

#: Requirement code -> the threat or policy it derives from (Table 4). 22 threat requirements,
#: 5 policy requirements.
ESP_IA_REQUIREMENTS: MappingProxyType[str, str] = MappingProxyType(
    {
        "RFS-EVA-01": "T.EVASION",
        "RFS-INJ-01": "T.INJECTION",
        "RFS-INJ-02": "T.INJECTION",
        "RFS-EXT-01": "T.EXTRACTION",
        "RFS-MEM-01": "T.MEMBERSHIP",
        "RFS-INV-01": "T.INVERSION",
        "RFS-POI-01": "T.POISONING",
        "RFS-POI-02": "T.POISONING",
        "RFS-POI-03": "T.POISONING",
        "RFS-POI-04": "T.POISONING",
        "RFS-DIS-01": "T.DISCLOSURE",
        "RFS-DIS-02": "T.DISCLOSURE",
        "RFS-DIS-03": "T.DISCLOSURE",
        "RFS-DIS-04": "T.DISCLOSURE",
        "RFS-DIS-05": "T.DISCLOSURE",
        "RFS-AGE-01": "T.AGENCY",
        "RFS-AGE-02": "T.AGENCY",
        "RFS-AGE-03": "T.AGENCY",
        "RFS-AGE-04": "T.AGENCY",
        "RFS-AGE-05": "T.AGENCY",
        "RFS-EXH-01": "T.EXHAUSTION",
        "RFS-EXH-02": "T.EXHAUSTION",
        "RFS-OVS-01": "P.OVERSIGHT",
        "RFS-OVS-02": "P.OVERSIGHT",
        "RFS-TRA-01": "P.TRACEABILITY",
        "RFS-TRA-02": "P.TRACEABILITY",
        "RFS-TRA-03": "P.TRACEABILITY",
    }
)


@dataclass(frozen=True)
class EspIaRule:
    """One row of the applicability matrix (Table 2).

    ``all_of`` must all be yes; ``any_of``, when not empty, needs one more yes (only ``RP02``
    uses it). The guide also attaches a condition between declared elements to most rules ("the
    interface of C01 reaches the model of C02"): this tool tests one target, so it reads the
    condition as met whenever the answers are, and says so wherever it prints a rule.
    """

    code: str
    all_of: tuple[str, ...]
    threat: str
    requirements: tuple[str, ...]
    any_of: tuple[str, ...] = ()
    #: Whether the guide attaches a condition between elements (every rule but ``RP02``).
    conditional: bool = True


ESP_IA_RULES: tuple[EspIaRule, ...] = (
    EspIaRule("R01", ("C01", "C02"), "T.EVASION", ("RFS-EVA-01",)),
    EspIaRule("R02", ("C01", "C03"), "T.INJECTION", ("RFS-INJ-01",)),
    EspIaRule("R03", ("C03", "C04"), "T.INJECTION", ("RFS-INJ-02",)),
    EspIaRule("R04", ("C05", "C21"), "T.EXTRACTION", ("RFS-EXT-01",)),
    EspIaRule("R05", ("C05", "C10"), "T.MEMBERSHIP", ("RFS-MEM-01",)),
    EspIaRule("R06", ("C05", "C11"), "T.INVERSION", ("RFS-INV-01",)),
    EspIaRule("R07", ("C08",), "T.POISONING", ("RFS-POI-01",)),
    EspIaRule("R08", ("C07", "C08"), "T.POISONING", ("RFS-POI-02",)),
    EspIaRule("R09", ("C09",), "T.POISONING", ("RFS-POI-03",)),
    EspIaRule("R10", ("C07", "C09"), "T.POISONING", ("RFS-POI-04",)),
    EspIaRule("R11", ("C12",), "T.DISCLOSURE", ("RFS-DIS-01",)),
    EspIaRule("R12", ("C12", "C13"), "T.DISCLOSURE", ("RFS-DIS-02",)),
    EspIaRule("R13", ("C12", "C14"), "T.DISCLOSURE", ("RFS-DIS-03",)),
    EspIaRule("R14", ("C12", "C18"), "T.DISCLOSURE", ("RFS-DIS-04",)),
    EspIaRule("R15", ("C12", "C15", "C18"), "T.DISCLOSURE", ("RFS-DIS-05",)),
    EspIaRule("R16", ("C16",), "T.AGENCY", ("RFS-AGE-01",)),
    EspIaRule("R17", ("C15", "C16"), "T.AGENCY", ("RFS-AGE-02",)),
    EspIaRule("R18", ("C16", "C17"), "T.AGENCY", ("RFS-AGE-03",)),
    EspIaRule("R19", ("C15", "C17"), "T.AGENCY", ("RFS-AGE-04",)),
    EspIaRule("R20", ("C15", "C16", "C17"), "T.AGENCY", ("RFS-AGE-05",)),
    EspIaRule("R21", ("C19",), "T.EXHAUSTION", ("RFS-EXH-01",)),
    EspIaRule("R22", ("C19", "C20"), "T.EXHAUSTION", ("RFS-EXH-02",)),
    EspIaRule("RP01", ("C16", "C16a"), "P.OVERSIGHT", ("RFS-OVS-01", "RFS-OVS-02")),
    EspIaRule(
        "RP02",
        (),
        "P.TRACEABILITY",
        ("RFS-TRA-01", "RFS-TRA-02", "RFS-TRA-03"),
        any_of=("C02", "C16"),
        conditional=False,
    ),
)

# --- what a black-box runtime scanner cannot reach, and why --------------------------------

ESP_IA_OUT_OF_REACH: MappingProxyType[str, str] = MappingProxyType(
    {
        "RFS-POI-02": (
            "how the post-deployment training or adaptation pipeline guards its input: a "
            "property of the operator's pipeline, and a reply does not show it ran"
        ),
        "RFS-POI-03": (
            "provenance and integrity checks on third-party models and datasets before they are "
            "used: answered by supply-chain records, not by an endpoint"
        ),
        "RFS-POI-04": (
            "authenticating and verifying an update to an AI artifact before it changes the "
            "deployed behaviour: a release control no reply shows"
        ),
        "RFS-OVS-02": (
            "an operator's ability to stop or reject a critical action before it takes effect: "
            "an operator-side control, exercised by a person and not by a request"
        ),
        "RFS-TRA-01": "what the product records: its log is not in any reply",
        "RFS-TRA-02": "whether the records suffice to reconstruct the activity: not in any reply",
    }
)

#: Requirements this scanner **deliberately does not test**, with the reason: reachable in
#: principle, left out by a decision that could be revisited.
ESP_IA_NOT_TESTED_BY_DESIGN: MappingProxyType[str, str] = MappingProxyType(
    {
        "RFS-EXH-02": (
            "safe degradation once the AI functionality is exhausted: testing it means driving "
            "the target to exhaustion, which the safety charter forbids (docs/02: availability "
            "specs are budget-capped)"
        ),
    }
)


def unknown_esp_ia_codes(codes: Iterable[str] | None) -> list[str]:
    """The codes in ``codes`` that are not in the pinned table, once each, in the order given."""

    return [code for code in dict.fromkeys(codes or []) if code not in ESP_IA_REQUIREMENTS]


def applicable_rules(answers: Mapping[str, bool]) -> tuple[EspIaRule, ...]:
    """The matrix rules ``answers`` satisfy, in the guide's order (they are cumulative)."""

    def yes(question: str) -> bool:
        return answers.get(question, False)

    return tuple(
        rule
        for rule in ESP_IA_RULES
        if all(yes(q) for q in rule.all_of)
        and (not rule.any_of or any(yes(q) for q in rule.any_of))
    )
