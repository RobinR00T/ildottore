"""The MITRE CWE entries a spec may name, pinned as data with MITRE's own mapping usage (u02 A-110).

A spec's ``cwe`` list names the weakness a FAIL of that spec is evidence of in the application
under test. It is a label for the operator's tracker and for SARIF consumers (GitHub code
scanning reads ``external/cwe/cwe-NNN`` rule tags); it decides nothing and is outside the spec
digest, as ``aisvs`` is.

MITRE says, per entry, whether it may be used to map a real-world vulnerability ("Vulnerability
Mapping Notes", ``Usage``). This table records that usage for every entry the battery names, and
for the entries an AI finding is most often mapped to by mistake, so the lint can refuse those:

* ``Allowed`` and ``Allowed-with-Review``: a spec may name it.
* ``Discouraged`` and ``Prohibited``: the lint refuses it. Two that matter here:
  **CWE-1426** (Improper Validation of Generative AI Output) is ``Discouraged``, its notes
  pointing at CWE-77, CWE-94 or CWE-116 instead, and the AI/ML grouping **CWE-1446** is
  ``Prohibited``. **CWE-1427** (Improper Neutralization of Input Used for LLM Prompting) is
  ``Allowed``: it is the prompt-injection weakness.

An entry outside the table is a lint warning, not an error: CWE has some 950 weaknesses, a
third-party spec pack may name one the battery does not, and its usage is not known here.

**Transcribed on 2026-10-30** from MITRE's ``cwec_v5.0.xml`` (CWE 5.0, released 2026-10-28):
each ID's ``Name`` and its ``Mapping_Notes/Usage``. Re-check when a new CWE version lands: usage
changes (1426's own notes warn it may). CWE is (c) The MITRE Corporation; the names are
reproduced for mapping, as its terms of use allow, with this attribution.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from types import MappingProxyType
from typing import Final

__all__ = [
    "CWE_CODE_RE",
    "CWE_ENTRIES",
    "CWE_MAPPABLE_USAGES",
    "CWE_SOURCE",
    "CWE_VERSION",
    "cwe_sarif_tag",
    "unknown_cwe_codes",
    "unmappable_cwe_codes",
]

CWE_VERSION: Final = "5.0"
CWE_SOURCE: Final = "MITRE cwec_v5.0.xml, CWE 5.0, 2026-10-28"

#: ``CWE-<n>``, no leading zero. Mirrors the spec schema's ``cwe`` item pattern.
CWE_CODE_RE: Final = re.compile(r"\ACWE-[1-9][0-9]{0,4}\Z")

#: The usages under which MITRE lets an entry map a real-world vulnerability.
CWE_MAPPABLE_USAGES: Final = frozenset({"Allowed", "Allowed-with-Review"})

#: ID -> (MITRE's name, MITRE's mapping usage), CWE 5.0.
CWE_ENTRIES: Final = MappingProxyType(
    {
        # Named by the battery.
        "CWE-78": (
            "Improper Neutralization of Special Elements used in an OS Command",
            "Allowed",
        ),
        "CWE-79": ("Improper Neutralization of Input During Web Page Generation", "Allowed"),
        "CWE-89": (
            "Improper Neutralization of Special Elements used in an SQL Command",
            "Allowed",
        ),
        "CWE-94": ("Improper Control of Generation of Code", "Allowed-with-Review"),
        "CWE-201": ("Insertion of Sensitive Information Into Sent Data", "Allowed"),
        "CWE-266": ("Incorrect Privilege Assignment", "Allowed"),
        "CWE-290": ("Authentication Bypass by Spoofing", "Allowed"),
        "CWE-359": (
            "Exposure of Private Personal Information to an Unauthorized Actor",
            "Allowed",
        ),
        "CWE-451": (
            "User Interface (UI) Misrepresentation of Critical Information",
            "Allowed-with-Review",
        ),
        "CWE-488": ("Exposure of Data Element to Wrong Session", "Allowed"),
        "CWE-489": ("Active Debug Code", "Allowed"),
        "CWE-497": (
            "Exposure of Sensitive System Information to an Unauthorized Control Sphere",
            "Allowed",
        ),
        "CWE-639": ("Authorization Bypass Through User-Controlled Key", "Allowed"),
        "CWE-770": ("Allocation of Resources Without Limits or Throttling", "Allowed"),
        "CWE-862": ("Missing Authorization", "Allowed-with-Review"),
        "CWE-915": (
            "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
            "Allowed",
        ),
        "CWE-918": ("Server-Side Request Forgery", "Allowed"),
        "CWE-1427": ("Improper Neutralization of Input Used for LLM Prompting", "Allowed"),
        # Mappable alternatives MITRE's notes point at, not named by the battery today.
        "CWE-77": (
            "Improper Neutralization of Special Elements used in a Command",
            "Allowed-with-Review",
        ),
        "CWE-116": ("Improper Encoding or Escaping of Output", "Allowed-with-Review"),
        "CWE-863": ("Incorrect Authorization", "Allowed-with-Review"),
        # Refused: what an AI finding is most often mapped to by mistake.
        "CWE-20": ("Improper Input Validation", "Discouraged"),
        "CWE-74": (
            "Improper Neutralization of Special Elements in Output Used by a Downstream Component",
            "Discouraged",
        ),
        "CWE-200": ("Exposure of Sensitive Information to an Unauthorized Actor", "Discouraged"),
        "CWE-269": ("Improper Privilege Management", "Discouraged"),
        "CWE-284": ("Improper Access Control", "Discouraged"),
        "CWE-285": ("Improper Authorization", "Discouraged"),
        "CWE-345": ("Insufficient Verification of Data Authenticity", "Discouraged"),
        "CWE-400": ("Uncontrolled Resource Consumption", "Discouraged"),
        "CWE-668": ("Exposure of Resource to Wrong Sphere", "Discouraged"),
        "CWE-693": ("Protection Mechanism Failure", "Discouraged"),
        "CWE-1426": ("Improper Validation of Generative AI Output", "Discouraged"),
        "CWE-1446": ("Weaknesses That are Specific to AI/ML Technology", "Prohibited"),
    }
)


def unknown_cwe_codes(codes: Iterable[str]) -> list[str]:
    """The codes not in the pinned table, in first-seen order, each once."""

    return [c for c in dict.fromkeys(codes) if c not in CWE_ENTRIES]


def unmappable_cwe_codes(codes: Iterable[str]) -> list[tuple[str, str]]:
    """The codes MITRE says not to map a vulnerability to, with that usage, each once."""

    return [
        (c, CWE_ENTRIES[c][1])
        for c in dict.fromkeys(codes)
        if c in CWE_ENTRIES and CWE_ENTRIES[c][1] not in CWE_MAPPABLE_USAGES
    ]


def cwe_sarif_tag(code: str) -> str:
    """``CWE-79`` -> ``external/cwe/cwe-079``: the rule tag GitHub code scanning reads.

    The number is zero-padded to three digits, as CodeQL writes it (``cwe-079``, ``cwe-1427``).
    """

    return f"external/cwe/cwe-{int(code.removeprefix('CWE-')):03d}"
