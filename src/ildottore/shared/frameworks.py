"""The OWASP LLM and MITRE ATLAS universes, pinned as data (the framework denominators).

Companion to :mod:`ildottore.shared.iopc`, and here for the same structural reason: the
linter validates a spec's declared framework codes against these sets, the reporting layer
measures coverage against them, and ``registry`` and ``reporting`` are peers that must not
import each other (``docs/01 §2``). Keeping the universes in one place is also what makes
"accepted by lint" and "counted in coverage" two statements about the same set.

Each universe carries the edition/release it was transcribed from, and that label is printed
next to every figure derived from it. That is not decoration: both frameworks renumber and
rename between editions, and a percentage whose taxonomy version is unstated is a percentage
that cannot be checked.
"""

from __future__ import annotations

__all__ = [
    "ATLAS_MATRIX_RELEASE",
    "ATLAS_OUT_OF_MATRIX",
    "ATLAS_TACTIC_UNIVERSE",
    "NIST_FUNCTIONS",
    "NIST_SUBCATEGORY_RE",
    "NOT_TESTED_BY_DESIGN",
    "OUT_OF_REACH",
    "OWASP_LLM_EDITION",
    "OWASP_LLM_TOTAL",
    "OWASP_LLM_UNIVERSE",
    "OWASP_RAI_UNIVERSE",
    "malformed_nist_mapping",
    "nist_subcategories",
    "not_tested_by_design_reason",
    "out_of_reach_reason",
    "unknown_atlas_tactic",
    "unknown_owasp_code",
]

import re

#: Which OWASP edition the ``owasp`` codes on our specs belong to, printed next to every
#: OWASP figure. Not decoration: OWASP published a **renumbered** list in August 2026 (the
#: exact day is secondary-sourced: the project page still lists 2025 as latest, so treat
#: "early August 2026" as the claim), and in the 2026 numbering ``LLM03`` is Excessive Agency
#: and ``LLM04`` is Supply Chain. Our specs are
#: mapped to the 2025 numbering (``LLM06`` = Excessive Agency, 25 of 75 specs). An unlabelled
#: gap list saying "not covered: LLM03, LLM04" therefore reads, to anyone holding the new
#: edition, as "Excessive Agency untested", which is our single most covered category. The
#: label travels with the number for the same reason the IoPC taxonomy pins its date.
OWASP_LLM_EDITION = "2025"

#: OWASP LLM Top 10 (2025) has exactly ten categories (LLM01…LLM10). The denominator for
#: OWASP surface coverage - a run that exercises 6 distinct categories covers 60%.
OWASP_LLM_TOTAL = 10

#: The ten codes themselves. Specs may also carry a Responsible-AI code (``RAI01``,
#: ``RAI02``), which is a DIFFERENT framework and must never count toward this denominator:
#: without this filter the battery's 8 LLM codes plus 2 RAI codes read as a perfect 10/10,
#: reporting 100% OWASP coverage while LLM03 and LLM04 are untested. ATLAS already filters
#: against its universe for the same reason.
OWASP_LLM_UNIVERSE: tuple[str, ...] = tuple(f"LLM{n:02d}" for n in range(1, OWASP_LLM_TOTAL + 1))

#: The companion Responsible-AI codes our responsible-ai specs carry in the same ``owasp``
#: field (6 of 75 specs). They are a DIFFERENT framework, so they are excluded from the OWASP
#: numerator above and listed here instead: the linter accepts them, coverage never counts
#: them. Without this second set, "accepted" and "counted" would be the same thing, which is
#: how ``LLM11``, ``LLM00`` and a lowercase code all used to pass lint with zero warnings and
#: then quietly vanish from the numerator.
OWASP_RAI_UNIVERSE: tuple[str, ...] = ("RAI01", "RAI02")

#: The ATLAS release these tactic names were transcribed from, printed next to the figure.
ATLAS_MATRIX_RELEASE = "2026.09"

#: The MITRE ATLAS tactic universe (the columns of the ATLAS matrix). Coverage is measured
#: against this known set so "passed the scan" cannot hide an unexercised tactic. Specs carry
#: the human-readable tactic name (see ``specs/`` + ``MitreAtlas.tactic``), so the universe is
#: keyed by **name**, which makes it sensitive to upstream renames as well as additions.
#:
#: Transcribed from ``mitre-atlas/atlas-data``, ``dist/v6/ATLAS-2026.09.yaml`` (release
#: 2026.09, format-version 6.0.0), cross-checked against that repo's ``CHANGELOG.md``, which
#: states "1 matrix, 16 tactics" for this release. Upstream disagrees with itself on the day:
#: the changelog header says 2026-09-14, the manifest and the file's own ``modified-date``
#: say 2026-09-15. The tactic SET last changed in 2026.08 (``matrix.modified-date``
#: 2026-08-31), which is the rename that mattered here.
#:
#: Read the source carefully, because two artefacts in the same directory disagree. The
#: legacy-format ``dist/ATLAS.yaml`` (version 5.6.0) still calls ``AML.TA0001`` "AI Attack
#: Staging"; the 2026.08 changelog records the rename to **"AI Attack Adaptation"**
#: ("Previously 'AI Attack Staging'"), and the v6 release carries the new name. The v6
#: release line is the current one, so that is what this pins.
#:
#: This tuple held **14** names until 2026-09-21, and two of them were retired spellings
#: ("ML Model Access", "ML Attack Staging", both renamed upstream to "AI ..."), while
#: ``Lateral Movement`` (AML.TA0015, added in 5.1.0 on 2025-11-06) and ``Command and
#: Control`` (AML.TA0014) were missing entirely. Since coverage matches by exact string, our
#: two lateral-movement specs scored **zero in silence** and the published figure was wrong in
#: the numerator AND the denominator: 12/14 (86%) against a true 13/16 (81%).
#:
#: Re-diff against upstream when ATLAS cuts a release; a name outside this set is now a lint
#: error, so a rename surfaces as a refusal rather than as a quietly shrinking numerator.
ATLAS_TACTIC_UNIVERSE: tuple[str, ...] = (
    "AI Model Access",  # AML.TA0000
    "AI Attack Adaptation",  # AML.TA0001 (was "AI Attack Staging" before 2026.08)
    "Reconnaissance",  # AML.TA0002
    "Resource Development",  # AML.TA0003
    "Initial Access",  # AML.TA0004
    "Execution",  # AML.TA0005
    "Persistence",  # AML.TA0006
    "Defense Evasion",  # AML.TA0007
    "Discovery",  # AML.TA0008
    "Collection",  # AML.TA0009
    "Exfiltration",  # AML.TA0010
    "Impact",  # AML.TA0011
    "Privilege Escalation",  # AML.TA0012
    "Credential Access",  # AML.TA0013
    "Command and Control",  # AML.TA0014
    "Lateral Movement",  # AML.TA0015
)

#: Tactic values our specs legitimately carry that are NOT ATLAS matrix columns: the
#: responsible-AI specs assert a class of harm rather than an adversary tactic. Same split as
#: :data:`OWASP_RAI_UNIVERSE`: the linter accepts these, the ATLAS numerator ignores them.
ATLAS_OUT_OF_MATRIX: tuple[str, ...] = (
    "Responsible AI (safety)",
    "Responsible AI (fairness)",
)


#: The four NIST AI RMF 1.0 functions. A spec's ``nist_ai_rmf`` reads
#: ``MEASURE 2.7 (security & resilience)``: a subcategory plus a free-text gloss, sometimes
#: two of them joined by ``/`` or ``;``.
NIST_FUNCTIONS: tuple[str, ...] = ("GOVERN", "MAP", "MEASURE", "MANAGE")

#: Shape of one subcategory token. **Shape, not membership**, and the difference is the whole
#: point: we have not transcribed the NIST AI RMF subcategory list from its primary source
#: (NIST AI 100-1), so claiming "this subcategory exists" would be a claim we cannot back.
#: This catches the drift that a free-text field really suffers (a lowercase function, a
#: misspelled one, a missing number, an empty value) and says nothing about the rest.
#:
#: The field feeds a rollup (``by_framework.nist``) and a SARIF tag, never a denominator, so
#: an unrecognised value cannot inflate or deflate a percentage the way an OWASP or ATLAS one
#: could. That is why this is a shape rule and not a universe.
NIST_SUBCATEGORY_RE = re.compile(rf"\b(?:{'|'.join(NIST_FUNCTIONS)})\s+\d+\.\d+")


def nist_subcategories(value: str | None) -> list[str]:
    """Every ``FUNCTION n.n`` token in a spec's ``nist_ai_rmf`` string, in order."""

    if not value:
        return []
    return [m.group(0) for m in NIST_SUBCATEGORY_RE.finditer(value)]


def malformed_nist_mapping(value: str | None) -> str | None:
    """Return ``value`` when it carries no well-formed subcategory token, else ``None``."""

    if value is None:
        return None
    return None if nist_subcategories(value) else value


def unknown_owasp_code(code: str | None) -> str | None:
    """Return ``code`` when it belongs to no framework we recognise, else ``None``.

    Accepts the OWASP LLM codes and the companion Responsible-AI codes; rejects everything
    else, including the near-misses that used to pass silently (``LLM11``, ``LLM00``, a
    lowercase spelling). Rejecting is the point: an unrecognised value never reaches a
    numerator, so without a refusal it shrinks coverage without anyone being told.
    """

    if code is None:
        return None
    if code in OWASP_LLM_UNIVERSE or code in OWASP_RAI_UNIVERSE:
        return None
    return code


def unknown_atlas_tactic(tactic: str | None) -> str | None:
    """Return ``tactic`` when it is neither an ATLAS matrix column nor a declared non-matrix
    value, else ``None``.

    Matching is by exact string, which is what makes an upstream **rename** as damaging as a
    typo: "ML Attack Staging" was a real tactic name until 2026.08 and scores zero today.
    """

    if tactic is None:
        return None
    if tactic in ATLAS_TACTIC_UNIVERSE or tactic in ATLAS_OUT_OF_MATRIX:
        return None
    return tactic


#: Framework values a black-box runtime scanner **cannot reach**, with the reason. Physics, not
#: preference: there is no request whose answer would settle them.
#:
#: The distinction from the dict below matters, and getting it wrong was the first version of
#: this file. "Out of reach" and "we chose not to" are different sentences, and printing a
#: decision under the first one tells a reader the category is impossible when what is true is
#: that this product does not do it. An audit put it plainly: it dresses a design decision as a
#: law of nature.
#:
#: Everything here stays in the **denominator**. Dropping it would raise every percentage by
#: redefining the universe as the part we can already do, which is the denominator-over-
#: survivors move the reporting layer refuses everywhere else (clause A-12).
OUT_OF_REACH: dict[str, str] = {
    "LLM03": (
        "supply chain: provenance, packages and adapters cannot be asked of an endpoint. One "
        "of the nine items in the 2025 list, a deprecated model still in service, IS visible "
        "to `dottore fingerprint`, and is not yet asserted as a finding"
    ),
    "LLM04": (
        "data and model poisoning: the training and fine-tuning stages need the pipeline. The "
        "embedding stage, which the 2025 text also covers, is exercised by this battery and "
        "counted under LLM08"
    ),
    "IOPC-T2.003": (
        "training and fine-tuning data poisoning: the same pipeline access LLM04 needs, and the "
        "same limit from the outside"
    ),
    "IOPC-T8.003": (
        "offline attack staging: it happens on the attacker's own machine, so there is nothing "
        "to send and nothing to observe at the target"
    ),
}

#: Framework values this scanner **deliberately does not test**, with the reason. Every one is a
#: decision that could be revisited, and none of them is a property of the category.
NOT_TESTED_BY_DESIGN: dict[str, str] = {
    "AI Attack Adaptation": (
        "adapting an attack from the target's answers. Not implemented on purpose: the turns of "
        "a multi-turn attack are pinned in the spec, which is what makes a finding replayable. "
        "Parts of this tactic are reachable through an inference API, so this is a roadmap "
        "decision, not a limit of black-box testing"
    ),
    "AI Model Access": (
        "how an adversary reaches a model. This scanner's own precondition is an authorized "
        "endpoint in scope, so it does not test acquiring access to one"
    ),
    "IOPC-T8.004": (
        "acquiring access to an AI system: the scanner only touches endpoints it is already "
        "authorized for, which is an authorization policy rather than a limit of reach"
    ),
}

# Deliberately in NEITHER dict, and therefore in the roadmap: "Command and Control". The first
# version called it adversary-side infrastructure that the replies cannot show, while this
# repository ships `AG-PERSIST-BEACON-001` (an agent writing a cron entry that calls a C2-shaped
# address) and `AG-EXFIL-EGRESS-001` (egress over a C2 channel), whose fixtures are exactly that
# behaviour observed in a target's own tool calls. A claim of unobservability contradicted by
# our own battery is a claim to withdraw, not to qualify.


def not_tested_by_design_reason(code: str) -> str | None:
    """Why ``code`` is deliberately untested, or ``None``."""

    return NOT_TESTED_BY_DESIGN.get(code)


def out_of_reach_reason(code: str) -> str | None:
    """Why ``code`` is not something a black-box runtime scanner can cover, or ``None``."""

    return OUT_OF_REACH.get(code)
