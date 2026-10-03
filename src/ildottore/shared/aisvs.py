"""The OWASP AISVS 1.0 requirement universe, pinned as data (a fourth coverage axis).

The AI Security Verification Standard is a checklist of 191 requirements in twelve chapters,
each one written as "Verify that <a control exists>" and assigned a level (1 baseline, 2
production with sensitive data, 3 high assurance). It is a different kind of framework from the
other three this repository maps against, and the difference sets how the mapping may be read:

* OWASP LLM, ATLAS and IoPC name **attacks**. A spec exercising one of them is a test *of* it.
* AISVS names **controls**. A black-box runtime scanner cannot verify that a control exists: it
  never sees the classifier, the policy engine or the log. What it can do is catch the control
  **failing**. So a spec's ``aisvs`` list means "a FAIL of this spec is evidence that these
  controls are absent or ineffective". A PASS means these probes did not falsify them, never
  that they are verified. That is the only reading the field supports, and the docs say so.

Most of the standard is out of reach for this kind of tool by construction (training data,
infrastructure, logging, cryptographic identity), and the classification below says which, why,
and which gaps are a decision rather than physics. Everything stays in the denominator (clause
A-26), so the AISVS percentages are low, and they are meant to be: a tool that reported a high
AISVS figure from the outside would be reporting controls it cannot see.

**Transcribed from upstream on 2026-10-03**, ``OWASP/AISVS`` at commit ``05c62d1`` (``main``,
2026-10-01), directory ``1.0/en``: 191 requirement rows (51 level 1, 95 level 2, 45 level 3),
cross-checked by counting the table rows in the twelve chapter files. Requirement IDs follow the
standard's own citation form, ``v1.0-C<chapter>.<section>.<n>``, whose version prefix is what
keeps a citation stable when 1.01 renumbers.

**Licence.** AISVS is published under CC-BY-SA 4.0 and this repository is MIT. Only the
identifiers, the levels and the section headings are reproduced here, for mapping, the same way
ATLAS tactic names and IoPC titles are. The requirement **text is deliberately not copied**: a
copied requirement would carry the ShareAlike obligation into an MIT codebase. Read the text
upstream: https://github.com/OWASP/AISVS (attribution: the OWASP AISVS project and contributors).

Levels are cumulative in the standard (aligned with ASVS: verifying at level N assumes the
levels below it), but each requirement is *assigned* exactly one level, so the three coverage
axes partition the universe and a requirement is never counted twice.

Re-diff against upstream when 1.01 is released. A spec declaring an ID outside this table is a
lint error, because an ID that matches nothing would otherwise shrink the numerator in silence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from types import MappingProxyType

__all__ = [
    "AISVS_CODE_RE",
    "AISVS_LEVELS",
    "AISVS_NOT_TESTED_BY_DESIGN",
    "AISVS_OUT_OF_REACH",
    "AISVS_REQUIREMENTS",
    "AISVS_SOURCE",
    "AISVS_TITLES",
    "AISVS_VERSION",
    "aisvs_universe",
    "unknown_aisvs_codes",
]

#: The edition the IDs below belong to, printed next to every AISVS figure (clause A-14).
AISVS_VERSION = "1.0"

#: Exactly what the table was transcribed from, for whoever re-diffs it.
AISVS_SOURCE = "OWASP/AISVS@05c62d1, 1.0/en, 2026-10-01"

#: Shape of one ID. The schema enforces the same shape; the table below enforces existence.
# ``\Z``, not ``$``: in Python's ``re`` a ``$`` also matches before a trailing newline.
AISVS_CODE_RE = re.compile(r"^v1\.0-C[1-9][0-9]?\.[1-9][0-9]?\.[1-9][0-9]?\Z")

AISVS_LEVELS: tuple[int, ...] = (1, 2, 3)

#: ``(section, heading, levels)``: one character per requirement, in order, so ``"12223"`` on
#: ``C1.1`` reads "C1.1.1 is level 1, C1.1.2 to C1.1.4 are level 2, C1.1.5 is level 3". Kept in
#: this form because it diffs line by line against the upstream tables.
_SECTIONS: tuple[tuple[str, str, str], ...] = (
    ("C1.1", "Training Data Origin & Data Security", "12223"),
    ("C1.2", "Data Labeling and Annotation Security", "122"),
    ("C1.3", "Training Data Quality and Security Assurance", "22223"),
    ("C2.1", "Prompt Injection Defenses", "11111223"),
    ("C2.2", "Content & Policy Screening", "1123"),
    ("C3.1", "Model Authorization & Integrity", "122"),
    ("C3.2", "Model Validation & Testing", "123"),
    ("C3.3", "Controlled Deployment & Rollback", "222"),
    ("C3.4", "Secure Development Practices", "12"),
    ("C3.5", "Pipeline Fine-Tuning", "2333"),
    ("C4.1", "AI Workload Sandboxing & Validation", "1133"),
    ("C4.2", "AI Hardware Security", "23333"),
    ("C4.3", "Edge & Distributed AI Security", "12333"),
    ("C5.1", "Authentication", "33"),
    ("C5.2", "AI Resource Authorization & Classification", "2222233"),
    ("C5.3", "Multi-Tenant Isolation", "23"),
    ("C6.1", "Model Artifact Integrity", "1122"),
    ("C6.2", "AI BOM & Supply Chain Monitoring", "122"),
    ("C7.1", "Output Format Enforcement", "11"),
    ("C7.2", "Hallucination Detection & Mitigation", "223"),
    ("C7.3", "Output Safety", "1223"),
    ("C7.4", "Source Attribution & Citation Integrity", "1123"),
    ("C8.1", "Access Controls on Memory & RAG Indices", "122"),
    ("C8.2", "Embedding Sanitization & Validation", "12233"),
    ("C8.3", "Memory Expiry & Revocation", "223"),
    ("C9.1", "Execution Budgets, Loop Control, and Circuit Breakers", "112"),
    ("C9.2", "High-Impact Action Approval and Irreversibility Controls", "1222222333"),
    ("C9.3", "Component Isolation and Tool Authorization", "11222223"),
    ("C9.4", "Agent and Orchestrator Identity", "2233"),
    ("C9.5", "Agent Authorization, Delegation, and Continuous Enforcement", "222223"),
    ("C9.6", "Shutdown and Graceful Degradation", "123"),
    ("C10.1", "Component Integrity", "122"),
    ("C10.2", "Authentication & Authorization", "1112222"),
    ("C10.3", "Secure Transport", "11223"),
    ("C10.4", "Schema, Message, and Input Validation", "11122223"),
    ("C11.1", "Model Alignment, Safety, and Robustness Testing and Training", "11123"),
    ("C11.2", "Membership-Inference and Model-Inversion Mitigation", "11223"),
    ("C11.3", "Model-Extraction Defense", "1233"),
    ("C11.4", "Model Runtime Anomaly Detection", "223"),
    ("C12.1", "Request & Response Logging", "1222"),
    ("C12.2", "Detection and Alerting", "122223"),
    ("C12.3", "Model, Data, and Performance Drift Detection", "1223"),
    ("C12.4", "Proactive Security Behavior Monitoring", "222"),
    ("C12.5", "Training Data & Model Lifecycle Audit", "1122"),
)


def _expand() -> dict[str, tuple[int, str]]:
    table: dict[str, tuple[int, str]] = {}
    for section, heading, levels in _SECTIONS:
        for n, level in enumerate(levels, start=1):
            table[f"v{AISVS_VERSION}-{section}.{n}"] = (int(level), f"{section} {heading}")
    return table


#: ID → (level, section heading). The heading stands in for a title because the requirement
#: text itself is not reproduced (see the licence note above).
AISVS_REQUIREMENTS: MappingProxyType[str, tuple[int, str]] = MappingProxyType(_expand())

#: ID → section heading, the shape the coverage axes take for titles.
AISVS_TITLES: MappingProxyType[str, str] = MappingProxyType(
    {code: heading for code, (_level, heading) in AISVS_REQUIREMENTS.items()}
)


def aisvs_universe(level: int) -> tuple[str, ...]:
    """Every requirement ID assigned ``level``, in standard order."""

    return tuple(code for code, (lvl, _h) in AISVS_REQUIREMENTS.items() if lvl == level)


def unknown_aisvs_codes(codes: Iterable[str] | None) -> list[str]:
    """The IDs in ``codes`` that are not in the pinned table, once each, in the order given."""

    return [code for code in dict.fromkeys(codes or []) if code not in AISVS_REQUIREMENTS]


def _resolve(pattern: str) -> list[str]:
    """``C4`` is a chapter, ``C3.1`` a section, ``C9.2.3`` one requirement."""

    prefix = f"v{AISVS_VERSION}-{pattern}"
    depth = pattern.count(".")
    if depth == 2:
        matched = [prefix] if prefix in AISVS_REQUIREMENTS else []
    else:
        matched = [code for code in AISVS_REQUIREMENTS if code.startswith(prefix + ".")]
    if not matched:
        raise ValueError(f"AISVS classification pattern {pattern!r} matches no requirement")
    return matched


def _classify(groups: tuple[tuple[str, tuple[str, ...]], ...]) -> dict[str, str]:
    """Expand ``(reason, patterns)`` groups, refusing a pattern that matches nothing and a
    requirement claimed by two groups (a code with two reasons has no reason)."""

    out: dict[str, str] = {}
    for reason, patterns in groups:
        for pattern in patterns:
            for code in _resolve(pattern):
                if code in out:
                    raise ValueError(f"AISVS requirement {code} is classified twice")
                out[code] = reason
    return out


# --- what a black-box runtime scanner cannot reach, and why --------------------------------
#
# Grouped by reason rather than written per ID: 105 near-identical sentences would hide the
# few that differ. Membership is pinned per bucket in ``tests/cli/test_coverage_cmd.py``, so
# moving a requirement between buckets shows up as a test change next to the argument for it.

_PROCESS = (
    "a process the operator runs, and a reply cannot show that it ran. Running this battery on "
    "every model change and comparing runs with `dottore diff` is one way to satisfy it; the "
    "battery digest is what proves the same suite was used both times"
)

_OUT_OF_REACH_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "training-data controls (sourcing, labelling, poisoning defences): answered by the data "
        "pipeline and its records, and no reply settles them",
        ("C1.1", "C1.2", "C1.3.1", "C1.3.2", "C1.3.4", "C1.3.5"),
    ),
    (
        "model lifecycle and change control (registry, signatures, rollout and rollback, "
        "environment isolation, fine-tuning stages): properties of the operator's pipeline, not "
        "of a reply",
        ("C3.1", "C3.3", "C3.4", "C3.5"),
    ),
    (_PROCESS, ("C3.2", "C6.1.4", "C11.1.2", "C11.1.3", "C11.1.5")),
    (
        "an evaluation the operator runs on its models, and a reply cannot show it was done. "
        "BIAS-STEREOTYPE-001 is one such probe, of a hiring decision rather than a security "
        "one, so here it is an instrument and not evidence",
        ("C1.3.3",),
    ),
    (
        "infrastructure and hardware (workload sandboxes, attestation, accelerators, enclaves, "
        "edge packaging): not visible in a reply",
        ("C4",),
    ),
    (
        "how identity and privileged access are built (step-up authentication, token lifetimes, "
        "just-in-time access, where the policy engine runs, label propagation). What a reply can "
        "show is whether an authorization boundary was crossed, and that is mapped where AISVS "
        "asks for it (C5.2.2, C5.2.4 and C9.5)",
        ("C5.1", "C5.2.3", "C5.2.5", "C5.2.6", "C5.2.7", "C5.3.2"),
    ),
    (
        "supply chain (artifact scanning, approved sources, integrity, AI BOMs): answered by SBOM "
        "and vendor controls, not by an endpoint",
        ("C6.1.1", "C6.1.2", "C6.1.3", "C6.2"),
    ),
    (
        "an internal step (a confidence score, a second verification pass): a reply shows the "
        "answer, not whether the step ran",
        ("C7.2.1", "C7.2.3"),
    ),
    (
        "vector-store internals (metadata immutability, outlier quarantine, contradiction "
        "alerts): store-side checks with no reply that shows whether they ran",
        ("C8.1.2", "C8.2.2", "C8.2.5"),
    ),
    (
        "how the agent runtime is built (tool sandboxes and quotas, kill-switches, cryptographic "
        "identities and approvals, tool manifests, whether an AI reviewer exists): a reply "
        "shows the action the model proposes, not the mechanism behind it. Whether a dangerous "
        "action is proposed without approval IS observable, which is why C9.2.1 sits in the "
        "roadmap rather than here",
        (
            "C9.1.1",
            "C9.1.3",
            "C9.2.3",
            "C9.2.6",
            "C9.2.8",
            "C9.2.9",
            "C9.3.1",
            "C9.3.3",
            "C9.3.8",
            "C9.4",
            "C9.6",
        ),
    ),
    (
        "training-time or weight-level properties (differentially private training, weight "
        "watermarking) and internal detectors: no reply settles them",
        ("C11.2.4", "C11.3.1", "C11.3.3", "C11.4.3"),
    ),
    (
        "monitoring, logging and drift tracking happen behind the endpoint: a reply does not "
        "show what was logged, tracked or alerted on",
        ("C12.1.3", "C12.2.6", "C12.3", "C12.4", "C12.5"),
    ),
    (
        "logging, detection and alerting happen in the operator's monitoring, which a reply "
        "does not show. A campaign's stored probes, with their timestamps and run id, are the "
        "test traffic to check those logs and alerts against",
        ("C12.1.1", "C12.1.2", "C12.1.4", "C12.2.1", "C12.2.2", "C12.2.3", "C12.2.4", "C12.2.5"),
    ),
)

# --- what this scanner deliberately does not test, and why ---------------------------------

_NOT_TESTED_BY_DESIGN_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "MCP server and transport conformance (token validation, OAuth claims, Origin and Host "
        "checks, payload limits, response signing): protocol testing against an MCP server, a "
        "different target from the model endpoint this scanner talks to. A protocol test suite "
        "is the right tool; this product could add one and has not",
        (
            "C10.2",
            "C10.3.1",
            "C10.3.3",
            "C10.3.5",
            "C10.4.3",
            "C10.4.4",
            "C10.4.5",
            "C10.4.6",
        ),
    ),
    (
        "MCP client behaviour (which servers it installs and from where, sandboxing local "
        "servers, consent on install, re-approval when a tool definition changes): a property of "
        "the agent harness a user runs locally, a different target class (docs/REFERENCES.md, "
        "agent-harness attacks)",
        ("C10.1", "C10.3.2", "C10.3.4", "C10.4.7", "C10.4.8"),
    ),
    (
        "rate limits sized to the extraction threat: measuring them means sending at the rate an "
        "extractor would, which is load testing. This scanner caps its own request rate and "
        "spend on purpose",
        ("C11.2.2",),
    ),
    (
        "watermarks on generated media: this scanner does not test image, audio or video "
        "generation, so there is no generated media to inspect. Checkable from outside in "
        "principle, so a scope decision rather than physics",
        ("C7.4.4",),
    ),
)

#: Requirement ID → why a black-box runtime scanner cannot reach it. Merged into
#: ``shared.frameworks.OUT_OF_REACH`` so one lookup serves every axis.
AISVS_OUT_OF_REACH: MappingProxyType[str, str] = MappingProxyType(_classify(_OUT_OF_REACH_GROUPS))

#: Requirement ID → why this scanner deliberately does not test it. A decision, revisitable.
AISVS_NOT_TESTED_BY_DESIGN: MappingProxyType[str, str] = MappingProxyType(
    _classify(_NOT_TESTED_BY_DESIGN_GROUPS)
)

if set(AISVS_OUT_OF_REACH) & set(AISVS_NOT_TESTED_BY_DESIGN):  # pragma: no cover - import guard
    raise ValueError("an AISVS requirement is both out of reach and not tested by design")
