"""The Nova IoPC taxonomy universe (``docs/15``), pinned as data.

"Indicators of Prompt Compromise" is a third framework we map the battery against, alongside
the OWASP LLM Top 10 and MITRE ATLAS. This module carries the **denominator**: the full set of
codes, so coverage can answer "of *what*?" rather than only listing what a run happened to
touch. That mirrors how ``reporting.summary`` pins ``OWASP_LLM_TOTAL`` and
``ATLAS_TACTIC_UNIVERSE``; it lives in ``shared`` because both the linter (which validates that
a spec's declared codes exist) and the reporting layer need it, and those two are peers that
must not import each other.

The taxonomy has **two axes**, and they answer different questions:

* **Techniques** (``IOPC-T<family>.<nnn>``), the *how*: direct injection, memory poisoning,
  orchestration abuse. Nine tactic families, T1 to T9.
* **Impacts** (``IOPC-R<nnn>``), the *damage*: fraud, malware generation, disinformation.
  This is the axis a non-technical reader understands, so it is reported separately rather
  than folded into the technique count.

**Transcribed from the LIVE taxonomy on 2026-09-19** (53 entries: 30 techniques + 23 impacts).

Read that sentence carefully, because the obvious label would be wrong. The site banner says
``v2.0.0-alpha``, but that is the only *published* release (2026-08-15) and it contains
something else: **46 entries, 8 techniques and 38 impacts**, with 19 of the impact titles under
their older names. The whole T4 to T9 range did not exist yet. Upstream has ~460 unreleased
changelog entries sitting on top of that release, so the banner is stale rather than
descriptive. Pinning to the release artifact would therefore drop most of the techniques our
own specs map to; pinning to the live state is correct, and calling it "v2.0.0-alpha" is not.

The impact numbering has gaps (R001-R004, R006, R007, R011, R016-R021, R029, R038 are absent).
Those are real: upstream marks them ``merged``, meaning they were retired into canonical T
codes and are no longer active. 38 registry records minus 15 merged is the 23 impacts here.

Re-diff against upstream when a new release is finally cut. A spec declaring a code outside
these sets is a lint error, because a typo would otherwise silently under-report coverage.

Attribution: IoPC taxonomy by Thomas Roccia / SecurityBreak
(``promptintel.novahunting.ai/taxonomy``). Only the identifiers and their short titles are
reproduced here, for mapping, the same way MITRE ATLAS tactic names are.
"""

from __future__ import annotations

import re
from types import MappingProxyType

__all__ = [
    "IMPACT_CODE_RE",
    "IOPC_IMPACTS",
    "IOPC_IMPACT_UNIVERSE",
    "IOPC_TAXONOMY_VERSION",
    "IOPC_TECHNIQUES",
    "IOPC_TECHNIQUE_UNIVERSE",
    "TECHNIQUE_CODE_RE",
    "unknown_codes",
]

#: What these sets were transcribed from. Deliberately NOT "2.0.0-alpha": see the module
#: docstring, that published release holds 46 different entries.
IOPC_TAXONOMY_VERSION = "live-2026-09-19"

#: Well-formedness of a code, enforced by the JSON schema too (defence in depth: the schema
#: rejects a malformed code, the universe rejects a well-formed but non-existent one).
# ``\Z``, not ``$``: in Python's ``re`` a ``$`` also matches BEFORE a trailing newline, so
# "IOPC-T1.002\n" would pass and then match nothing, silently shrinking the numerator.
TECHNIQUE_CODE_RE = re.compile(r"^IOPC-T[1-9]\d*\.\d{3}\Z")
IMPACT_CODE_RE = re.compile(r"^IOPC-R\d{3}\Z")

#: Technique code → short title (the *how*). Families T1..T9.
IOPC_TECHNIQUES: MappingProxyType[str, str] = MappingProxyType(
    {
        # T1 Prompt Manipulation
        "IOPC-T1.001": "Direct Prompt Injection",
        "IOPC-T1.002": "Indirect Prompt Injection",
        "IOPC-T1.003": "Agent Data Injection",
        "IOPC-T1.004": "Jailbreak & Safety Bypass",
        "IOPC-T1.005": "Triggered & Delayed Instruction Activation",
        # T2 Poisoning & supply chain
        "IOPC-T2.001": "Retrieval / RAG Poisoning",
        "IOPC-T2.002": "Persistent Memory Poisoning",
        "IOPC-T2.003": "Training & Fine-tuning Data Poisoning",
        "IOPC-T2.004": "AI Supply Chain Compromise",
        "IOPC-T2.005": "Hallucinated Dependency Exploitation",
        # T3 Agentic
        "IOPC-T3.001": "Agentic Tool Misuse",
        "IOPC-T3.002": "Tool and Context Poisoning",
        "IOPC-T3.003": "Cross-Agent Context Propagation",
        "IOPC-T3.004": "Human-Agent Trust Exploitation",
        # T4 Identity, execution, drift
        "IOPC-T4.001": "Agent Identity & Privilege Abuse",
        "IOPC-T4.002": "Unexpected Code Execution",
        "IOPC-T4.003": "Agent Goal Drift",
        # T5 Disclosure & output
        "IOPC-T5.001": "System Prompt & Configuration Disclosure",
        "IOPC-T5.002": "Sensitive Data Disclosure",
        "IOPC-T5.003": "Insecure Output Handling",
        # T6 Consumption
        "IOPC-T6.001": "Unbounded Consumption & Cost Abuse",
        # T7 Model attacks
        "IOPC-T7.001": "Model Extraction & Inversion",
        "IOPC-T7.002": "Adversarial Evasion",
        # T8 Reconnaissance & staging
        "IOPC-T8.001": "AI System Reconnaissance",
        "IOPC-T8.002": "Model & Agent Fingerprinting",
        "IOPC-T8.003": "Offline Attack Staging",
        "IOPC-T8.004": "AI System Access Acquisition",
        # T9 Persistence & evasion
        "IOPC-T9.001": "Agent Configuration & Prompt Logic Tampering",
        "IOPC-T9.002": "Detection & Attribution Evasion",
        "IOPC-T9.003": "Self-Replicating Prompt (AI Worm)",
    }
)

#: Impact code → short title (the *damage*).
IOPC_IMPACTS: MappingProxyType[str, str] = MappingProxyType(
    {
        "IOPC-R005": "Transform-based instruction smuggling",
        "IOPC-R008": "Disinformation generation at scale",
        "IOPC-R009": "Malware and exploit code generation",
        "IOPC-R010": "Target reconnaissance via model",
        "IOPC-R012": "Fraud and social engineering content",
        "IOPC-R013": "Malicious workflow automation",
        "IOPC-R014": "LLM-enabled offensive tooling",
        "IOPC-R015": "Model resource hijacking",
        "IOPC-R022": "Encoding and obfuscation",
        "IOPC-R023": "Unicode and homoglyph manipulation",
        "IOPC-R024": "Multi-step prompt chaining",
        "IOPC-R025": "Roleplay and fictional framing",
        "IOPC-R026": "Instruction fragmentation",
        "IOPC-R027": "Adversarial token perturbation",
        "IOPC-R028": "Cross-modal payload delivery",
        "IOPC-R030": "Telemetry and provenance evasion",
        "IOPC-R031": "System prompt leak",
        "IOPC-R032": "Credential leak in output",
        "IOPC-R033": "PII exposure in output",
        "IOPC-R034": "Sensitive document disclosure",
        "IOPC-R035": "Guardrail and reasoning disclosure",
        "IOPC-R036": "Harmful content generation",
        "IOPC-R037": "Working exploit or payload output",
    }
)

#: Ordered denominators for coverage (sorted so reports are deterministic).
IOPC_TECHNIQUE_UNIVERSE: tuple[str, ...] = tuple(sorted(IOPC_TECHNIQUES))
IOPC_IMPACT_UNIVERSE: tuple[str, ...] = tuple(sorted(IOPC_IMPACTS))


def unknown_codes(techniques: list[str] | None, impacts: list[str] | None) -> list[str]:
    """Codes this taxonomy does not contain, de-duplicated, in first-seen order.

    Covers two shapes with the same consequence: a code that is well formed but does not
    exist (a transposed digit, a code from a newer upstream release), and a code that is
    simply malformed. Either would sit in a spec for ever matching nothing and quietly
    shrinking the coverage numerator, so the linter turns both into an error.

    De-duplicated because a spec that repeats the same bad code should produce one complaint,
    not one per occurrence.
    """
    seen: dict[str, None] = {}
    for code in techniques or []:
        if code not in IOPC_TECHNIQUES:
            seen.setdefault(code, None)
    for code in impacts or []:
        if code not in IOPC_IMPACTS:
            seen.setdefault(code, None)
    return list(seen)
