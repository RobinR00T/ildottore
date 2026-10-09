"""Shared StrEnums for Il Dottore.

Values are byte-identical to ``schemas/attack-spec.schema.json`` enums and to
``docs/04-05``/``docs/10``. A drift between an enum here and the schema is a test
failure, not a choice (contract §4 KEEP).
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Author's a-priori impact class (schema ``severity``)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(StrEnum):
    """Attack taxonomy family (schema ``category``)."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_LEAKAGE = "data_leakage"
    AGENT_TOOL_ABUSE = "agent_tool_abuse"
    RAG_SECURITY = "rag_security"
    OUTPUT_SECURITY = "output_security"
    AVAILABILITY_COST = "availability_cost"
    # Responsible-AI families (adjacent to security; NIST AI RMF, docs/12 P2). Optional pack,
    # not part of the OWASP-security core: safety = harmful-content generation on a direct ask;
    # bias_fairness = demographic bias / stereotyping / unfair differential treatment.
    SAFETY_CONTENT = "safety_content"
    BIAS_FAIRNESS = "bias_fairness"


# Families whose raw payloads are dangerous outside a controlled test and therefore MUST
# carry ``test_only: true`` (registry contract §4 KEEP; docs/02 S5, docs/03 §2). Derived from
# docs/02 S5 "dangerous outside a test" + the shipped DOS-TOKEN-FLOOD-001 fixture which sets
# test_only. Prompt-injection / RAG / output specs are diagnostic (they probe handling), so they
# are not force-flagged. Lives here, not in ``registry``, because two layers read it: the linter
# (``MISSING_TEST_ONLY``) and the policy gate, which refuses an unmarked spec at run time.
FLAGGED_FAMILIES: frozenset[Category] = frozenset(
    {
        Category.JAILBREAK,
        Category.DATA_LEAKAGE,
        Category.AGENT_TOOL_ABUSE,
        Category.AVAILABILITY_COST,
        # Harmful-content safety probes carry disallowed requests, so they must be test_only
        # (bias_fairness prompts are benign demographic questions, so they are not flagged).
        Category.SAFETY_CONTENT,
    }
)


class TargetType(StrEnum):
    """Kind of target under test (schema ``target_type``)."""

    MODEL = "model"
    CHATBOT = "chatbot"
    API = "api"
    AGENT = "agent"
    RAG = "rag"


class VerdictStatus(StrEnum):
    """Evaluator verdict polarity (``docs/04 §0``).

    ``pass`` = the target behaved securely (the attack failed);
    ``fail`` = the target was exploited. Fixed repo-wide.
    """

    PASS = "pass"  # noqa: S105 - verdict polarity value, not a credential
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class EvaluatorType(StrEnum):
    """The MVP evaluator types (schema ``evaluators.items.type`` enum)."""

    REGEX_ABSENCE = "regex_absence"
    REGEX_PRESENCE = "regex_presence"
    EXACT_MATCH = "exact_match"
    REFUSAL = "refusal"
    SECRET_LEAKAGE = "secret_leakage"  # noqa: S105 - evaluator type name, not a credential
    TOOL_CALL = "tool_call"
    TOOL_SEQUENCE = "tool_sequence"
    SEMANTIC_JUDGE = "semantic_judge"
    PII_DETECTOR = "pii_detector"
    SECRET_SHAPE = "secret_shape"  # noqa: S105 - evaluator type name, not a credential
    VERBATIM_OVERLAP = "verbatim_overlap"
    LOGPROB_MEMBERSHIP = "logprob_membership"
    AUTHZ_LEAK = "authz_leak"
    KILL_CHAIN_PROGRESSION = "kill_chain_progression"


class EvaluatorLogic(StrEnum):
    """Boolean combination of evaluator verdicts (schema ``evaluator_logic``)."""

    ALL_PASS = "all_pass"  # noqa: S105 - logic mode name, not a credential
    ANY_FAIL = "any_fail"
    WEIGHTED = "weighted"


class Capability(StrEnum):
    """Target-declared capability flags (``docs/01 §3``; ``Capabilities`` model fields).

    Distinct vocabulary from the spec-level ``requires`` enum (``RequiresCapability``):
    this set carries ``seed`` (a sampling capability) but not ``system_prompt``. Contract
    §3: ``requires`` ⊇ ``Capabilities`` + ``{system_prompt, seed}`` - related but distinct.
    """

    TOOLS = "tools"
    RAG = "rag"
    MEMORY = "memory"
    STREAMING = "streaming"
    SEED = "seed"
    LOGPROBS = "logprobs"
    MULTI_IDENTITY = "multi_identity"
    MULTIMODAL = "multimodal"
    AUDIO = "audio"
    SAMPLING = "sampling"


class RequiresCapability(StrEnum):
    """Spec-level ``requires`` vocabulary - **1:1 with the JSON Schema** ``requires`` enum.

    Deliberately distinct from ``Capability``: the schema's ``requires`` enum carries
    ``system_prompt`` (a setup prerequisite) but **not** ``seed``. A drift between this
    enum and ``schemas/attack-spec.schema.json`` is a test failure (contract §4 KEEP).
    """

    RAG = "rag"
    TOOLS = "tools"
    MEMORY = "memory"
    SYSTEM_PROMPT = "system_prompt"
    STREAMING = "streaming"
    LOGPROBS = "logprobs"
    MULTI_IDENTITY = "multi_identity"
    MULTIMODAL = "multimodal"
    AUDIO = "audio"


class ScanBand(StrEnum):
    """Severity band mapped from a ``RiskScore`` (``docs/05 §3``)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Alias - the contract §3 interface registry also refers to this as ``Band``.
Band = ScanBand


class ReportFormat(StrEnum):
    """Reporter output formats (``docs/01 §3``)."""

    JSON = "json"
    HTML = "html"
    SARIF = "sarif"
    JUNIT = "junit"


class InconclusiveReason(StrEnum):
    """Closed reason for an ``inconclusive`` verdict (``docs/01 §4``).

    Extensible only via ADR (contract §9). Seeded per ADR-0006 reconciliation.
    """

    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    JUDGE_COMPROMISED = "judge_compromised"


#: The reasoning prefix of an ``inconclusive`` verdict whose in-band scene never reached the model
#: (OD-18): its untrusted content was in a tool result no call fetched. The summary does not
#: count such an attempt as exercising the spec.
SETUP_NOT_REACHED: str = "setup_not_reached"


# A mutation variant decides confirmation and reproducibility ON ITS OWN only with at least
# this many attempts. Read by the runner (``confirmed``) and the scorer (``k / N``), which is
# why it lives here. With ``--runs 1`` every variant is 1 of 1, so "the best variant" made any
# single exploit among six sends confirmed and Critical, where the pooled rate says 1/6 and
# Low (review of PR #32). Below the minimum, the pooled rate over every attempt decides.
MIN_VARIANT_ATTEMPTS: int = 2
