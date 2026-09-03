"""Il Dottore evaluators (u06) - turn a target response into a :class:`Verdict`.

Public surface: the twelve built-in evaluators, the hardened LLM-as-judge, the verdict
:func:`~ildottore.evaluators.combine.combine` and the
:class:`~ildottore.evaluators.registry.EvaluatorRegistry` (built-ins + ``dottore.evaluators``
entry-point discovery). Each evaluator implements
:class:`ildottore.shared.protocols.Evaluator` (``type: str`` + ``async evaluate(ctx)``).
Polarity is fixed repo-wide: ``pass`` = secure (attack failed), ``fail`` = exploited
(``docs/04 §0``).
"""

from __future__ import annotations

from ildottore.evaluators.authz_leak import AuthzLeakEvaluator
from ildottore.evaluators.base import BaseEvaluator, mask_value, mask_values, shannon_entropy
from ildottore.evaluators.combine import AGGREGATE_TYPE, combine
from ildottore.evaluators.exact import ExactMatchEvaluator
from ildottore.evaluators.kill_chain import KillChainEvaluator
from ildottore.evaluators.logprob_membership import LogprobMembershipEvaluator
from ildottore.evaluators.pii_detector import PIIDetectorEvaluator
from ildottore.evaluators.refusal import RefusalEvaluator
from ildottore.evaluators.regex import RegexAbsenceEvaluator, RegexPresenceEvaluator
from ildottore.evaluators.registry import (
    ENTRY_POINT_GROUP,
    EvaluatorProtocolError,
    EvaluatorRegistry,
    build_default_registry,
)
from ildottore.evaluators.secret_leakage import SecretLeakageEvaluator
from ildottore.evaluators.secret_shape import SecretShapeEvaluator
from ildottore.evaluators.semantic_judge import JudgeVerdict, SemanticJudgeEvaluator
from ildottore.evaluators.tool_call import ToolCallEvaluator
from ildottore.evaluators.verbatim_overlap import VerbatimOverlapEvaluator

__all__ = [
    "AGGREGATE_TYPE",
    "ENTRY_POINT_GROUP",
    "AuthzLeakEvaluator",
    "BaseEvaluator",
    "EvaluatorProtocolError",
    "EvaluatorRegistry",
    "ExactMatchEvaluator",
    "JudgeVerdict",
    "KillChainEvaluator",
    "LogprobMembershipEvaluator",
    "PIIDetectorEvaluator",
    "RefusalEvaluator",
    "RegexAbsenceEvaluator",
    "RegexPresenceEvaluator",
    "SecretLeakageEvaluator",
    "SecretShapeEvaluator",
    "SemanticJudgeEvaluator",
    "ToolCallEvaluator",
    "VerbatimOverlapEvaluator",
    "build_default_registry",
    "combine",
    "mask_value",
    "mask_values",
    "shannon_entropy",
]
