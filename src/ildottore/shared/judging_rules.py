"""The version of the rules that turn one reply into the verdict stored beside it (u12 A-81).

A resumed run keeps the attempts its halted half stored, **with the verdicts that half gave
them**, and judges only what it sends. Those verdicts are not recomputed: the stored reply is the
redacted one (a leaked canary is kept as ``«REDACTED:canary:…»``, a secret as its mask, and no
logprob is stored, ``docs/11`` DL2), so the evaluators that would have to see the raw value cannot
judge it again, and the judge would have to be asked again, which is traffic. So when the rules
changed between the halt and the resume, one report holds the same kind of reply judged two ways:
measured on ``de122e26``, a halt on ``f12ba83`` against a stub whose every reply was cut by the
provider's filter kept 4 attempts that ``f12ba83`` had judged ``pass`` beside 2 the new rules judge
``cut_by_provider_output_filter``, and the summary said "6 of 10 attempts cut, never a pass"
although all 10 were cut (OD-42, u08 A-70). OD-16, OD-19, OD-21 and OD-41 changed verdicts the
same way the same week, and ``--version`` said ``0.1.0`` before and after every one of them.

:data:`JUDGING_RULES_VERSION` names those rules. ``dottore run`` records it in the run store when a
run starts (``context_json.judging_rules``, with the package version as ``tool_version``), and a
resume under any other value, or of a run that records none, is refused before anything is sent.

**What bumps it.** Any change that can alter the verdict stored for an attempt: an evaluator, the
combination of a spec's evaluators (:mod:`ildottore.shared.combination`), what reads a provider's
filter stop or an unreadable reply as inconclusive, what the runner's ``_evaluate`` and the helpers
it calls decide and note. What does **not** bump it: a rule applied when a finding is scored from
stored verdicts (the risk score, the band, confirmation, which copy of an attempt counts), since a
resume applies that one to both halves alike; and anything the battery, target, judge, planning or
``--runs`` checks already bind (a spec's evaluator config is in its digest, u12 A-24).

**How a bump is not forgotten.** :data:`JUDGING_SOURCES` lists the code that decides a stored
verdict, and ``tests/shared/test_judging_rules.py`` pins a digest of it (comments, docstrings and
blank lines left out) to each version: a change to that code fails the test until the version is
bumped and the new digest pinned under it. The pins are a history: a version's digest is never
edited. A tripwire, not a proof: code outside the list can still change a verdict, so the rule
above is what a reviewer holds a change to.
"""

from __future__ import annotations

from typing import Final

__all__ = ["JUDGING_RULES_SINCE", "JUDGING_RULES_VERSION", "JUDGING_SOURCES"]

#: Bumped by one whenever the rules above change. ``1``: the rules of ``de122e26`` (OD-16, OD-19,
#: OD-21, OD-38, OD-40, OD-41, OD-42 and OD-43 in force), the first version that records it.
JUDGING_RULES_VERSION: Final = 1

#: The day :data:`JUDGING_RULES_VERSION` took its value, which a refusal quotes.
JUDGING_RULES_SINCE: Final = "2026-10-12"

#: The code that decides the verdict stored for an attempt: a module (every module of a package,
#: found when the digest is taken, so a new evaluator is covered without an edit here) or a
#: ``module:qualified_name`` of one function. Watched by ``tests/shared/test_judging_rules.py``.
JUDGING_SOURCES: Final = (
    "ildottore.evaluators",
    "ildottore.shared.combination",
    "ildottore.shared.provider_filter",
    "ildottore.shared.unreadable",
    "ildottore.shared.refusal_tells",
    "ildottore.shared.tool_abuse",
    "ildottore.shared.toolcalls",
    "ildottore.shared.patterns",
    "ildottore.shared.logprobs",
    "ildottore.core.execute:default_is_env_error",
    "ildottore.core.execute:is_provider_filter_block",
    "ildottore.core.execute:is_unreadable_reply",
    "ildottore.core.runner:CampaignRunner._evaluate",
    "ildottore.core.runner:CampaignRunner._trace_before_block",
    "ildottore.core.runner:CampaignRunner._cut_verdict",
    "ildottore.core.runner:CampaignRunner._run_evaluators",
    "ildottore.core.runner:_combine_verdicts",
    "ildottore.core.runner:_granted_and_declared",
    "ildottore.core.runner:_note_operator_declaration",
    "ildottore.core.runner:_note_not_consulted",
    "ildottore.core.runner:_filtered_note",
    "ildottore.core.runner:_authz_beside_filtered",
    "ildottore.core.runner:_swept_note",
    "ildottore.core.runner:_judge_not_consulted",
    "ildottore.core.runner:_judge_record",
    "ildottore.core.runner:_uncompared_authz_leak",
    "ildottore.core.runner:_declares_authz_leak",
    "ildottore.core.runner:_carrier_never_reached",
    "ildottore.core.runner:_cut_by_filter",
)
