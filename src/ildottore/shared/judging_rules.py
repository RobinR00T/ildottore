"""The version of the rules that turn one reply into the verdict stored beside it (u12 A-81).

A resumed run keeps the attempts its halted half stored, **with the verdicts that half gave
them**, and judges only what it sends. Those verdicts are not recomputed: the stored reply is the
redacted one (a leaked canary is kept as ``«REDACTED:canary:…»``, a secret as its mask, and no
logprob is stored, ``docs/11`` DL2), so the evaluators that would have to see the raw value cannot
judge it again, and the judge would have to be asked again, which is traffic. So when the rules
changed between the halt and the resume, one report holds the same kind of reply judged two ways:
measured on ``de122e26``, a halt on ``f12ba83`` against a stub whose every reply was cut by the
provider's filter kept 4 attempts that ``f12ba83`` had judged ``pass`` beside 2 the new rules judge
``cut_by_provider_output_filter``, and the summary said ``Cut by the provider's output filter: 6
attempt(s) in 2 spec(s) came back cut or replaced ... never a pass`` although all 10 were cut
(OD-42, u08 A-70). OD-16, OD-19, OD-21 and OD-41 changed verdicts the same way the same week, and
``--version`` said ``0.1.0`` before and after every one of them.

:data:`JUDGING_RULES_VERSION` names those rules. ``dottore run`` records it in the run store when a
run starts (``context_json.judging_rules``, with the package version as ``tool_version`` and every
invocation's in ``tool_versions``), and a resume under any other value, or of a run that records
none (every run a version before :data:`JUDGING_RULES_SINCE` halted), is refused before anything is
sent.

**What bumps it.** Any change that can alter the verdict stored for an attempt: an evaluator, the
combination of a spec's evaluators (:mod:`ildottore.shared.combination`), what reads a provider's
stop reason, a filter block or an unreadable reply (the adapters' reply mapping included), what the
runner's ``_evaluate`` and the helpers it calls decide and note. What does **not** bump it: a rule
applied when a finding is scored from stored verdicts (the risk score, the band, confirmation,
which copy of an attempt counts), since a resume applies that one to both halves alike; and
anything the battery, target, judge, planning or ``--runs`` checks already bind (a spec's evaluator
config is in its digest, u12 A-24). An evaluator a plugin registers (``dottore.evaluators`` entry
points) is outside this package: the run records which plugins it loaded, and a resume under
others is refused the same way.

**How a bump is not forgotten.** :data:`JUDGING_SOURCES` lists the code that decides a stored
verdict, and ``tests/shared/test_judging_rules.py`` pins a digest of it (comments, docstrings and
blank lines left out) to each version: a change to that code fails the test until the version is
bumped and the new digest pinned under it, and the pins are an append-only history the test
checks. The same test walks what every listed entry refers to, so a name on the verdict path that
is neither listed nor exempted in :data:`JUDGING_EXEMPT` (with its reason) fails it too. A
tripwire, not a proof: data flow the walk cannot see (a value passed in, not referred to) still
needs the rule above, which is what a reviewer holds a change to.

**Landing.** Version ``1`` is the rules as of the merge that introduced the version. Whatever
lands before that merge is in it: at the merge, :data:`JUDGING_SOURCES` is brought up to date with
the closure test, version ``1`` is pinned on the final tree, and :data:`JUDGING_RULES_SINCE` is set
to the merge day, the one place the docs name for that date.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "JUDGING_EXEMPT",
    "JUDGING_RULES_SINCE",
    "JUDGING_RULES_VERSION",
    "JUDGING_SOURCES",
]

#: Bumped by one whenever the rules above change. ``1``: the rules as of the merge that introduced
#: the version, the first that records it (OD-16, OD-19, OD-21, OD-38, OD-40, OD-41, OD-42 and
#: OD-43 in force).
JUDGING_RULES_VERSION: Final = 1

#: The day :data:`JUDGING_RULES_VERSION` took its value, which a refusal quotes and the docs name
#: (as ``JUDGING_RULES_SINCE``) instead of writing the date: set once, at the merge.
JUDGING_RULES_SINCE: Final = "2026-10-12"

#: The code that decides the verdict stored for an attempt, watched by
#: ``tests/shared/test_judging_rules.py``. An entry is a module (every module of a package, found
#: when the digest is taken, so a new evaluator is covered without an edit here), or
#: ``module:name`` for one function, class or module-level assignment, or ``module:Class.method``.
#: The test also walks what each entry refers to: every ``ildottore`` name a listed module imports,
#: or a listed function, class or assignment refers to, must be listed here or exempted in
#: :data:`JUDGING_EXEMPT` with its reason, so a new verdict module cannot be left out unseen.
JUDGING_SOURCES: Final = (
    # The evaluators, and the one rule that combines them.
    "ildottore.evaluators",
    "ildottore.shared.combination",
    # What a provider's filter stop, an unreadable reply and a tool call are read as.
    "ildottore.shared.provider_filter",
    "ildottore.shared.unreadable",
    "ildottore.shared.refusal_tells",
    "ildottore.shared.tool_abuse",
    "ildottore.shared.toolcalls",
    "ildottore.shared.patterns",
    "ildottore.shared.logprobs",
    "ildottore.shared.wellformed",
    "ildottore.shared.nesting:NestedTooDeeply",
    "ildottore.shared.nesting:bounded_loads",
    "ildottore.shared.amounts:is_count",
    "ildottore.shared.enums:SETUP_NOT_REACHED",
    # The redactor's own detectors the PII and secret evaluators decide with.
    "ildottore.redactor:EMAIL",
    "ildottore.redactor:LABELLED_CARD",
    "ildottore.redactor:follows_phone_label",
    "ildottore.redactor:glued_to_identifier",
    "ildottore.redactor:is_date_stamp",
    "ildottore.redactor:skipped",
    # How an attempt's reply becomes the flags the runner judges it by (env error, filter block,
    # filter cut, unreadable), and a conversation's.
    "ildottore.core.execute:default_is_env_error",
    "ildottore.core.execute:is_provider_filter_block",
    "ildottore.core.execute:is_unreadable_reply",
    "ildottore.core.execute:_unreadable_result",
    "ildottore.core.execute:execute_attempt",
    "ildottore.core.conversation:reproduce_conversation",
    # What the runner decides and notes for one attempt.
    "ildottore.core.runner:CampaignRunner._evaluate",
    "ildottore.core.runner:CampaignRunner._trace_before_block",
    "ildottore.core.runner:CampaignRunner._cut_verdict",
    "ildottore.core.runner:CampaignRunner._run_evaluators",
    "ildottore.core.runner:CampaignRunner._run_spec",
    "ildottore.core.runner:CampaignRunner._sweep_identities",
    "ildottore.core.runner:CampaignRunner._reproduce_single_turn",
    "ildottore.core.runner:CampaignRunner._reproduce_multi_turn",
    "ildottore.core.runner:CampaignRunner._tagged_unsent",
    "ildottore.core.runner:sweeps_identities",
    "ildottore.core.reproduce:reproduce",
    "ildottore.adapters.base:BaseAdapter.sends_sampling",
    "ildottore.adapters.openai:OpenAIAdapter.sends_sampling",
    "ildottore.adapters.anthropic:AnthropicAdapter.sends_sampling",
    "ildottore.adapters.openai:OpenAIAdapter.logprobs_enabled",
    "ildottore.adapters.websocket:WebSocketAdapter.max_frame_bytes",
    "ildottore.core.runner:CUT_DECIDING_EVALUATORS",
    "ildottore.core.runner:PROVIDER_FILTER_CUT",
    "ildottore.core.runner:_JUDGE_NOTE_CHARS",
    "ildottore.core.runner:_NOT_CONSULTED",
    "ildottore.core.runner:_TRACE_EVALUATORS",
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
    "ildottore.core.runner:_is_multi_identity",
    "ildottore.core.runner:_carrier_never_reached",
    "ildottore.core.runner:_cut_by_filter",
    "ildottore.core.runner:_tagged_seeded",
    # A deployment's own tool names judged as the spec's, and whether its scene was seeded.
    "ildottore.core.setup_delivery:IN_BAND",
    "ildottore.core.setup_delivery:SEEDED",
    "ildottore.core.setup_delivery:TRACE_EVALUATORS",
    "ildottore.core.setup_delivery:canonical_tool_calls",
    "ildottore.core.setup_delivery:tool_name_map",
    "ildottore.core.setup_delivery:is_seeded",
    # How each adapter maps a provider's reply to text, tool calls, logprobs, a stop reason and
    # its side, a filter block or an unreadable reply.
    "ildottore.adapters.base:AdapterError",
    "ildottore.adapters.base:AdapterEnvError",
    "ildottore.adapters.base:AdapterProductError",
    "ildottore.adapters.base:ResponseTooLarge",
    "ildottore.adapters.base:ResponseUndecodable",
    "ildottore.adapters.base:ResponseTooDeep",
    "ildottore.adapters.base:ResponseMalformed",
    "ildottore.adapters.base:ProviderFilterBlock",
    "ildottore.adapters.base:SamplingRefused",
    "ildottore.adapters.base:azure_prompt_filter",
    "ildottore.adapters.base:BaseAdapter._handle_final_response",
    "ildottore.adapters.base:BaseAdapter._checked",
    "ildottore.adapters.base:BaseAdapter._unreadable",
    "ildottore.adapters.base:BaseAdapter._prompt_blocked",
    "ildottore.adapters.openai:OpenAIAdapter._parse_response",
    "ildottore.adapters.openai:OpenAIAdapter._extract_logprobs",
    "ildottore.adapters.anthropic:AnthropicAdapter._parse_response",
    "ildottore.adapters.rest:get_path",
    "ildottore.adapters.rest:RestAdapter._prompt_blocked",
    "ildottore.adapters.rest:RestAdapter._parse_body",
    "ildottore.adapters.rest:RestAdapter._guardrail_side",
    "ildottore.adapters.rest:_acted",
    "ildottore.adapters.websocket:WebSocketAdapter._turn",
    "ildottore.adapters.mcp:MCPAdapter._render",
    # ... and what those refer to that decides too (the closure test lists what is missing).
    "ildottore.shared.amounts:MAX_EXACT_COUNT",
    "ildottore.shared.nesting:MAX_DEPTH",
    "ildottore.shared.nesting:_profile",
    "ildottore.redactor:SKIP",
    "ildottore.redactor:_DATE_SHAPED",
    "ildottore.redactor:_DATE_STAMP",
    "ildottore.redactor:_GLUE",
    "ildottore.redactor:_LABEL_TAIL",
    "ildottore.redactor:_PHONE_LABEL_BEFORE",
    "ildottore.core.execute:AttemptResult",
    "ildottore.core.execute:NOT_RETRYABLE_MARK",
    "ildottore.core.execute:UnreadableReplies",
    "ildottore.core.execute:_attempt",
    "ildottore.core.conversation:execute_conversation",
    "ildottore.core.setup_delivery:scene_tool_names",
    "ildottore.adapters.base:AdapterStatusError",
    "ildottore.adapters.base:FILTER_REFUSED",
    "ildottore.adapters.base:MAX_RESPONSE_BYTES",
    "ildottore.adapters.base:_AZURE_FILTER_CODE",
    "ildottore.adapters.base:_CATEGORY",
    "ildottore.adapters.base:_MAX_CATEGORIES",
    "ildottore.adapters.base:_SAMPLING_PARAMS",
    "ildottore.adapters.base:map_logprobs",
    "ildottore.adapters.base:sampling_params_named",
    "ildottore.adapters.base:BaseAdapter.reads_array_body",
    "ildottore.adapters.base:BaseAdapter._parse_array_response",
    "ildottore.adapters.rest:RestAdapter.reads_array_body",
    "ildottore.adapters.rest:RestAdapter._parse_array_response",
    "ildottore.adapters.rest:RestAdapter._parse_response",
    "ildottore.adapters.rest:_CONVERSE_STOP_PATH",
    "ildottore.adapters.rest:_GEMINI_PROMPT_BLOCKS",
    "ildottore.adapters.rest:_GEMINI_TEXT_ROOT",
    "ildottore.adapters.rest:_GUARDRAIL_INTERVENED",
    "ildottore.adapters.rest:_GUARDRAIL_POLICIES",
    "ildottore.adapters.rest:_INPUT_ACTIONS",
    "ildottore.adapters.rest:_OUTPUT_ACTIONS",
    "ildottore.adapters.websocket:MAX_FRAMES_PER_TURN",
    "ildottore.adapters.websocket:WebSocketOverflow",
    "ildottore.adapters.websocket:WebSocketServerError",
    "ildottore.adapters.websocket:WebSocketTurnTimeout",
    "ildottore.adapters.websocket:WebSocketAdapter._ignored",
    "ildottore.adapters.websocket:WebSocketAdapter._is_final",
    "ildottore.adapters.websocket:WebSocketAdapter._recv_frame",
    "ildottore.adapters.websocket:WebSocketAdapter._tool_call",
    "ildottore.adapters.websocket:WebSocketAdapter._unreadable",
    "ildottore.adapters.websocket:WebSocketAdapter._closed",
    "ildottore.adapters.websocket:WebSocketFrameTooDeep",
    "ildottore.adapters.websocket:MAX_FRAME_DEPTH",
    "ildottore.adapters.websocket:_depth",
    "ildottore.adapters.websocket:_same",
    "ildottore.adapters.base:_LEADING",
    "ildottore.adapters.base:_QUOTED",
    "ildottore.adapters.base:_UnreadableLogprob",
    "ildottore.adapters.base:_coerce_top",
    "ildottore.adapters.base:_figure",
    "ildottore.core.conversation:_aggregate_attempt",
    "ildottore.core.conversation:_argument_bytes",
    "ildottore.core.conversation:_neutral_calls",
    "ildottore.core.setup_delivery:MAX_CALLS_PER_ROUND",
    "ildottore.core.setup_delivery:MAX_ROUND_ARGUMENT_BYTES",
    "ildottore.core.setup_delivery:MAX_TOOL_ROUNDS",
    "ildottore.redactor:_CLOCK",
    "ildottore.redactor:_DATE",
    "ildottore.redactor:_PHONE_WORDS",
    "ildottore.shared.nesting:_NOT_BRACKET",
    "ildottore.shared.nesting:_STEP",
    "ildottore.shared.nesting:_STRING",
    "ildottore.adapters.websocket:WebSocketClosed",
    "ildottore.adapters.websocket:WebSocketUndecodable",
    "ildottore.adapters.websocket:_INVALID_PAYLOAD",
    "ildottore.adapters.websocket:_MESSAGE_TOO_BIG",
)

#: The reasons an exemption gives, one per kind.
_SHAPE = (
    "a data shape: a spec's and a target's are in their digests (u12 A-24), a reply's and a "
    "verdict's are the stored record (report-1.0, the schema tests); no rule decides here"
)
_NAME = (
    "an enumeration a verdict stores by value: a value that changes fails to load, loudly, and "
    "re-judges nothing"
)
_IFACE = "an interface (a Protocol), no code"
_MONEY = (
    "money and pacing: what a halt spends and when it stops, never what a reply is judged as (a "
    "reply a ceiling stops is stored without a verdict and sent again, u12 A-24)"
)
_TEXT = "the words of a message, or the masking of what a verdict quotes: never a status"
_SCORED = (
    "applied when a finding is scored from stored verdicts, to both halves of a resume alike: no "
    "stored verdict changes"
)
_GATE = (
    "which specs are sent at all: bound by the battery and the target (u12 A-24); a spec it stops "
    "stores no attempt a resume keeps"
)
_TARGET = (
    "the target's own configuration (its file's websocket block, a template given through the "
    "Python API), not a rule of this package; a target file's is in its digest (u12 A-24)"
)
_WIRE = (
    "what is sent, not how the reply is read: bound by the battery, the target and --runs (u12 "
    "A-24)"
)

#: Names a listed entry refers to that do not decide a verdict, each with its reason. The closure
#: test walks into nothing here. ``module:name`` exempts one name; a bare module, all of it.
JUDGING_EXEMPT: Final = {
    "ildottore.shared.models:Attempt": _SHAPE,
    "ildottore.shared.models:EvalContext": _SHAPE,
    "ildottore.shared.models:ModelRequest": _SHAPE,
    "ildottore.shared.models:ModelResponse": _SHAPE,
    "ildottore.shared.models:Sampling": _SHAPE,
    "ildottore.shared.models:TokenLogprob": _SHAPE,
    "ildottore.shared.models:Verdict": _SHAPE,
    "ildottore.shared.enums:EvaluatorLogic": _NAME,
    "ildottore.shared.enums:EvaluatorType": _NAME,
    "ildottore.shared.enums:InconclusiveReason": _NAME,
    "ildottore.shared.enums:Severity": _NAME,
    "ildottore.shared.enums:VerdictStatus": _NAME,
    "ildottore.shared.protocols:Evaluator": _IFACE,
    "ildottore.shared.protocols:TargetAdapter": _IFACE,
    "ildottore.core.budgets:BudgetExhausted": _MONEY,
    "ildottore.core.execute:CeilingAtUnreadable": _MONEY,
    "ildottore.core.execute:ReplyOverBudget": _MONEY,
    "ildottore.core.execute:RetryPolicy": _MONEY,
    "ildottore.core.execute:_reconcile_tokens": _MONEY,
    "ildottore.core.execute:_send_with_timeout": _MONEY,
    "ildottore.core.execute:reserve_tokens": _MONEY,
    "ildottore.core.reproduce:DEFAULT_N": _WIRE,
    "ildottore.core.reproduce:attempt_id_for": _WIRE,
    "ildottore.adapters.websocket:WebSocketAdapter._send_template": _WIRE,
    "ildottore.core.conversation:_turn_request": _WIRE,
    "ildottore.core.conversation:_assistant_turn": _WIRE,
    "ildottore.core.conversation:_fallback_id": _WIRE,
    "ildottore.redactor:Redactor": _TEXT,
    "ildottore.redactor:visible_stash_delimiters": _TEXT,
    "ildottore.shared.config_errors:quoted": _TEXT,
    "ildottore.adapters.base:BaseAdapter._request_path": _TEXT,
    "ildottore.adapters.base:BaseAdapter.unreadable_advice": _TEXT,
    "ildottore.adapters.base:redact_ids": _TEXT,
    "ildottore.adapters.base:reply_excerpt": _TEXT,
    "ildottore.adapters.websocket:WebSocketAdapter._shown": _TEXT,
    "ildottore.adapters.websocket:WebSocketAdapter._safe": _TEXT,
    "ildottore.adapters.websocket:WebSocketAdapter.unreadable_advice": _TEXT,
    "ildottore.adapters.websocket:_scrub": _TEXT,
    "ildottore.adapters.base:BaseAdapter._parse_response": "abstract: each adapter's own is listed",
    "ildottore.core.runner:CampaignRunner._score_finding": _SCORED,
    "ildottore.core.runner:CampaignRunner._gated_prior": _SCORED,
    "ildottore.core.runner:CampaignRunner._holds_plan": _SCORED,
    "ildottore.core.runner:_one_per_attempt_id": _SCORED,
    "ildottore.core.runner:CampaignRunner._blocked_finding": _GATE,
    "ildottore.core.runner:CampaignRunner._capability_skipped_finding": _GATE,
    "ildottore.core.runner:CampaignRunner._media_error_finding": _GATE,
    "ildottore.core.runner:_BLOCKED": _GATE,
    "ildottore.core.runner:_undelivered": _GATE,
    "ildottore.core.setup_delivery:delivers_in_band": _GATE,
    "ildottore.core.setup_delivery:in_band_setup": _GATE,
    "ildottore.core.setup_delivery:needs_seeding": _GATE,
    "ildottore.core.setup_delivery:trace_gap": _GATE,
    "ildottore.core.runner:_WatchedAdapter": _MONEY,
    "ildottore.core.runner:CampaignRunner._param_accepted": _WIRE,
    "ildottore.core.runner:CampaignRunner._sampling": _WIRE,
    "ildottore.core.runner:_base": _WIRE,
    "ildottore.core.runner:_base_prompt": _WIRE,
    "ildottore.core.runner:_build_request": _WIRE,
    "ildottore.core.runner:_is_multi_turn": _WIRE,
    "ildottore.shared.media:MediaError": _WIRE,
    "ildottore.core.runner:CampaignRunner._apply_mutation": _WIRE,
    "ildottore.core.runner:CampaignRunner._turn_mutator": _WIRE,
    "ildottore.core.runner:spec_sampling": _WIRE,
    "ildottore.core.runner:unsent_fields": _WIRE,
    "ildottore.core.runner:SAMPLING_NOT_SENT": _TEXT,
    "ildottore.core.reproduce:_pin_attempt_index": _WIRE,
    "ildottore.adapters.base:BaseAdapter.id": _TEXT,
    "ildottore.adapters.base:BaseAdapter.redactor": _TEXT,
    "ildottore.adapters.base:BaseAdapter._redact_ids": _TEXT,
    "ildottore.adapters.mcp:MCPAdapter.redactor": _TEXT,
    "ildottore.adapters.websocket:WebSocketAdapter.id": _TEXT,
    "ildottore.adapters.websocket:WebSocketAdapter.redactor": _TEXT,
    "ildottore.adapters.websocket:WebSocketAdapter.api_key": _TEXT,
    "ildottore.adapters.websocket:WebSocketAdapter.spec": _TARGET,
    "ildottore.adapters.rest:RestAdapter.template": _TARGET,
}
