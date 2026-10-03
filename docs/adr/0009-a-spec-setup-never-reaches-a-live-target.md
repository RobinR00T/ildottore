# ADR-0009: a spec's setup never reaches a live target (OD-18)

* **Status:** proposed, awaiting the owner's decision
* **Date:** 2026-10-03
* **Context:** OD-18 in `specs/contracts/00-INDEX.md`; found by the AISVS mapping audit of the
  same day and verified in the code before this was written

## The problem

A spec declares the scene its attack needs: `setup.documents` (a poisoned file for RAG),
`setup.tools` (mock tools, with what each one `returns`), `setup.memory_seed` (a planted prior
session). The runner never sends any of it. `core/runner.py` `_build_request` builds the request
from the prompt, the system prompt, the sampling and the media, and nothing else; the three setup
fields are read only by the evaluators, the lint fixture engine and the linter.

**32 of the 75 specs depend on that setup** (6 on documents, 26 on tools, 2 on memory), and 26 of
them are not policy-blocked, so they do go out against a target that declares the capability.
What goes out is a user turn that refers to a document, a tool or a memory the target does not
have ("summarise the uploaded document", "look up ticket 4831 with the lookup_ticket tool").

Two consequences, and the second is worse:

* **a PASS on those specs means nothing** unless the operator has seeded the same content into
  the deployment, which nothing asks for and nothing checks;
* **a FAIL can be false.** The `tool_call` evaluator flags any tool name outside the spec's
  allowlist as `unauthorized tool call` (`evaluators/tool_call.py`). A real agent calls its own
  tools under its own names, so on a live target every legitimate call is "unauthorized". The REST
  adapter returns no tool calls at all, so there the arm is silent instead.

Two documents state the opposite. `docs/01` §4 step 2 says the runner materialises the setup
"via the adapter's capabilities"; no such code exists. `docs/16` says a fully capable target
"skips nothing: 67 run", which is true of what is sent and not of what is tested. Both are
corrected in the change that adds this ADR.

The adapters are not the obstacle: the OpenAI and Anthropic adapters already forward
`request.tools` when it is set. Nothing sets it.

## Options

**A. Deliver the setup in-band.** Tools go on the wire as tool definitions, with a small loop
that answers the model's tool call with the spec's `returns` and lets it continue; documents go in
as retrieved context, marked as such; a memory seed becomes prior turns. This measures how the
**model** handles untrusted content in its context, which is the core of indirect injection, and
makes the 26 specs meaningful against a bare model endpoint. It does **not** test the target's
own retrieval or tool pipeline, and the report has to say so. Cost: a tool loop in `core` (a
contract change in u08), evidence that records the simulated trace, and one more thing a live
run validates.

**B. Operator-seeded, declared, and refused when absent.** The target file declares which specs'
setup the operator has seeded, with a map from the spec's tool names to the target's real ones.
A setup-dependent spec whose setup is not declared seeded is `inconclusive:
setup_not_seeded`, never sent as if it meant something. Cost: a config field, a runner gate, an
alias map the `tool_call` evaluator reads, and documentation. Honest from the first day; it asks
work of the operator.

**C. Both:** A for a bare model endpoint (`type: model`), B for a deployed application.

## Recommendation

**C, in two steps: B first, then A.** B is cheap and turns every current overstatement into a
true sentence: an unseeded spec stops passing in silence and the false "unauthorized tool" FAIL
disappears behind the alias map. A is the larger piece and the one that makes the battery useful
against a raw model, but it changes what those specs measure, so it lands with its own
measurement. **Either step should come before the live validation in `docs/16`.** Without one,
26 of the 67 specs that runbook would send produce numbers that do not mean what their names say.

## Consequences

If B: `target.yaml` gains a seeded-setup declaration and a tool-name map, the runner gains a gate
before sending, `tool_call` reads the map, and `docs/16`'s estimate table splits "sent" from
"tested". If A as well: u08 gains a tool loop, the evidence store records the simulated tool
trace, and the manual says which specs test the model and which test the application.
