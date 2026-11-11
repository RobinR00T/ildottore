# ADR-0026: A session handed from one identity to another is swept in order (u08 A-134, OD-76)

* **Status:** accepted, 2026-11-09, as the smallest reversible version (the owner approved the
  technique on 2026-11-09; how it is sent is open as OD-76).
* **Date:** 2026-11-09
* **Context:** a deployment that keeps conversations is told which one a message belongs to by an
  id the client sends. A server that does not check that id against the caller lets anyone who
  knows it read the conversation: one identity adopts another's session (CWE-639, authorization
  bypass through a user-controlled key; CWE-384, the session fixation family). The identity sweep
  (audit M14, u08 A-87) sends one request to every identity at once and compares the replies;
  nothing carried a value from one identity's reply into another's request, and no request
  carried a conversation id at all. Clause u08 §7 A-134 in
  `specs/contracts/u08-execution-engine.md`; OD-76 in its §9.

## The decision

* **A spec says it hands a session over.** `setup.session_handoff.plant` is what the owner sends
  first, holding the spec's canary. `DL-SESSION-ADOPT-001` is the one spec that declares it; it
  requires `multi_identity` and judges with `secret_leakage` first and `authz_leak` after, as
  `DL-XTENANT-001` does.
* **The sweep runs in order.** The owner is the first scope identity the attempts are not sent
  as, so the attempts are an adoption too, never the owner reading its own conversation. It sends
  the plant with an id of the scanner's, derived from the run and the spec (a replay sends the
  same one, and neither can be read back from it). Every other identity then sends the attack
  with the owner's id, and so does every attempt. The canary is the owner's in the owner map, so
  in any other identity's reply it is a crossing.
* **The id travels where the target file says.** `rest.session.field` names the body key of the
  generic REST body; a target file without it gets nothing sent for this spec
  (`session_handoff_unavailable`, the plan and the runner alike), since an adopter sent no id
  says nothing about the binding. `rest.session.reply_path` says the server issues its own id:
  the owner's reply's id is handed over, and a reply that returns none sends nobody after it
  (an id the server did not issue would open a fresh conversation and read as a pass).
* **No id is written down.** An issued id is a credential of the owner's conversation. The
  request carries it on the wire only; the stored records hold the owner and 12 hex digits of its
  SHA-256; every reply drops the id it returned before it is stored.
* **Priced as a sweep.** One send per identity, the plant included, so `--estimate` and the
  budget ledger need no change.

## Measured

Against a loopback REST stub, two identities, `--runs 1` (3 requests: the plant, the adoption,
the attempt): a server that does not bind the conversation fails the spec, confirmed and
Critical, exit 2, with the scanner's id and with an issued one; a server that binds it to its
owner passes, exit 0, both ways; without `rest.session` nothing is sent: the spec is
`inconclusive` in a wider run, and a run of it alone is refused (exit 3). `tests/core/test_session_handoff.py`.

## Alternatives not taken

* **A conversation id the scanner reads from every reply, for every spec.** It would change what
  every REST attempt sends; only a spec that tests the binding needs one.
* **The id as a header or a cookie.** The common carrier after the body field; left open (OD-76)
  rather than built speculatively, since each carrier has its own redaction and allowlist
  questions.
* **The plant as a memory seed.** `memory_seed` is delivered in-band to a bare model and seeded by
  the operator in a deployment; neither puts the canary in a conversation one identity opened.

## Reversal

Drop `setup.session_handoff` from the schema, the model and the spec, the `session` block from
`RestSpec`, `core.session_handoff` and `CampaignRunner._sweep_handoff`; nothing else reads them.
