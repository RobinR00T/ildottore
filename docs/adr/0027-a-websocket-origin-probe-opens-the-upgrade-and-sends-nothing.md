# ADR-0027: A WebSocket Origin probe opens the upgrade and sends nothing (u04 A-133, OD-75)

* **Status:** proposed, 2026-11-09. Built as the smallest reversible version; the owner decides
  (OD-75 in `specs/contracts/u04-target-adapters.md` §9 and in the index ledger).
* **Date:** 2026-11-09
* **Context:** a chat served over a WebSocket is open to cross-site WebSocket hijacking
  (CWE-1385) when the endpoint upgrades the socket whatever the request's `Origin` says. A browser
  attaches the user's cookies to a WebSocket upgrade from any page and applies no same-origin
  policy to the socket, so any site the user visits can open the chat as the user and read the
  replies. Every spec of the battery so far was a prompt, and the WebSocket adapter dialled with
  the library's default upgrade: no `Origin` header, and none the operator could choose per
  request. Nothing could ask the question.

## The decision

* **A capability that follows the provider.** `websocket_origin` (a `Capabilities` flag and a
  `requires` value, the schema's enum included) is true exactly when the target's provider is
  `websocket`; the target loader sets it, as it sets `mcp` (OD-44). Declared `false` on a
  WebSocket target, or `true` on a live target of another provider, it is refused; an offline mock
  may declare it only when it replays the fixtures (`vulnerable`, `hardened`), since a canned
  reply holds no probe and the oracle would fail it (OD-16). A fleet entry may not declare it.
  It is left out of the target digest when false or set by the provider, so a stored run resumes.
* **The runner marks the request; the adapter probes.** For a spec that requires the capability,
  `_build_request` adds `metadata["probe"] = "websocket_origin"` (`shared.probes`, because `core`
  writes it and an adapter reads it). `WebSocketAdapter.send` then runs the probe in place of a
  turn, after the allowlist, the credential check and the guard, as every send does.
* **Two upgrades, no frame.** The first offers the `Origin` of the page the chat is served from:
  the target file's new optional `websocket.origin` (an origin only: `http` or `https`, a host,
  an optional port), else one derived from the endpoint (`ws` to `http`, `wss` to `https`, the
  same host and port). The second offers `https://dottore-cross-site.invalid`, under `.invalid`
  (RFC 2606), which names no real site and never resolves. Neither upgrade sends the handshake
  template, the session start or a query. An `Origin` in the file's `headers` is replaced for the
  probe. An accepted upgrade is held one second (`ORIGIN_HOLD_S`) and then closed: a server that
  checks the `Origin` after the upgrade and closes at once (1008) reads as refusing it.
* **A control the server refuses is not a verdict.** The control upgrade refused, or closed, says
  the probe cannot tell an `Origin` check from a refusal of every upgrade:
  `WebSocketProbeUntestable`, an environment error, not retried, and the attempt is
  `inconclusive`. A 401 or 403 to the control is the guard's authentication failure when the file
  declares a guard. A 429 or 5xx, a refused connection or a timeout is an environment error the
  runner retries; any other status to the cross-site upgrade is its answer.
* **The reply is a rendering.** Three lines (a header, the control, the cross-site upgrade), each
  `accepted (HTTP 101, held open 1s)`, `closed by the server after the upgrade (close code N)` or
  `refused (HTTP N)`, and the outcomes under `raw_ids["websocket"]["origin_probe"]`.
* **The spec.** `AC-WS-ORIGIN-001` (`requires: [websocket_origin]`, CWE-1385, LLM02, the
  `access-control` suite) fails on `cross-site origin ...: accepted` (`regex_absence`) and passes
  only on the probe's own words for a refusal (`regex_presence`), so a reply with no probe line
  is never a pass (ADR-0007). CWE-1385 joins the pinned CWE table (Allowed).

## Not taken

* **Probing with a chat message.** Sending the handshake and a query on the cross-site upgrade
  would show more (that the session answers), but it puts a credential and a prompt on a socket
  opened as a foreign page; the upgrade's answer is the defect.
* **A `null` Origin or a look-alike host.** A sandboxed iframe sends `null` and some servers allow
  it; a suffix (`chat.example.com.attacker`) catches a prefix match. Both are further probes, each
  a line more; one cross-site origin is the smallest test of the check existing at all.
* **No control.** Without it, an endpoint that refuses every upgrade without a cookie would pass
  for checking the `Origin`.

## Costs, stated

Two upgrades and two seconds per attempt when both are accepted; the spec runs three times by
default. A server that accepts any `Origin` but authenticates by a token in the first frame is
less exploitable than one that trusts a cookie; the probe cannot see which, and the finding
says the upgrade was accepted, not that a session was read.

## Reversal

Delete the spec, the `websocket_origin` value from both enums and the schema, `_build_request`'s
mark, `shared.probes`, the adapter's `_probe_origin` and `_try_origin`, and `WebSocketSpec.origin`
(left out of the digest when absent, so stored runs are unaffected).
