# Il Dottore, Roadmap

Where the project is and what is left. The living, prioritized gap analysis is
[`docs/12-gaps-backlog.md`](docs/12-gaps-backlog.md); this file is the shorter, human-facing view.

**Legend:** ✅ shipped · 🟡 partial · ⬜ not started · ⛔ deferred on purpose (with the reason).

## Shipped

The battery is **75 specs across 14 suites**, aligned to OWASP LLM Top 10 (2025), MITRE ATLAS,
NIST AI 600-1 and the Nova IoPC taxonomy. Everything below runs offline against a mock and, where
noted, over the wire.

- ✅ **Core engine**: spec-driven attacks, deterministic reproduction (N sends), evaluator
  combination (deterministic-first, LLM judge as a hardened secondary), risk scoring, evidence
  store with redaction-at-rest, `replay`, `diff`, coverage reporting.
- ✅ **Adapters**: OpenAI-compatible, Anthropic, generic REST, and MCP (read-only discovery over
  Streamable HTTP and stdio). `--judge` wires an LLM-as-judge for live scans.
- ✅ **Attack families**: prompt injection (direct / indirect-RAG / indirect-tool), jailbreak,
  system-prompt & data leakage (canary-proven), insecure output handling, excessive agency,
  unbounded consumption, multi-turn (Crescendo / Linear / Sequential / Bad-Likert / Tree),
  access-control (BFLA / BOLA / RBAC / SSRF / debug / shell-injection / tool-metadata poisoning /
  argument-smuggling), OWASP-Agents-2026 agentic breadth, agentic-extortion (policy-gated),
  embeddings, MCP tool-metadata poisoning, guardrail/moderation-layer evasion, an optional
  Responsible-AI pack (safety-content + bias/fairness), a **NOVA/IoPC coverage-gap battery**
  (delayed-trigger injection, persistent memory poisoning, slopsquatting, self-replicating prompt,
  deceptive human approval, unicode/homoglyph deception, phishing-BEC, disinformation, target
  recon, log/provenance tampering: see [`docs/15`](docs/15-nova-iopc-gap-analysis.md)), and a
  **function-calling & structured-output** battery (argument smuggling, out-of-schema field
  coercion, enum escape).
- ✅ **Multimodal**: visual/typographic prompt injection (direct override + document-image), a
  harmful-request-via-image safety check, and spoken prompt injection carried in a pinned audio
  clip. Carriers render deterministically (image) or ship as a pinned asset (audio); a
  chain-of-custody `media_sha256` is recorded and the raw bytes are kept out of evidence.
- ✅ **Operator surface**: `fleet` (many targets in one file), `run --estimate` (pre-run request +
  token gloss, zero sends), `calibrate` (score findings against operator labels, HITL),
  `render-media` (preview a multimodal carrier), fingerprinting, MANUAL / FAQ / INSTALL / examples /
  man pages, and `make gates` mirroring the CI wall.

## Near-term (candidates, not committed)

- ⬜ **Live validation matrix**: run the multimodal (image + audio) battery end-to-end against real
  vision/audio models (a local Ollama vision model and/or a hosted provider) and record the
  results. The attacks are golden-proven offline; a live pass is the highest-credibility next step.
- 🟡 **Multimodal breadth**: the image side now covers a direct override, a document-image
  injection, a **payload split across two carriers** and a **visual-to-agentic bridge** (an image
  driving an unauthorized tool call). Remaining gap: audio input still targets only OpenAI
  `input_audio`; add other providers as their APIs land.
- ✅ **Function-calling / structured-output depth**: `forbidden_args` covers what the model sends
  *into* a tool; `OUT-JSON-SCHEMA-COERCE` and `OUT-JSON-ENUM-ESCAPE` now cover what it hands
  *back* to the application (out-of-schema privileged field, out-of-enum exposure value), in the
  `structured-output` suite.
- ✅ **Tool-orchestration abuse**: shipped as a new deterministic `tool_sequence`
  evaluator plus `AG-TOOLCHAIN-EXFIL-001`. The evaluator fails when an **ordered** chain of
  individually-authorized calls completes (read-record then send-mail), matching as a
  subsequence so an interleaved no-op cannot evade it, and treats a partial chain as a pass.
  A per-call check cannot express this: `tool_call` passes the very trace `tool_sequence`
  flags, and a regression test pins that complementarity.

## Deferred on purpose

- ⛔ **Streaming pre-moderation leakage**: needs a streaming adapter and is inherently
  timing-dependent, which is in tension with the reproducibility thesis.
- ⛔ **Timing / token-probability side-channels**: infra-dependent and non-reproducible by nature;
  out of scope for a deterministic scanner.
- ⛔ **Live gradient adversarial-suffix optimization (GCG)**: needs model gradients and is
  non-reproducible. The published universal suffix ships as a reproducible transfer mutator instead.
- ⛔ **Real MCP tool invocation (`tools/call`)**: breaks safe-by-design. MCP support is read-only
  discovery only; if ever added it would be a policy-gated, off-by-default capability with an
  explicit safe-tool allowlist.

## Principles that gate what gets built

1. **Reproducible or it does not ship.** Same suite + target + seed yields the same findings.
2. **Safe-by-design.** No real destructive actions or exfiltration; tools are mocked; egress is
   allowlisted default-deny; dangerous payloads are `test_only`.
3. **Evidence over volume.** A finding must be reproducible, evidenced and mapped to a risk.
4. **The battery is data, not code.** Adding a technique is a spec, not a code change, wherever the
   evaluators already cover it.
