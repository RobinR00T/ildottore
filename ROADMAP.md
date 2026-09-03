# Il Dottore, Roadmap

Where the project is and what is left. The living, prioritized gap analysis is
[`docs/12-gaps-backlog.md`](docs/12-gaps-backlog.md); this file is the shorter, human-facing view.

**Legend:** ✅ shipped · 🟡 partial · ⬜ not started · ⛔ deferred on purpose (with the reason).

## Shipped

The battery is **57 specs across 12 suites**, aligned to OWASP LLM Top 10 (2025), MITRE ATLAS and
NIST AI 600-1. Everything below runs offline against a mock and, where noted, over the wire.

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
  embeddings, MCP tool-metadata poisoning, guardrail/moderation-layer evasion, and an optional
  Responsible-AI pack (safety-content + bias/fairness).
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
- 🟡 **Multimodal breadth**: audio input currently targets OpenAI `input_audio`; add other
  providers as their APIs land. A document-image battery beyond the single indirect spec.
- 🟡 **Function-calling depth**: `forbidden_args` covers argument smuggling; deepen JSON-schema
  poisoning and structured-output coercion.
- ⬜ **Finding dedupe across specs**: the runner already collapses mutation variants into one
  finding; cross-*spec* semantic dedup stays a human judgment for now (lossy, can hide signal).
- ⬜ **Packaging**: a tagged release and a published distribution if the tool is to be installed by
  others (see [`RELEASING.md`](RELEASING.md)).

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
