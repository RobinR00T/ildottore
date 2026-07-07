# 01 — Architecture

## 1. Component model

```
                         ┌─────────────────────────────────────────┐
                         │              Scanner Core                │
   scope.yaml ─────────► │  campaign orchestration · rate limit ·   │
   suite.yaml ─────────► │  retries · timeouts · N-run repro ·      │
   target.yaml ────────► │  scheduling                              │
                         └───┬───────────┬───────────┬───────────┬──┘
                             │            │           │           │
                   ┌─────────▼──┐  ┌──────▼─────┐ ┌───▼──────┐ ┌──▼─────────┐
                   │  Attack    │  │  Prompt    │ │  Target  │ │  Policy    │
                   │  Spec      │  │  Mutator   │ │  Adapter │ │  Engine    │
                   │  Registry  │  │            │ │          │ │(allowlist, │
                   │ (pluggable)│  │            │ │          │ │ scope,     │
                   └─────────┬──┘  └──────┬─────┘ └───┬──────┘ │ safety)    │
                             │            │           │        └────────────┘
                             └────────────┴─────┬─────┘
                                                │  (prompt, response, traces)
                                        ┌───────▼────────┐
                                        │   Evaluator    │  regex · exact · refusal ·
                                        │   pipeline     │  secret · tool-call ·
                                        └───────┬────────┘  semantic-judge (hardened)
                                                │  verdicts + reasoning + confidence
                                        ┌───────▼────────┐
                                        │  Risk Scorer   │  (see docs/05)
                                        └───────┬────────┘
                                                │  Finding
                          ┌─────────────────────┼─────────────────────┐
                   ┌──────▼──────┐        ┌──────▼──────┐       ┌───────▼──────┐
                   │  Evidence   │        │  Reporting  │       │  Store       │
                   │  Store      │        │ JSON/HTML/  │       │ (runs,       │
                   │ (artifacts) │        │ SARIF/JUnit │       │  findings)   │
                   └─────────────┘        └─────────────┘       └──────────────┘
```

## 2. Dependency rule (enforced)

`apps → packages`; within packages the only allowed direction is:

```
scanner-core ─► (interfaces of) target-adapters, evaluators, reporting, policy-engine, store
target-adapters ─► (nothing in this repo except shared models)
evaluators ─► (shared models; may call an LLM via an adapter *interface* for judge)
```

- `scanner-core` depends on **interfaces**, never concretes. Concretes are injected at the
  composition root (`apps/cli`, `apps/api`).
- Shared, dependency-free models (`AttackSpec`, `Target`, `TestRun`, `Finding`, `Attempt`,
  `Verdict`, `Evidence`) live in a `packages/shared` module imported by everyone.
- Enforced in CI by `import-linter` (contract in `docs/07`).

## 3. Core interfaces (contracts the AI must implement)

```python
# packages/shared/models.py — dependency-free Pydantic models (see schemas/)

class TargetAdapter(Protocol):
    async def send(self, request: ModelRequest) -> ModelResponse: ...
    def capabilities(self) -> Capabilities: ...     # tools, rag, memory, streaming, seed,
    id: str                                          #   logprobs, multi_identity, multimodal
    # ModelResponse carries token logprobs when capabilities.logprobs is true (used by
    # logprob_membership + confidence side-channels). A target may expose >1 auth identity
    # (multi_identity) so cross-tenant/authz specs can compare A vs B — see scope, §6.

class Evaluator(Protocol):
    type: str                                        # "regex_absence", "semantic_judge", ...
    async def evaluate(self, ctx: EvalContext) -> Verdict: ...
    #   Verdict = {status: pass|fail|inconclusive, confidence: float, reasoning: str,
    #              matched: list[str]}

class Mutator(Protocol):
    name: str
    def mutate(self, text: str, seed: str) -> str: ...   # deterministic, intent-preserving

class RiskScorer(Protocol):
    def score(self, spec: AttackSpec, verdicts: list[Verdict],
              attempts: list[Attempt]) -> RiskScore: ...

class EvidenceStore(Protocol):
    def put(self, run_id: str, attempt: Attempt) -> EvidenceRef: ...

class RunStore(Protocol):
    def save_run(self, run: TestRun) -> None: ...
    def save_finding(self, f: Finding) -> None: ...

class Reporter(Protocol):
    format: str                                      # "json", "html", "sarif", "junit"
    def render(self, run: TestRun, findings: list[Finding]) -> bytes: ...
```

## 4. Execution flow (one attack spec against one target)

1. **Policy check** — target in scope? endpoint on allowlist? spec allowed by policy pack?
   Any dangerous payload marked `test_only`? Else → abort attempt, record `blocked_by_policy`.
2. **Setup** — materialize spec `setup` (e.g. index test documents for RAG) via the adapter's
   capabilities. If capability missing → `inconclusive: capability_unavailable`.
3. **Mutate** — Prompt Mutator expands the base attack into declared variants (language,
   encoding, roleplay, nesting, obfuscation, indirect-injection carriers). Each variant is a
   deterministic transform seeded by `(spec.id, variant.name)`.
4. **Execute N times** — send with pinned sampling params (temperature, top_p, seed if the
   provider supports it). Handle rate limit / retries / timeout. Record every attempt.
5. **Evaluate** — run the evaluator pipeline; combine per the spec's `evaluator_logic`
   (default: all `regex/rule` must pass AND judge must pass). Judge input is sandboxed
   (`docs/04`).
6. **Score** — reproducibility = successful-attack rate across N; risk per `docs/05`.
7. **Persist** — attempts → Evidence Store; finding → Run Store. Emit to reporters.

## 5. Determinism & reproducibility (why this is architectural, not a detail)

LLMs are non-deterministic; a scanner that reports a boolean "vulnerable/not" is
scientifically weak. Therefore:

- Every attempt records the **full sampling config** and provider request/response ids.
- Reproducibility is a **statistical quantity**: `repro = successful_attacks / N` over N runs
  (N configurable, default 5), with the raw per-attempt outcomes stored so a reader can
  recompute it. A single lucky success is a *low-reproducibility* finding, not a headline.
- Where the provider supports a `seed`, pin it and record it; where it does not, record that
  determinism was best-effort.
- The **same suite + same target + same seed** must produce the **same set of findings**
  modulo provider-side non-determinism, which is quantified, not hidden.

## 6. Scope / safety gate (Policy Engine)

- `scope.yaml` (signed / checksum-verified) lists authorized targets and an endpoint
  **allowlist** (host + path prefixes). Requests outside it are refused at the adapter layer.
- Policy packs declare which attack categories/specs are permitted for a given engagement
  (e.g. "no DoS category against prod"). Data-leak layer-B specs and PII elicitation are
  **off unless the policy pack enables them** (`docs/11 §5`).
- `scope.yaml` may declare **≥2 auth identities** for one target (`multi_identity`) so
  cross-tenant/authz specs can compare identity A vs B. A central **redactor** masks
  secrets/PII in logs, evidence and reports.
- All of `docs/02-threat-model.md` and the safety/legal gates in `docs/11 §5` are normative
  for this component.
