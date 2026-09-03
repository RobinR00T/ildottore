# 06: Extensibility: pluggable suites & new techniques

**Requirement:** the operator must be able to define new test sets and drop in new techniques
that appear in the future, ideally **without touching core code**. This is a first-class
feature, not an afterthought.

## 1. Three extension levels (in order of how often they happen)

| Level | What you add | Code? | Mechanism |
|---|---|---|---|
| **L1: New test** (most common) | a new `*.yaml` attack spec | **No** | Drop YAML in a spec dir; reference from a suite. |
| **L2: New suite/pack** | a `suite.yaml` referencing specs | **No** | Ship a "spec pack" directory. |
| **L3: New primitive** | a new evaluator type or mutator strategy | Yes (small, isolated) | Register via plugin entry point. |

The design goal: **95% of "new techniques" are L1/L2 (pure declarative), zero code.**

## 2. L1/L2: Spec packs (data-only, hot-loadable)

- A **spec pack** is a directory: `pack.yaml` (id, version, provenance, framework map) +
  `attacks/*.yaml` + `suites/*.yaml` + `fixtures/`.
- Packs are discovered from configured search paths (`--spec-path`, env, config) and merged
  into the **Attack Spec Registry** at startup. Later packs can extend but not silently
  override earlier ids (id collisions are a lint error).
- Loading a pack **executes no code and makes no network calls** (S-threat-model): it is parse
  + schema-validate + register only.
- Every pack is versioned; the registry records which pack/version a finding came from, so
  results stay reproducible as packs evolve.

**Adding a future technique (typical flow):**
1. `dottore new-spec --family prompt_injection --id PI-XYZ-042` → scaffolds a YAML + empty
   fixtures.
2. Fill `attack`, `expected_secure_behavior`, `evaluators`, `fixtures.vulnerable/hardened`.
3. `dottore lint specs/` → schema + policy + "fixtures actually prove detection" checks.
4. Add the id to a suite. Done: no core code changed.

## 3. L3: Plugin registration (new evaluator / mutator type)

When a technique needs a genuinely new *primitive* (e.g. a new obfuscation, or an evaluator
that parses a novel trace format), register it via Python entry points:

```toml
# pyproject.toml of a plugin package
[project.entry-points."dottore.evaluators"]
my_semantic_v2 = "my_pkg.evaluators:SemanticV2Evaluator"

[project.entry-points."dottore.mutators"]
homoglyph_v2 = "my_pkg.mutators:HomoglyphV2"

[project.entry-points."dottore.adapters"]
bedrock = "my_pkg.adapters:BedrockAdapter"
```

- Core discovers plugins at startup, validates each against the `Evaluator` / `Mutator` /
  `TargetAdapter` protocol, and exposes the new `type` string to specs.
- A spec referencing an unknown `type` fails the linter with a clear message: never a silent
  skip.
- Plugins are sandboxed by the same policy engine (allowlist, `test_only`, budgets).

## 4. Registry & versioning contract

- Spec ids are immutable once published; a changed test = a new id (`...-002`) or bumped
  `spec_version`. This preserves historical reproducibility.
- The registry exposes: `list(filter=category|owasp|tag|pack)`, `get(id)`, `resolve(suite)`.
- `dottore registry ls / describe <id>` for humans.

## 5. Safety of third-party packs

- Packs are treated as **untrusted content**: schema-validated, `test_only` enforced on
  flagged families, no execution/network at load, and gated by the engagement's policy pack
  (a pack can be present but disallowed for a given target).
- Optional pack signing (checksum manifest) for supply-chain integrity of shared packs.

## 6. Community / framework sync

Framework mappings (`owasp`, `mitre_atlas`, `nist_ai_rmf`) live in a versioned
`frameworks/*.yaml` so that when OWASP LLM Top 10 or ATLAS update, you bump the mapping file,
not every spec.
