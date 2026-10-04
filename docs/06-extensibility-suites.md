# 06: Extensibility: pluggable suites & new techniques

**Requirement:** the operator must be able to define new test sets and drop in new techniques
that appear in the future, ideally **without touching core code**. This is a first-class
feature, not an afterthought.

## 1. Three extension levels (in order of how often they happen)

| Level | What you add | Code? | Mechanism |
|---|---|---|---|
| **L1: New test** (most common) | a new `*.yaml` attack spec | **No** | Drop YAML in a spec dir; reference from a suite. |
| **L2: New suite/pack** | a `suite.yaml` referencing specs | **No** | Ship a "spec pack" directory. |
| **L3: New primitive** | a new evaluator type or mutator strategy | Yes (small, isolated) | Register via plugin entry point. Works for mutators today; see §3 for evaluators and adapters. |

The design goal: **95% of "new techniques" are L1/L2 (pure declarative), zero code.**

## 2. L1/L2: Spec packs (data-only, hot-loadable)

- A **spec pack** is a directory: `pack.yaml` (`id`, `pack_version`, `name`, optional
  `specs`, `suites`, `signature`, `checksum`) + `attacks/*.yaml` + `suites/*.yaml`. Fixtures
  live inline in each spec (`fixtures.vulnerable` / `fixtures.hardened`); a sidecar fixtures
  directory is not supported (OD-7).
- Packs are discovered from configured search paths (`--spec-path`, env, config) and merged
  into the **Attack Spec Registry** at startup. Later packs can extend but not silently
  override earlier ids (id collisions are a lint error).
- Loading a pack **executes no code and makes no network calls** (S-threat-model): it is parse
  + schema-validate + register only.
- Every pack is versioned. The design has the registry record which pack/version a finding
  came from; that is not built: a `Finding` and a `TestRun` carry no pack reference. What a run
  does record is a digest of every spec it executed, which is what binds a resume to its
  battery.

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

Four groups are read or declared, and the scanner's own `pyproject.toml` declares only three
of them (`dottore.evaluators`, `dottore.mutators`, `dottore.adapters`); a plugin package
declares its own. What works today, per group:

- **Mutators: built.** `mutators/registry.py` loads the `dottore.mutators` entry points, and a
  spec's `mutations` is a list of names, so a spec can use the plugin. A name that no
  registered mutator answers to is `UNKNOWN_MUTATOR_TYPE` in `dottore lint` (a plugin that
  fails to load is the warning `MUTATOR_PLUGIN_ERROR`).
- **The mutator plugin contract** is the `Mutator` protocol (`name: str`,
  `mutate(text: str, seed: str) -> str`) plus an optional class attribute `accepted_params`,
  which decides what a `name:param` mutation may say:
  - `None` (the default on `BaseMutator`, and what a plugin that does not declare it gets): not
    declared, so any `name:param` is accepted and the whole `name:param` reaches the mutator in
    its seed (`<spec-id>::<name:param>`), as before the attribute existed;
  - a `frozenset` of strings: the parameters it implements, compared lower-cased and stripped;
  - an empty `frozenset`: it takes no parameter.

  Every built-in declares it: `translate` accepts its four languages and the other eighteen
  accept none. `dottore lint` reports an unaccepted parameter as `UNKNOWN_MUTATOR_TYPE`, and the
  runner refuses the spec with `unknown_mutator_parameter` and sends nothing for it.
- **Scorers: discovered, not used by a run.** `scoring/registry.py` loads a
  `dottore.scorers` group and checks each entry against the `RiskScorer` protocol, but nothing
  on the run path calls `get_scorer`: the composition root always builds `DefaultRiskScorer`.
- **Evaluators: discovered, not reachable from a spec.** `evaluators/registry.py` loads the
  `dottore.evaluators` entry points, but a spec's evaluator `type` is the closed enum
  `EvaluatorType` (the schema's `enum`), so `type: my_semantic_v2` fails validation before the
  registry is consulted. Opening the enum (or a `plugin:` namespace) is needed first.
- **Adapters: design only.** `pyproject.toml` declares the `dottore.adapters` group and nothing
  reads it; the adapter is chosen by the hard-coded provider switch in `cli/wiring.py`
  (`openai`, `anthropic`, `mcp`, anything else to the generic REST adapter).
- A spec referencing an unknown evaluator `type` fails schema validation in the linter, and an
  unknown mutation fails `UNKNOWN_MUTATOR_TYPE`: never a silent skip.
- The policy engine gates the requests the scanner sends (allowlist, `test_only`, budgets),
  whichever mutator produced them. A plugin is Python code running in the scanner's own
  process: those gates do not sandbox what the plugin code itself does.

## 4. Registry & versioning contract

- Spec ids are immutable once published; a changed test = a new id (`...-002`) or bumped
  `spec_version`. This preserves historical reproducibility.
- The registry exposes: `list(filter=category|owasp|tag|pack)`, `get(id)`, `resolve(suite)`.
- `dottore registry ls [--category] [--owasp] [--tag] [--suite]` and `dottore describe <id>`
  for humans (the CLI filters by suite, not by pack).

## 5. Safety of third-party packs

- Packs are treated as **untrusted content**: schema-validated, `test_only` enforced on
  flagged families, no execution/network at load, and gated by the engagement's policy pack
  (a pack can be present but disallowed for a given target).
- Optional pack signing (checksum manifest) for supply-chain integrity of shared packs. The
  manifest model has `signature` and `checksum` fields; they are parsed and not verified
  today.

## 6. Community / framework sync

The design put the framework universes in a versioned `frameworks/*.yaml`. They live in
Python instead, each pinned with the edition it was transcribed from: OWASP LLM and MITRE ATLAS
in `src/ildottore/shared/frameworks.py`, Nova IoPC in `shared/iopc.py`, OWASP AISVS in
`shared/aisvs.py`. There is no `frameworks/` directory. The NIST AI RMF field is checked by
shape only (the subcategory list is not transcribed). Each spec still carries its own codes, so
a renumbered framework means a table bump plus a lint pass over the specs that cite the moved
codes.
