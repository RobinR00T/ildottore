# u01-config-scope-policy.md

Config, scope authorization, policy packs and the central redactor. 9-section anatomy per
`docs/00 §2`. Read `AGENTS.md` + `docs/01 §6` + `docs/02` (normative) + `docs/11 §5` +
`shared/` before implementing. Depends on **u00** only.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/policy/`: `scope.py` (scope.yaml loader/validator), `allowlist.py`
  (endpoint default-deny matcher), `packs.py` (policy-pack loader + spec/category gate),
  `identities.py` (multi-identity resolution), `errors.py`; `src/ildottore/config.py` (app
  config + env/vault sourcing); `src/ildottore/redactor.py` (central secret/PII masking).
- **MUST NOT touch:** `shared/`, `adapters/`, `evaluators/`, `core/`, `store/`, `reporting/`,
  any spec YAML, `schemas/`.

## §2 Intended behavior
Load and validate `scope.yaml` (the **authorization record**, S4): parse targets, per-target
endpoint allowlist (host + path prefixes), ≥1 auth identity ref (`auth_ref`, never inline
secrets), optional ≥2 identities (`multi_identity`). Verify file integrity by **checksum** and
expose its hash so a run records it (S4). Provide `PolicyEngine.check(target, endpoint, spec)`
→ `allow` | `blocked_by_policy(reason)` answering: target in scope? endpoint on allowlist
(default-deny, S3)? spec's category/id enabled by the active **policy pack**? dangerous payload
marked `test_only` (S5)? Layer-B / PII-elicitation specs **off unless the pack enables them**
(`docs/11 §5`, DL4/DL5). `config.py` sources scanner secrets from **env/vault**, never files.
`redactor.py` is the single choke point masking secrets/keys/PII in logs, console, evidence and
reports (S6, DL2); it is import-cheap and dependency-free so every layer can call it.

## §3 Dependencies & interface contracts
- Consumes `shared.models.{Target, Capabilities}` and any `shared` enums for categories; does
  NOT redefine them. `multi_identity` maps to `Capabilities.multi_identity`.
- Exposes (candidates for `shared.protocols`, confirm with u00): `PolicyEngine.check(...)`,
  `Redactor.redact(text|obj) -> masked`, `Redactor.register(pattern)`. Verdict polarity and
  model shapes are the u00 registry: changing them is a program-level OD, not a u01 choice.
- Adapters (u04) call the allowlist matcher to refuse out-of-scope hosts at the adapter layer
  (S3); the runner (u08) calls `PolicyEngine.check` before every attempt. u01 provides the
  interfaces; it does not import u04/u08.

## §4 Known constraints: KEEP / DECIDE
- KEEP: **default-deny** everywhere: unknown target/endpoint/spec ⇒ blocked, never allowed.
- KEEP: redactor masks by **type**, storing typed + masked/hashed sample only; raw secret/PII
  never reaches a log line, evidence blob or report (DL2, S6). Redaction is idempotent.
- KEEP: no network I/O during scope/pack loading (SSRF-safe spec loading, `docs/02 §4`).
- KEEP: `test_only` payloads never rendered raw without `--unsafe-render` (S5): u01 exposes the
  flag state; rendering is u11.
- DECIDE (OD-2): scope.yaml signing: SHA-256 checksum now, sigstore later.

## §5 Implementation plan (each step its own commit, green before next)
1. `errors.py` + `config.py`: typed config model (Pydantic v2), env/vault sourcing, `--unsafe-render`
   and `--allow-pii-elicitation` flag surface.
2. `redactor.py`: pattern registry (key prefixes `sk-`/`ghp_`/`AKIA`/`xoxb-`/JWT/PEM + PII:
   email/phone/card/IBAN/national-id/IP), masking with type-tag, structural walk over dict/list.
3. `scope.py`: schema-validated loader + SHA-256 integrity + hash accessor.
4. `allowlist.py`: host + path-prefix default-deny matcher.
5. `identities.py`: single + multi-identity resolution to `auth_ref` handles (no secret values).
6. `packs.py` + `PolicyEngine.check`: category/spec gate, `test_only`, layer-B/PII opt-in.

## §6 Data/wire shapes
`scope.yaml`: `{version, targets:[{id, base_url, endpoints:[{host, path_prefix}], identities:[{name,
auth_ref}]}], checksum?}`. Policy pack: `{name, allow_categories:[...], allow_specs:[...],
deny:[...], enable_layer_b: bool, allow_pii_elicitation: bool, budgets?}`. Check result:
`{decision: "allow"|"blocked_by_policy", reason: str|null}`. Redaction output preserves shape,
replacing values with `«REDACTED:<type>»` (+ salted hash for corroboration where needed).

## §7 Acceptance criteria (machine-checkable)
- `pytest tests/policy -q` green; coverage ≥ 90% for `policy/` + `config.py` + `redactor.py`.
- **Default-deny gate:** parametrized fixtures: out-of-scope host, off-allowlist path, unlisted
  spec, layer-B spec with pack disabled, `test_only` unmarked payload → all `blocked_by_policy`;
  in-scope/enabled counterparts → `allow`.
- **Multi-identity:** `scope.yaml` with 2 identities resolves both `auth_ref`s; single-identity
  scope → authz/xtenant specs report skip-eligible (not error).
- **Integrity:** tampered scope body ⇒ checksum mismatch raises; hash exposed and stable.
- **Redaction (DL2/S6):** property test (Hypothesis): for planted secrets/PII of every type,
  `redact` output contains **zero** raw values; asserts no raw secret/PII in a captured log
  buffer or a serialized evidence stub. Idempotent: `redact(redact(x)) == redact(x)`.
- **No-network:** loading a scope/pack with a URL field performs no egress (monkeypatched socket
  asserts 0 connections).
- `ruff check`, `ruff format --check`, `mypy src/ildottore/policy src/ildottore/config.py
  src/ildottore/redactor.py` clean; `lint-imports` green.

## §8 Out of scope / forbidden
- MUST NOT execute attacks, send requests, or import adapters/evaluators/core/store/reporting.
- MUST NOT persist or print raw secrets/PII (redactor is the only path).
- MUST NOT do network I/O on load; MUST NOT render dangerous payloads (that's u11).
- MUST NOT implement scoring (u07), budget enforcement (u08 enforces; u01 only carries budget
  values from the pack), or evidence encryption (u10, OD-4).
- Not its call: signing scheme (OD-2) · evidence at-rest encryption (OD-4).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-2** scope.yaml signing: SHA-256 checksum in MVP‑1, sigstore/cosign later? (propose
  checksum now, pluggable verifier interface so sigstore drops in without a shape change).
- Redactor entropy threshold for unknown-shape secrets: global vs per-key-type (propose reuse of
  u06 `secret_shape` policy once that lands; interim global threshold, documented).
