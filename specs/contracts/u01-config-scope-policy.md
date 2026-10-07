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
expose its hash so a run records it (S4). (As built: the checksum is optional, verified only when
present, and unkeyed, so it is not a signature (OD-2). Since 2026-10-05,
`load_scope_with_digest()` returns the scope with the `scope_hash()` of the bytes it parsed, and
`dottore run` records it in the run store and every report, audit D-17. Since 2026-10-06 a key
written twice in one YAML mapping is refused with both positions, through `safe_yaml`, and two
identities of one target with the same name or the same canary are refused.) Provide
`PolicyEngine.check(target, endpoint, spec)`
→ `allow` | `blocked_by_policy(reason)` answering: target in scope? endpoint on allowlist
(default-deny, S3)? spec's category/id enabled by the active **policy pack**? dangerous payload
marked `test_only` (S5; enforced from the category, A-29)? Layer-B / PII-elicitation specs **off unless the pack enables them**
(`docs/11 §5`, DL4/DL5). `config.py` sources scanner secrets from **env/vault**, never files.
(A target's `auth_ref` resolves `env://` only; `vault://` is deferred and raises.)
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
  flag state; rendering is u11. (As built: `config.SafetyFlags.unsafe_render` exists, off; no
  CLI flag sets it.)
- DECIDE (OD-2): scope.yaml signing: SHA-256 checksum now, sigstore later. (The checksum half is
  built and optional; signing is still open.)

## §5 Implementation plan (each step its own commit, green before next)
1. `errors.py` + `config.py`: typed config model (Pydantic v2), env/vault sourcing, `--unsafe-render`
   and `--allow-pii-elicitation` flag surface. (As built: the typed `SafetyFlags` carry both
   values, default off; neither is a CLI flag, so the DL4 run key cannot be turned on from
   `dottore`.)
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

**A-18 Authorization is reachability, not membership (added 2026-09-22).** The gate answers
"may this target be reached at the URL the adapter will actually request", and the CLI
pre-flight and the per-attempt check call **the same predicate** (`policy.authorize_target`).
Asking only whether the id is present in the scope passed a scope with an empty endpoint
allowlist, which then denied every attempt: the false green the gate exists to prevent, one
typo away. A differential test enumerates scope/target shapes and asserts the two answers never
diverge.

**A-19 Schemes are allowlisted.** `https`, loopback `http` and the offline `mock` scheme; every
other scheme is denied. Refusing `http` off-loopback and letting the rest through to the host
check meant `ws://`, `ftp://`, `file:///etc/passwd` and a scheme-relative `//host/path` all
passed, with the invariant resting on adapter implementation rather than on the gate.

**A-20 One answer per target.** A scope declaring an id twice is refused: `Scope.target()`
returns the first match, so a permissive entry silently shadowed a narrowing one, including its
credential allowlist.

**A-56 A fleet's ids are unique ignoring case, on every file system (added 2026-10-07).**
`dottore fleet` writes one `target-<id>.yaml` per target, and on a case-insensitive file system
(the macOS and Windows default) `target-Prod.yaml` and `target-prod.yaml` are one file.
`materialize_fleet` compared ids exactly, so a fleet declaring `Prod` and `prod` wrote `prod`
over `Prod`, listed two target files and exited 0, and the `dottore run` it printed (and
`fleet --run`) refused "two target files declare the id 'prod'", an id the fleet declared once
(delta audit of PR #76). Two target ids equal under `casefold()` are refused before anything is
written, on one line with both locations, both ids and both file names. Every refusal of the
fleet's ids locates its entries as the validation errors of the same command do
(`targets.1.id`, counted from 0; `judge.id`), an exact duplicate included, because the CLI
masks what its redactor reads as high entropy and a model name such as
`Meta-Llama-3-70B-Instruct` comes out masked, ids and file names alike (pre-commit audit; the
first version counted from 1, delta audit). A judge id spelled as a target's only up to case is
refused the same way: no file collides (the judge is written to `judge.yaml`), but it got a
scope entry of its own beside the target's, two ids that differ only by case in the record
that authorizes both. The same spelling still shares the target's entry when the endpoint and
credential match (A-30). Both judge refusals say when the id is the default `judge` of a
`judge:` block that names none, and only then. Target pairs are reported before the judge. The
rule holds on a case-sensitive file system too, where nothing collided, so a fleet file means
the same wherever it is expanded (OD-33). Fleet ids are ASCII (`[A-Za-z0-9._-]`), so
`casefold()` is lowercasing here and no Unicode normalization arises (writing all 4,092 ids of
one or two characters on APFS gave 1,440 files, the number of distinct ids under `casefold()`).
Out of reach, stated rather than hidden: ids that only look alike (`Ilama`, `llama`, `lIama`)
are distinct and accepted. Not changed, measured: `run`'s own duplicate check and
`load_scope`'s (A-20) stay exact. No file of a run is named by a target id (evidence and probes
sit under the run id), and the run store keys a finding by its run id and
`<spec id>::<target id>` under SQLite's default, case-sensitive collation; two hand-written
target files `Prod` and `prod` in one run get two run ids and two evidence trees, every report
format lists both with their own results, and `--resume` of one against the other is refused.
Checks: `tests/cli/test_fleet_case_ids.py`, including all 1,332 fleets of one to three targets
named from `a`, `A`, `b` and `c`, with no judge or a judge `a`, `A`, `c` or `d` on its own
endpoint or any target's, each checked against the start of the refusal (locations included)
that the rules, written apart from the code, require.

**A-29 A gate keys on what a spec cannot opt out of (added 2026-10-03).** The `test_only`
criterion above is enforced at run time from the spec's **category**: an unmarked spec in a
flagged family is `blocked_by_policy`. The engine used to read the mark as rendering-only and
allow everything, so a copy of a shipped spec with the mark deleted, loaded with `--spec-path`,
was sent while `dottore lint` reported it (audit SEC-06). Tags that drive a gate are compared
after normalising case and `-`/`_`, and the PII-elicitation gate also keys on the `layer_b_pii`
capability: the one shipped PII spec was tagged `pii-elicitation`, the gate compared
`pii_elicitation`, and the two-key DL4 gate never fired for it (audit F-22). Residual, stated
rather than hidden: the `offensive_simulation` capability is still declared by the spec itself.
Checks: `tests/policy/test_policy_audit_2026_10_03.py` (the shipped spec under a capability-only
pack, every flagged family unmarked, the `run` refusal of an unmarked copy).

**A-30 The allowlist authorizes the path the client sends, on the port it names, and refuses
the encodings an origin could decode into a separator (added 2026-10-03, corrected the same
evening).** Dot segments are resolved exactly as httpx resolves them, and a differential test
over generated paths pins the two together: refusing to pop an empty segment let
`/v1/chat/completions/x//../../../../admin` pass while httpx sent `/v1/admin` (review of
PR #32). A path carrying an encoded slash or backslash (`%2f`, `%5c`), a literal backslash or a
`%25` double encoding is refused, not rewritten: `/v1/chat/..%2f..%2fadmin` passed the prefix
check and was `/admin` to a decoding origin (audit SEC-03). The forms only some origins decode
are refused too since 2026-10-04: `;` path parameters (literal or `%3b`), `%uXXXX` escapes,
overlong or impossible UTF-8 (`%c0`, `%c1`, `%e0%8x`/`%e0%9x`, `%f0%8x`, lead bytes `%f5` and
up), segments of dots and spaces only (Windows strips them to `..`), and any non-ASCII
character, literal or percent-encoded, whose NFKC form contains `.`, `/`, `\`, `%` or `;` (a
literal fullwidth dot passed when only encodings were listed: httpx encodes it after the
gate). Not covered: legacy code pages (Shift_JIS, GBK, cp1252) and Windows best-fit look-alikes
that are not NFKC-equivalent (U+2215 and similar). A bracketed IPv6 host splits
into host and port (`[::1]:8080`), so an IPv6 entry can be pinned (SEC-13), and the scope `fleet`
generates pins every endpoint to its port. The judge `fleet` authorizes comes from the fleet
file's own `judge:` block, never from a `--judge` file, which could otherwise name any host and
any credential and have both written into the scope (SEC-04). Checks: the same file, plus
`tests/cli/test_fleet.py`.

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
- **OD-33** fleet ids that differ only by case. **Decided 2026-10-07 by the conductor, reversible,
  built (A-56):** refused on every file system, not only where the file system folds case: it is
  portable and the simplest rule (`run` already compares report paths case-folded everywhere),
  and a fleet file then means the same wherever it is expanded. What it costs: a fleet with
  `Prod` and `prod` that expanded on Linux is now refused there too, and so is a judge spelled as
  a target only up to case, which worked. The alternative (refuse only where the `--out`
  directory's file system folds case, found by probing it) is the owner's to choose.
