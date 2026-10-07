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
identities of one target with the same name or the same canary are refused. Since 2026-10-07 a
scope or policy pack that is too large or too deep with its aliases expanded is refused before
it is built, by the spec loader's own measure, A-37.) Provide
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

**A-37 Every YAML file is measured with its aliases expanded, by one measure (added 2026-10-07).** A
scope, target, fleet, labels, policy pack or signature pack file holding more than 100,000 nodes
with every alias counted where it is used (a text one more node per 64 characters), nested deeper
than 100 levels, or holding a recursive alias is refused before anything is built from it, as a YAML
error with no quoted line (exit 3 at the CLI) and with the position where the value crosses the
limit (a list or a map written past the depth limit is refused where it starts, as it is composed:
A-52). The measure is `safe_yaml.check_expanded`, the one the spec loader uses (u02 §4): one
bottom-up pass over the node graph, each node measured once and each size saturating just past the
cap, too deep reported before too large. Composition itself stops once the nodes written pass the
cap, an alias counting the node it names (each document counted on its own), as the expanded value
can only weigh more, so such a document is reported as too large before its depth or a recursion is
checked, unless composition reaches a list or a map past the depth limit before the count crosses
(A-52); and a tag longer than 256 characters is refused there, unquoted. Only the spec loader had
the size cap (SEC-09), so the loaders of the operator's own files expanded whatever they were given:
an 835-byte labels file of 45 anchors, each a list of two aliases of the one before, ran `calibrate`
past 25 s at 1.7 GB while it formatted the verdict, and a `<<` merging the previous map twice
doubles the pairs inside PyYAML itself, so no caller had to walk the value (pre-merge audit of #61).
The fix's own audits found four more ways to the same cost: a size without saturation grew with the
square of an anchor chain, so the measure was itself the amplification; a measure run only on a
composed document let a 3 MB list of plain texts cost 785 MB first; a count that skipped aliases let
a list of aliases do the same; and a `%TAG` prefix, copied into the tag of every node that uses its
handle, held 187 MB for 1,000 nodes, quoted whole in PyYAML's refusal. Construction costs under the
cap (a base-60 integer, integer keys sharing one hash) are A-41's; the byte size of the file read
is its own task. Checks: `tests/cli/test_yaml_expansion.py` (the cap exactly, the
position, a recursive alias's anchor, the precedence, where composition stops for texts, long texts,
empty lists, aliases and aliases of a long text, the per-document count, the tag limit on texts,
lists and maps, linear memory on a 20,000-anchor chain, each loader, and in a subprocess bounded at
20 s and 256 MiB: `calibrate` on the alias bomb and on the flat list, `run -t`, `run --scope`,
`fleet`, and `lint` on a merge bomb).

**A-41 A YAML value that costs far more to build than it weighs is refused before it is built (added
2026-10-07).** Every loader (the spec loader and `safe_yaml.safe_load`, so the scope, target, fleet
and labels files and the policy and signature packs) refuses, as it composes the document and before
anything is built, a number written in more than 1,000 characters (`cannot build this value (a
number written in over 1000 characters)`), wherever it is written (a value, a key, a list item, in
flow, at the root), and the key that takes a document past 1,000 keys that are numbers, in block or
flow mappings, a key merged in by `<<` counted in every mapping it is merged into, through as many
merges as pass it on (`document has over 1000 keys that are numbers ...`): a YAML error at that
number, that key or what the `<<` merges in, quoting no value, exit 3 at the CLI and a `PARSE_ERROR`
in `lint`. The rest of the file is not parsed. The size cap (A-37) bounds what a document holds, not
what PyYAML spends building it, and two shapes cost far more than they weigh: YAML 1.1 reads
`1:59:59` as a base-60 integer, built by a loop whose time grows with the square of its length, and
integers that differ by a multiple of `sys.hash_info.modulus` share one hash, so the dict of a
mapping of them is built in time that grows with the square of their count. A spec just under the 1
MiB cap took `lint` 55 s with one base-60 value and 24 s with 36,320 such keys, and `run --dry-run`
accepted a 450 KB target with a base-60 value after 37 s and a 1.3 MB target with 45,000 such keys
after 247 s, at a load average of 6 to 10 on 15 cores (found by the pre-commit audit of A-37,
measured on its branch); each is now refused in 1 to 1.5 s. The keys are counted from their tags, so
before any of them is hashed, and across the whole document, not per mapping: 1,000 keys per mapping
still allowed about fifty such mappings under the node cap. Only numbers count: text, bytes, dates
and timestamps without an offset hash with a key Python draws at random for each process, a
timestamp with an offset hashes by its instant, with no thousand instants sharing one hash within
reach, and booleans and null have three distinct values between them, a fourth being a repeated key.
A number of 1,000 hexadecimal digits has about 1,204 decimal digits, under the 4,300 Python converts
by default (a lower `PYTHONINTMAXSTRDIGITS` is A-40's). No YAML file the repository ships has a key
that is a number or a number over 20 characters. Checks: `tests/cli/test_yaml_construction_cost.py`
(each number notation at 1,001 characters in each position and at 1,000 as a value; a long text;
1,000 and 1,001 keys sharing one hash, in block and flow mappings; two mappings; three merge shapes,
a map merged where it is written, a map that merges passing its keys on; where composition stops; a
stream of documents; keys that are not numbers; both loaders; and in a subprocess bounded at 15 s:
`lint` on each 1 MiB spec, and `run --dry-run` on the 450 KB and the 1.3 MB target).

**A-52 A list or a map written past the depth limit is refused where it starts, as the document is
composed (added 2026-10-07).** Every loader (the spec loader and `safe_yaml.safe_load`, so the
scope, target, fleet and labels files and the policy and signature packs) refuses a list or a map,
flow or block, written inside 100 others, with the depth limit's message (`document is nested too
deeply`) at the position where it starts, before anything in it or after it is composed (the scanner
reads ahead to the end of that line, at most 1,024 characters, and one token past it, each token
read whole however long, so an error in that window, such as a character no token can start or a bad
escape in a long quoted text, is reported instead): a YAML error, exit 3 at the CLI and a
`PARSE_ERROR` in `lint`. PyYAML's pure-Python scanner keeps one possible simple key per open flow
level and walks them all on every token, so a token costs in proportion to the flow levels open
around it, and A-37 measured the depth only on the composed document, after that cost: a 198 KB list
of chains of `[` 320 deep was refused (`at line 1, column 101`) once all of it was composed, 3.3 to
6.7 times what as many flat texts take, depending on the machine's load (pre-commit audit of A-41
and A-42, the same on `main` and on #71). Measured on #71's head, best of three at a load average of
9 to 14: 11.3 s against 2.5 s for the flat list, and the scanner walked 97.4 million possible keys
against 0.3 million; now 0.11 s and 1.1 million, a constant (what it reads ahead on the first line).
A list or a map is written at most as deep as its aliases expand it, so through these two loaders
this refuses earlier only what A-37 refuses (`SafeValueLoader` used directly, by `yaml.load_all` for
instance, has no A-37 and now refuses such a document where it accepted it; nothing in `src/` uses
it that way). It names where the first list or map written past the limit starts; A-37 named the
first node at that depth down the first of the deepest branches, aliases expanded: the same place
unless another branch is deeper, or as deep and written first (a branch deepened by an alias
included), or that list or map is empty and a text or a key at its level is written before it (`k:
[]`). Refusals made while composing are reported in the order they are made, which is not always the
order written: this one and the tag limit as a node starts, the size cap's count and A-41's numbers
once a node is composed (each at the position where that node starts), so a list or a map past the
depth limit inside a collection is reported before the count that the collection's own end takes
past the cap. All of them come before what A-37 measures on the whole document, wherever that is
written: a recursive alias written before the nesting is no longer the one reported. A text or an
alias opens no level and is not refused by this check: one written at level 101 is refused where it
was (an alias at its anchor), by A-37 once the document is composed, unless another check refuses it
while it is composed, at the cost of a document accepted at the limit. Nesting written thousands of
levels deep, which overflowed PyYAML's recursive composer and was refused without a position, now
has one. Not covered, OD-30: under the limit the cost per token stays, and the same 198 KB of chains
98 deep is accepted in 5.5 to 5.6 s, about 2.3 times the flat list here (3 to 4 times at depth 95 in
the audit, under another load), the scanner walking 29.8 million keys; chains 98 deep holding 300
texts at the bottom walk 52 million and take about 3 times the flat list, the worst accepted shape
the audit found. Checks: `tests/cli/test_yaml_written_nesting.py` (where composition stops, by a
character no token can start written lines inside the collection at level 101, for flow and block
lists and maps and in both loaders; the position against `check_expanded`'s on the whole document;
several branches; a key before an empty list; a text, an alias and a map's keys at level 101; every
shape at the limit, siblings included, loading as plain PyYAML loads it; the precedence, in the
order written and in the order checked; one count per document; a tag too long reported first, as
before; 5,000 levels; a `RecursionError` while composing, raised without recursing, and in a
subprocess a caller with little stack left, both still refused as too deep; and in a subprocess
bounded at 20 s, the possible keys the scanner walks for `lint` and `calibrate` on the audit's 198
KB file, under 5 million: 1.1 million now, 97.4 million before).

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
- **OD-30** (2026-10-07) Flow nesting under the depth limit still costs per token. A-52 refuses a
  list or a map written past the limit before the scanner pays for what follows, but PyYAML's
  pure-Python scanner walks one possible simple key per open flow level on every token, so a
  document nested close to the limit is accepted at a few times what a flat one costs (A-52 gives
  the measure). Options: (A) a lower limit for flow nesting only: the repository's 130 YAML files
  nest at most 2 flow levels (6 of any style), so a limit of, say, 20 would bound each walk of the
  scanner at about 20 keys (it passes over them about three times per token) without refusing any of
  them; (B) libyaml's scanner (`yaml.CSafeLoader`, in the installed PyYAML), whose composer is C, so
  the per-node checks of `safe_yaml` (the size count, the tag limit, keys written twice, A-52) would
  have to move to its events, to be measured; (C) leave it: each walk is bounded at about 100 keys.
  Owner's call.
