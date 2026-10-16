# u01-config-scope-policy.md

Config, scope authorization, policy packs and the central redactor. 9-section anatomy per
`docs/00 §2`. Read `AGENTS.md` + `docs/01 §6` + `docs/02` (normative) + `docs/11 §5` +
`shared/` before implementing. Depends on **u00** only.

## §1 Scope & ownership
- **OWNS:** `src/ildottore/policy/`: `scope.py` (scope.yaml loader/validator), `allowlist.py`
  (endpoint default-deny matcher), `packs.py` (policy-pack loader + spec/category gate),
  `identities.py` (multi-identity resolution), `errors.py`; `src/ildottore/config.py` (app
  config + env/vault sourcing); `src/ildottore/redactor.py` (central secret/PII masking);
  `src/ildottore/safe_yaml.py` (the safe YAML loader every loader shares, measured by A-37,
  A-52 and A-58; recorded 2026-10-12).
- **MUST NOT touch:** `shared/`, `adapters/`, `evaluators/`, `core/`, `store/`, `reporting/`,
  any spec YAML, `schemas/`.

## §2 Intended behavior
Load and validate `scope.yaml` (the **authorization record**, S4): parse targets, per-target
endpoint allowlist (host + path prefixes), ≥1 auth identity ref (`auth_ref`, never inline
secrets), optional ≥2 identities (`multi_identity`). Verify file integrity by **checksum** and
expose its hash so a run records it (S4). (As built: the checksum is optional, verified only when
present, and unkeyed, so it is not a signature; signed off as integrity only on 2026-10-11, with
authenticity a non-goal until key management exists (OD-2). Since 2026-10-05,
`load_scope_with_digest()` returns the scope with the `scope_hash()` of the bytes it parsed, and
`dottore run` records it in the run store and every report, audit D-17. Since 2026-10-06 a key
written twice in one YAML mapping is refused with both positions, through `safe_yaml`, and two
identities of one target with the same name or the same canary are refused. Since 2026-10-07 a
scope or policy pack that is too large or too deep with its aliases expanded is refused before
it is built, by the spec loader's own measure, A-37.) Provide
`PolicyEngine.check(target, endpoint, spec)`
→ `allow` | `blocked_by_policy(reason)` answering: target in scope? endpoint on allowlist
(default-deny, S3)? spec's category/id enabled by the active **policy pack**? dangerous payload
marked `test_only` (S5; enforced from the category, A-29)? Layer-B / PII-elicitation specs **off
unless the pack enables them** (`docs/11 §5`, DL4/DL5). `config.py` sources scanner secrets from
**env/vault**, never files. (A target's `auth_ref` resolves `env://` only; `vault://` is deferred
and raises.) `redactor.py` is the single choke point masking secrets/keys/PII in logs, console,
evidence and reports (S6, DL2); it is import-cheap and dependency-free so every layer can call it.

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
- DECIDED (OD-2, 2026-10-11, under the owner's delegation, revisable): the optional SHA-256
  checksum is integrity only; signing (authenticity) is a non-goal until key management exists,
  and the operator signs out of band (§9).

## §5 Implementation plan (each step its own commit, green before next)
1. `errors.py` + `config.py`: typed config model (Pydantic v2), env/vault sourcing,
   `--unsafe-render` and `--allow-pii-elicitation` flag surface. (As built: the typed `SafetyFlags`
   carry both values, default off; neither is a CLI flag, so the DL4 run key cannot be turned on
   from `dottore`. OD-11, decided 2026-10-11: the run flag is added only together with a flag that
   loads a policy pack, never alone, since alone it would enable nothing.)
2. `redactor.py`: pattern registry (key prefixes `sk-`/`ghp_`/`AKIA`/`xoxb-`/JWT/PEM + PII:
   email/phone/card/IBAN/national-id/IP), masking with type-tag, structural walk over dict/list.
   (Since A-78 the documented key formats of 11 providers, every hex run of 32 digits or more and
   the UUID shape too, whatever their entropy.)
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

**A-19 Schemes are allowlisted.** `https`, loopback `http`, the offline `mock` scheme and, since
the WebSocket adapter (2026-10-07), `wss` (as `https`, default port 443) and loopback `ws` (as
`http`); every other scheme is denied. Refusing `http` off-loopback and letting the rest
through to the host check meant `ws://`, `ftp://`, `file:///etc/passwd` and a scheme-relative
`//host/path` all passed, with the invariant resting on adapter implementation rather than on
the gate. `tests/policy/test_allowlist.py` pins both halves.

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
credential match (A-30; the credential half had no test until the pre-merge audit of #85, and
is now tested with the key on either side).
Every refusal that names the judge's id says when it is the default `judge` of a `judge:` block
that names none, and only then, the `--judge` file mismatch included. Target pairs are
reported before the judge, and one refusal names one pair: the first entry whose id repeats
an earlier one under `casefold()`, with that earlier entry (`[A, B, b, a]` names targets.1 and
targets.2). The
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

**A-31 A mask depends only on what it masks (added 2026-10-07).** With the salt fixed, one value is
masked the same way in every process and wherever it appears: a digest is computed over the value
as it is written in the text, never over the redactor's own stash tokens (their numbers count the
masks set aside before them) nor over anything a set orders (its order changes with
`PYTHONHASHSEED`). A private key's digest depended on both: six hash seeds of twelve gave one
digest and six another, and in one process the same key had another digest after a mask. The same
set order decided which of two overlapping registered credentials was masked and left the other's
tail readable; overlapping credentials are one run now, named after the longest. The URL rule holds
when part of the URL is already masked: a URL's password stayed readable because its user was a
registered credential, set aside before the rule ran, and since #96 when a registered credential
holds one of the URL's separators: one holding its `://` (two overlapping credentials masked as one
run included, which covered the `://` that the one-at-a-time replacement before A-31 left), its
`:`, or the password's `@` with no later `@` stopped the rule and left the password, or its part
outside the credential, readable. The URL is read in the text as written (every registered
credential written out, every other mask one neutral character), last in each pass, after every
other rule, and what of its password is still readable becomes one `url_password` mask; a URL the
rule read at a `://` in the text as it reads is left as the rule masked it, an email mask is read as
holding an `@` (where the rule found no URL, the email rule took the password's tail and a dotted
host as one address), and the `:` after the user of a URL the next pass can read stays out of the
mask. A credential holding an `@` across the URL's `@`, in the user or the password, still lets the
rule read on to a later `@`; when that `@` is a labelled value's, the URL mask takes the label and
the value's head, and since #96, after the other rules of the pass and only where they left text
readable, the rest of the value after the mask's `@` is masked as the value is, with its digest (the
one the redactor before A-31 gave it when no other rule masked something inside the value first), up
to a `://` that a `:` and then an `@` follow before any whitespace (what the rule needs to read a
URL there, in this pass or the next: a mask only hides characters), and the labelled rule is run
again from where the value ends (not from where the tail stops), without reading its tail for a
label, as the redactor before A-31 read it (PR #56
left the tail readable, and a label in it took the next label into its value: pre-merge audit of
#96). The pre-merge audit's proposal for #96, leaving such a password to the other rules, left
readable a character main masked in 15,239 of 300,000 differential texts (the password's head before
the credential); the fix leaves none, and is checked by a differential fuzz against main before a
change to these rules is merged. A pass that joined the password to such a credential before the
other rules ran was backed out of PR #56 after the audits of its two versions each found a new hole
in it. (Left open after #96: where the URL rule did read a URL, its reading stands, so after a
registered credential holding the user's `:` the rest of the user is shown
(`redis://ops:svc-keyXYZ:<password>@host` with `ops:svc-key` registered shows `XYZ`, which urllib
reads as the password's head); a labelled value whose label sits in the user of a URL read through a
mask or behind an empty user (both read since #56), or is glued to the word before it
(`...3password="x@host.tld`, a label to no version), keeps what follows the URL's `@` readable as
its host, where the redactor before #56 masked it whole or as an address; the rest of a labelled
value after a URL mask stops before a `://` that a `:` and then an `@` follow before any whitespace
(the shape the URL rule needs, in this pass or the next), so what of the value lies past that `://`
is left to the other rules (`secret=AETw://0G1h9.mGle` and U+200B before `://u:<password>@h` shows
`0G1h9.mGle`); a raw `@` in a URL's user or unregistered
password leaves the password, or its part after the `@`, readable; and a URL whose `://` is split by
an invisible character (`s3:/<U+FEFF>/bob:...`) is read by no URL rule.
Not yet every
rule either: the labelled-secret rule stops at a mask, so `api_key=<registered credential><tail>`
keeps its tail readable, as before A-31. Nor every key: the key pattern's 16 KB bound counts each
mask inside the key as a stash token whose length grows with the masks before it, so a key near
the bound is masked as a key or not depending on the text before it, and one a single pass cannot
take whole is masked as a key later, over its text with the masks inside it, or never; before
A-31 too.)
Checks: `tests/test_redactor_url_password_and_digests.py` (twelve hash seeds in subprocesses,
digests against an HMAC computed in the test, the evidence store's leak guard, a property over
URL shapes, credentials holding a URL's separators inside the user or the password), and
`tests/test_redactor_url_separator_credentials.py` (#96: the issue's two cases, a credential
across each separator, a property over URLs with one or two credentials across a separator, the
labelled tail's limits the fuzz found, memory and linear time on 2 MB of hostile echoes).

**A-32 A registered credential is matched with the characters that do not show ignored (added
2026-10-07).** In a text holding a control character (C0, DEL, C1, U+2028, U+2029, a lone
surrogate), a format character (Unicode Cf, pinned to Unicode 16.0, in three named kinds since
the pre-merge audit of `3f7b1254`: `EMPTY_FORMAT_RANGES`, `FORMAT_SIGN_RANGES` and `TAG_RANGES`,
the one list `shared.provider_filter.blank_text` reads too) or U+FFFD (what half a
character in a reply reads as where the reply is parsed, u04 A-47), `redact_text` finds each
registered credential in the text with those characters dropped, and the stretch it covers, the
characters inside included, becomes the mask an unsplit occurrence gets, with the same digest;
overlapping credentials are masked as one, named by the longest as it shows (the first to start on
a tie), and a credential too short to be matched without those characters is matched as written and
masked with what it overlaps. Split by a newline or a zero-width space a credential was kept in two
readable halves in every report, in the evidence and on the terminal, while split by `\x00` it was
masked (audit of PR #51). Text without such a character is redacted byte for byte as before, unless
a registered credential itself holds one (a differential fuzz against main is the check, run before
a change to this match is merged), redaction stays a fixed point, and the match is linear in time
and memory: the terminal-only first version took about 140 MB a megabyte of control characters.
Checks: `tests/test_redactor_split_credentials.py` (every Cf character of the running Python, the
JSON report, evidence, run store and CLI paths, a property test for the fixed point, memory and
scaling on multi-megabyte hostile text), and in `tests/cli/test_lone_surrogate.py` a credential
split by half a character in a reply (escaped, as raw bytes, or a U+FFFD the target wrote).

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
is A-43's. Checks: `tests/cli/test_yaml_expansion.py` (the cap exactly, the
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

**A-43 An operator's file is read up to 1 MiB, and its validation errors are listed up to 20
(added 2026-10-07).** The scope, target, fleet and labels files and the policy and signature
packs are read through `shared.files.read_text_capped`: a regular file over 1 MiB
(`MAX_FILE_BYTES`, the spec loader's `MAX_YAML_BYTES`, pinned equal by a test) is refused on its
size before any of it is read, and anything else (a pipe, a device) is read up to one byte past
the cap and refused if that byte comes, so `/dev/zero` costs one cap. The refusal is an
`OSError` (`EFBIG`) with the path and the sizes written with thousands separators, which every
loader already reported as a file it cannot read, exit 3 at the CLI: written bare, a size of
nine digits or more was masked as a phone number by the CLI's redactor (found by this clause's
own CLI test). The text is what `Path.read_text(encoding="utf-8")` gave, line endings included,
so a scope checksum covers the same text. `dottore fleet` measures every file it would write
before it writes any, one at a time, and refuses one over the cap: the scope repeats each
endpoint, so an 845,022-byte fleet file wrote a 1,355,024-byte scope with exit 0 that the `run`
it printed then refused (pre-commit audit of this clause); with entries of about 170 bytes the
crossing is at 3,870. A target or the judge file can be the one over the cap, as non-ASCII text
is written escaped (a 600,000-byte model name makes a 1,260,144-byte target), so the refusal
names the file and says to split the fleet only for the scope. The judge file is measured only
when the printed command reads it, not when `--judge` names another. Measuring every rendered
file before writing held them all at once (29 MiB for 60 targets sharing one 500 KB anchor,
delta audit); one is held at a time. `shared.config_errors.validation_problems` lists the first
20 errors by default, counts the rest, and cuts a field path or a reason past 300 characters, as
the spec loader cuts its schema messages; the scope, fleet and policy-pack loaders use that
default, and so does the target loader for `capabilities` and `sampling_defaults` since #73
(A-45). Both holes were found by the pre-commit audit of the alias-expansion cap (PR #71): the
files were read whole with `Path.read_text`, so a scope or labels file padded with 100 MB of
comments was read and parsed whole (39.5 s and 244 MB) and a sparse gigabyte of labels peaked at
about 2 GiB (2,009 and 2,116 MiB in two measures), and a limit on the parsed document does not
bound the text it is parsed from; and every validation error was listed whole, so a 5.5 MB scope
with 5,500 extra keys of 1,000 characters printed one `error:` line of 5,687,058 characters from
`dottore run --dry-run`. The figure and reading any file type, not only a regular one, are the
owner's decisions of 2026-10-07 (OD-26): `--scope <(cat scope.yaml)`, `dottore fleet <(...)` and
a labels file through a pipe worked and still do, and a named pipe with no writer still blocks,
as before. A target file could not be a pipe while `run` read it four times and `fingerprint`
three; since #77 parses it once (A-42), `run -t <(...)` and `fingerprint <(...)` read it through
a pipe as well (a `--judge <(...)` file already could: it was read once). An anchor used many
times is A-37's, not this clause's: this read cap and the listing do not bound it (a 30,852-byte
scope of aliases peaked at 1,066 MiB in validation before A-37 was in, pre-merge audit), and
A-37's node cap refuses that file. Not covered (OD-26): the report JSON that `dottore diff` and
`calibrate` read, and the evidence artifacts `replay` and `run --resume` read. An error outside
the validation listing quoted a value of the file whole (an unknown target `type`, a duplicate
target id, an undefined YAML alias), bounded only by the 1 MiB read: A-51 cuts it. Checks:
`tests/cli/test_operator_file_cap.py` (the cap exactly, before the read and after a growth, a
pipe and `/dev/zero` under a time and memory limit, the text `read_text` gave, each loader, the
`fleet` boundary, each target and the judge measured one at a time, the listing and its cut, the
CLI's exit 3 and its one short line, and a sparse gigabyte in a subprocess bounded at 20 s and
256 MiB).

**A-51 A refusal of an operator's file quotes a value of it up to 300 characters, and names a file
that is not UTF-8 (added 2026-10-07).** The refusals written by hand that name a value of the scope,
target, fleet or labels file go through `shared.config_errors.quoted`: the value's `repr` when that
is 300 characters or fewer, exactly as before; past that, its first 300 characters and its length
(`... (N characters)`), or for a list, mapping or set its first 300 characters and how many items it
holds (`... (N items)`), without building the `repr` whole, because YAML aliases make it larger than
its file (90 KB of a list of 20,000 aliases of one 10 KB text is 200,080,000 characters of `repr`,
about 200 MB to build); an integer Python will not write out (a YAML hex or base-60 integer past
4,300 digits, whose `repr` raises) is shown as `shared.digits` describes it (A-40, #81), `a number
too long to write out (over N digits)`, inside a list or mapping too. They are: an invalid target
`type`, refused before the enum looks it up, because the enum's own error built the whole `repr`
(that 90 KB file as a `type:` took 1.28 to 1.49 GB of resident memory and 29 to 50 s in five
measures on `a0bca70`, and printed a line of about 200 MB; it takes 72 MB and 0.6 s now: audit of
this clause), and an invalid `mock_scenario`; a duplicated scope target id, a duplicated identity
name and an identity that shares a canary, with the id of the target they belong to; a labels entry
with an invalid verdict (its spec id); two target files with one id in `run`; the target id and the
endpoint in the authorization refusal (`policy.authorize_target`, so `run`, `fingerprint` and the
engine's gate on each attempt; since #96 the endpoint as `shared.config_errors.shown_endpoint`
quotes one, below, since cut first a password whose `@` fell past the cut was not read as a URL's
by the CLI's redactor, and 287 characters of a 308-character one were printed), the target id that
`run` and `fingerprint` write in front of it, and
the ids the scope authorizes, which they list after it (the first 20, each cut, then `and N more`:
`shared.config_errors.listed`), since a target the scope names and refuses by endpoint or command
came back whole there; the target id in the `--hardened`, stdio and credential refusals of `run`,
and the references the scope declares, listed by the credential refusal (20, each as
`shown_auth_ref` quotes it, and how many more: 3,000 references of 290 characters printed 885,131
bytes), and the variable a reference names when its value holds a control character; an `auth_ref`
reference wherever `shown_auth_ref` quotes one (a literal is still never shown; since #96 one
holding
an `@` is quoted as an endpoint is, without its userinfo); the target id, and
the one the run store recorded, in the three refusals that bind `run --resume` to its target (an id
of 900,000 characters printed 900,276 bytes); in `dottore fleet`, an endpoint with an invalid port,
the judge id and the judge fields a `--judge` file gets wrong; and, cut as one text with
`shared.config_errors.cut`, the unknown keys of a target's `seeded_setup` and the tools it both maps
and grants. PyYAML's problem text (`shared.config_errors.yaml_problem`, so every YAML loader, the
spec loader and `dottore lint` included) is cut the same way. A label's verdict, a target's
`provider` and `transport`, and the keys of its `seeded_setup` are checked as text before anything
turns them into text: `str()` of a list of aliases took about 675 MB of resident memory (400 to 600
MB traced by the test on `a0bca70`), and of an integer past 4,300 digits it raised Python's own
`Exceeds the limit (4300 digits)` error, naming no file (delta audit); a labels key or a
`seeded_setup` key that is such an integer is refused as A-40 (#81) words it, and a `seeded_setup`
key that is text or a date is written as `str()` writes it (a date stays `2024-01-01`). A `provider`
or `transport` that is not text, read as no provider here, is refused since u12 A-53 by the target
file's top-level check, naming the file and still without turning it into text; the tests of an
integer `provider` and of a `transport` of aliases expect that refusal now. An endpoint
or a `base_url` that urllib cannot read (a bracket, a host NFKC turns into a path, a port that is
not a number or has thousands of digits) raised urllib's or Python's error with no file named, and
for a host NFKC turns into a path, a bracketed host that is not an IP address or a port that is not
a number that error quoted the netloc, the host or the port whole (about 900 KB from a
900,000-character value: pre-merge audit). The target loader reads the endpoint stripped, as the
gate reads it (read raw, a leading U+00A0 hid the host from it and urllib's error reached the
terminal later with the endpoint's password: delta audit), and refuses an unreadable one naming the
file and the field and not the value, which can hold a password; `EndpointAllowlist.is_allowed`
denies what it cannot read, as its docstring always said, so the authorization refusal quotes the
URL cut, and an allowlist entry pinned to a port `int()` cannot read (thousands of digits, U+00B2)
pins a port no URL has, so it matches nothing instead of raising and denying every URL checked after
it (read as a bare host, it matched an IPvFuture literal that repeated it: second delta audit); and
`dottore fleet` reads an endpoint stripped too and refuses an unreadable one, or one with a port it
cannot read, or a `--judge` endpoint that differs, quoting it as urllib reads it, its tabs and line
breaks removed, cut and without what precedes the last `@` of its authority
(`shared.config_errors.shown_endpoint` since #96, which the authorization refusal uses too; the
CLI masks a password only in the `user:password@` shape, so a space or a second `@`
printed it, and an empty user did until A-31; and a tab or a line break between the
two slashes, which urllib removes, hid the authority from a search for `//`: final
audit, 0 leaks in 102,024 refused endpoints of its fuzz since). The adapter
`run` builds still reads the target's endpoint unstripped: an endpoint with a Unicode space in front
passes the gate and the run stops at its first send (exit 3, `EndpointNotAllowed`), its password
masked, as on `a0bca70` for `run` and newly for `fleet --run`, which stopped at the pre-flight
before. Before, each quoted the value whole, bounded only by A-43's 1 MiB read: a 1 MB `type:`
printed an `error:` line of 1,000,108 bytes, a duplicated target id of 500 KB one of 500,136, and an
undefined alias of a million characters about 1,000,100 from `run --scope`, `calibrate` and `lint`
(pre-commit audit of A-43, in its measure, file paths included); this clause's sweep found the rest,
up to 2,000,108 bytes from `fingerprint` for a target id of a million characters (the id in the
message and again in the reason), and the 24 refusals of the test's table, with values of 300,000 to
1,000,000 characters, printed lines of 400,080 to 2,000,247 characters on `c9f27cc` and `a0bca70`.
The lengths are written bare, as the spec loader writes them; for the `repr` of a text value the
length stays under 10,485,762, short of the nine digits the CLI's redactor masks as a phone number
(`repr` writes at most ten characters for a character the file spends a byte or more on), and an
item count is smaller. The redactor can still read a head that ends in digits (after a character
that is not a letter, or a value made of digits, a 900-digit `type`), together with the `... (N`
behind it, as one phone number, and masks both (a head ending in `:7` shows `:«REDACTED:phone»
characters)`, the 900-digit `type` `«REDACTED:phone» characters)`): the masking errs toward hiding,
and the length is lost. Bytes that are not UTF-8 in any of these files, or in a policy or signature
pack, are refused by `shared.files.read_text_capped` as an `OSError` (`EILSEQ`) with the path and
the offset of the first bad byte in the file, in the spec loader's words (`not UTF-8 text (byte
N)`), exit 3 in `run`, `fleet`, `calibrate` and `fingerprint`: they raised `read_text`'s own
`UnicodeDecodeError`, which named no file (`error: 'utf-8' codec can't decode byte 0xff in position
15: invalid start byte`). The path is shown as the CLI shows every path (A-38): an existing absolute
one as written, a relative one as written when it exists and is one word, any other through the
redactor, which masks a directory name that looks random.
A valid file's text, and so a scope checksum, is unchanged. Not covered: the stdio advice's command
line, which is meant to be copied exactly, is written whole; so is a target's endpoint wherever a
run that has started prints it (the plan, the reports and the run store), and a labels spec id where
`calibrate` lists the labels the report does not cover. A target or scope id and an identity name
are bounded at 128 characters when their file is loaded since A-57 (OD-27), so a run prints at most
that many characters, or a `repr` of at most 1,282; the id cases of this clause's table use ids of
128 characters whose `repr` is 1,282 (`\U000e0001` or `\U000e0020` for each character), which a
refusal still cuts. A stdio `command` made of YAML aliases is joined into one text wherever the
target is authorized (`wiring.request_url_for`, the engine's gate included) and in that advice:
20,000 aliases of one 10 KB text, a 90 KB file, make a line of about 200 MB, 1.09 to 1.49 GB of
resident memory and about 30 s (five measures; the times depend on the machine), on this branch as
on `a0bca70`. Since this branch merged #71, A-37's node cap (100,000 nodes with the aliases
expanded) refuses that file when it is loaded (`document is too large`, exit 3, 0.3 s and 71 MB);
under the cap a value's `repr` can still be tens of megabytes (60,004,000 characters from a 28 KB
file of 1,000 aliases of 6,000 characters `repr` writes as ten each: audit of the merge), which
`quoted` never builds, and the memory tests use 10 to 16 KB files of 1,000 aliases of a
6,000-character text (a `repr` of 6,004,000 characters). The integer cases use a 600-digit hex
number under the digit limit Python allows at its lowest (640), as #77 refuses a YAML number of more
than 1,000 characters. Checks: `tests/cli/test_operator_file_quoted_values.py` (each refusal of the
table through the CLI with a value past the cut: the line under 5,000 characters (2,500 until #51
wrote a format character out, as up to ten: the two ids of 128 tag characters a refusal names whole
then take 1,280 each), the file named
where the refusal names it, the exact cut and no mask; twenty ids or references listed and the rest
counted, through `run`, `fingerprint` and the credential refusal; the three refusals of `--resume`;
a `repr` of exactly 300 characters quoted whole and one of 301 cut; the head equal to the start of
`repr` over generated values; a list and a mapping of aliases quoted, and refused as a `type`
through `load_target`, under a memory bound; an integer Python will not write, and no other failure
of `repr` hidden; nested aliases one level down; a verdict and a `provider` of aliases not turned
into text; an integer labels key and `seeded_setup` key, and a date key written as before; verdicts
in any case and with spaces; a stdio target real only with a command; a `transport` of aliases;
twelve URLs urllib cannot read, through `run`, `fingerprint` and `fleet`, the endpoint never quoted
by the target loader and its password never printed, by `fleet` either, a tab between the slashes
and a second `@` included; an unreadable allowlist entry matching nothing whatever its place, an
IPvFuture literal included; the variable name; a `--judge` file whose id differs from the fleet's
judge; the UTF-8 refusal through each command, and its offset past one decoder chunk), and the
reader test of `tests/cli/test_operator_file_cap.py`, changed on purpose from "the same
`UnicodeDecodeError` as `read_text`" to "an `OSError` at the same byte, naming the file". On
`4a572f0` (#76 with #81 merged in), with the new helpers stubbed to what the base does (`quoted` and
fleet's `_shown_endpoint` as `repr`, `listed` as a plain join), 84 of these 107 tests (the 106 of
the file and the changed reader test) fail, each for its reason; of the 23 that pass, 4 were fixed
first by #81 (A-40: a labels key and a `provider` that are huge integers, a `provider` and a
`transport` of aliases), and 19 guard what must not change (two of them, an endpoint with no user
information quoted as `repr` quotes it): a short value quoted as before, any other failure of `repr`
raised, verdicts in any case and with spaces, a stdio target real only with a command, a date key
written as before. Of 76 mutants, one per site and one per fix of the audits, 74 are killed; the two
that live are equivalent (they quote a fleet id, which the fleet's model holds to 64 characters).
These counts were measured with ids of 300,000 to 1,000,000 characters, before A-57 bounded them;
A-57 changed those cases to ids of 128 characters whose `repr` still passes 300, and the sites that
quote a target id or an identity name are still killed as mutants (A-57 counts them).

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
has one. Not covered here, OD-30: under the limit of 100 the cost per token stayed, and the same 198
KB of chains 98 deep was accepted in 5.5 to 5.6 s, about 2.3 times the flat list (3 to 4 times at
depth 95 in the audit, under another load), the scanner walking 29.8 million keys; chains 98 deep
holding 300 texts at the bottom walked 52 million and took about 3 times the flat list, the worst
accepted shape the audit found. A-58 bounds it with a limit of its own for flow style. Checks:
`tests/cli/test_yaml_written_nesting.py` (where composition stops, by a character no token can start
written lines inside the collection at level 101, for flow and block lists and maps and in both
loaders; the position against `check_expanded`'s on the whole document; several branches; a key
before an empty list; a text, an alias and a map's keys at level 101; every shape at the limit,
siblings included, loading as plain PyYAML loads it; the precedence, in the order written and in the
order checked; one count per document; a tag too long reported first, as before; 5,000 levels; a
`RecursionError` while composing, raised without recursing, and in a subprocess a caller with little
stack left, both still refused as too deep; the scanner's work on the audit's file is A-58's, which
refuses it first). Since A-58 its shapes reach level 101 in block style, or in block style with 20
flow levels inside.

**A-57 A target or scope id, and an identity name, is at most 128 characters (added 2026-10-07,
OD-27).** `policy.scope.MAX_ID_CHARS` (128) bounds a scope target's `id` and an identity's `name` in
the scope model, so a longer one is a validation problem of the scope file (`targets.0.id: String
should have at most 128 characters`, listed as A-43 lists them), and `cli.wiring._target_from`,
which `load_target` and `read_target_file` share, refuses a target file, or a `--judge` file, whose
`id` is longer (`target file <path> 'id' is 1,000,000 characters, over the 128-character limit`, the
length and never the value), exit 3 in `run`, `fingerprint` and `fleet --judge`. The length is
counted as Python counts a text, in code points. Before, such an id loaded and a run that started
wrote it whole: the `--dry-run` plan, the `-sV` lines, the reports and the run store (the plan of an
id of a million characters ran just over 1 MB, exit 0; the file is now refused, exit 3, on one line
of a few hundred bytes with its path), and so did messages of `run` that A-51 did not reach, among
them `nothing would be sent: every selected spec is unrunnable on <id>`, the `-sV` probe ceiling
refusal and its resume notice, `run on <id> did not complete`, the warning for a live target with no
`--judge`, and the `--estimate` and `-sn` lines, which now print at most 128 characters or a `repr`
of at most 1,282. A bound when the file is loaded (OD-27, decided 2026-10-07 by the implementer, the
owner having left the choice to them) was chosen over cutting the id everywhere it is printed, which
would leave reports without the id the scope names, and over leaving it. The figure is twice the 64
a fleet's ids are held to (they name files) and about six times the longest id in this repository's
examples (21 characters); a fleet's ids keep their 64 characters and their pattern, and no pattern
is imposed here, so an id with spaces or other characters loads as before. A-51's quote of an id
still matters: an id of 128 characters can have a `repr` of 1,282 (U+E0001 is written `\U000e0001`),
so A-51's cases of a long id use such ids, and its test checks that no id is quoted whole anywhere
in the output, which a second, cut quote of the same id on the line would otherwise hide: it looks
for the opening quote of the id's `repr` and the 300 characters after it (one more than a cut keeps;
the quote since #51, which writes an id named whole in the same escapes without one), with
the line breaks removed first so that a message Rich folds would be caught too (none that quotes an
id goes through Rich today, so that part is defensive). The `-sV` probe ceiling refusal and its
resume notice write the `repr` whole, and no case of that test reaches them. Not covered: a spec id
has a pattern and no length bound, and a run prints it whole (a spec id of 500,003 characters
printed about 507 KB on a mock run, exit 0); `dottore diff` prints a report's target id whole when
two reports disagree, and `dottore diff` and `calibrate` list every target id of a report with
several targets whole, a report being the tool's own output (OD-26) and one written before A-57 able
to hold a longer id; a run stored with a longer id cannot be resumed, its target file being refused
now; and an id may hold control and format characters, which the plan and `-sV` lines print as they
are (errors and warnings write them out since #51, u12 §6, up to ten characters each). Endpoints,
`auth_ref` references and labels spec ids stay unbounded, cut in refusals, and `calibrate` still
lists the labels a report does not cover whole, as its normal output. Checks:
`tests/cli/test_operator_id_length.py` (the figure; 128 characters load and 129 are refused, for a
scope id, an identity name and a target id; a long id refused when its file is loaded, through
`run`, `run --judge`, `fingerprint` and `fleet --judge`, on one short line that names the file and
never the value; an id of 128 characters runs and the plan names it), 9 of its 11 tests failing
without the bound, and 5 mutants (each bound removed, `>=` for `>`, a limit of 64) killed; and
A-51's cases in `tests/cli/test_operator_file_quoted_values.py`, where each of the 19 sites that
quote a target id or an identity name (on 18 lines; the ids of a fleet, held to 64 characters,
aside), written as `repr`, is a mutant killed (14 of them survived the whole suite when those cases
were removed, as the audits of A-57 found; 3 are killed only by the check of the whole output). The
control mutant survives both.

**A-58 A list or a map written in flow style inside 20 others written in flow style is refused where
it starts (added 2026-10-08, OD-30).** Every loader (the spec loader and `safe_yaml.safe_load`, so
the scope, target, fleet and labels files and the policy and signature packs) refuses a list or a
map written with brackets or braces inside 20 others written that way, at the position where it
starts and before anything in it is composed, with `document is nested too deeply in flow style
(over 20 levels of brackets or braces)`: a YAML error, exit 3 at the CLI and a `PARSE_ERROR` in
`lint`. Block nesting does not count toward it, only toward A-52's limit of 100, which is checked
first, so a collection that crosses both gets A-52's message. A single pair in a flow list (`[k:
v]`, `[? k : v]`) is a map in flow style with no bracket of its own, and the scanner opens no level
for it, so it does not count either; the first version counted it and refused 11 such lists
(pre-commit audit). Only a text or bytes is looked at for brackets: read from a file object, every
list or map in flow style counts. PyYAML's pure-Python scanner keeps one possible simple key per
open flow level and passes over them about three times on every token, so each open flow level costs
on every token written inside it: under A-52's limit a 198 KB list of chains of `[` 98 deep was
accepted after the scanner walked 29.8 million keys, and the same chains holding 300 texts each
after 52.0 million (1.65 s and 2.34 s, 2.0 and 2.8 times the 0.82 s of a flat list of as many texts,
best of three at a load average of 4.5; audits of #84). Both are now refused at the 21st `[` in 0.01
s, the scanner walking 0.17 and 0.31 million keys, and chains 19 deep in the root list holding 300
texts each, the costliest shape the audits of #84 found, walk 11.4 million keys in 1.11 s, about
1.35 times the flat list. The limit bounds what each token walks, about 21 keys a pass, not what a
file walks: a denser file, whose entries carry an anchor and a tag (four tokens each), walks 21.0
million keys in 789 KB, 2.3 times a flat list (pre-commit audit). As for A-52, the scanner still
reads ahead past the 21st `[`, to the end of its line, at most 1,024 characters, and one token past
it. The limit counts what is written: an alias repeats no text for the scanner to walk. A file
written as JSON is flow style throughout, so it too nests at most 20 levels. The YAML files the
repository ships nest at most 2 flow levels (a test reads every YAML file in it). The depth tests of
A-52, u12 A-9 and A-37 that wrote their depth as chains of `[` now write it in block style, or in
block style with 20 flow levels inside. The alias-depth tests of u12 A-9 wrote each anchor 101 deep,
so since #84 their files were refused as they were written, not for their aliases, and their
assertions, `nested too deeply` only, could not tell: they now nest 20 levels per anchor, under both
written limits, and assert it (`written_nesting` in `tests/cli/conftest.py`). Checks:
`tests/cli/test_yaml_flow_nesting.py` (flow lists, maps, the two mixed and flow inside block maps at
21 levels, a tag or an anchor before the bracket, single pairs in flow lists at 20 and 21, a file
object, with the position, the message and composition stopping before the rest of the collection,
in both loaders; every shape at 20 levels, siblings included, loading as plain PyYAML loads it; the
depth limit checked first; one count per document; the repository's files; and in a subprocess
bounded at 30 s, the keys the scanner walks for `lint` and `calibrate` on chains 98 and 320 deep,
under 1 million, and for `lint` on chains at the limit holding 300 texts each, under 12 million).

**A-63 An error's class name is never masked by the redactor (added 2026-10-09).** The terminal, the
stored evidence and the reports get an error through the redactor, and some messages write an error
with its class: an attempt's error and an adapter's last failure (`<class>: <message>`), a halt
reason (`aborted on <class>: <message>`), the unreachable reason, which quotes the first attempt's
error, a probe recorded as failed (`<layer>/<probe>: <class>`) and a mutator's error in the carrier
layer. The high-entropy rule masks a token of 16 characters or more, not shaped as a separated
identifier or path, at 3.7 bits a character or more, so such a class name reads
`«REDACTED:high_entropy:<digest>»` there: the failure class is lost and the line reads as if a
secret had been masked. PR #87 renamed four of the WebSocket adapter's, which reached the CLI error
and the evidence. A walk of the package's 45 exception classes on `f12ba83` found four more, none of
which any message wrote with its class: `ChecksumMismatchError` (21 characters, 3.78 bits),
`ProbeCeilingReached` (19, 3.72), `BudgetExhaustedAfterReply` (25, 3.97) and `_ImpossibleFigure`
(17, 3.73). Raised from a mock target's adapter, the first read `error: run on mock-t did not
complete: aborted on «REDACTED:high_entropy:2559426b»: scope checksum mismatch: ...` on the terminal
and in `summary.status.reason`. They are `ScopeChecksumError` (18, 3.57), `ProbeCeilingHit` (15),
`ReplyOverBudget` (15) and `_UnreadableLogprob` (18, 3.61), named for what `readable_logprob`
refuses (a string that spells a number, a bool, anything that is not a JSON number, as well as a
figure no model produces); `ChecksumMismatchError`, which `ildottore.policy` exported in 0.1.0,
stays as an alias of the same class, so code that imports or catches it still works. The rule is not
changed: a name is chosen that it keeps, as a figure is written so the phone rule keeps it (u08 A-6,
u12 A-61). Checked by `tests/policy/test_redactor_error_class_names.py` (CI Gate 3), which imports
every module of the package, takes every class `BaseException.__subclasses__` reaches that the
package defines, and fails on any whose name `redact_text` changes, alone or in six lines shaped as
those messages write it. A class written inside a function body exists only once the function runs,
so whether that walk sees it depends on which tests ran first: every class written in a function
body, at any depth, is read from the source instead and its name checked in the same lines (there
are none; a test shows the pass finds one in an `if`, in a function inside a function and in a
method). On `f12ba83` two of its four tests fail: the walk, naming the four in 24 lines, and the
alias. It replaces #87's test, which read the WebSocket adapter's `__all__` only. Not covered: the
names of other packages' exceptions, which cannot be renamed: of 216 distinct names in Python's
builtins, the standard-library modules the adapters use and the ten declared dependencies, the rule
masks 12, among them httpx's `TooManyRedirects` (never raised: no send follows a redirect, and the
adapters catch only `TimeoutException` and `TransportError`), websockets' `InvalidProxyStatus` and
`InvalidProxyMessage` (an `InvalidHandshake`, reworded without its class) and six of pydantic's
(`PydanticSchemaGenerationError` among them); nor a plugin's own.

**A-77 A reply kept in pieces is masked as the text the pieces make (added 2026-10-12, audit of
main `de122e26`, HIGH 1 and MEDIUM 2, amended after the pre-merge audit of `c4bd2012`; halves in
u04, u08, u10 and u11).** The redactor masked each string on its own, and the evidence store and
the reports inherit that: `response.text` read masked while the same text was kept in pieces of 1
to 4 characters in `response.logprobs[*].token` and each token's `top` alternatives (the OpenAI
adapter asks for logprobs by default, so every `provider: openai` target) and in the deltas of
`raw_ids.websocket.frames`, each piece too short for any rule. Against a loopback stub, joining
the `token` fields of the evidence and of `r.json` gave back the run's canary and an `sk-proj-`
key, and joining a transcript's deltas a registered credential, an email and a key.
`redactor.redact_split(redactor, value)` reads the streams of a value as the text they make. A
logprob list (a list of objects each with a string `token` and a `logprob`: the stored
`TokenLogprob` and OpenAI's wire shape) gives its tokens; a WebSocket transcript (an object with
`frames`, each `{direction, frame}`, and `protocol_paths`, u04's half) gives each field of the
frames received that is not under a protocol path, field by field (a logprob item's alternatives
aside, under `top` or `top_logprobs`, as in a list). A stream's pieces are joined
in order and redacted once, and the masks are placed back on the joined text: each literal of the
redacted copy is placed as early and as late as it can be, so a mask spans every character it
could stand for (`_placed_masks`). The first piece a mask covers shows it in place of the part it
covers, and every later piece it covers loses that part (one it covers whole is empty), so,
joined, the pieces show each mask once and never more than the redacted text; they show less
only where a literal between two masks could stand in more than one place, since the masks then
merge and that literal goes (8 of 1,500 realistic replies and 309 of 1,500 hostile ones in the
second pre-merge audit, always towards masking more). A mask shown in every piece it covered
read, joined, `user:«REDACTED:url_password»«REDACTED:url_password»...@host`, which the URL rule
masks again as one, and the store's guard refused a URL password the redactor had masked (18 of
18 connection strings at token sizes 1 to 8, and two in WebSocket deltas; the run aborted, where
`main` exits 0: pre-merge audit of `c4bd2012`, HIGH 1). A mask that cannot be placed masks its
stream (`«REDACTED:fragment»`, a type the tool writes, in the first piece). A token a mask covers
has its alternatives masked once the item's every edit is made (an alternative written as the
token shows what the token shows, any other the token's masks; a later edit used to undo them and
leave 10 characters of a labelled password, MEDIUM 2), and wherever a token or an alternative is
masked, by its stream or on its own, the `bytes` OpenAI writes beside it go, since they spell it
(LOW 4); so in a transcript's frame, where an OpenAI chunk streamed with logprobs holds one
logprob item (found with the fourth pre-merge audit's fix: the chunks' `bytes` spelled a key an
event stream's excerpt masked, on `main` and on `5dd87b42`, and each rank of alternatives was
joined across the chunks, so 4 of 6 clean replies streamed with alternatives were masked). The
alternatives are no stream: a rank of them side by side, or the alternatives of one token, is
text no one wrote, and joining a rank masked 6.9% of all the alternatives of clean
replies (5,794 of 83,950 on the auditor's 898 clean replies), each beside a token that was kept
(LOW 5; none now). Then each string is redacted
on its own (`Redactor.redact`), and both again while either masks more, so the result is a fixed
point of both; a text holding a stash delimiter is read both ways `redact_text` reads it. The
figures, the shape and every piece no mask covers are kept, so `logprob_membership`, `dottore
replay` and a reviewer read what they read before. The pieces are masked rather than dropped (the
audit's other proposal, since `response.text` holds the text) because the alternatives and a
transcript's other content fields are in no other field, a figure is read with its token, and a
transcript is the record of what went over the socket (OD-34). Only streams are joined: joined,
every list of a transcript read its frame types as one high-entropy token
(`auth_oksessiondeltapingdelta...`) and masked the type of every frame, so a list of records
(messages, tool calls, matched values) is masked string by string as before; a transcript that
names no `protocol_paths` (stored before they were recorded, or built by hand) is read with the
frame type at `type`, the default `type_path`. `redactor.split_texts` gives the joined texts the
store's guard checks, `redactor.withhold_split` empties every piece of a value's streams (the
runner's answer to a refused write, u08's half), and `redactor.mask_keys` masks a mapping's keys
with the store's numbering (moved from the store; the store and the reports both use it, MEDIUM 2;
`KeysNotDistinct` where no number tells two apart). An unreadable reply's excerpt reads only a head
of the body (u04's half): a stream the head cuts has its streamed text withheld, not masked, its
keys, structure, numbers and protocol fields kept, only the lines `main`'s excerpt shows whole
quoted (fifth pre-merge audit: emptied lines are short, and the excerpt reached lines `main`'s never
reached), and of those only blank lines, JSON lines and the format's `data`, `event`, `id` and
`retry` fields (sixth: a comment after a label in the withheld text lost the mask `main` gave it
through the label), and says so once. That is the owner's decision of 2026-10-13, under the
delegation (best practice): fail closed, an excerpt may show less than `main`, never more. A secret
whose pieces cross the cut is never read whole, so no rule masks it: masked across the head, a URL
password with symbols showed its beginning at 7 of 31 cuts and a 300-character registered credential
at 70 of 111 (fourth pre-merge audit, MEDIUM), and with only the head's first half shown and a
stream's open tail left out, a 600-character URL password of words still showed 20 to 61 of its
characters (`main` 0 to 3) and a stream that paused past the head showed its secret's beginning;
withheld, none shows at any offset. Not covered: a secret a target splits over a list of its own
JSON that is no stream (a REST body's array); a secret its alternatives alone spell while the tokens
beside them are kept (a rank of `top` or `top_logprobs`, and the `bytes` of those alternatives, as
an unreadable reply's excerpt quotes them: no model's alternatives spell a text, each being weighed
for the token the model wrote before it, and joining them masked clean replies); in an unreadable
reply's excerpt: a line that is no field of an event stream (a `data:` after a space, a `Data:`
line, a delta on a plain line); pieces in a comment, an `event:` or an `id:` line; data whose pieces
each begin with a space the format keeps (`data:  x`); an event whose JSON a raw CR or LF breaks
(read as text); JSON lines in any shape but Ollama's and OpenAI's chunks (they are records, masked
string by string), JSON lines with one line that is not a JSON object (a trailing `[DONE]`, a
leading log line), lines of JSON strings or with CR-only ends, and a body mixing events with JSON
lines; in a body the read head cuts, a secret split over the fields kept there (the protocol's
fields, a role or a finish reason, a key), quoted as `main` quotes them, each string redacted on its
own and no further into the body than `main`'s excerpt; and any other line-based format (u04's half
says what is read); a secret encoded rather than split; a field of a transcript that the target file
declares as the protocol's; and evidence written before A-77, whose pieces stay on disk. Checks:
`tests/test_redactor_split_values.py` (a property test cuts a key, a registered credential, an email
and four URLs with a password into pieces of 1 to 4 characters, as tokens and as deltas, and checks
every joined text is a fixed point), `tests/store/test_split_values_at_rest.py`,
`tests/reporting/test_split_values_and_keys.py`, `tests/adapters/test_split_values_in_replies.py`
and `tests/cli/test_split_values_e2e.py`.

**A-78 The documented key formats, every run of 32 hex digits and the UUID shape are masked whatever
their entropy, adding masks to what the redactor masked before and taking none away (a text holding
U+0000 or U+0001 aside, under *Not covered*); what the tool computes in those shapes stays readable
where it writes it, and a report names its target as before; and every adapter refuses a credential
under 8 characters (added 2026-10-11, pre-merge security audit, MEDIUM 4 and LOW 6; revised
2026-10-12 after the pre-merge audit of this clause, H1, H2, M1, M2 and L1 to L5, and 2026-10-13
after its second round, R2-H1 and R2-L1 to R2-L6).** Only `sk-`,
`ghp_`, `AKIA` and `xox` had a rule: `sk-ant-`, `sk-proj-` (whose `-` cut the `sk-` rule),
`github_pat_`, `AIza`, `glpat-` and `hf_` rested on the entropy rule, so a body of low entropy (a
repeated pattern) was printed, and `\b` refused a key after `_`, a word character, so a key glued
to padding was diluted below the threshold: 30 `_` before printed 155 of 200 `ghp_` tokens and
every `AKIA`, `glpat-` and `hf_` one, 20 `=` on either side every `AIza`, `glpat-` and `hf_` one, 20
`-` before every `glpat-` one. Hex caps at 4 bits a character and a short draw seldom shows all 16
digits, so the threshold printed 74.7% of random 32-hex keys (an Azure key), 47.5% of 40-hex, 5.5%
of 64-hex and 47.7% of v4 UUIDs (the auditor's generators, 2,000 draws each; 46.8% for UUIDs in the
rerun on `de122e26`).

*The rule.* `redactor._late_patterns` holds the documented formats, each sourced in its docstring
(OpenAI `sk-`, `sk-proj-`, `sk-svcacct-`, `sk-admin-`, `sk-None-`; Anthropic `sk-ant-`; GitHub
`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`; GitLab's 13 prefixes; AWS `AKIA`, `ASIA`,
`ABIA`, `ACCA`; Google `AIza`; Hugging Face `hf_`; Slack `xox[abeprs]-`, `xoxe.xoxb-`, `xoxe.xoxp-`,
`xapp-`, `xoxe.xapp-`, `xwfp-`; Stripe `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`, `sk_org_`,
`whsec_`; npm `npm_`; PyPI `pypi-`), a JWT, and the UUID (8-4-4-4-12 hex digits, any version). Each
starts where no letter or digit precedes it (`(?<![A-Za-z0-9])`, not `\b`), takes its body
greedily, and is hashed. They run last in each pass, after the labelled rule, the entropy rule and
the URL rule as written: run before them, a key glued to a word took less than the entropy rule took
of its token (`x_<key>` showed `x_`, `ghs_<app id>_<JWT>` the app id), a greedy body took the label
glued after it (`<AIza key>-x-api key : <secret>` showed the secret), and a mask's `:` made the URL
rule as written take a URL for one its rule had read (the pre-commit differential fuzz of this
clause against main: 5,120 of 20,000 texts showed text main masks, 1,662 of them 8 characters of a
planted secret). The four rules the redactor had run where they ran, as they were. A token the
entropy rule masks whole is typed by the format it holds (`OPENAI_API_KEY=sk-proj-...` reads
`«REDACTED:openai_key:...»`, the same mask as before, named). A run of 32 or more hex digits (a `0x`
in front included) is the entropy rule's, masked as `hex_token` inside any token the rule does not
mask whole, a separator-structured one too; one inside a late pattern's match is left to it. Each
late pattern carries the literals a match holds (`Pattern.hints`): a text or a token holding none is
not searched.

*A number read inside a UUID.* The card and phone rules, and the labelled ones, read a UUID's
digit-only groups as a number: main masked it where it read it, and the UUID was cut, what of it
lay between the masks readable. What of such a number lies inside a UUID is written instead in
stand-ins of the same length, from a block of the Private Use Area the text does not use
(`redactor._Cuts`); outside the UUID it is masked as before. Every rule after it reads a stand-in as
it read main's mask: a later number rule stops at it, a labelled value runs through it, the entropy
rule's token ends at it. So the cuts are main's, occurrence by occurrence, and the entropy rule
judges each piece main judged, once each (`Redactor._cut_spans`, linear), and masks each cut UUID
whole together with the pieces that overlap it. The late patterns read the stand-ins back, so the
UUID is matched whole at the same place; a stand-in no mask took would become the number's mask, as
main wrote it (a guard: the entropy rule masks every UUID a stand-in is in); a labelled value's
digest is that of the value as written. The used blocks are found in one pass (`_Cuts.for_text`;
testing each block against each character took 2.2 s on the 137,468 characters of the Private Use
Area, R2-L2, now 0.025 s). With no free block, which a text holding one character of each of the
1,072 blocks makes, the number is masked as main masked it, a UUID's included, so the target
controls that fallback; it shows nothing main hid. A redactor without the entropy rule or the UUID
pattern (the CLI's first pass, the model-name twin below) uses no stand-ins and masks the number as
main did. The first version of this clause left the UUID whole and recorded the cuts by the UUID's
text (`_uuid_spans`): with two cut UUIDs in one token the pieces it judged were not main's, so a
value glued between them was readable (160 of 200,000 such tokens in the audit, up to 38 characters,
M1); each piece it judged ran to an end of the token, so a token of glued UUIDs took quadratic time
(32.8 s at 160 KB, about 5.7 h at the 4 MiB reply cap, H2); and a phone rule read across a card's
cut that main's mask had stopped it at, which joined two lines for the labelled rule and showed the
secret of the next label (L1).

*Masks a target writes.* A mask is kept as written when its type is one the tool writes, so a second
pass, the evidence store's check, a report and a resume in another process leave the tool's own
masks alone; the nine types A-78 added (`hex_token`, `uuid`, `anthropic_key`, `gitlab_token`,
`google_api_key`, `huggingface_token`, `stripe_key`, `npm_token`, `pypi_token`:
`redactor._LATE_MASK_TYPES`) are kept as the older ones are, whoever wrote the mask. The labelled
rule alone reads a mask of one of them as text, as the redactor before A-78 read it: kept, as in the
first version, `password: «REDACTED:uuid»Summer2026x` in a reply ended the labelled value and showed
the password, which main masked (83 of the 93 regressions of the audit's mixed fuzz, L3); read as
text there, the value is masked whole, as on main. The redactor writes no such mask where the
labelled rule would take it: a labelled value of 32 hex letters or more is no plain word
(`Redactor._plain_word`), so it is masked as a labelled secret rather than left to the hex rule,
whose mask the next pass would read as text after its label. The rule holds no state, so a mask
reads the same in every pass and every process. The second version kept a mask of the nine types
only when the process had written it, in a record of two bounded generations: a 4 MiB reply holds
about 161,000 such masks, so under a long campaign the first turn's were forgotten before the
evidence store checked the attempt again, read as text they changed, and the store refused the
write, exit 3 where main completes (round 2, R2-H1); a new process read every stored one as text
(R2-L3); and the public identity salt let a target that knows its own id's UUID forge a recorded
mask (R2-L1). The class predates A-78 for the older types
(`password: «REDACTED:high_entropy»<secret>`) and stays as it was.

*A URL the URL rule read.* The URL rule as written (#96) leaves alone a URL the URL rule read in the
pass, and told one by matching the URL rule's pattern on the text at its `://`, where a mask laid
after the URL rule could supply the `:` the URL lacked: the rule then took the URL for one it had
read, and its password stayed readable. A phone or entropy mask did it on main
(`postgres://<credential>Part1xyz-0000000a-...@db` with `admin:Pa55word` registered printed
`Part1xyz`); the hex-run and UUID masks added triggers (L2). The check reads the URL with every mask
of the pass one neutral character (`_AsWritten.in_view`), as the URL rule saw the URL it read, its
password mask included.

*What the tool computes.* The hex rule belongs to the entropy rule: a redactor built without it
(`without_entropy`, an infinite threshold) masks no hex run, so what keeps a value out of that rule
keeps it out of this one: the CLI's carried digests (`TamperError`, `ScopeChecksumError`) and
evidence names (`<sha256>.json`), an existing path (a report named after a commit SHA), a provider's
model name. The reports restore the evidence references (sha256 and the store's own path, R1) and
the scope digest as before, and now the SHA-256 of each media part a request records
(`request.metadata.media_sha256`, kept only as a list of 64 lowercase hex digits; the JSON report of
a multimodal battery at `--runs 2` masked 24 of its 28 on `de122e26`) and each evidence reference's
attempt id, as written, as the attempts' own ids are (u11's half). The evidence store keeps the
media digests as before, and the run store writes the spec, target and judge digests and the scope
digests unredacted (u10). A run id is 12 hex digits, under the floor, and the tool writes no
UUID of its own.

*The target a report names.* A report masks the target id, which the operator wrote, and masked it
with the process-random salt: once A-78 masked UUIDs, an id holding one (`tenant-<uuid>`, a common
naming scheme) had another mask in every run, in the JSON, SARIF, JUnit and HTML reports, and
`dottore diff` refused two reports of one target as two targets, exit 3 (H1; main fails the same
way for a high-entropy id). Each finding's `target_id` and each `run.targets[].id` are now masked by
the rules before A-78 with the fixed identity salt (`redactor.report_identity`, u11's half): such an
id reads as main's reports show it, so a baseline written by `de122e26` compares with a run of this
change (exit 0), and a high-entropy id masks to the same text in every process. The salt is fixed
and public, so a masked high-entropy target id is the same text in every report, of every user, and
anyone holding a guess of the id can confirm it against the 8-digit digest (32 bits); it cannot
recover an id of real entropy. That is the price of comparing two reports (R2-L5); the run store
already paid it, locally. The run store keeps the identity mask by the current rules, as since the
first version of this clause, in its `target_id` column and now in the run row's `target_ids` too,
which took the store's per-process salt (u10, R2-L6).

*Checked end to end.* A full offline run through the CLI (the 75 specs, `--runs 2`, `-sV`, `-vv`,
`-oA`, the evidence store under a UUID directory, the run store, `replay`, `diff`,
`fingerprint --offline`, `--dry-run`, `--estimate`, `-sn`, a `replay` refused for an unknown run,
and a second target whose id holds a UUID, run with `--quick` and diffed), with the salt and the run
id pinned, on `de122e26` and on this change from one working directory: the 240 evidence files,
every terminal output, the SARIF and the JUnit reports are byte for byte equal; the JSON reports
differ in the 24 media digests, now readable, and the timestamps, the HTML in the timestamps, and
the run store of the first target in its wall time. Only the run store of the UUID-named target
differs otherwise: it keeps the target's identity mask (`tenant-«REDACTED:uuid:...»`), which a
resume accepts with main's (below). `dottore diff` has no `--json` option (the first version of
this clause listed one; on `de122e26` and here it prints `No such option: --json`). In a second
full run of the battery (`--runs 2`, `-sV`, `-oA`, the stores, `replay`), every output searched
for each value the tool computed by the digest its mask would carry: none of them (222 artifact
digests, 18 probe digests, 7 media digests, 75 spec digests, the target and scope digests, the run
id) is masked anywhere.

*The CLI.* `cli.app._masked` runs the late patterns on each stretch of the message its entropy pass
reads, after that pass; what it keeps (a carried digest, an existing path, a spec file name) is kept
from them too: run over the whole message, as in the first version, they masked the UUID directory
of an existing evidence root, which main printed as written (L5). Its two redactors run without
them (`late=False`), so each keeps as a mask only the types it had, and one written in the error
(`«REDACTED:jwt:...»` inside a labelled value) is read as text by its entropy pass, which then masks
the value, as before; and its first redactor, without the UUID pattern, masks a number inside a UUID
as main did, so the paths it leaves to keep are main's. A provider's model name goes through the
no-entropy twin (`Redactor.without_entropy`), which drops the UUID pattern with the entropy rule, a
shape rather than a documented format: a deployment's model name holding one (`my-deploy-<uuid>`, a
Bedrock custom-model ARN) reads as before A-78 for the fingerprint's metadata layer (L5); the key
formats and the JWT stay. The evidence store, the run store and the reports apply their own full
redactor to everything they keep, the model name included.

*A run halted before A-78.* The identity mask the run store keeps for a target id, a finding and a
declared tool changed for a value holding one of these shapes: `redactor.identity_masks` returns the
current mask and the one main wrote (main's patterns, no late pass, no hex rule, numbers read inside
a UUID); the resume's target and declaration checks accept either, and the store drops a finding's
row under the old key when it writes it under the new one (u10).

*Credentials under 8 characters (LOW 6).* The redactor masks a registered credential by value only
from 8 characters (`KNOWN_SECRET_MIN_LEN`): the WebSocket adapter refused a shorter one before any
dial, while the OpenAI, Anthropic, REST and MCP-over-HTTP adapters sent it, the `auth_ref` key and a
password in the endpoint URL alike (u04's half). `adapters.base.refuse_short_credential` refuses it
with the WebSocket adapter's message (`<id>: the credential is shorter than 8 characters, which the
redactor cannot mask by value; nothing was sent`, `CredentialTooShort`): in the pre-flight, for the
target and the judge (`check_target_credential`) and for each scope identity of a plan that sweeps
identities (`check_identity_credentials`), so `--dry-run`, `-sn` and `--estimate` say what the run
would; when an adapter is built; for each identity of the sweep (named); and in each adapter before
its first request; the judge raises it rather than abstain. The first version checked the sweep's
identities only at the send, so the three pre-flight modes exited 0 for a scope whose run then
stopped at exit 3 (L4). A password as written and as it reads percent-decoded is checked; an empty
one is no credential (`https://<token>:@host` sends a user only); a stdio MCP target
(`provider: mcp`, `transport: stdio`) and an offline mock are sent no key and are not checked; any
other provider sends its key over the wire whatever its `transport` says, and is checked (the first
version exempted it, L4).

*Measured.* The differential fuzz against `de122e26`'s redactor, a grammar of the new shapes glued
to padding, words, labels, emails, phones, URLs and masks, five draws of 300,000 texts: in each,
about 76,000 texts show 8 characters of a planted secret on main and not here; 19 texts of the
1,500,000 show a stretch of text main masks, 3 of them 8 characters of a planted secret main hides
and the rest glue or padding, every one of them holding U+0000 or U+0001 (*Not covered*), none
without (the first version: 24 and 2, every one holding one too); the #96 re-audit's grammar,
300,000 texts: no text readable that main masks; `cli.app._masked`, 20,000 messages: no stretch
main masks and no planted-secret window readable. The auditor's fuzzers (its own grammar and
generators, a regression being a readable stretch of this change's output inside no readable
stretch of main's, a mask copied from the input counted as text), rerun on this version: its
grammar without U+0000, U+0001 or masks of the A-78 types, 8 draws of 60,000: none (36 at the first
audit); the same without the entropy rule, with registered credentials and through the identity
mask, 3 draws of 40,000 each: none in each mode; its mixed grammar (masks of every type in the
input, U+0000 and U+0001 among the glue), 4 draws of 40,000: 52, every one holding U+0000 or
U+0001 (as at the second audit); the same with Private Use characters sprinkled in, 4 draws of
30,000: none without U+0000 or U+0001 and 27 with (`3a9a4dfa`: the same 7 on the draw compared), no
stand-in in any output; a value of 8 to 40 characters glued between two or three UUIDs, 100,000 and
200,000 tokens: none (157 of the 200,000 on `0b4b1f14`); idempotency, 4 draws of 30,000: every
output a fixed point, here as on main; the output read again by a fresh redactor, 4 draws of
30,000: none changes (426 of 120,000 on `3a9a4dfa`, R2-L3). The share left unmasked, the auditor's
generators: 32-hex 73.4% to 0%, 40-hex 48.8% to 0%, 64-hex 5.6% to 0%, UUID v4 40.3% to 0%. Every
prefix 0 of 200 after `_`, `=` and `-` padding; the registered-credential suite equal or better in
every cell; the sinks identical (first version, unchanged by the revisions). End to end, the
auditor's loopback stub answering every turn of JB-CRESCENDO-001 with about 3.8 MiB (a URL whose
user is a GitLab token, a labelled hex value, 155,000 distinct GitLab feed tokens): exit 0 here, on
main and on a trial merge with `fix/no-secret-in-fragments` at `06caf3c3` (exit 3 on `3a9a4dfa`,
R2-H1), no token readable here (144 on main); a scan halted by `--budget-requests 4` and resumed in
another process, the random salt in each: no broken mask in the resumed reports (8 of 20 on
`3a9a4dfa`). Time and peak memory on 4 MB texts, with main's in brackets, on one machine: UUIDs
whose groups are all digits glued by `_` into one token 2.98 s and 169 MiB (2.11 s, 73 MiB), linear
(160 KB 0.11 s, 1 MB 0.71 s, 2 MB 1.40 s; the first version took 32.80 s at 160 KB), by `/` 3.24 s
(1.71 s); the same space-separated 3.15 s and 127 MiB (1.35 s, 53 MiB, which left most of each
readable); v4 UUIDs 1.98 s (2.41 s); UUIDs after phone numbers 2.81 s (1.50 s); `0x` and 80 hex
digits 1.34 s (1.16 s); base64 tokens 1.92 s (1.46 s); prose 1.01 s (0.83 s); the 137,468 Private
Use characters 0.13 s (0.08 s; 4.19 s on `3a9a4dfa`, R2-L2). A short text pays what a pass costs
before any rule matches: one search for a literal some late pattern needs, and none for the
stand-ins in a text with no `-` (no UUID holds none); 24,000 evidence keys `user<i>@x.io` are masked
in 0.74 s (main at `0be0be71` 0.67 s; 1.12 s before that prefilter, which put a time-bound test over
its limit under the coverage tracer of a CI runner, PR #113). The ratios, not the seconds, hold
across the two machines measured.

*Not covered.* A key glued to a letter or a digit (40 `0` or 40 `A` before it) is the middle of a
longer word to the late patterns and stays the entropy rule's, which the padding dilutes, as on
main; so are an `AKIA` with a lowercase body (no AWS format) and a random token with no prefix
(22.9% of 16 URL-safe characters and 20.6% of 20 upper-case letters and digits print, as before). A
text holding U+0000 or U+0001 is redacted with them dropped when that masks anything, and with them
shown otherwise (`redact_text`), so a secret one of them splits and that is glued to padding, or a
mask of a type the tool writes with one inside it, is masked or not depending on the rest of the
text, on main as here (an address anywhere in it flips it); masking more, A-78 flips it more often:
every text the fuzzers above find where this change shows what main masks holds one of them, and
none without. In a CLI error, a UUID the number rules read a number in is masked as main masked it
(the number masked, the rest as the other rules leave it); one they read none in is masked whole. A
mask of one of the nine types that a target writes is kept outside a labelled value, where main read
it as text: as a URL's user (`ws://«REDACTED:uuid»:<password>@h`) it stays whole and the password is
masked, where main masked from its first `:` on; nothing it holds is a secret main masked but the
mask's own text. The `secret_shape` evaluator keeps its own rules
(`sk-`, `gh[pousr]_`, `AKIA`, `xox`, JWT, PEM), so a verdict is unchanged.

*Checks.* `tests/test_redactor_key_formats.py` (every format in 12 contexts and with low-entropy
bodies, the shapes, the guards above; 590 tests, 414 fail on `de122e26`),
`tests/reporting/test_own_values_readable.py` (9; 2 fail on `de122e26`),
`tests/store/test_identity_masks_before_a78.py` (13; on `de122e26` it stops at collection, which
has no `identity_masks`, and with the compatibility code taken out, `identity_masks` returning the
current mask only, 9 fail; the first version gave 3, without saying how it was counted; 1 fails on
`3a9a4dfa`, the run row's target ids), `tests/adapters/test_short_credentials.py` (40; on
`de122e26` it stops at collection, which has neither `MIN_CREDENTIAL_LEN` nor
`refuse_short_credential`; the first version's 19 was counted with the two given stand-ins in a
copy of the file), `tests/cli/test_short_credential_cli.py` (18; 15 fail on `de122e26`);
`tests/test_redactor_number_cuts.py` (16; 9 fail on `de122e26`, 1 on `3a9a4dfa`, the block count),
`tests/test_redactor_url_read_check.py` (4; 2 on `de122e26`),
`tests/test_redactor_own_late_masks.py` (35; 5 on `de122e26`, 3 on `3a9a4dfa`: a new process
rereading the output, the record, a key as a URL's user kept), `tests/cli/test_report_target_id.py`
(5: two runs of a UUID-named target in two processes with the random salt, then `diff`; 4 fail on
`de122e26`, where the end-to-end case passes) and `tests/cli/test_uuid_identifiers_readable.py` (4;
2 on `de122e26`). The store test of `test_redactor_own_late_masks.py` passes on `3a9a4dfa` too: its
campaign stays under that version's record; the auditor's 3.8 MiB scan is the check of R2-H1. A test
that imports a name the older tree lacks counts as failing there.

**A-82 (u12's clause; this unit's half, added 2026-10-11) A scope is of version 1 and its
identities name environment variables.** `load_scope` refuses a `version` other than `1` or
`1.<minor>` (`SCOPE_VERSION`; any text was read as this format, CLI audit L7), and an identity
whose `auth_ref` starts with `env://` and names no variable, `[A-Za-z_][A-Za-z0-9_]*`
(`shared.credential_refs`), naming the target and the identity, never the value
(`_refuse_unnamed_variables`; `dottore fleet` wrote `env://<the key>` for a key pasted as
`api_key_env`, M8). Another scheme (`vault://`) is still a reference this loader keeps, refused
where it is read. A scope or policy pack whose name is too long to open is refused by its length,
never the name (`shared.files.read_failure`; `--scope <5,000 digits>` printed `«REDACTED:phone»`
twice, pre-merge audit LOW e). `env://NONE` is the identity that carries no credential: its variable
is never read (`cli.wiring.resolve_auth_ref`). Checked
by `tests/cli/test_credential_variables.py` and `tests/cli/test_report_and_file_versions.py`.

**A-85 (u08's clause; this unit's half, added 2026-10-16).** `load_scope` refuses an identity
`canary` a reply can hold by chance (`policy.scope.weak_canary`): shorter than `MIN_CANARY_CHARS`
(8), holding a space, holding no digit or no letter, or inside an identity's name or the target id
in any case; one holding `{{run_id}}` passes. Refused where it is declared, so every reader of the
scope exits 3 before anything is sent, naming the identity and the reason, never the canary
(`tests/policy/test_scope_canary_shape.py`). The redactor gains one accessor,
`key_format_patterns()` (the late patterns without the UUID), which `secret_shape` reads: the A-78
sentence above that the evaluator "keeps its own rules" held until A-85.

## §8 Out of scope / forbidden
- MUST NOT execute attacks, send requests, or import adapters/evaluators/core/store/reporting.
- MUST NOT persist or print raw secrets/PII (redactor is the only path).
- MUST NOT do network I/O on load; MUST NOT render dangerous payloads (that's u11).
- MUST NOT implement scoring (u07), budget enforcement (u08 enforces; u01 only carries budget
  values from the pack), or evidence encryption (u10, OD-4).
- Not its call: signing scheme (OD-2) · evidence at-rest encryption (OD-4).

## §9 Open decisions (human sign-off → rolls to 00-INDEX ledger)
- **OD-2** scope.yaml signing. **Decided 2026-10-11 under the owner's delegation (best practice),
  revisable: the checksum is signed off as integrity only, and authenticity is an explicit
  non-goal until key management exists (`NON-GOALS.md`).** The optional top-level `checksum:`
  (SHA-256 of the body, verified when present behind the `IntegrityVerifier` seam,
  `load_scope(require_checksum=False)`) catches an accidental edit and an edit that forgot to
  recompute it; it lives in the file it protects, so it cannot catch an editor who recomputes or
  deletes it, and the docs say so wherever they name it. Why not more now: a signature the tool
  verified would be only as good as the list of keys it trusts, and that list, who may sign and
  how a key is revoked are key management the project does not have; a key or a list of keys
  beside the scope proves nothing more than the checksum does. What an operator does instead,
  documented in `docs/MANUAL.md` §4.1 and run for real: sign the scope with tooling whose keys
  they already manage (`ssh-keygen -Y sign` with an `allowed_signers` file, `cosign sign-blob`,
  a signed commit behind review), under two custody rules the recipe states (the reviewer signs
  on their own machine with a key only they hold, and the trusted keys are read from a place the
  scope's editors cannot write; added after the pre-merge audit of `be3f2e71`), verify one
  private copy before `dottore run` and run that copy, and match the report's
  `scope_sha256` (recorded since 2026-10-05, audit D-17) with the signed bytes: for a file with
  LF line ends and no top-level `checksum:` line it is the file's plain SHA-256 (checked: an
  `ssh-keygen -Y verify` that passed, a run, and `shasum -a 256` equal to `run.scope_sha256`;
  one appended line made the verify exit 255). Alternatives not taken: (a) built-in verification
  of a detached signature (an SSH signature against an `allowed_signers` file, or sigstore)
  behind the existing seam, the smallest standard option, deferred until a trusted-keys list has
  an owner, so the seam stays; (b) a keyed MAC with its key in an environment variable, a shared
  secret that in practice sits beside the file in CI; (c) a flag requiring the checksum, which
  adds a step and no assurance, since anyone who edits the file can recompute it.
  `require_checksum=True` stays for a library caller; no CLI path passes it. Reversal (to build
  signing): an `IntegrityVerifier` that checks a detached signature (an SSH signature against an
  `allowed_signers` file, or sigstore) in `policy/scope.py`, a `run` option naming the signature
  and the trusted-keys file, the bullet in `NON-GOALS.md` and the "verifies no signature" of
  `docs/MANUAL.md` §4.1 removed.
- **OD-15** redactor entropy threshold for unknown-shape secrets: global vs per-key-type.
  **Resolved (`00-INDEX.md`): an interim global threshold, documented, then the reuse of u06's
  `secret_shape` policy once it lands.** Status: `secret_shape` has landed with per-key-type
  thresholds; the redactor still uses its own global one (`redactor.py`), so the reuse half is
  pending (audit F-25).
- **OD-26** reading the operator's files. **Decided 2026-10-07 by the owner, built (A-43):** 1
  MiB, the spec loader's figure, for the scope, target, fleet and labels files and the policy
  and signature packs; any file type, with the read bounded at one byte past the cap. **Open:**
  two reads of the tool's own output are still whole, the report JSON `cli/diff.load_findings`
  reads for `dottore diff` and `calibrate`, and the evidence artifacts `store/replay.py` reads
  for `replay` and `run --resume` (512 MiB held twice, 1,092 MiB, in the audit's measure); both
  can pass 1 MiB legitimately, so each cap needs a figure measured on a real run.
- **OD-27** a length bound on the ids of the operator's files. **Decided 2026-10-07: (a), chosen by
  the implementer at the owner's request, built (A-57):** 128 characters for a scope or target id
  and an identity name, refused when the file is loaded, with no pattern; endpoints, `auth_ref`
  references and labels spec ids stay unbounded and are cut in refusals. The question (from A-51): a
  target id was written whole wherever a run that had started printed it, the `--dry-run` plan, the
  `-sV` lines, the reports and the run store. The options were (a) a bound at load,
  refusing files that loaded; (b) cutting the id everywhere it is printed, which leaves reports
  without the id the scope names; (c) leaving it.
- **OD-30** (2026-10-07) Flow nesting under the depth limit still costs per token. A-52 refuses
  a list or a map written past the limit before the scanner pays for what follows, but PyYAML's
  pure-Python scanner walks one possible simple key per open flow level on every token, so a
  document nested close to the limit is accepted at a few times what a flat one costs (A-52
  gives the measure). Options: (A) a lower limit for flow nesting only: the repository's 130
  YAML files nest at most 2 flow levels (6 of any style), so a limit of, say, 20 would bound
  each walk of the scanner at about 20 keys (it passes over them about three times per token)
  without refusing any of them; (B) libyaml's scanner (`yaml.CSafeLoader`, in the installed
  PyYAML), whose composer is C, so the per-node checks of `safe_yaml` (the size count, the tag
  limit, keys written twice, A-52) would have to move to its events, to be measured; (C) leave
  it: each walk is bounded at about 100 keys. **Decided 2026-10-08 by the owner: A, with a limit
  of 20; built (A-58).**
- **OD-33** fleet ids that differ only by case. **Decided 2026-10-07 by the conductor and
  confirmed by the owner the same evening, built (A-56):** refused on every file system, not
  only where the file system folds case: it is portable and the simplest rule (`run` already
  compares report paths case-folded everywhere), and a fleet file then means the same wherever
  it is expanded. What it costs: a fleet with `Prod` and `prod` that expanded on Linux is now
  refused there too, and so is a judge spelled as a target only up to case, which worked. The
  alternative not taken: refuse only where the `--out` directory's file system folds case, found
  by probing it.
- **OD-46** (shared with u12; numbered 2026-10-12; open, owner to decide): a CLI flag that loads a
  policy pack. This unit's half: `policy.packs.load_pack` loads and validates a pack and no command
  calls it, so the 8 specs that declare `requires_policy` never send from `dottore`. Recommended
  (`00-INDEX.md`): one `run` option that loads a pack through that loader, printed in the plan and
  recorded with the run, landing with OD-11's `--allow-pii-elicitation` (u12 §9).
