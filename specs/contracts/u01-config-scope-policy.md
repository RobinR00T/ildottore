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
engine's gate on each attempt), the target id that `run` and `fingerprint` write in front of it, and
the ids the scope authorizes, which they list after it (the first 20, each cut, then `and N more`:
`shared.config_errors.listed`), since a target the scope names and refuses by endpoint or command
came back whole there; the target id in the `--hardened`, stdio and credential refusals of `run`,
and the references the scope declares, listed by the credential refusal (20, each as
`shown_auth_ref` quotes it, and how many more: 3,000 references of 290 characters printed 885,131
bytes), and the variable a reference names when its value holds a control character; an `auth_ref`
reference wherever `shown_auth_ref` quotes one (a literal is still never shown); the target id, and
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
key that is text or a date is written as `str()` writes it (a date stays `2024-01-01`). An endpoint
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
breaks removed, cut and without what precedes the last `@` of its authority (the CLI masks a
password only in the `user:password@` shape, so an empty user, a space or a second `@` printed it;
and a tab or a line break between the two slashes, which urllib removes, hid the authority from a
search for `//`: final audit, 0 leaks in 102,024 refused endpoints of its fuzz since). The adapter
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
table through the CLI with a value past the cut: the line under 2,500 characters, the file named
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
for the 300 characters of the id's `repr` after the opening quote, one more than a cut keeps, with
the line breaks removed first so that a message Rich folds would be caught too (none that quotes an
id goes through Rich today, so that part is defensive). The `-sV` probe ceiling refusal and its
resume notice write the `repr` whole, and no case of that test reaches them. Not covered: a spec id
has a pattern and no length bound, and a run prints it whole (a spec id of 500,003 characters
printed about 507 KB on a mock run, exit 0); `dottore diff` prints a report's target id whole when
two reports disagree, and `dottore diff` and `calibrate` list every target id of a report with
several targets whole, a report being the tool's own output (OD-26) and one written before A-57 able
to hold a longer id; a run stored with a longer id cannot be resumed, its target file being refused
now; and an id may hold control characters, which reach the terminal as they are. Endpoints,
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
