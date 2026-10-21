"""``scope.yaml`` loader + validator + integrity verification (u01, S3/S4).

The scope file is the **authorization record** (``docs/02 §3``): it lists the
authorized targets, a per-target endpoint **allowlist** (host + path prefixes)
and ``≥1`` auth identity *reference* (never an inline secret). Loading performs
**no network I/O** (SSRF-safe, ``docs/02 §4``) and verifies file integrity via a
**pluggable verifier**. OD-2, decided 2026-10-11 (under the owner's delegation, revisable): the
SHA-256 checksum is integrity only, and authenticity (who wrote or approved the scope) is a
non-goal until there is key management; an operator signs the file out of band. The verifier
seam stays, so a signature check can drop in without a shape change when that exists.
"""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ildottore import safe_yaml
from ildottore.policy.errors import ScopeChecksumError, ScopeError
from ildottore.shared.config_errors import quoted, validation_problems, yaml_problem
from ildottore.shared.credential_refs import ENV_NAME_RULE, env_name_of, is_env_name
from ildottore.shared.files import read_failure, read_text_capped
from ildottore.shared.folding import folded, visible


class Endpoint(BaseModel):
    """One allowlisted endpoint: a host plus a set of allowed path prefixes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    path_prefixes: list[str] = Field(default_factory=lambda: ["/"])


#: The longest target id or identity name a scope or target file may give (OD-27, decided
#: 2026-10-07). Unbounded, an id of a million characters was printed whole wherever a run that
#: started wrote it: the `--dry-run` plan, the `-sV` lines, the reports and the run store. A
#: fleet's ids are held to 64, as they name files; one written by hand gets twice that. The
#: longest id in this repository's examples is 21 characters. Clause A-57.
MAX_ID_CHARS: Final = 128

#: The scope versions this build reads: ``1`` and ``1.<minor>`` (``"1.0"`` in every example).
SCOPE_VERSION: Final = re.compile(r"1(?:\.[0-9]+)?")

#: The fewest characters an identity's canary may have (u08 A-85), the floor the docs state as
#: "at least 16 random characters". It is the length the entropy floor below lets a random token
#: reach: under it the floor refused most random tokens (an 8 to 10 character one always, since
#: ``n`` distinct characters carry ``n * log2(n)`` bits, 24 to 33.2; a random 12-hex one 46% of the
#: time), while the refusal promised 8 (audit of ``bc5ddcb1``, LOW 2). At 16 it refuses about one
#: random 16-digit number in 200 (4,819 of a million draws), one random 16-hex token in 15,000
#: (68), two lowercase ones in a million, and no letters-and-digits one of 100,000 draws holding
#: no label; a 3-character target id such as ``tgt`` refuses about one random 16-character
#: letters-and-digits token in 1,400 that happens to hold it (a hex one never).
MIN_CANARY_CHARS: Final = 16

#: The fewest bits of character entropy a canary must carry (its length times the Shannon entropy
#: of its characters): `abababababababab` carries 16, `CANARY-B-7f3a91c2` 65, a random 16-digit
#: number about 44. It rates how varied the characters are, not how random the token was.
MIN_CANARY_BITS: Final = 36.0

#: A label (an identity's name, the target id) shorter than this is not looked for inside a canary:
#: one or two characters sit inside most tokens, and a reply naming them names no canary.
MIN_LABEL_CHARS: Final = 3

#: The placeholder a canary may hold, substituted with the run id at run time.
RUN_ID_PLACEHOLDER: Final = "{{run_id}}"


class Identity(BaseModel):
    """A named auth identity **reference** - ``auth_ref`` resolves to a secret elsewhere.

    The scope file never carries the secret value itself (S6, contract §2).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(max_length=MAX_ID_CHARS)
    auth_ref: str
    # The tenant-scoped canary this identity legitimately owns (audit M14, multi_identity).
    # A `{{run_id}}` placeholder is substituted per run. If this canary reaches ANOTHER
    # identity's response, authz_leak flags a confirmed cross-tenant leak.
    canary: str | None = None


class ScopeTarget(BaseModel):
    """One authorized target: id, base URL and its endpoint allowlist + identities."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(max_length=MAX_ID_CHARS)
    base_url: str
    endpoints: list[Endpoint] = Field(default_factory=list)
    identities: list[Identity] = Field(min_length=1)
    # Authorized stdio MCP command lines (exact match). Default-deny: a stdio MCP target is
    # launched only if its command line appears here, mirroring the endpoint allowlist for the
    # over-the-wire transports.
    commands: list[str] = Field(default_factory=list)

    @property
    def multi_identity(self) -> bool:
        """True when ≥2 identities are declared (maps to ``Capabilities.multi_identity``)."""

        return len(self.identities) >= 2


class Scope(BaseModel):
    """The parsed, validated ``scope.yaml`` authorization record (contract §6)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str
    targets: list[ScopeTarget] = Field(min_length=1)
    checksum: str | None = None

    def target(self, target_id: str) -> ScopeTarget | None:
        """Return the authorized target by id, or ``None`` if out of scope."""

        for t in self.targets:
            if t.id == target_id:
                return t
        return None


@runtime_checkable
class IntegrityVerifier(Protocol):
    """Pluggable scope-integrity verifier (OD-2).

    ``compute`` derives an integrity token over the raw scope bytes;
    ``verify`` checks a recorded token against freshly-computed bytes. SHA-256 is the only
    implementation (OD-2: integrity, not authenticity); a signature verifier can replace it
    without a shape change to :class:`Scope` once trusted keys are managed somewhere.
    """

    def compute(self, raw: bytes) -> str: ...

    def verify(self, raw: bytes, recorded: str) -> bool: ...


class Sha256Verifier:
    """Default :class:`IntegrityVerifier` - SHA-256 hex digest of the scope body."""

    def compute(self, raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    def verify(self, raw: bytes, recorded: str) -> bool:
        return self.compute(raw) == recorded


def _refuse_shared_identities(file_path: Path, entry: ScopeTarget) -> None:
    """Refuse two identities of one target with the same name or the same canary.

    The identity sweep keys each response by identity name, so with two ``tenant`` entries the
    second response replaced the first: two identities read as one and ``authz_leak`` had no
    pair to compare, and with three, two merged (pre-merge audit of PR #45). A canary maps back
    to the identity that owns it, so two owners of one canary made each one's own canary read
    as the other's leak. ``authz_leak`` reads a canary case-folded, with its format characters
    and default ignorable code points removed (``shared.folding``, u08 A-87, A-92), so two
    canaries that differ only there are one canary to it, and are refused alike. The canary is
    not quoted: it is a marker the target must not learn.
    """

    names: set[str] = set()
    canaries: set[str] = set()
    for identity in entry.identities:
        if identity.name in names:
            raise ScopeError(
                f"scope file {file_path} target {quoted(entry.id)} declares identity "
                f"{quoted(identity.name)} more than once; each identity needs its own name"
            )
        names.add(identity.name)
        if identity.canary:  # the runner ignores an empty one
            form = folded(identity.canary)
            if form in canaries:
                raise ScopeError(
                    f"scope file {file_path} target {quoted(entry.id)}: identity "
                    f"{quoted(identity.name)} declares the canary of another identity (or one "
                    "that differs from it only in letter case or invisible characters, which "
                    "authz_leak reads as the same); each canary has one owner"
                )
            canaries.add(form)


def weak_canary(canary: str, labels: list[str]) -> str | None:
    """Why ``canary`` is one a reply can hold by chance, or ``None`` for a canary that is not.

    ``authz_leak`` reads an identity's canary in another identity's reply as that identity's data
    received, a confirmed Critical, so a canary ordinary text can hold gave false fails: ``ACME``
    in "your ACME invoice", ``tenant-b`` in "I cannot show tenant-b's records" (pre-merge audit of
    the scoring branch, #112, queued as pre-existing; measured through the CLI on ``7d01521f``:
    five such shapes, each a confirmed Critical, exit 2). A canary needs
    :data:`MIN_CANARY_CHARS` characters, no space and :data:`MIN_CANARY_BITS` of character
    entropy, so a word, a year or a repeated pattern does not pass. ``labels`` are the identities'
    names and the target's id: an operator names an identity after its tenant, and a reply names
    it, so a canary may not be part of one, and one that holds a label (of
    :data:`MIN_LABEL_CHARS` or more, in any case) must pass the same floors without it, read
    case-folded (``tenant-b-2026-10-16`` does not, ``CANARY-TENANT-B-3f9c1e7a5b2d8064`` does:
    refusing every canary that held a label refused random ones, audit of ``bc5ddcb1``, LOW 4).
    Every floor measures the canary as ``authz_leak`` and ``secret_leakage`` read it
    (:func:`~ildottore.shared.folding.folded`: case-folded, invisible characters removed), not as
    written: ``ab`` and the 16 variation selectors passed as written and read as ``ab``, so every
    reply holding ``ab`` was a confirmed Critical (u08 A-93, L3 of the A-92 audit; with 15
    distinct format characters it did before A-92 too). The entropy is that of the folded form,
    so letter case adds none (``AaBbCcDdAaBbCcDd`` carries 32 bits, not 48). The floors hold for
    the visible form too (invisible characters removed, case kept), since case folding can lengthen
    a canary (``ß`` reads as ``ss``): ``Straßenbahnhöfe`` is 15 characters and stays refused. Length
    times entropy never drops as characters are added, so every canary these floors accept, the
    floors as written accepted too (pre-merge audit of A-93, MEDIUM 1).
    A canary holding the run id (:data:`RUN_ID_PLACEHOLDER`) is a new token in every run. A
    heuristic that catches obvious shapes only: a structured id (``invoice-2026-0001``), an
    address, a version or a timestamp of 16 characters or more passes, and so does a long word.
    """

    if RUN_ID_PLACEHOLDER in canary:
        return None
    form, shown = folded(canary), visible(canary)
    hidden = (
        ""
        if shown == canary
        else ", once its invisible characters are removed, as authz_leak reads it"
    )
    if min(len(form), len(shown)) < MIN_CANARY_CHARS:
        return f"it is shorter than {MIN_CANARY_CHARS} characters{hidden}"
    if any(char.isspace() for char in canary):
        return "it holds a space, so it reads as words"
    names = sorted({folded(label) for label in labels}, key=len, reverse=True)
    if any(form in name for name in names):
        return f"it is part of an identity's name or the target id, which a reply can name{hidden}"
    # A label long enough as written or as read is taken out, so the floors accept no canary the
    # floors as written refused (a name of three characters with an invisible one among them).
    rest = form
    for name in sorted(
        {
            folded(label)
            for label in labels
            if max(len(label), len(folded(label))) >= MIN_LABEL_CHARS
        },
        key=len,
        reverse=True,
    ):
        rest = rest.replace(name, "")
    if rest != form and (why := _weak_token(rest)) is not None:
        return (
            "it holds an identity's name or the target id, which a reply can name, and what is "
            f"left without it {why}{hidden}"
        )
    why = _weak_token(form) or _weak_token(shown)
    return None if why is None else f"it {why}{hidden}"


def _weak_token(token: str) -> str | None:
    """How ``token`` falls under the length or the entropy floor (a predicate), or ``None``."""

    if len(token) < MIN_CANARY_CHARS:
        return f"is shorter than {MIN_CANARY_CHARS} characters"
    if _entropy_bits(token) < MIN_CANARY_BITS:
        return "has too few or too repeated characters to be a random token"
    return None


def _entropy_bits(text: str) -> float:
    """``len(text)`` times the Shannon entropy of its characters, in bits."""

    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return -sum(count * math.log2(count / len(text)) for count in counts.values())


def _refuse_weak_canaries(file_path: Path, entry: ScopeTarget) -> None:
    """Refuse an identity canary a reply can hold by chance (:func:`weak_canary`, u08 A-85).

    Refused where it is declared, so every reader of the scope (``run``, ``--dry-run``,
    ``--estimate``, ``-sn``, a resume) stops before anything is sent. ``fleet --run`` writes no
    canary. The canary is not quoted, as in :func:`_refuse_shared_identities`.
    """

    labels = [entry.id, *(identity.name for identity in entry.identities)]
    for identity in entry.identities:
        why = weak_canary(identity.canary, labels) if identity.canary else None
        if why is not None:
            raise ScopeError(
                f"scope file {file_path} target {quoted(entry.id)} identity "
                f"{quoted(identity.name)}: its canary can appear in a reply by chance ({why}), "
                "and authz_leak would read it there as that identity's data received; a canary is "
                f"a token of at least {MIN_CANARY_CHARS} random characters (invisible ones do "
                "not count) with no space, not part of an identity's name or the target id, and "
                "still that long without any it holds: write one (as CANARY-<16 random hex "
                "digits>) and plant it in that identity's data"
            )


def _refuse_unnamed_variables(file_path: Path, entry: ScopeTarget) -> None:
    """Refuse an identity whose ``env://`` reference names no environment variable (u12 A-82).

    ``dottore fleet`` wrote ``auth_ref: env://<the key>`` for a key pasted as ``api_key_env``,
    and this loader took it (CLI audit M8). Never quoted: what follows ``env://`` there is most
    often the key. Another scheme (``vault://``) is a reference this loader keeps, refused
    where it is read.
    """

    for identity in entry.identities:
        name = env_name_of(identity.auth_ref)
        if name is not None and not is_env_name(name):
            raise ScopeError(
                f"scope file {file_path} target {quoted(entry.id)} identity "
                f"{quoted(identity.name)}: auth_ref names no environment variable after env:// "
                f"(a name is {ENV_NAME_RULE}, not shown here); write env://NAME with the "
                "variable's name, never the key"
            )


def _strip_checksum_line(raw_text: str) -> str:
    """Return the scope body with any top-level ``checksum:`` line removed.

    The integrity token is computed over the body *excluding* the recorded
    checksum, so a scope can carry its own hash without a chicken-and-egg loop. Only a line
    that starts at column 0 is that key: an indented ``checksum:`` line (inside a folded
    command line, say) was dropped too, so the digest and the checksum did not cover it and two
    scopes authorizing different commands had one hash (pre-commit audit of D-17).
    """

    # Lines end at "\n" only: `str.splitlines` also cut at U+0085, U+2028 and U+2029, so a
    # `checksum:` "line" could start inside a value (delta audit of D-17). Whether the line
    # removed was really the top-level key is checked by the loader, which parses the rest.
    lines = re.split(r"(?<=\n)", raw_text)  # each line keeps its "\n", as before
    return "".join(line for line in lines if not line.startswith("checksum:"))


def load_scope(
    path: str | Path,
    *,
    verifier: IntegrityVerifier | None = None,
    require_checksum: bool = False,
) -> Scope:
    """Load, validate and integrity-check a ``scope.yaml`` file (:func:`load_scope_with_digest`)."""

    return load_scope_with_digest(path, verifier=verifier, require_checksum=require_checksum)[0]


def load_scope_with_digest(
    path: str | Path,
    *,
    verifier: IntegrityVerifier | None = None,
    require_checksum: bool = False,
) -> tuple[Scope, str]:
    """Load, validate and integrity-check a ``scope.yaml`` file, and digest what was loaded.

    The digest is :func:`scope_hash` computed over the same bytes that were parsed, so a run
    records the record that authorized it, not a second read of a file that may have changed
    in between (audit D-17, threat model S4).

    * Reads at most 1 MiB of the file (``shared.files.read_text_capped``, clause A-43).
    * Parses YAML with a **safe** loader - no code execution, no network.
    * Validates the :class:`Scope` model (default-deny: unknown fields rejected).
    * If a ``checksum`` is present, verifies it via ``verifier`` (SHA-256 by
      default); a mismatch raises :class:`ScopeChecksumError` (S4 tamper).
    * ``require_checksum=True`` rejects a scope that omits its checksum.

    Never performs network I/O (``docs/02 §4``).
    """

    verifier = verifier if verifier is not None else Sha256Verifier()
    file_path = Path(path)
    try:
        raw_text = read_text_capped(file_path)
    except OSError as exc:  # over the 1 MiB cap (A-43), or a filesystem error
        raise ScopeError(read_failure("scope file", file_path, exc)) from exc

    try:
        data = safe_yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ScopeError(f"invalid YAML in scope file {file_path}: {yaml_problem(exc)}") from exc

    if not isinstance(data, dict):
        raise ScopeError(f"scope file {file_path} must be a mapping at top level")

    try:
        scope = Scope.model_validate(data)
    except ValidationError as exc:
        # Location and reason only: pydantic's own text echoes the offending input, and in a
        # scope that can be a key pasted as an `auth_ref` (fourth audit of the residuals).
        raise ScopeError(
            f"scope file {file_path} failed validation: {validation_problems(exc)}"
        ) from exc
    except Exception as exc:  # a validator that raised something pydantic did not wrap
        raise ScopeError(f"scope file {file_path} failed validation: {exc}") from exc

    # Any text was a version, so a scope written for another major version of this format was
    # read as this one (u12 A-82, CLI audit L7).
    if not SCOPE_VERSION.fullmatch(scope.version):
        raise ScopeError(
            f"scope file {file_path} has version {quoted(scope.version)}; this build reads scope "
            'version 1: write version: "1.0" ("1" and "1.<minor>" are read too)'
        )

    # A duplicate id is refused, not resolved. ``Scope.target()`` returns the FIRST match,
    # so two entries for one id meant the first silently won: a permissive entry could
    # shadow a narrowing one (including its identity allowlist, so an ``auth_ref`` the second
    # entry refuses was accepted), and reversing the order turned it into a false refusal.
    # The authorization record has to have one answer per target. ``materialize_fleet``
    # already refuses duplicates on its side, so this closes the same hole on the other.
    seen: set[str] = set()
    for entry in scope.targets:
        if entry.id in seen:
            raise ScopeError(
                f"scope file {file_path} declares target id {quoted(entry.id)} more than once; "
                "an authorization record must have exactly one entry per target"
            )
        seen.add(entry.id)
        _refuse_shared_identities(file_path, entry)
        _refuse_weak_canaries(file_path, entry)
        _refuse_unnamed_variables(file_path, entry)

    stripped = _strip_checksum_line(raw_text)
    if stripped != raw_text:
        # The body the checksum and the run's digest cover must say exactly what was loaded,
        # bar the checksum. A quoted value may continue at column 0 (`- "python srv` then a
        # line `checksum: --port 1"`), and removing that line changed the command without
        # changing the digest: two scopes authorizing different commands had one checksum.
        try:
            rest = safe_yaml.safe_load(stripped)
        except yaml.YAMLError:
            rest = None
        expected = {key: value for key, value in data.items() if key != "checksum"}
        if rest != expected:
            raise ScopeError(
                f"scope file {file_path}: a line starting with `checksum:` is part of another "
                "value, so the checksum would not cover it; keep `checksum:` as one top-level "
                "line and move the value"
            )
    body = stripped.encode("utf-8")
    if scope.checksum is not None:
        if not verifier.verify(body, scope.checksum):
            raise ScopeChecksumError(scope.checksum, verifier.compute(body))
    elif require_checksum:
        raise ScopeError(f"scope file {file_path} is missing a required checksum")

    return scope, verifier.compute(body)


def scope_hash(path: str | Path, *, verifier: IntegrityVerifier | None = None) -> str:
    """Return the integrity token over a scope file's body, to write as its ``checksum:``.

    Stable across calls for identical bytes; excludes the recorded ``checksum``
    line so it equals the value a well-formed scope carries. It does not validate: a file the
    loader refuses (a ``checksum:`` line inside another value) can share its value with one
    that loads. What a run records comes from :func:`load_scope_with_digest`, which refuses it.
    """

    verifier = verifier if verifier is not None else Sha256Verifier()
    raw_text = read_text_capped(path)
    return verifier.compute(_strip_checksum_line(raw_text).encode("utf-8"))
