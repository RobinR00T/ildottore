"""``scope.yaml`` loader + validator + integrity verification (u01, S3/S4).

The scope file is the **authorization record** (``docs/02 §3``): it lists the
authorized targets, a per-target endpoint **allowlist** (host + path prefixes)
and ``≥1`` auth identity *reference* (never an inline secret). Loading performs
**no network I/O** (SSRF-safe, ``docs/02 §4``) and verifies file integrity via a
**pluggable verifier** (OD-2: SHA-256 checksum in MVP-1, sigstore later drops in
without a shape change).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ildottore import safe_yaml
from ildottore.policy.errors import ChecksumMismatchError, ScopeError
from ildottore.shared.config_errors import quoted, validation_problems, yaml_problem
from ildottore.shared.files import read_text_capped


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
    ``verify`` checks a recorded token against freshly-computed bytes. SHA-256 in
    MVP-1; a sigstore/cosign implementation can replace this without a shape
    change to :class:`Scope`.
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
    as the other's leak. The canary is not quoted: it is a marker the target must not learn.
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
            if identity.canary in canaries:
                raise ScopeError(
                    f"scope file {file_path} target {quoted(entry.id)}: identity "
                    f"{quoted(identity.name)} declares the canary of another identity; each "
                    "canary has one owner"
                )
            canaries.add(identity.canary)


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
      default); a mismatch raises :class:`ChecksumMismatchError` (S4 tamper).
    * ``require_checksum=True`` rejects a scope that omits its checksum.

    Never performs network I/O (``docs/02 §4``).
    """

    verifier = verifier if verifier is not None else Sha256Verifier()
    file_path = Path(path)
    try:
        raw_text = read_text_capped(file_path)
    except OSError as exc:  # over the 1 MiB cap (A-43), or a filesystem error
        raise ScopeError(f"cannot read scope file {file_path}: {exc}") from exc

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
            raise ChecksumMismatchError(scope.checksum, verifier.compute(body))
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
