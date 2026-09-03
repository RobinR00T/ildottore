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
from pathlib import Path
from typing import Protocol, runtime_checkable

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ildottore.policy.errors import ChecksumMismatchError, ScopeError


class Endpoint(BaseModel):
    """One allowlisted endpoint: a host plus a set of allowed path prefixes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str
    path_prefixes: list[str] = Field(default_factory=lambda: ["/"])


class Identity(BaseModel):
    """A named auth identity **reference** - ``auth_ref`` resolves to a secret elsewhere.

    The scope file never carries the secret value itself (S6, contract §2).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    auth_ref: str
    # The tenant-scoped canary this identity legitimately owns (audit M14, multi_identity).
    # A `{{run_id}}` placeholder is substituted per run. If this canary reaches ANOTHER
    # identity's response, authz_leak flags a confirmed cross-tenant leak.
    canary: str | None = None


class ScopeTarget(BaseModel):
    """One authorized target: id, base URL and its endpoint allowlist + identities."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
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


def _strip_checksum_line(raw_text: str) -> str:
    """Return the scope body with any top-level ``checksum:`` line removed.

    The integrity token is computed over the body *excluding* the recorded
    checksum, so a scope can carry its own hash without a chicken-and-egg loop.
    """

    kept = [
        line
        for line in raw_text.splitlines(keepends=True)
        if not line.lstrip().startswith("checksum:")
    ]
    return "".join(kept)


def load_scope(
    path: str | Path,
    *,
    verifier: IntegrityVerifier | None = None,
    require_checksum: bool = False,
) -> Scope:
    """Load, validate and integrity-check a ``scope.yaml`` file.

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
        raw_text = file_path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem error surface
        raise ScopeError(f"cannot read scope file {file_path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ScopeError(f"invalid YAML in scope file {file_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ScopeError(f"scope file {file_path} must be a mapping at top level")

    try:
        scope = Scope.model_validate(data)
    except Exception as exc:  # pydantic.ValidationError → typed ScopeError
        raise ScopeError(f"scope file {file_path} failed validation: {exc}") from exc

    body = _strip_checksum_line(raw_text).encode("utf-8")
    if scope.checksum is not None:
        if not verifier.verify(body, scope.checksum):
            raise ChecksumMismatchError(scope.checksum, verifier.compute(body))
    elif require_checksum:
        raise ScopeError(f"scope file {file_path} is missing a required checksum")

    return scope


def scope_hash(path: str | Path, *, verifier: IntegrityVerifier | None = None) -> str:
    """Return the integrity token over a scope file's body (recorded by a run, S4).

    Stable across calls for identical bytes; excludes the recorded ``checksum``
    line so it equals the value a well-formed scope carries.
    """

    verifier = verifier if verifier is not None else Sha256Verifier()
    raw_text = Path(path).read_text(encoding="utf-8")
    return verifier.compute(_strip_checksum_line(raw_text).encode("utf-8"))
