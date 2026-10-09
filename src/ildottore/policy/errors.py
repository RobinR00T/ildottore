"""Typed errors for the config / scope / policy layer (u01).

Dependency-free (stdlib only) so every layer can import and raise/catch these
without pulling heavy dependencies. All inherit from :class:`PolicyError` so a
caller can catch the whole family at a boundary.
"""

from __future__ import annotations


class PolicyError(Exception):
    """Base class for every u01 (config/scope/policy) error."""


class ScopeError(PolicyError):
    """The ``scope.yaml`` authorization record is malformed or invalid."""


class ScopeChecksumError(ScopeError):
    """The recorded scope checksum does not match the scope body (S4, tamper).

    Its 0.1.0 name, ``ChecksumMismatchError``, is one the redactor masks as high entropy, so an
    error line that wrote the class, as an attempt's error and a halt reason do, would read
    ``«REDACTED:high_entropy:...»`` (u01 A-63).
    """

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        # The digest the CLI may print in clear: the one this tool computed. ``expected`` is
        # whatever the operator typed in the ``checksum:`` field and is not quoted at all: the
        # redactor masked a real sha256 there as high entropy about 19 times in 20, so it
        # mostly appeared in clear when it was NOT a digest, a key typed by mistake (audits of
        # the residuals).
        self.digests = (actual,)
        super().__init__(
            f"scope checksum mismatch: the scope body hashes to {actual!r}, not to the "
            "recorded checksum"
        )


#: The 0.1.0 name, kept because ``ildottore.policy`` exported it: the same class, so code that
#: imports it or catches it still works. An error line writes the class's own name.
ChecksumMismatchError = ScopeChecksumError


class IdentityError(PolicyError):
    """An auth-identity reference could not be resolved (or none were declared)."""


class PolicyPackError(PolicyError):
    """The policy pack is malformed or references unknown categories/specs."""


class NetworkAccessError(PolicyError):
    """A load path attempted network egress (SSRF-safe loading is required, S3)."""
