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


class ChecksumMismatchError(ScopeError):
    """The recorded scope checksum does not match the scope body (S4, tamper)."""

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"scope checksum mismatch: expected {expected!r}, got {actual!r}")


class IdentityError(PolicyError):
    """An auth-identity reference could not be resolved (or none were declared)."""


class PolicyPackError(PolicyError):
    """The policy pack is malformed or references unknown categories/specs."""


class NetworkAccessError(PolicyError):
    """A load path attempted network egress (SSRF-safe loading is required, S3)."""
