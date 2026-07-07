"""Endpoint allowlist — host + path-prefix **default-deny** matcher (u01, S3).

Adapters (u04) call this to refuse any host/path not explicitly authorized by the
scope. The default answer is always **deny** — an unknown host, an unlisted path,
or an empty allowlist all return ``False`` (contract §4 KEEP). No network I/O:
matching is pure string/URL parsing.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from ildottore.policy.scope import Endpoint, ScopeTarget


def _normalize_path(path: str) -> str:
    """Ensure a leading slash and strip a trailing one (except root)."""

    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path


def _host_matches(candidate: str, allowed: str) -> bool:
    """Case-insensitive exact host match (port-insensitive)."""

    return candidate.split(":", 1)[0].lower() == allowed.split(":", 1)[0].lower()


def _path_allowed(path: str, prefixes: Iterable[str]) -> bool:
    """True if ``path`` lies under any allowed prefix (segment-aware).

    ``/v1`` allows ``/v1`` and ``/v1/chat`` but **not** ``/v1beta`` — a prefix
    only matches on a segment boundary, closing the ``/adminx`` bypass.
    """

    norm = _normalize_path(path)
    for prefix in prefixes:
        pref = _normalize_path(prefix)
        if pref == "/":
            return True
        if norm == pref or norm.startswith(pref + "/"):
            return True
    return False


class EndpointAllowlist:
    """Default-deny matcher over a target's allowlisted endpoints."""

    def __init__(self, endpoints: Iterable[Endpoint]) -> None:
        self._endpoints: list[Endpoint] = list(endpoints)

    @classmethod
    def from_target(cls, target: ScopeTarget) -> EndpointAllowlist:
        """Build an allowlist from a scope target's declared endpoints."""

        return cls(target.endpoints)

    def is_allowed(self, url: str) -> bool:
        """True only if ``url``'s host is allowlisted **and** its path is under an
        allowed prefix. Everything else — unknown host, off-prefix path, empty
        allowlist, unparseable URL — is denied (S3 default-deny).
        """

        parts = urlsplit(url)
        host = parts.hostname
        if not host:
            return False
        path = parts.path or "/"
        for endpoint in self._endpoints:
            if _host_matches(host, endpoint.host) and _path_allowed(path, endpoint.path_prefixes):
                return True
        return False
