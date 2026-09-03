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


def _remove_dot_segments(path: str) -> str:
    """Resolve ``.``/``..`` segments exactly as the HTTP client will before egress.

    The gate must authorize the SAME path the transport actually requests: ``httpx``
    (and any RFC-3986 client) collapses ``/v1/../admin`` to ``/admin`` before putting
    it on the wire, so a naive prefix check on the raw path is bypassable. This applies
    RFC 3986 §5.2.4 remove_dot_segments (over-popping clamps at root, matching httpx).
    """

    out: list[str] = []
    for seg in path.split("/"):
        if seg == "..":
            if out and out[-1] != "":
                out.pop()
        elif seg != ".":
            out.append(seg)
    resolved = "/".join(out)
    if not resolved.startswith("/"):
        resolved = "/" + resolved
    return resolved or "/"


def _normalize_path(path: str) -> str:
    """Ensure a leading slash and strip a trailing one (except root)."""

    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path


def _split_host_port(value: str) -> tuple[str, int | None]:
    """Split ``host[:port]`` into a lowercased host and an optional int port."""

    host, sep, port = value.partition(":")
    if sep and port.isdigit():
        return host.lower(), int(port)
    return value.lower(), None


def _host_matches(candidate: str, candidate_port: int | None, allowed: str) -> bool:
    """Case-insensitive host match; port-exact **iff** the allowed host pins a port.

    An allowed host of ``api.vendor.com`` matches any port (backward compatible), but
    ``api.vendor.com:443`` matches only port 443, so an operator can refuse egress to
    other ports (e.g. ``:2375`` Docker, ``:22``) on an otherwise-allowed host.
    """

    allowed_host, allowed_port = _split_host_port(allowed)
    if candidate.lower() != allowed_host:
        return False
    return allowed_port is None or allowed_port == candidate_port


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
        # cleartext http is refused except to loopback (a local model like Ollama), so a
        # bearer token is never sent in the clear to a remote host (defense in depth). Other
        # schemes (https, and the offline ``mock://`` used in tests) are left to the host/path
        # check, the real adapters only ever speak http(s) over the wire.
        if parts.scheme == "http" and host.lower() not in ("localhost", "127.0.0.1", "::1"):
            return False
        # Resolve dot-segments to the path the transport will actually request (S3: the
        # gate and the wire must agree, closes the ``/v1/../admin`` bypass).
        path = _remove_dot_segments(parts.path or "/")
        # Fill the scheme's default port so a pinned ``host:443`` matches an implicit-port
        # https URL while still rejecting an explicit ``:2375`` on the same host.
        port = parts.port or (443 if parts.scheme == "https" else 80)
        for endpoint in self._endpoints:
            if _host_matches(host, port, endpoint.host) and _path_allowed(
                path, endpoint.path_prefixes
            ):
                return True
        return False
