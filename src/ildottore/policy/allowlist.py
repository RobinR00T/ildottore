"""Endpoint allowlist - host + path-prefix **default-deny** matcher (u01, S3).

Adapters (u04) call this to refuse any host/path not explicitly authorized by the
scope. The default answer is always **deny** - an unknown host, an unlisted path,
or an empty allowlist all return ``False`` (contract §4 KEEP). No network I/O:
matching is pure string/URL parsing.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from urllib.parse import unquote, urlsplit

from ildottore.policy.scope import Endpoint, ScopeTarget


def _decode_dot_segments(path: str) -> str:
    """Percent-decode only ``%2e`` (a dot), so ``/v1/%2e%2e/admin`` resolves like ``/v1/../admin``.

    Deliberately narrow: decoding the whole path would change the meaning of an encoded
    slash or an encoded space, and this gate must not rewrite anything the transport will
    send. Only the one sequence that can synthesise a dot segment is decoded.
    """

    if "%2e" not in path and "%2E" not in path:
        return path
    return path.replace("%2e", ".").replace("%2E", ".")


# Sequences an origin may decode into a path separator, or into another percent escape.
# ``%2f`` is an encoded ``/`` (so ``/v1/chat/..%2f..%2fadmin`` is ``/admin`` to a decoding
# origin), ``%5c`` an encoded backslash, and ``%25`` re-encodes a ``%`` (``%252f`` decodes to
# ``%2f``, then to ``/``). Matched case-insensitively.
_ENCODED_SEPARATORS = ("%2f", "%5c", "%25", "%3b")

# Forms only some origins decode, refused for the same reason (left open by the review of
# PR #32, closed 2026-10-04): a ``;`` path parameter (Tomcat and Jetty read ``..;`` as ``..``),
# an IIS ``%uXXXX`` escape, and an overlong UTF-8 sequence (``%c0%ae`` is ``.`` and ``%c0%af``
# is ``/`` to a lenient decoder; never valid UTF-8), including the 5- and 6-byte forms and every
# lead byte from F5 up, none of which UTF-8 allows.
_ORIGIN_DECODED = re.compile(r";|%u[0-9a-f]{4}|%c[01]|%e0%[89]|%f0%8|%f[5-9a-f]", re.IGNORECASE)


def _normalizes_to_separator(path: str) -> bool:
    """True if a non-ASCII character of ``path``, literal or percent-encoded, becomes a dot, a
    slash, a backslash, a percent sign or a semicolon under NFKC, as on an origin that
    normalises Unicode, or if a segment is made only of dots and spaces.

    The fullwidth full stop and solidus, the one- and two-dot leaders and the small full stop
    all do. Listing their encodings missed the literal forms: httpx encodes a literal fullwidth
    dot (U+FF0E) on the way out, after the gate had passed it (pre-commit audit of the leftovers).
    """

    decoded = unquote(path, errors="replace")
    for char in decoded:
        if ord(char) > 0x7F and any(c in "./\\%;" for c in unicodedata.normalize("NFKC", char)):
            return True
    # A segment of dots and spaces only, other than `.` and `..` (resolved above): Windows
    # strips trailing dots and spaces, so `..%20` and `...` are `..` to such an origin. Read
    # after NFKC, so a no-break or ideographic space counts as a space.
    normalized = unicodedata.normalize("NFKC", decoded)
    return any(
        seg not in (".", "..") and seg and set(seg) <= {".", " "} for seg in normalized.split("/")
    )


def _has_ambiguous_separator(path: str) -> bool:
    """True if ``path`` carries a separator the gate cannot resolve the way an origin might.

    Refused rather than decoded: rewriting the path would break the property that the gate
    authorizes exactly what the transport sends. A literal backslash is refused too, since some
    origins (IIS among them) treat it as ``/``. Only the ``%2e`` dot escape used to be handled,
    so an encoded slash walked out of an authorized prefix on an authorized host (audit SEC-03,
    2026-10-03).
    """

    lowered = path.lower()
    return (
        "\\" in path
        or any(seq in lowered for seq in _ENCODED_SEPARATORS)
        or _ORIGIN_DECODED.search(path) is not None
        or _normalizes_to_separator(path)
    )


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
            # Pop ANY segment except the leading root one, empty segments included. Refusing
            # to pop an empty segment made ``/v1/chat/x//../../admin`` resolve to a path under
            # the prefix here while httpx sent ``/v1/admin``: the gate and the wire disagreed
            # with no encoding involved (review of PR #32). A differential test against httpx
            # pins the two together.
            if len(out) > 1:
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
    """Split ``host[:port]`` into a lowercased host and an optional int port.

    A bracketed IPv6 literal (``[::1]``, ``[::1]:8080``) is unwrapped. Partitioning it on the
    first colon used to leave the whole string as the host, so a port-pinned IPv6 entry never
    matched anything and IPv6 targets could not be pinned to a port at all (audit SEC-13).
    A bare IPv6 literal (``::1``) is a host with no port.
    """

    if value.startswith("["):
        host, bracket, rest = value[1:].partition("]")
        if not bracket:
            return value.lower(), None
        if not rest:
            return host.lower(), None
        port = _port(rest[1:]) if rest.startswith(":") else None
        if port is not None:
            return host.lower(), port
        return value.lower(), None
    if value.count(":") > 1:
        return value.lower(), None
    host, sep, text = value.partition(":")
    port = _port(text) if sep else None
    if port is not None:
        return host.lower(), port
    return value.lower(), None


#: The port an entry pins when ``int()`` cannot read its digits: no URL has it.
_UNREADABLE_PORT = -1


def _port(text: str) -> int | None:
    """``text`` as the port an entry pins, or ``None`` when it is not digits.

    ``int()`` refuses digits ``isdigit`` accepts (U+00B2) and more than 4,300 of them: an entry
    pinned to such a port raised, and denied every URL checked after it, its neighbours'
    included (delta audit of A-51). It pins :data:`_UNREADABLE_PORT` now, so it matches nothing
    and the other entries still decide; read as a bare host instead, it matched an IPvFuture
    literal that repeated it, ``[v1.a:<digits>]`` (second delta audit).
    """

    if not text.isdigit():
        return None
    try:
        return int(text)
    except ValueError:
        return _UNREADABLE_PORT


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

    ``/v1`` allows ``/v1`` and ``/v1/chat`` but **not** ``/v1beta`` - a prefix
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


#: Schemes carried over TLS, allowed to any allowlisted host (default port 443).
_SECURE_SCHEMES: frozenset[str] = frozenset({"https", "wss"})
#: Cleartext schemes, allowed to loopback only (default port 80): a credential must not cross
#: the network in the clear.
_CLEARTEXT_SCHEMES: frozenset[str] = frozenset({"http", "ws"})


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
        allowed prefix. Everything else - unknown host, off-prefix path, empty
        allowlist, unparseable URL - is denied (S3 default-deny).

        Unparseable is denied, not raised: urllib refuses a host it cannot read (a bracket, a
        host NFKC turns into a path) or a port that is not a number, with no file named, and
        some of its errors quoted the whole URL, 900 KB from a scope or target file (pre-merge
        audit of A-51). The refusal quotes the URL cut instead.
        """

        try:
            return self._allows(url)
        except ValueError:
            return False

    def _allows(self, url: str) -> bool:
        """:meth:`is_allowed`, raising ``ValueError`` on a URL or an entry it cannot read."""

        parts = urlsplit(url)
        host = parts.hostname
        if not host:
            return False
        # Schemes are ALLOWLISTED, not blocklisted. This used to refuse the literal scheme
        # ``http`` off-loopback and let everything else through to the host/path check, so
        # ``ws://``, ``ftp://``, ``file://`` and a scheme-relative ``//host/path`` all passed.
        # Nothing in the tool spoke those then, which made the invariant rest on adapter
        # implementation rather than on the gate: default-deny has to be the gate's answer.
        # ``mock://`` is the offline scheme (no I/O). The WebSocket adapter speaks ``wss``,
        # which is ``https`` with an upgrade, and cleartext ``ws`` stays loopback-only as
        # ``http`` does, so a handshake token is never sent in the clear to a remote host.
        scheme = parts.scheme.lower()
        if scheme in _CLEARTEXT_SCHEMES:
            if host.lower() not in ("localhost", "127.0.0.1", "::1"):
                return False
        elif scheme not in _SECURE_SCHEMES and scheme != "mock":
            return False
        raw_path = parts.path or "/"
        if _has_ambiguous_separator(raw_path):
            return False
        # Resolve dot-segments to the path the transport will actually request (S3: the
        # gate and the wire must agree, closes the ``/v1/../admin`` bypass). Percent-encoded
        # dot segments are decoded first: httpx forwards ``%2e%2e`` verbatim, so the gate and
        # the wire still agree, but an origin server that decodes it would resolve a path this
        # allowlist never authorized.
        path = _remove_dot_segments(_decode_dot_segments(raw_path))
        # Fill the scheme's default port so a pinned ``host:443`` matches an implicit-port
        # https (or wss) URL while still rejecting an explicit ``:2375`` on the same host.
        port = parts.port or (443 if scheme in _SECURE_SCHEMES else 80)
        for endpoint in self._endpoints:
            if _host_matches(host, port, endpoint.host) and _path_allowed(
                path, endpoint.path_prefixes
            ):
                return True
        return False
