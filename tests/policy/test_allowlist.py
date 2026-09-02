"""Endpoint allowlist default-deny tests (S3)."""

from __future__ import annotations

import pytest

from ildottore.policy.allowlist import EndpointAllowlist
from ildottore.policy.scope import Endpoint, Identity, ScopeTarget


def _target(endpoints: list[Endpoint]) -> ScopeTarget:
    return ScopeTarget(
        id="t",
        base_url="https://api.acme.test/v1",
        endpoints=endpoints,
        identities=[Identity(name="a", auth_ref="vault://a")],
    )


@pytest.fixture
def allowlist() -> EndpointAllowlist:
    return EndpointAllowlist.from_target(
        _target([Endpoint(host="api.acme.test", path_prefixes=["/v1", "/health"])])
    )


def test_in_scope_host_and_path_allowed(allowlist: EndpointAllowlist) -> None:
    assert allowlist.is_allowed("https://api.acme.test/v1/chat/completions")
    assert allowlist.is_allowed("https://api.acme.test/v1")
    assert allowlist.is_allowed("https://api.acme.test/health")


def test_off_prefix_path_denied(allowlist: EndpointAllowlist) -> None:
    assert not allowlist.is_allowed("https://api.acme.test/admin")


def test_segment_boundary_prevents_prefix_bypass(allowlist: EndpointAllowlist) -> None:
    # /v1beta must NOT be allowed by a /v1 prefix.
    assert not allowlist.is_allowed("https://api.acme.test/v1beta/models")


def test_unknown_host_denied(allowlist: EndpointAllowlist) -> None:
    assert not allowlist.is_allowed("https://evil.test/v1/chat")


def test_host_is_case_and_port_insensitive(allowlist: EndpointAllowlist) -> None:
    assert allowlist.is_allowed("https://API.ACME.TEST:443/v1/chat")


def test_empty_allowlist_denies_everything() -> None:
    empty = EndpointAllowlist([])
    assert not empty.is_allowed("https://api.acme.test/v1/chat")


def test_unparseable_url_denied(allowlist: EndpointAllowlist) -> None:
    assert not allowlist.is_allowed("not a url")
    assert not allowlist.is_allowed("/v1/chat")  # no host


def test_root_prefix_allows_any_path() -> None:
    al = EndpointAllowlist([Endpoint(host="api.acme.test")])  # default prefix "/"
    assert al.is_allowed("https://api.acme.test/anything/at/all")


def test_trailing_slash_prefix_normalized() -> None:
    al = EndpointAllowlist([Endpoint(host="api.acme.test", path_prefixes=["/v1/"])])
    assert al.is_allowed("https://api.acme.test/v1/chat")
    assert al.is_allowed("https://api.acme.test/v1")


# --- audit regressions (2026-09-01) ------------------------------------------


def test_dot_segment_traversal_is_denied(allowlist: EndpointAllowlist) -> None:
    """C1: a ``..`` path that httpx would collapse past the allowed prefix is denied."""

    assert allowlist.is_allowed("https://api.acme.test/v1/chat") is True
    assert allowlist.is_allowed("https://api.acme.test/v1/../admin/keys") is False
    assert allowlist.is_allowed("https://api.acme.test/v1/../../internal") is False
    assert allowlist.is_allowed("https://api.acme.test/v1/./chat") is True  # bare '.' is fine


def test_pinned_port_rejects_other_ports() -> None:
    """M4: an allowed host that pins a port refuses egress to other ports on that host."""

    pinned = EndpointAllowlist([Endpoint(host="api.acme.test:443", path_prefixes=["/v1"])])
    assert pinned.is_allowed("https://api.acme.test/v1/x") is True  # implicit 443
    assert pinned.is_allowed("https://api.acme.test:2375/v1/x") is False  # Docker daemon port


def test_cleartext_http_denied_except_loopback() -> None:
    """Low: http to a remote host is denied (no bearer in cleartext); loopback is allowed."""

    remote = EndpointAllowlist([Endpoint(host="api.acme.test", path_prefixes=["/v1"])])
    assert remote.is_allowed("http://api.acme.test/v1/x") is False
    local = EndpointAllowlist([Endpoint(host="localhost", path_prefixes=["/v1"])])
    assert local.is_allowed("http://localhost:11434/v1/chat/completions") is True
