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
