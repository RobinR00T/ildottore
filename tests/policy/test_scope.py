"""Scope loader, integrity (S4) and no-network (docs/02 §4) tests."""

from __future__ import annotations

import hashlib
import socket
from pathlib import Path

import pytest

from ildottore.policy.errors import ChecksumMismatchError, ScopeError
from ildottore.policy.scope import (
    Scope,
    Sha256Verifier,
    load_scope,
    scope_hash,
)


def _write(tmp_path: Path, text: str, name: str = "scope.yaml") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_load_valid_single_identity(tmp_path: Path, scope_single_text: str) -> None:
    scope = load_scope(_write(tmp_path, scope_single_text))
    assert isinstance(scope, Scope)
    assert scope.version == "1.0"
    target = scope.target("acme-bot")
    assert target is not None
    assert target.multi_identity is False
    assert len(target.identities) == 1
    assert target.identities[0].auth_ref == "vault://acme/primary"


def test_load_valid_multi_identity(tmp_path: Path, scope_multi_text: str) -> None:
    scope = load_scope(_write(tmp_path, scope_multi_text))
    target = scope.target("acme-bot")
    assert target is not None
    assert target.multi_identity is True


def test_target_out_of_scope_returns_none(tmp_path: Path, scope_single_text: str) -> None:
    scope = load_scope(_write(tmp_path, scope_single_text))
    assert scope.target("unknown") is None


def test_unknown_field_rejected(tmp_path: Path) -> None:
    text = (
        'version: "1.0"\n'
        "targets:\n"
        "  - id: t\n"
        "    base_url: https://x.test\n"
        "    identities:\n"
        "      - name: a\n"
        "        auth_ref: vault://a\n"
        "    bogus_field: nope\n"
    )
    with pytest.raises(ScopeError):
        load_scope(_write(tmp_path, text))


def test_missing_identity_rejected(tmp_path: Path) -> None:
    text = 'version: "1.0"\ntargets:\n  - id: t\n    base_url: https://x.test\n    identities: []\n'
    with pytest.raises(ScopeError):
        load_scope(_write(tmp_path, text))


def test_non_mapping_top_level_rejected(tmp_path: Path) -> None:
    with pytest.raises(ScopeError):
        load_scope(_write(tmp_path, "- just\n- a\n- list\n"))


def test_invalid_yaml_rejected(tmp_path: Path) -> None:
    with pytest.raises(ScopeError):
        load_scope(_write(tmp_path, "version: '1.0'\n  bad: : indent\n"))


def test_checksum_verifies_and_is_stable(tmp_path: Path, scope_single_text: str) -> None:
    body = scope_single_text
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    with_checksum = body + f'checksum: "{digest}"\n'
    path = _write(tmp_path, with_checksum)
    scope = load_scope(path)  # verifies without raising
    assert scope.checksum == digest
    # hash accessor excludes the checksum line and equals the recorded value
    assert scope_hash(path) == digest
    assert scope_hash(path) == scope_hash(path)  # stable


def test_tampered_body_raises_checksum_mismatch(tmp_path: Path, scope_single_text: str) -> None:
    digest = hashlib.sha256(scope_single_text.encode("utf-8")).hexdigest()
    tampered = scope_single_text.replace("acme-bot", "evil-bot")
    path = _write(tmp_path, tampered + f'checksum: "{digest}"\n')
    with pytest.raises(ChecksumMismatchError) as exc:
        load_scope(path)
    assert exc.value.expected == digest


def test_require_checksum_when_absent_raises(tmp_path: Path, scope_single_text: str) -> None:
    with pytest.raises(ScopeError):
        load_scope(_write(tmp_path, scope_single_text), require_checksum=True)


def test_pluggable_verifier(tmp_path: Path, scope_single_text: str) -> None:
    class ConstVerifier:
        def compute(self, raw: bytes) -> str:
            return "CONST"

        def verify(self, raw: bytes, recorded: str) -> bool:
            return recorded == "CONST"

    path = _write(tmp_path, scope_single_text + 'checksum: "CONST"\n')
    scope = load_scope(path, verifier=ConstVerifier())
    assert scope.checksum == "CONST"
    assert scope_hash(path, verifier=ConstVerifier()) == "CONST"


def test_sha256_verifier_roundtrip() -> None:
    v = Sha256Verifier()
    raw = b"hello"
    assert v.verify(raw, v.compute(raw))
    assert not v.verify(raw, "deadbeef")


def test_no_network_on_load(
    tmp_path: Path, scope_single_text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """docs/02 §4: loading a scope (with URL fields) opens zero sockets."""

    calls: list[object] = []

    def _boom(*args: object, **kwargs: object) -> None:
        calls.append(args)
        raise AssertionError("network egress during scope load")

    monkeypatch.setattr(socket.socket, "connect", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    load_scope(_write(tmp_path, scope_single_text))
    assert calls == []
