"""No-exec / no-network load-isolation gate (contract §7).

Loads a malicious YAML fixture (``!!python/object`` tag + anchor bomb) with sockets
monkeypatched to raise, and asserts:
  * parse **rejects** the unsafe tag (no code executes — ``os.system`` is never called),
  * **zero** network calls happen at load,
  * the loader surfaces a PARSE_ERROR rather than crashing.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from ildottore.registry import LintCode, load_path, safe_load_yaml
from ildottore.registry.schema import SafeLoadError


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any socket use during a load an immediate, loud failure."""

    def _boom(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("network access attempted during spec load")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)


def test_malicious_yaml_tag_is_rejected() -> None:
    payload = "x: !!python/object/apply:os.system ['echo pwned']"
    with pytest.raises(SafeLoadError):
        safe_load_yaml(payload)


def test_no_code_executed_via_os_system(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    import os

    def _record(cmd: str) -> int:
        calls.append(cmd)
        return 0

    monkeypatch.setattr(os, "system", _record)
    with pytest.raises(SafeLoadError):
        safe_load_yaml("x: !!python/object/apply:os.system ['echo pwned']")
    assert calls == []  # constructor never ran → os.system untouched


def test_loader_reports_parse_error_on_malicious_pack(packs_root: Path) -> None:
    # No pack.yaml in the malicious dir → loaded as a loose tree; the evil file is the only
    # doc and must produce a PARSE_ERROR, not an exception, with zero specs constructed.
    result = load_path(packs_root / "malicious")
    assert result.errors
    assert any(e.code is LintCode.PARSE_ERROR for e in result.errors)
    assert all(not p.specs for p in result.packs)
