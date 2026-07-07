"""Self-tests for the shared harness scaffolding in ``tests/conftest.py``.

Covers the fixtures and the no-live-socket guard that u14 owns, so the wiring itself is
tested rather than only trusted. Owned by ``u14-self-validation-ci``.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from pathlib import Path

import pytest

from ildottore.adapters.mock import MockTarget


def test_repo_and_fixture_paths_exist(repo_root: Path, fixtures_dir: Path, specs_dir: Path) -> None:
    assert (repo_root / "pyproject.toml").is_file()
    assert fixtures_dir.is_dir()
    assert specs_dir.is_dir()


def test_frozen_clock_advances(frozen_clock: Callable[[], float]) -> None:
    assert frozen_clock() == 0.0
    frozen_clock.advance(2.5)  # type: ignore[attr-defined]
    assert frozen_clock() == 2.5


def test_mock_target_factory_builds_deterministic_target(
    mock_target_factory: Callable[..., MockTarget],
) -> None:
    target = mock_target_factory("hello world", id="t1")
    assert isinstance(target, MockTarget)
    assert target.id == "t1"


def test_no_live_socket_blocks_external_host() -> None:
    """The autouse guard raises on any non-loopback connect attempt."""

    with pytest.raises(RuntimeError, match="No-live-socket guard"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(("198.51.100.7", 443))  # TEST-NET-2, never routable
        finally:
            sock.close()


def test_no_live_socket_allows_loopback() -> None:
    """Loopback is permitted so sqlite / in-process transports keep working."""

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect(("127.0.0.1", port))  # must NOT raise
        finally:
            client.close()
    finally:
        server.close()
