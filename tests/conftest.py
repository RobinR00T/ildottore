"""Root test configuration - shared, cross-unit fixtures and the no-live-socket guard.

Owned by ``u14-self-validation-ci``. This file provides *only* scaffolding that every unit
can reuse without colliding with the per-unit ``conftest.py`` files (which own their own
domain fixtures). Nothing here duplicates a fixture a sub-package already defines:

* repo/fixture path discovery (``repo_root``, ``fixtures_dir``, ``load_fixture_json``)
* a deterministic :class:`FrozenClock` (``frozen_clock``) for wall-budget tests
* a :class:`MockTarget` factory (``mock_target_factory``) reusing the u03 public surface
* an **autouse, session-scoped no-live-socket guard** (validation-plan layer 5 / CI §4):
  any attempt to open a TCP connection to a non-loopback host during the test run raises,
  so an accidental real provider call fails closed instead of leaking a live key.

The socket guard allows loopback (127.0.0.0/8, ::1) and AF_UNIX so sqlite, tmp files and
in-process transports keep working; ``respx``-based adapter tests never touch a real socket.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from ildottore.adapters.mock import MockScenario, MockTarget
from ildottore.shared.models import Capabilities

# --------------------------------------------------------------------------------------------
# Path discovery
# --------------------------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Absolute path to the repository root (parent of ``tests/`` and ``src/``)."""

    return _REPO_ROOT


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Absolute path to ``tests/fixtures/`` (shared golden/labeled/adversarial corpora)."""

    return _FIXTURES_DIR


@pytest.fixture(scope="session")
def specs_dir(repo_root: Path) -> Path:
    """Absolute path to the shipped ``specs/`` tree (attacks + suites)."""

    return repo_root / "specs"


@pytest.fixture
def load_fixture_json() -> Callable[[str], Any]:
    """Return a loader that reads a JSON file under ``tests/fixtures/`` by relative path."""

    def _load(relative_path: str) -> Any:
        path = _FIXTURES_DIR / relative_path
        return json.loads(path.read_text(encoding="utf-8"))

    return _load


# --------------------------------------------------------------------------------------------
# Deterministic clock (wall-budget / DoS-cap tests, validation-plan layer 13)
# --------------------------------------------------------------------------------------------


class FrozenClock:
    """A monotonic clock the test advances explicitly - no real time passes.

    Matches the ``core`` conftest's ``FakeClock`` shape so a wall-budget test can be lifted
    between units unchanged: callable returns the current seconds, ``advance`` moves it.
    """

    def __init__(self, start: float = 0.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def frozen_clock() -> FrozenClock:
    """A :class:`FrozenClock` starting at t=0 for deterministic budget/timeout assertions."""

    return FrozenClock()


# --------------------------------------------------------------------------------------------
# MockTarget factory (golden-harness wiring, validation-plan layer 6)
# --------------------------------------------------------------------------------------------


@pytest.fixture
def mock_target_factory() -> Callable[..., MockTarget]:
    """Return a factory that builds a deterministic :class:`MockTarget` from raw responses.

    ``factory(response, *, id=..., capabilities=..., tool_calls=...)`` wraps the u03
    :class:`MockScenario`/:class:`MockTarget` public surface so per-unit tests do not each
    re-import them. ``response`` may be a single string or a sequence (N-run repro).
    """

    def factory(
        response: str | list[str],
        *,
        id: str = "mock",
        capabilities: Capabilities | None = None,
        tool_calls: list[dict[str, Any]] | None = None,
        finish_reason: str | None = None,
    ) -> MockTarget:
        scenario = MockScenario(
            response=response,
            tool_calls=list(tool_calls or []),
            capabilities=capabilities if capabilities is not None else Capabilities(),
            finish_reason=finish_reason,
        )
        return MockTarget(scenario, id=id)

    return factory


# --------------------------------------------------------------------------------------------
# No-live-socket guard (CI contract §4 KEEP: no real provider calls / keys in CI)
# --------------------------------------------------------------------------------------------

_ALLOWED_HOST_PREFIXES = ("127.", "::1", "localhost")


def _is_loopback(address: object) -> bool:
    """True when ``address`` is a loopback/local endpoint the guard permits."""

    if isinstance(address, str):  # AF_UNIX socket path
        return True
    if isinstance(address, tuple) and address:
        host = str(address[0])
        return host == "" or any(host.startswith(p) for p in _ALLOWED_HOST_PREFIXES)
    return False


@pytest.fixture(scope="session", autouse=True)
def no_live_socket() -> Iterator[None]:
    """Fail closed if any test opens a real outbound connection to a non-loopback host.

    Guarantees the CI KEEP invariant: adapters are exercised only via cassettes/respx, never
    a live provider. Loopback and AF_UNIX are allowed so sqlite and in-process transports work.
    """

    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: Any, /) -> Any:
        if not _is_loopback(address):
            raise RuntimeError(
                "No-live-socket guard: an outbound connection to a non-loopback host was "
                f"attempted during the test run ({address!r}). Tests must use cassettes/"
                "respx - never a live provider (CI contract §4)."
            )
        return real_connect(self, address)

    socket.socket.connect = guarded_connect  # type: ignore[method-assign,assignment]
    try:
        yield
    finally:
        socket.socket.connect = real_connect  # type: ignore[method-assign]
