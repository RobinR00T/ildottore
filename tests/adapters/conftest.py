"""Shared fixtures + cassette/golden loaders for the u04 adapter suite.

No live keys, no real network — every httpx call is stubbed by ``respx`` from a
recorded-style JSON cassette (contract §7 KEEP). A cassette is
``{"status_code": int, "json": {...}}``; a golden is the expected serialized
:class:`~ildottore.shared.models.TokenLogprob` list.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ildottore.policy import EndpointAllowlist
from ildottore.policy.scope import Endpoint

_CASSETTES = Path(__file__).parent / "cassettes"
_GOLDEN = Path(__file__).parent / "golden" / "logprobs"


def load_cassette(provider: str, name: str) -> dict[str, Any]:
    """Load a recorded cassette JSON for ``provider`` (openai/anthropic/rest)."""

    raw = (_CASSETTES / provider / f"{name}.json").read_text(encoding="utf-8")
    return json.loads(raw)  # type: ignore[no-any-return]


def load_golden(name: str) -> list[dict[str, Any]]:
    """Load an expected golden logprob list by name."""

    raw = (_GOLDEN / f"{name}.json").read_text(encoding="utf-8")
    return json.loads(raw)  # type: ignore[no-any-return]


@pytest.fixture
def openai_allowlist() -> EndpointAllowlist:
    """Allowlist authorizing ``api.openai.com/v1``."""

    return EndpointAllowlist([Endpoint(host="api.openai.com", path_prefixes=["/v1"])])


@pytest.fixture
def anthropic_allowlist() -> EndpointAllowlist:
    """Allowlist authorizing ``api.anthropic.com/v1``."""

    return EndpointAllowlist([Endpoint(host="api.anthropic.com", path_prefixes=["/v1"])])


@pytest.fixture
def rest_allowlist() -> EndpointAllowlist:
    """Allowlist authorizing ``llm.example.com/generate``."""

    return EndpointAllowlist([Endpoint(host="llm.example.com", path_prefixes=["/generate"])])
