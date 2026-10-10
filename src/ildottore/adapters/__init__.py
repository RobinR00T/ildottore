"""Target adapters (u04) - provider-neutral requests over ``httpx`` (ADR-0002).

Public surface: the shared :class:`~ildottore.adapters.base.BaseAdapter` plumbing
(allowlist gate, retry/timeout, logprob mapping, redaction) and the three
concrete adapters - :class:`~ildottore.adapters.openai.OpenAIAdapter`,
:class:`~ildottore.adapters.anthropic.AnthropicAdapter`, the long-tail
:class:`~ildottore.adapters.rest.RestAdapter`, the read-only
:class:`~ildottore.adapters.mcp.MCPAdapter` (Model Context Protocol servers) and the
template-driven :class:`~ildottore.adapters.websocket.WebSocketAdapter` (a chat endpoint
over a WebSocket).
Each implements ``shared.protocols.TargetAdapter`` and enforces u01's default-deny
endpoint allowlist **before** any egress (contract §2/§4).

The mock adapter (``adapters/mock.py``) belongs to u03 and is intentionally not
exported here - this package exposes only the real over-the-wire adapters.
"""

from __future__ import annotations

from ildottore.adapters.anthropic import AnthropicAdapter
from ildottore.adapters.base import (
    AdapterEnvError,
    AdapterError,
    AdapterProductError,
    AdapterStatusError,
    BaseAdapter,
    EndpointNotAllowed,
    ProviderFilterBlock,
    RetryConfig,
    map_logprobs,
)
from ildottore.adapters.mcp import MCPAdapter
from ildottore.adapters.openai import OpenAIAdapter
from ildottore.adapters.rest import RestAdapter, RestTemplate
from ildottore.adapters.websocket import WebSocketAdapter

__all__ = [
    "AdapterEnvError",
    "AdapterError",
    "AdapterProductError",
    "AdapterStatusError",
    "AnthropicAdapter",
    "BaseAdapter",
    "EndpointNotAllowed",
    "MCPAdapter",
    "OpenAIAdapter",
    "ProviderFilterBlock",
    "RestAdapter",
    "RestTemplate",
    "RetryConfig",
    "WebSocketAdapter",
    "map_logprobs",
]
