"""Application configuration for Il Dottore (u01).

Sources the scanner's own operational secrets (its LLM/judge keys, vault token)
from the **environment or a pluggable vault**, never from files checked into the
repo (S6, AGENTS.md §2). Carries the safety-flag surface - ``--unsafe-render``
(S5, OD-12) and ``--allow-pii-elicitation`` (DL4, OD-11) - as typed config so the
policy engine and the reporter (u11) can read one authoritative state.

This module does **no** network I/O and imports nothing from ``adapters``,
``core`` or any other unit - only ``shared`` types and the stdlib.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, SecretStr


@runtime_checkable
class SecretProvider(Protocol):
    """A pluggable source of scanner secrets (env, vault, KMS…).

    Implementations return ``None`` for an absent key; the raw value never
    passes through a log line (callers wrap it in ``SecretStr``).
    """

    def get(self, key: str) -> str | None: ...


class EnvSecretProvider:
    """Default :class:`SecretProvider` backed by ``os.environ`` (S6).

    A ``prefix`` (default ``DOTTORE_``) namespaces the scanner's own variables so
    they cannot collide with a target's credentials.
    """

    def __init__(self, prefix: str = "DOTTORE_", environ: Mapping[str, str] | None = None) -> None:
        self._prefix = prefix
        self._environ: Mapping[str, str] = os.environ if environ is None else environ

    def get(self, key: str) -> str | None:
        return self._environ.get(f"{self._prefix}{key}")


class SafetyFlags(BaseModel):
    """The run-wide safety opt-in surface (S5 / DL4).

    Both default **off**; nothing dangerous is enabled implicitly (default-deny,
    contract §4 KEEP). ``allow_pii_elicitation`` is audited by the caller.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    unsafe_render: bool = False
    allow_pii_elicitation: bool = False


class AppConfig(BaseModel):
    """Top-level scanner configuration.

    Secrets are :class:`~pydantic.SecretStr` so a stray ``repr``/log never emits
    the raw value; the central redactor is still the masking choke point for any
    string that *does* reach a sink.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    llm_api_key: SecretStr | None = None
    judge_api_key: SecretStr | None = None
    vault_token: SecretStr | None = None
    safety: SafetyFlags = Field(default_factory=SafetyFlags)

    @classmethod
    def from_provider(
        cls,
        provider: SecretProvider | None = None,
        *,
        unsafe_render: bool = False,
        allow_pii_elicitation: bool = False,
    ) -> AppConfig:
        """Build config, sourcing secrets from ``provider`` (env by default).

        No files are read for secrets (S6); no network I/O is performed here.
        """

        src = provider if provider is not None else EnvSecretProvider()

        def _secret(key: str) -> SecretStr | None:
            value = src.get(key)
            return SecretStr(value) if value else None

        return cls(
            llm_api_key=_secret("LLM_API_KEY"),
            judge_api_key=_secret("JUDGE_API_KEY"),
            vault_token=_secret("VAULT_TOKEN"),
            safety=SafetyFlags(
                unsafe_render=unsafe_render,
                allow_pii_elicitation=allow_pii_elicitation,
            ),
        )
