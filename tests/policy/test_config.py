"""AppConfig / secret-sourcing tests (S6) — no secrets from files, env/vault only."""

from __future__ import annotations

import pytest

from ildottore.config import (
    AppConfig,
    EnvSecretProvider,
    SafetyFlags,
    SecretProvider,
)


class DictProvider:
    """A test :class:`SecretProvider` backed by an in-memory dict."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, key: str) -> str | None:
        return self._values.get(key)


def test_env_provider_prefixes_and_reads() -> None:
    prov = EnvSecretProvider(prefix="DOTTORE_", environ={"DOTTORE_LLM_API_KEY": "abc"})
    assert prov.get("LLM_API_KEY") == "abc"
    assert prov.get("MISSING") is None


def test_from_provider_sources_secrets() -> None:
    prov = DictProvider(
        {"LLM_API_KEY": "sk-live", "JUDGE_API_KEY": "sk-judge", "VAULT_TOKEN": "hvs.x"}
    )
    cfg = AppConfig.from_provider(prov)
    assert cfg.llm_api_key is not None
    assert cfg.llm_api_key.get_secret_value() == "sk-live"
    assert cfg.judge_api_key is not None
    assert cfg.vault_token is not None


def test_missing_secrets_are_none() -> None:
    cfg = AppConfig.from_provider(DictProvider({}))
    assert cfg.llm_api_key is None
    assert cfg.judge_api_key is None
    assert cfg.vault_token is None


def test_secret_not_in_repr() -> None:
    cfg = AppConfig.from_provider(DictProvider({"LLM_API_KEY": "sk-super-secret"}))
    assert "sk-super-secret" not in repr(cfg)
    assert "sk-super-secret" not in str(cfg)


def test_safety_flags_default_off() -> None:
    cfg = AppConfig.from_provider(DictProvider({}))
    assert cfg.safety.unsafe_render is False
    assert cfg.safety.allow_pii_elicitation is False


def test_safety_flags_surface() -> None:
    cfg = AppConfig.from_provider(DictProvider({}), unsafe_render=True, allow_pii_elicitation=True)
    assert cfg.safety == SafetyFlags(unsafe_render=True, allow_pii_elicitation=True)


def test_default_provider_is_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DOTTORE_LLM_API_KEY", raising=False)
    cfg = AppConfig.from_provider()  # uses EnvSecretProvider by default
    assert cfg.llm_api_key is None


def test_env_provider_satisfies_protocol() -> None:
    prov: SecretProvider = EnvSecretProvider()
    assert isinstance(prov, SecretProvider)


def test_config_is_frozen() -> None:
    cfg = AppConfig.from_provider(DictProvider({}))
    try:
        cfg.safety = SafetyFlags(unsafe_render=True)  # type: ignore[misc]
    except Exception as exc:  # pydantic raises on frozen mutation
        assert "frozen" in str(exc).lower() or "instance is frozen" in str(exc).lower()
    else:  # pragma: no cover
        raise AssertionError("AppConfig should be frozen")
