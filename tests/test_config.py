"""Tests for environment configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from ioc_hunter.config import Settings

_ALL_KEYS = (
    "ABUSE_CH_AUTH_KEY",
    "ABUSEIPDB_API_KEY",
    "OTX_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "SHODAN_API_KEY",
    "IOC_CACHE_TTL",
    "IOC_CACHE_DIR",
    "IOC_LOG_LEVEL",
    "IOC_MAX_CONCURRENCY",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Run every test from an isolated cwd with no real env vars leaking in."""
    for key in _ALL_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)


def test_defaults_when_env_empty() -> None:
    settings = Settings.from_env()
    assert settings.abuse_ch_auth_key is None
    assert settings.abuseipdb_api_key is None
    assert settings.cache_ttl == 86_400
    assert settings.cache_dir == Path("./cache")
    assert settings.log_level == "INFO"
    assert settings.max_concurrency == 8


def test_reads_keys_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSE_CH_AUTH_KEY", "abc")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "xyz")
    settings = Settings.from_env()
    assert settings.abuse_ch_auth_key == "abc"
    assert settings.virustotal_api_key == "xyz"


def test_empty_string_is_treated_as_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTX_API_KEY", "   ")
    settings = Settings.from_env()
    assert settings.otx_api_key is None


def test_invalid_int_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IOC_CACHE_TTL", "not-a-number")
    settings = Settings.from_env()
    assert settings.cache_ttl == 86_400


def test_loads_from_dotenv_in_cwd(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("ABUSE_CH_AUTH_KEY=from_dotenv\nIOC_MAX_CONCURRENCY=16\n")
    settings = Settings.from_env()
    assert settings.abuse_ch_auth_key == "from_dotenv"
    assert settings.max_concurrency == 16


def test_explicit_env_wins_over_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".env").write_text("VIRUSTOTAL_API_KEY=from_dotenv\n")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "from_shell")
    settings = Settings.from_env()
    assert settings.virustotal_api_key == "from_shell"
