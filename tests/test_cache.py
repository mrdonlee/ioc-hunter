"""Tests for the SQLite TTL cache."""

from __future__ import annotations

from pathlib import Path

import pytest

from ioc_hunter.cache import TICache
from ioc_hunter.core.types import IOCType


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def cache(tmp_path: Path, clock: FakeClock) -> TICache:
    return TICache(tmp_path / "test.db", default_ttl=60, now=clock)


def test_set_and_get_roundtrip(cache: TICache) -> None:
    payload = {"verdict": "malicious", "confidence": 0.92}
    cache.set("urlhaus", IOCType.URL, "https://evil.com/x", payload)
    entry = cache.get("urlhaus", IOCType.URL, "https://evil.com/x")
    assert entry is not None
    assert entry.payload == payload
    assert entry.source == "urlhaus"
    assert entry.ioc_type is IOCType.URL


def test_miss_returns_none(cache: TICache) -> None:
    assert cache.get("urlhaus", IOCType.URL, "https://nothing.example") is None


def test_expired_entry_returns_none(cache: TICache, clock: FakeClock) -> None:
    cache.set("otx", IOCType.IPV4, "1.2.3.4", {"hit": True}, ttl=10)
    assert cache.get("otx", IOCType.IPV4, "1.2.3.4") is not None
    clock.advance(11)
    assert cache.get("otx", IOCType.IPV4, "1.2.3.4") is None


def test_set_overwrites_existing(cache: TICache) -> None:
    cache.set("vt", IOCType.MD5, "abc" * 11, {"score": 1})
    cache.set("vt", IOCType.MD5, "abc" * 11, {"score": 99})
    entry = cache.get("vt", IOCType.MD5, "abc" * 11)
    assert entry is not None
    assert entry.payload == {"score": 99}


def test_purge_expired(cache: TICache, clock: FakeClock) -> None:
    cache.set("a", IOCType.DOMAIN, "evil.com", {}, ttl=5)
    cache.set("a", IOCType.DOMAIN, "still-fresh.com", {}, ttl=120)
    clock.advance(10)
    removed = cache.purge_expired()
    assert removed == 1
    assert cache.get("a", IOCType.DOMAIN, "evil.com") is None
    assert cache.get("a", IOCType.DOMAIN, "still-fresh.com") is not None


def test_stats(cache: TICache, clock: FakeClock) -> None:
    cache.set("s", IOCType.DOMAIN, "fresh.com", {}, ttl=60)
    cache.set("s", IOCType.DOMAIN, "old.com", {}, ttl=5)
    clock.advance(10)
    assert cache.stats() == {"total": 2, "fresh": 1, "expired": 1}


def test_context_manager_closes(tmp_path: Path) -> None:
    db = tmp_path / "ctx.db"
    with TICache(db) as cache:
        cache.set("x", IOCType.IPV4, "9.9.9.9", {"k": "v"})
        assert cache.get("x", IOCType.IPV4, "9.9.9.9") is not None


def test_persists_across_instances(tmp_path: Path) -> None:
    db = tmp_path / "persist.db"
    with TICache(db) as first:
        first.set("p", IOCType.SHA256, "f" * 64, {"persist": True})
    with TICache(db) as second:
        entry = second.get("p", IOCType.SHA256, "f" * 64)
        assert entry is not None
        assert entry.payload == {"persist": True}


def test_payload_with_unicode(cache: TICache) -> None:
    payload = {"actor": "Lazarus", "campaign": "тестовый кейс", "tags": ["apt", "🦠"]}
    cache.set("otx", IOCType.DOMAIN, "evil.com", payload)
    entry = cache.get("otx", IOCType.DOMAIN, "evil.com")
    assert entry is not None
    assert entry.payload == payload


def test_different_sources_are_independent(cache: TICache) -> None:
    cache.set("vt", IOCType.IPV4, "8.8.8.8", {"src": "vt"})
    cache.set("otx", IOCType.IPV4, "8.8.8.8", {"src": "otx"})
    assert cache.get("vt", IOCType.IPV4, "8.8.8.8").payload == {"src": "vt"}
    assert cache.get("otx", IOCType.IPV4, "8.8.8.8").payload == {"src": "otx"}
