"""Tests for the async orchestrator."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from ioc_hunter.cache import TICache
from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.engine import Engine
from ioc_hunter.sources.base import Source, SourceResult, Verdict


class _FakeSource(Source):
    """In-process source for engine tests — no HTTP."""

    def __init__(
        self,
        *,
        name: str,
        weight: float = 1.0,
        supported: frozenset[IOCType] | None = None,
        verdict: Verdict = Verdict.MALICIOUS,
        score: float = 0.9,
        delay: float = 0.0,
        requires_key: bool = False,
        api_key: str | None = "present",
        tags: tuple[str, ...] = (),
    ) -> None:
        super().__init__(httpx.AsyncClient(), api_key=api_key)
        self.name = name
        self.weight = weight
        self.supported_types = supported or frozenset({IOCType.IPV4})
        self.requires_key = requires_key
        self._verdict = verdict
        self._score = score
        self._delay = delay
        self._tags = tags
        self.calls = 0
        self.in_flight = 0
        self.peak_in_flight = 0

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        self.calls += 1
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        try:
            if self._delay:
                await asyncio.sleep(self._delay)
            return SourceResult(
                source=self.name,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                verdict=self._verdict,
                score=self._score,
                tags=self._tags,
            )
        finally:
            self.in_flight -= 1


_IOC = IOC(value="1.2.3.4", type=IOCType.IPV4)


@pytest.mark.asyncio
async def test_unconfigured_sources_skipped() -> None:
    src_a = _FakeSource(name="configured", requires_key=True, api_key="K")
    src_b = _FakeSource(name="unconfigured", requires_key=True, api_key=None)
    engine = Engine([src_a, src_b])
    await engine.lookup_one(_IOC)
    assert src_a.calls == 1
    assert src_b.calls == 0


@pytest.mark.asyncio
async def test_unsupported_type_skipped() -> None:
    src_ip = _FakeSource(name="ip-only", supported=frozenset({IOCType.IPV4}))
    src_domain = _FakeSource(name="domain-only", supported=frozenset({IOCType.DOMAIN}))
    engine = Engine([src_ip, src_domain])
    await engine.lookup_one(_IOC)
    assert src_ip.calls == 1
    assert src_domain.calls == 0


@pytest.mark.asyncio
async def test_no_applicable_sources_returns_unknown() -> None:
    src = _FakeSource(name="dom", supported=frozenset({IOCType.DOMAIN}), requires_key=True)
    engine = Engine([src])
    verdict = await engine.lookup_one(_IOC)
    assert verdict.verdict is Verdict.UNKNOWN
    assert src.calls == 0


@pytest.mark.asyncio
async def test_lookup_many_runs_in_parallel() -> None:
    src = _FakeSource(name="slow", delay=0.05)
    engine = Engine([src], max_concurrency=10)

    iocs = [IOC(value=f"1.2.3.{i}", type=IOCType.IPV4) for i in range(5)]
    start = asyncio.get_event_loop().time()
    verdicts = await engine.lookup_many(iocs)
    elapsed = asyncio.get_event_loop().time() - start

    assert len(verdicts) == 5
    # Five 50ms calls in parallel should finish well under 200ms.
    assert elapsed < 0.2


@pytest.mark.asyncio
async def test_semaphore_limits_concurrent_calls() -> None:
    src = _FakeSource(name="slow", delay=0.05)
    engine = Engine([src], max_concurrency=2)

    iocs = [IOC(value=f"1.2.3.{i}", type=IOCType.IPV4) for i in range(6)]
    await engine.lookup_many(iocs)
    assert src.peak_in_flight <= 2


@pytest.mark.asyncio
async def test_cache_hit_skips_source_call(tmp_path: Path) -> None:
    src = _FakeSource(name="cached", verdict=Verdict.MALICIOUS, score=0.9)
    cache = TICache(tmp_path / "engine.db")
    engine = Engine([src], cache=cache)

    # First call populates the cache.
    await engine.lookup_one(_IOC)
    assert src.calls == 1

    # Second call should hit cache and not invoke the source.
    verdict = await engine.lookup_one(_IOC)
    assert src.calls == 1
    assert verdict.verdict is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_cache_miss_then_persist(tmp_path: Path) -> None:
    src = _FakeSource(name="store", verdict=Verdict.MALICIOUS, score=0.7, tags=("apt",))
    cache = TICache(tmp_path / "persist.db")
    engine = Engine([src], cache=cache)
    await engine.lookup_one(_IOC)

    cached = cache.get("store", IOCType.IPV4, "1.2.3.4")
    assert cached is not None
    assert cached.payload["verdict"] == "malicious"
    assert cached.payload["tags"] == ["apt"]


@pytest.mark.asyncio
async def test_active_sources_property() -> None:
    a = _FakeSource(name="a", requires_key=True, api_key="K")
    b = _FakeSource(name="b", requires_key=True, api_key=None)
    c = _FakeSource(name="c", requires_key=False)
    engine = Engine([a, b, c])
    names = {s.name for s in engine.active_sources}
    assert names == {"a", "c"}
